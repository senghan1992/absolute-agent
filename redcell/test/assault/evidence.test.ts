/**
 * assault evidence — 증거(탈취 가능 정보) 수집·redaction 테스트.
 */
import { describe, it, expect } from "vitest";
import { collectEvidence, redactSample, categoryForPath } from "../../src/assault/evidence.js";
import type { ToolOutcome } from "../../src/assault/types.js";
import type { ToolContext } from "../../src/core/types.js";

const ctx: ToolContext = { target: { host: "h", port: 80, intent: "exploit" }, rps: 10 };

function outcome(tool: string, indicators: string[], finding?: ToolOutcome["finding"], data?: Record<string, unknown>): ToolOutcome {
  return { tool, stage: "exploit", ok: true, summary: "", durationMs: 1, fp: { indicators }, finding, data };
}

describe("redactSample", () => {
  it("KEY=value 값·이메일·긴 토큰을 마스킹한다", () => {
    const out = redactSample("DB_PASSWORD=sup3rSecretKey\nemail=kim@corp.local\nTOKEN=abcdefghijklmnopqrstuvwxyz0123456789\n");
    expect(out).not.toContain("sup3rSecretKey");
    expect(out).not.toContain("kim@");
    expect(out).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
    expect(out).toContain("***@");
  });

  it("redact=false 이면 원본 유지", () => {
    expect(redactSample("DB_PASSWORD=sup3rSecretKey", { redact: false })).toBe("DB_PASSWORD=sup3rSecretKey");
  });
});

describe("categoryForPath", () => {
  it("확장자/키워드로 범주를 정한다", () => {
    expect(categoryForPath("/.env")).toBe("secret");
    expect(categoryForPath("/backup.zip")).toBe("backup");
    expect(categoryForPath("/config.yml")).toBe("config");
    expect(categoryForPath("/users/1")).toBe("pii");
    expect(categoryForPath("/robots.txt")).toBe("endpoint");
  });
});

describe("collectEvidence", () => {
  it("지표에서 노출 항목을 만들고 cap/상한을 적용한다", async () => {
    const outs: ToolOutcome[] = [
      outcome("secret_scan", ["exposed /.env", "exposed /backup.zip"]),
      outcome("dir_enum", ["exposed .env"]), // 같은 대상(경로 정규화) 중복 → 1회만
    ];
    const got = await collectEvidence(outs, ctx, { cap: 20, maxItems: 40, grab: async (p) => "x".repeat(200) });
    expect(got.items.length).toBe(2);
    expect(got.grabbed).toBeGreaterThan(0);
    const env = got.items.find((i) => i.label.includes("/.env"));
    expect(env).toBeDefined();
    // cap 적용 + 레드액션된 샘플도 20+200 이하
    expect(env!.sample!.length).toBeLessThanOrEqual(220);
  });

  it("maxItems 를 넘지 않는다", async () => {
    const outs = Array.from({ length: 10 }, (_, k) => outcome("secret_scan", [`exposed /f${k}.env`]));
    const got = await collectEvidence(outs, ctx, { cap: 10, maxItems: 4, grab: async () => "" });
    expect(got.items.length).toBe(4);
    expect(got.items.map((i) => i.id)).toEqual(["ev01", "ev02", "ev03", "ev04"]);
  });

  it("동일 target+label 은 중복 제거한다", async () => {
    const got = await collectEvidence([outcome("secret_scan", ["exposed /.env"]), outcome("secret_scan", ["exposed /.env"])], ctx, { grab: async () => "" });
    expect(got.items.length).toBe(1);
  });
});
describe("collectEvidence — 익스플로잇 실증(exploit) 계열", () => {
  function exploitOutcome(tool: string, evidence: string, indicator: string, title: string): ToolOutcome {
    return outcome(
      tool,
      [indicator],
      { title, severity: "high", evidenceRefs: [] } as ToolOutcome["finding"],
      { evidence },
    );
  }

  it("xss_probe 증거는 exploit 범주로 수집되고 검증(verified)까지 오른다", async () => {
    const ev = "무해 마커가 HTML/JS 컨텍스트에 실행 가능하게 반사됨 (/, 태그/속성 breakout): rcabc123";
    const got = await collectEvidence(
      [exploitOutcome("xss_probe", ev, "reflected-xss /?q", "Reflected XSS (param=q)")],
      ctx,
      { grab: async () => "" },
    );
    expect(got.items).toHaveLength(1);
    const it = got.items[0];
    expect(it.category).toBe("exploit");
    expect(it.label).toContain("반사형 XSS");
    expect(it.verification.status).toBe("verified");
    expect(it.verification.proof).toContain("XSS 실증:");
  });

  it("ssti_probe 증거 → exploit + SSTI 실증", async () => {
    const ev = "산술식이 서버에서 평가되어 결과 58054189 노출 (path=/, payload={{7919*7331}})";
    const got = await collectEvidence(
      [exploitOutcome("ssti_probe", ev, "ssti /?name", "Server-Side Template Injection (param=name)")],
      ctx,
      { grab: async () => "" },
    );
    const it = got.items[0];
    expect(it.category).toBe("exploit");
    expect(it.verification.proof).toContain("SSTI 실증:");
    expect(it.verification.proof).toContain("58054189");
  });

  it("ssrf_probe 증거 → exploit + SSRF 실증", async () => {
    const ev = "메타데이터 시그니처가 응답에 반사됨 (path=/, target=http://169.254.169.254/latest/meta-data/)";
    const got = await collectEvidence(
      [exploitOutcome("ssrf_probe", ev, "ssrf /?url", "SSRF → 클라우드 메타데이터 접근 (param=url)")],
      ctx,
      { grab: async () => "" },
    );
    const it = got.items[0];
    expect(it.category).toBe("exploit");
    expect(it.label).toContain("SSRF");
    expect(it.verification.proof).toContain("SSRF 실증:");
  });

  it("path_traversal 증거 → exploit + LFI 실증(root 라인 확인)", async () => {
    const ev = "unix /etc/passwd 시그니처 노출 (path=/, payload=../../../../../../etc/passwd): root:x:0:0:0:root:/root:/bin/bash";
    const got = await collectEvidence(
      [exploitOutcome("path_traversal", ev, "lfi /?file", "Path Traversal / LFI (param=file)")],
      ctx,
      { grab: async () => "" },
    );
    const it = got.items[0];
    expect(it.category).toBe("exploit");
    expect(it.verification.status).toBe("verified");
    expect(it.verification.proof).toContain("LFI 실증:");
    expect(it.verification.proof).toContain("root");
  });

  it("open_redirect 증거 → exploit + 리다이렉트 실증(canary 도메인)", async () => {
    const ev = "HTTP 302 Location: https://trusted.example.com@redcell-canary.example.net/";
    const got = await collectEvidence(
      [exploitOutcome("open_redirect", ev, "open-redirect /?next", "Open Redirect (param=next)")],
      ctx,
      { grab: async () => "" },
    );
    const it = got.items[0];
    expect(it.category).toBe("exploit");
    expect(it.label).toContain("오픈 리다이렉트");
    expect(it.target).toBe("/?next");
    expect(it.verification.status).toBe("verified");
    expect(it.verification.proof).toContain("오픈 리다이렉트 실증:");
    expect(it.verification.proof).toContain("redcell-canary.example.net");
  });

  it("xxe_probe 증거 → exploit + XXE 실증", async () => {
    const ev = "내부 엔티티가 확장되어 마커 반사됨 → 외부 엔티티(파일/SSRF) 처리 가능성. 서버측 DTD 비활성 권고.";
    const got = await collectEvidence(
      [exploitOutcome("xxe_probe", ev, "xxe /api/import", "XML External Entity 처리 활성 (/api/import)")],
      ctx,
      { grab: async () => "" },
    );
    const it = got.items[0];
    expect(it.category).toBe("exploit");
    expect(it.verification.status).toBe("verified");
    expect(it.verification.proof).toContain("XXE 실증:");
  });

  it("실증 마커가 없는 익스플로잇 신호는 partial, 무관 응답은 unverified", async () => {
    const got = await collectEvidence(
      [
        exploitOutcome("xss_probe", "반사 신호만 있는 문자열", "reflected-xss /?q", "Reflected XSS (param=q)"),
        exploitOutcome("xss_probe", "완전히 무관한 본문", "reflected-xss /?q2", "Reflected XSS (param=q2)"),
      ],
      ctx,
      { grab: async () => "" },
    );
    const [a, b] = got.items;
    expect(a.verification.status).toBe("partial");
    expect(a.verification.proof).toContain("수동 재현 권고");
    expect(b.verification.status).toBe("unverified");
  });
});
