/**
 * provenance.test.ts — 프로세스 성숙도: 서명 리포트·waiver·직무분리.
 */

import { describe, it, expect } from "vitest";
import {
  computeRulesetHash,
  buildProvenance,
  digestReport,
  signDigest,
  applyWaivers,
  checkSeparationOfDuties,
  type WaiverEntry,
} from "../src/report/provenance.js";
import { toMarkdown } from "../src/report/report.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";
import type { EngagementFinding, EngagementLog, Tool } from "../src/core/types.js";

const tools = new DefaultToolBox().list();

function finding(sev: EngagementFinding["severity"], title: string): EngagementFinding {
  return { phase: "exploit", severity: sev, title, detail: "d", evidence: "e" };
}

describe("룰셋 해시(탐지 규칙 지문)", () => {
  it("동일 툴 집합이면 순서와 무관하게 같은 해시", () => {
    const a = computeRulesetHash(tools);
    const b = computeRulesetHash([...tools].reverse());
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });
  it("툴이 하나라도 바뀌면 해시가 달라진다", () => {
    const base = computeRulesetHash(tools);
    const extra: Tool = { name: "z_new_tool", description: "x", intent: "recon", async run() { return { ok: false, summary: "" }; } };
    expect(computeRulesetHash([...tools, extra])).not.toBe(base);
  });
});

describe("서명 리포트(무결성 다이제스트)", () => {
  const prov = buildProvenance({
    version: "1.2.3",
    tools,
    engagement: "e",
    authorizedBy: "auth",
    operator: "op",
    now: new Date("2026-09-03T00:00:00Z"),
  });

  it("같은 본문·출처면 다이제스트가 재현된다", () => {
    expect(digestReport("BODY", prov)).toBe(digestReport("BODY", prov));
  });
  it("본문이 한 글자라도 바뀌면 다이제스트가 달라진다(위변조 탐지)", () => {
    expect(digestReport("BODY", prov)).not.toBe(digestReport("BODY.", prov));
  });
  it("서명: 키 없으면 무서명, 키 있으면 HMAC(키에 따라 값이 다름)", () => {
    const d = digestReport("BODY", prov);
    expect(signDigest(d, undefined).algo).toBe("sha256-unsigned");
    const s1 = signDigest(d, "k1");
    const s2 = signDigest(d, "k2");
    expect(s1.algo).toBe("hmac-sha256");
    expect(s1.value).not.toBe(s2.value);
    expect(signDigest(d, "k1").value).toBe(s1.value); // 재현 가능
  });
});

describe("waiver(정식 위험수용)", () => {
  const findings = [finding("high", "Missing Security Headers 누락"), finding("critical", "SQL Injection 취약점")];
  const now = new Date("2026-09-03T00:00:00Z");

  it("완전일치 waiver 는 발견을 수용으로 분리(숨김 아님)", () => {
    // 완전일치: 제목과 정확히 같아야 한다(트림·대소문자 무시).
    const waivers: WaiverEntry[] = [{ match: "missing security headers 누락", reason: "수용", approved_by: "CISO", expires: "2026-12-31" }];
    const r = applyWaivers(findings, waivers, now);
    expect(r.waived.map((w) => w.finding.title)).toEqual(["Missing Security Headers 누락"]);
    expect(r.active.map((f) => f.title)).toEqual(["SQL Injection 취약점"]);
    expect(r.expired).toEqual([]);
    expect(r.invalid).toEqual([]);
  });

  it("정규식 waiver 는 /pattern/ 형태로 부분/패턴 매칭한다", () => {
    const waivers: WaiverEntry[] = [{ match: "/^Missing Security Headers/", reason: "수용", approved_by: "CISO", expires: "2026-12-31" }];
    const r = applyWaivers(findings, waivers, now);
    expect(r.waived.map((w) => w.finding.title)).toEqual(["Missing Security Headers 누락"]);
    expect(r.active.map((f) => f.title)).toEqual(["SQL Injection 취약점"]);
  });

  it("부분문자열은 완전일치가 아니므로 수용하지 않는다(과도 억제 방지)", () => {
    // 예전 부분문자열 매칭이라면 "Missing Security"가 수용됐지만, 이제는 완전일치가 아니라 미수용.
    const waivers: WaiverEntry[] = [{ match: "Missing Security", reason: "수용", approved_by: "CISO", expires: "2026-12-31" }];
    const r = applyWaivers(findings, waivers, now);
    expect(r.waived).toHaveLength(0);
    expect(r.active).toHaveLength(2);
  });

  it("빈 패턴/공백 match 는 거부한다(어떤 발견도 수용 안 함 → invalid 보고)", () => {
    const waivers: WaiverEntry[] = [{ match: "   ", reason: "수용", approved_by: "CISO", expires: "2026-12-31" }];
    const r = applyWaivers(findings, waivers, now);
    expect(r.waived).toHaveLength(0);
    expect(r.active).toHaveLength(2);
    expect(r.invalid).toHaveLength(1);
  });

  it("잘못된 정규식 match 는 무효로 거부한다(invalid 보고)", () => {
    const waivers: WaiverEntry[] = [{ match: "/[unclosed/", reason: "수용", approved_by: "CISO", expires: "2026-12-31" }];
    const r = applyWaivers(findings, waivers, now);
    expect(r.waived).toHaveLength(0);
    expect(r.invalid).toHaveLength(1);
  });

  it("만료된 waiver 는 적용하지 않고 발견을 살려둔다(감사용 expired 보고)", () => {
    const waivers: WaiverEntry[] = [{ match: "Missing Security Headers 누락", reason: "수용", approved_by: "CISO", expires: "2026-08-01" }];
    const r = applyWaivers(findings, waivers, now);
    expect(r.waived).toEqual([]);
    expect(r.active).toHaveLength(2);
    expect(r.expired).toHaveLength(1);
  });

  it("waiver 없으면 전부 active", () => {
    const r = applyWaivers(findings, undefined, now);
    expect(r.active).toHaveLength(2);
    expect(r.waived).toHaveLength(0);
  });
});

describe("직무분리(Separation of Duties)", () => {
  it("인가자와 운영자가 같으면 위반", () => {
    expect(checkSeparationOfDuties("alice", "alice").ok).toBe(false);
    expect(checkSeparationOfDuties("Alice", "alice").ok).toBe(false); // 대소문자 무시
  });
  it("운영자 미지정이면 위반(추적 불가)", () => {
    expect(checkSeparationOfDuties("alice", undefined).ok).toBe(false);
    expect(checkSeparationOfDuties("alice", "").ok).toBe(false);
  });
  it("인가자≠운영자면 통과", () => {
    expect(checkSeparationOfDuties("alice", "bob").ok).toBe(true);
  });
});

describe("리포트 통합(출처·수용된 위험 섹션 + 다이제스트 검증)", () => {
  const log: EngagementLog = {
    target: { host: "127.0.0.1", port: 8080 },
    fingerprint: { service: "nginx", tech: ["php"] },
    findings: [finding("critical", "SQL Injection 취약점")],
    usedPlaybooks: [],
    distilled: [],
    transcript: ["[recon] start"],
  };
  const prov = buildProvenance({
    version: "1.2.3",
    tools,
    engagement: "e",
    authorizedBy: "auth",
    operator: "op",
    targetRef: "app@git:9f3c1ab",
    now: new Date("2026-09-03T00:00:00Z"),
  });

  it("출처 섹션과 무결성 다이제스트가 붙는다", () => {
    const md = toMarkdown(log, { provenance: prov });
    expect(md).toContain("리포트 출처·무결성");
    expect(md).toContain(prov.rulesetHash);
    expect(md).toContain("app@git:9f3c1ab");
    expect(md).toMatch(/무결성 다이제스트\(SHA-256\): `[0-9a-f]{64}`/);
  });

  it("수용된 위험(waiver) 섹션에 승인자·만료가 표기된다", () => {
    const md = toMarkdown(log, {
      provenance: prov,
      waived: [{ finding: finding("high", "Missing Security Headers"), waiver: { match: "Missing", reason: "수용", approved_by: "CISO", expires: "2026-12-31" } }],
    });
    expect(md).toContain("수용된 위험(Accepted Risk / Waived)");
    expect(md).toContain("CISO");
    expect(md).toContain("2026-12-31");
  });

  it("배포된 리포트의 다이제스트를 재계산해 위변조를 검증할 수 있다", () => {
    const md = toMarkdown(log, { provenance: prov });
    // 리포트에서 다이제스트 라인을 추출한 뒤, 그 라인 이전(출처 섹션 제외)을 본문으로 재계산.
    const m = /무결성 다이제스트\(SHA-256\): `([0-9a-f]{64})`/.exec(md);
    expect(m).not.toBeNull();
    const printed = m![1];
    const body = md.slice(0, md.indexOf("\n\n## 리포트 출처·무결성"));
    expect(digestReport(body, prov)).toBe(printed);
  });
});
