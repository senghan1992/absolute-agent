/**
 * assault evidence — 증거(탈취 가능 정보) 수집·redaction 테스트.
 */
import { describe, it, expect } from "vitest";
import { collectEvidence, redactSample, categoryForPath } from "../../src/assault/evidence.js";
import type { ToolOutcome } from "../../src/assault/types.js";
import type { ToolContext } from "../../src/core/types.js";

const ctx: ToolContext = { target: { host: "h", port: 80, intent: "exploit" }, rps: 10 };

function outcome(tool: string, indicators: string[], finding?: ToolOutcome["finding"]): ToolOutcome {
  return { tool, stage: "exploit", ok: true, summary: "", durationMs: 1, fp: { indicators }, finding };
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
