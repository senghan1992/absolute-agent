/**
 * assault report — 보고서 렌더링(스모크) 테스트.
 */
import { describe, it, expect } from "vitest";
import { toMarkdown, toJson, logLine, fmtDur, toHtml } from "../../src/assault/report.js";
import type { AssaultReport } from "../../src/assault/types.js";

const rep: AssaultReport = {
  target: { url: "http://h:1/", scheme: "http", host: "h", port: 1, path: "/" },
  startedAt: "2026-01-01T00:00:00.000Z",
  finishedAt: "2026-01-01T00:00:05.000Z",
  durationMs: 5000,
  stages: {
    recon: { status: "done", durationMs: 1000, toolsRun: 3, findings: 0 },
    exploit: { status: "done", durationMs: 2000, toolsRun: 2, findings: 1 },
  },
  outcomes: [],
  findings: [{ phase: "exploit", severity: "high", title: "SQLi", detail: "d", evidence: "e", impact: "i" }],
  coverage: { reachable: true, toolsRun: 6, toolsTotal: 30, endpointsDiscovered: 1, authScanned: false, vulnClassesTested: ["sqli_probe"], requestErrors: 0, deterministic: true },
  verdict: "findings",
  verdictReason: "취약점 1건",
  exposed: [{ id: "ev01", category: "secret", label: "민감 파일 노출: /.env", source: "secret_scan", target: "/.env", severity: "high", attack: "a", sample: "DB_PASSWORD=sup3rSecretKey", redacted: true }],
  attackPaths: [{ id: "p1", label: "자격증명 노출", severity: "critical", chain: ["GET http://h:1/.env", "응답 확인"], evidenceRefs: ["ev01"], source: "deterministic" }],
  defense: [{ severity: "high", control: "시크릿 매니저", detail: "d" }],
  narrative: "# 전투 요약\n본문",
  transcript: ["[00:00:00] http_probe ok"],
  meta: { command: "assault --url http://h:1/", model: "deterministic", authPath: "/x", authKind: "ip-list", aiAnalyzed: false, fullExposure: false, redact: true },
};

describe("report renderers", () => {
  it("toMarkdown 은 7개 섹션과 판정·매니페스트를 렌더링한다", () => {
    const md = toMarkdown(rep);
    expect(md).toContain("전투 보고");
    expect(md).toContain("판정");
    expect(md).toContain("공격 경로");
    expect(md).toContain("방어 권고");
    expect(md).toContain("ev01");
  });

  it("toHtml 은 self-contained 구조(style 포함)를 만든다", () => {
    const html = toHtml(rep);
    expect(html).toMatch(/<!doctype html>/i);
    expect(html).toContain("<style");
    expect(html).toContain("ev01");
  });

  it("toJson 은 설정 메타를 보존한다", () => {
    const j = toJson(rep);
    expect(JSON.parse(j).meta.aiAnalyzed).toBe(false);
    expect(JSON.parse(j).verdict).toBe("findings");
  });

  it("logLine/fmtDur 포맷", () => {
    expect(logLine("http_probe", "ok")).toMatch(/^\[\d{2}:\d{2}:\d{2}\] http_probe\s+ok$/);
    expect(fmtDur(65_000)).toContain("1분");
  });
});
