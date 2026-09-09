
import { describe, it, expect } from "vitest";
import { deterministicAnalysis } from "../../src/assault/analysis.js";
import type { AssaultTarget, EvidenceItem, EngagementFinding } from "../../src/assault/types.js";

describe("analysis verified-item weighting", () => {
  it("실증(verified) 증거 경로를 미실증 경로보다 먼저 정렬한다", () => {
    const target: AssaultTarget = { host: "lab.local", port: 80, scheme: "http" };
    const exposed: EvidenceItem[] = [
      { id: "ev01", category: "secret", label: "/.env", target: "/.env", severity: "critical", attack: "자격증명 노출", sample: "DB_PASSWORD=***" },
      { id: "ev02", category: "error", label: "DB 오류", target: "/search", severity: "high",
        attack: "UNION 추출", sample: "UNION 데이터 추출 실증: MySQL/MariaDB 8.0.32 (컬럼 1개)",
        verification: { status: "verified", proof: "UNION 실증: … — 검증된 착취" } },
    ] as EvidenceItem[];
    const findings: EngagementFinding[] = [
      { id: "f1", severity: "critical", title: "민감 파일 노출", detail: "/.env 응답", evidenceRefs: ["ev01"] },
      { id: "f2", severity: "high", title: "SQL Injection 취약점 신호 (error-based, param=q)", detail: "/search q", evidenceRefs: ["ev02"] },
    ] as EngagementFinding[];
    const r = deterministicAnalysis({ target, findings, exposed, outcomes: [] });
    expect(r.attackPaths[0].evidenceRefs.join("+")).toContain("ev02");
  });
});
