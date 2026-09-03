/**
 * report — 피해 반경(blast radius) 출력 회귀 테스트.
 *
 * 리포트는 탐지에 그치지 않고 "이 취약점으로 어디까지·얼마나 뚫리는가"를 서술해야 한다.
 *   - 툴이 impact 를 직접 준 경우 그 문장을 그대로 출력
 *   - 안 준 경우 취약점 유형별 기본 피해 반경으로 보강
 */

import { describe, it, expect } from "vitest";
import { toMarkdown } from "../src/report/report.js";
import type { EngagementLog } from "../src/core/types.js";

function log(findings: EngagementLog["findings"]): EngagementLog {
  return {
    target: { host: "127.0.0.1", port: 8080 },
    fingerprint: { service: "nginx" },
    findings,
    usedPlaybooks: [],
    distilled: [],
    transcript: ["[test]"],
  };
}

describe("리포트 피해 반경 출력", () => {
  it("툴이 제공한 impact 문장을 그대로 출력한다", () => {
    const md = toMarkdown(
      log([{ phase: "enumerate", severity: "high", title: "Host Header Injection (/reset)", detail: "d", impact: "재설정 포이즈닝으로 대량 계정 탈취" }]),
    );
    expect(md).toContain("예상 영향(피해 반경): 재설정 포이즈닝으로 대량 계정 탈취");
  });

  it("impact 가 없으면 유형별 기본 피해 반경으로 보강한다", () => {
    const md = toMarkdown(log([{ phase: "exploit", severity: "high", title: "SQL Injection (param=id)", detail: "d" }]));
    expect(md).toMatch(/예상 영향\(피해 반경\):.*(DB|덤프|유출)/);
  });

  it("info 만 있으면 상세/피해 반경 섹션이 없다", () => {
    const md = toMarkdown(log([{ phase: "recon", severity: "info", title: "banner", detail: "d" }]));
    expect(md).not.toContain("예상 영향(피해 반경)");
  });
});

describe("게이트 커버리지 면책은 판정과 무관하게 항상 출력한다(거짓 안전 방지)", () => {
  const cov = {
    reachable: true,
    toolsRun: 10,
    toolsTotal: 10,
    endpointsDiscovered: 5,
    authScanned: false,
    vulnClassesTested: ["sqli", "xss"],
    requestErrors: 0,
    deterministic: true,
  };
  function gated(verdict: "clean" | "findings" | "inconclusive", findings: EngagementLog["findings"]): string {
    return toMarkdown({ ...log(findings), verdict, verdictReason: "test", coverage: cov });
  }

  it("findings 판정(취약점 발견)에도 범위 밖 계열 면책이 출력된다", () => {
    const md = gated("findings", [{ phase: "exploit", severity: "high", title: "SQL Injection (param=id)", detail: "d" }]);
    expect(md).toMatch(/의존성 CVE\(SCA\)|비즈니스 로직|저장형/);
    expect(md).toMatch(/"전체 안전"은 아닙니다|전체 안전을 보증하지 않습니다/);
  });

  it("clean 판정에도 면책이 출력된다", () => {
    const md = gated("clean", []);
    expect(md).toMatch(/전체 안전을 보증하지 않습니다/);
  });
});
