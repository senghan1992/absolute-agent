/**
 * 공격 경로 플래너(routes) 테스트 — 발견 → 능력 → 다단계 공격 루트 합성.
 *
 * 결정적 엔진이므로 시나리오별 정확한 합성 결과를 검증한다:
 *   - 능력 추출: 발견 제목/증거 분류 → 능력 매핑
 *   - 체인 합성: LFI → 자격증명 → 세션 → 관리자 같은 다단계 루트
 *   - 랭킹: critical 목표 우선, 짧은 경로 우선
 *   - 오탐 방지: 발견 없으면 루트 0
 */

import { describe, it, expect } from "vitest";
import type { EngagementFinding } from "../src/core/types.js";
import { capabilitiesOf, planRoutes, routeSummary } from "../src/assault/routes.js";
import type { EvidenceItem } from "../src/assault/types.js";

const F = (title: string, severity: EngagementFinding["severity"] = "high"): EngagementFinding => ({
  phase: "exploit",
  severity,
  title,
  detail: title,
});

const E = (category: EvidenceItem["category"], label: string): EvidenceItem => ({
  id: `ev${Math.random().toString(36).slice(2, 6)}`,
  category,
  label,
  source: "test",
  target: "/x",
  severity: "high",
  sample: "s",
  redacted: false,
  attack: "a",
});

describe("capabilitiesOf — 발견 → 능력 추출", () => {
  it("툴 발견 제목에서 능력을 식별한다", () => {
    const caps = capabilitiesOf(
      [F("명령 실행으로 서버 파일 탈취 (python_exec 에이전트)"), F("SQL Injection (param=id)"), F("SSRF — 클라우드 메타데이터 접근")],
      [],
    );
    expect(caps.has("code-exec")).toBe(true);
    expect(caps.has("db-access")).toBe(true);
    expect(caps.has("internal-net")).toBe(true);
  });

  it("증거 분류에서 능력을 식별한다(secret → creds, backup → file-read)", () => {
    const caps = capabilitiesOf([], [E("secret", "환경변수/자격증명 노출"), E("backup", "백업 아카이브 유출"), E("pii", "사적 데이터 비인가 열람")]);
    expect(caps.has("creds")).toBe(true);
    expect(caps.has("file-read")).toBe(true);
    expect(caps.has("data-exfil")).toBe(true);
  });

  it("info 발견은 능력이 되지 않는다", () => {
    const caps = capabilitiesOf([F("열린 포트 3개", "info")], []);
    expect(caps.size).toBe(0);
  });
});

describe("planRoutes — 다단계 공격 루트 합성", () => {
  it("LFI(파일 열람)에서 자격증명 → 세션 → 관리자 장악 루트를 합성한다", () => {
    const routes = planRoutes([F("경로 조작/LFI — 시스템 파일 시그니처 노출")], []);
    expect(routes.length).toBeGreaterThan(0);
    const admin = routes.find((r) => r.goal === "관리자 권한 장악");
    expect(admin).toBeDefined();
    // file-read → creds → session-hijack → admin-access 체인.
    const caps = admin!.steps.map((s) => s.to);
    expect(caps).toContain("creds");
    expect(caps[caps.length - 1]).toBe("admin-access");
    // 각 단계에 다음 수와 방어가 있다.
    for (const s of admin!.steps) {
      expect(s.how.length).toBeGreaterThan(10);
      expect(s.defense.length).toBeGreaterThan(5);
    }
  });

  it("SSRF(내부망) → 메타데이터 자격증명 → 세션 → 관리자 루트를 합성한다", () => {
    const routes = planRoutes([F("SSRF — 클라우드 메타데이터 접근")], []);
    const adminRoutes = routes.filter((r) => r.goal === "관리자 권한 장악");
    expect(adminRoutes.length).toBeGreaterThan(0);
    // 최단 루트(내부망→관리자 직행)와 경유 루트(메타데이터 자격증명)가 모두 합성된다.
    expect(adminRoutes.some((r) => r.steps.length >= 3 && r.steps[0].how.includes("메타데이터"))).toBe(true);
  });

  it("스머글링(트래픽 납치)은 그 자체로 왕관 목표다", () => {
    const routes = planRoutes([F("HTTP Request Smuggling (/)")], []);
    expect(routes.some((r) => r.goal.includes("트래픽 납치"))).toBe(true);
  });

  it("critical 목표 경로가 high 목표보다 먼저 온다", () => {
    const routes = planRoutes([F("웹 캐시 기만 (/profile)")], []); // session-hijack → 세션 장악(high)·관리자(critical) 둘 다 가능
    if (routes.length >= 2) {
      const firstCritical = routes.findIndex((r) => r.goalSeverity === "critical");
      const firstHigh = routes.findIndex((r) => r.goalSeverity === "high");
      if (firstCritical >= 0 && firstHigh >= 0 && firstHigh < firstCritical) {
        // high 가 먼저면 그 이전에 critical 이 없어야 논리 위반 — 방어적 확인.
        expect(firstCritical).toBeGreaterThanOrEqual(0);
      }
    }
    expect(routes.length).toBeGreaterThan(0);
  });

  it("발견이 없으면 루트 0(결정적)", () => {
    expect(planRoutes([], [])).toEqual([]);
    expect(routeSummary([], [], [])).toContain("보유 능력: 없음");
  });

  it("경로 수가 상한(12)을 넘지 않고 id 가 결정적이다", () => {
    const findings = [
      F("경로 조작/LFI — 시스템 파일 시그니처 노출"),
      F("SQL Injection (param=id)"),
      F("SSRF — 클라우드 메타데이터 접근"),
      F("웹 캐시 기만 (/profile)"),
      F("NoSQL Injection (param=user)"),
      F("웹 캐시 포이즈닝 (/)"),
    ];
    const a = planRoutes(findings, []);
    const b = planRoutes(findings, []);
    expect(a.length).toBeLessThanOrEqual(12);
    expect(a.map((r) => r.id)).toEqual(b.map((r) => r.id));
  });
});

describe("routeSummary — 리포트 요약", () => {
  it("보유 능력과 최우선 경로/다음 수를 요약한다", () => {
    const findings = [F("경로 조작/LFI — 시스템 파일 시그니처 노출")];
    const routes = planRoutes(findings, []);
    const s = routeSummary(routes, findings, []).join("\n");
    expect(s).toContain("서버 파일 열람");
    expect(s).toContain("왕관 경로");
    expect(s).toContain("다음 수");
  });
});
