/**
 * 외부 표준 취약앱 블라인드 검증 회귀 테스트.
 *
 * bench/vulnapp.ts(툴에 정답 경로 직접 주입)와 달리 여기서는 RedCell 을 힌트 없이 돌린다:
 * AutoPilot --full 이 crawl→deriveArgs→탐지만으로 DVWA/Juice Shop 스타일 표면을 공략한다.
 *
 * 회귀 바닥선:
 *   1) 탐지 기대 9개 클래스를 블라인드로 전부 잡는다(정찰→공격 자동배선 회귀 방지).
 *   2) sev>=medium 예상 밖 발견(오탐)이 없다.
 *   3) 심은 아키텍처/배선 한계 3개는 실제로 못 잡는다 → 정직한 미탐(과장 방지).
 */

import { describe, it, expect } from "vitest";
import { runExternalBench } from "../bench/external.js";

describe("외부 표준 취약앱 블라인드 검증", () => {
  it("탐지 기대 9개를 블라인드로 전부 잡고, 미탐 기대 3개는 정직하게 못 잡는다", async () => {
    const r = await runExternalBench();

    // 파이프라인이 실제로 돌았는지.
    expect(r.reachable).toBe(true);
    expect(r.endpointsDiscovered).toBeGreaterThanOrEqual(6);
    expect(r.verdict).toBe("findings");

    // 1) 탐지 기대 클래스는 하나도 놓치지 않는다.
    const missedDetectable = r.classes.filter((c) => c.detectable && !c.found);
    expect(missedDetectable.map((c) => c.klass)).toEqual([]);
    expect(r.recallDetectable).toBe(1);

    // 2) 심각(sev>=medium) 오탐 없음.
    const severeFp = r.unexpected.filter((f) => f.severity === "medium" || f.severity === "high" || f.severity === "critical");
    expect(severeFp).toEqual([]);

    // 3) 정직성: 심은 한계 3개는 실제로 미탐이어야 한다("100% 잡는다" 과장 방지).
    const surprises = r.classes.filter((c) => !c.detectable && c.found);
    expect(surprises.map((c) => c.klass)).toEqual([]);

    // 전체(12개) 기준 정직 재현율은 75%(9/12) — 이 값이 실전 신뢰도의 상한 근거다.
    expect(r.recallOverall).toBeCloseTo(9 / 12, 5);
  }, 30_000);
});
