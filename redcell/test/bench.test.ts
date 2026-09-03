/**
 * 벤치마크 회귀 테스트 — 탐지 정확도를 CI 에서 강제한다.
 *
 * 취약/견고 참조 앱을 띄우고 전체 탐지 케이스를 채점해:
 *   - 재현율(recall) ≥ 90% (취약점을 놓치지 않음)
 *   - 오탐(false positive) = 0 (견고 앱을 취약하다고 오경보하지 않음)
 * 두 기준이 깨지면 테스트가 실패해 회귀를 잡는다.
 */

import { describe, it, expect } from "vitest";
import { scoreBenchmark, CASES } from "../bench/score.js";

describe("탐지 정확도 벤치마크", () => {
  it("취약 앱은 모두 탐지(recall≥0.9)하고 견고 앱은 오탐 0(미끼 포함)", async () => {
    const r = await scoreBenchmark();

    // 실패 시 어떤 케이스가 문제인지 메시지에 드러나도록(미끼는 놓침 개념 없음 → 제외).
    const missed = r.vuln.filter((o, i) => CASES[i].kind !== "decoy" && !o.detected).map((o) => `${o.klass}(${o.tool}) sev=${o.sev}`);
    // 오탐: 견고 앱 탐지 + 미끼를 어느 앱에서든 탐지.
    const falsePos = [
      ...r.hard.filter((o, i) => CASES[i].kind !== "decoy" && o.detected).map((o) => `견고:${o.klass}(${o.tool})`),
      ...r.vuln.filter((o, i) => CASES[i].kind === "decoy" && o.detected).map((o) => `미끼:${o.klass}(${o.tool})`),
      ...r.hard.filter((o, i) => CASES[i].kind === "decoy" && o.detected).map((o) => `미끼:${o.klass}(${o.tool})`),
    ];

    expect(falsePos, `오탐: ${falsePos.join(", ")}`).toEqual([]);
    expect(r.recall, `놓침: ${missed.join(", ")}`).toBeGreaterThanOrEqual(0.9);
    expect(r.fp).toBe(0);
  }, 30_000);

  it("적어도 하나의 적대적 미끼(decoy) 케이스가 존재한다(벤치 정직성 감시)", () => {
    expect(CASES.some((c) => c.kind === "decoy")).toBe(true);
  });

  it("모든 케이스가 채점됐다", async () => {
    const r = await scoreBenchmark();
    const vulnCount = CASES.filter((c) => c.kind !== "decoy").length;
    const decoyCount = CASES.filter((c) => c.kind === "decoy").length;
    expect(r.vuln).toHaveLength(CASES.length);
    expect(r.hard).toHaveLength(CASES.length);
    // vuln 케이스만 tp/fn 에 기여(취약앱 1건씩), 미끼는 fp/tn 에만(두 앱 2건씩).
    expect(r.tp + r.fn).toBe(vulnCount);
    expect(r.fp + r.tn).toBe(vulnCount + decoyCount * 2);
  }, 30_000);
});
