import { describe, it, expect } from "vitest";
import { ContextualBandit, sampleBeta } from "../src/explore/bandit.js";

// 시드 고정 RNG(재현 가능한 테스트)
function seeded(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
}

describe("ContextualBandit", () => {
  it("보상이 높은 arm 으로 수렴한다 (UCB1)", () => {
    const rng = seeded(42);
    const b = new ContextualBandit("ucb1", Math.SQRT2, rng);
    const ctx = "s";
    const arms = ["good", "bad", "meh"];
    const trueReward: Record<string, number> = { good: 0.9, bad: 0.1, meh: 0.4 };

    for (let i = 0; i < 500; i++) {
      const a = b.select(ctx, arms);
      // 확률적 보상
      b.update(ctx, a, rng() < trueReward[a] ? 1 : 0);
    }
    expect(b.ranking(ctx)[0].arm).toBe("good");
    // good 이 가장 많이 당겨졌어야 함(활용)
    const pulls = Object.fromEntries(b.ranking(ctx).map((r) => [r.arm, r.pulls]));
    expect(pulls.good).toBeGreaterThan(pulls.bad);
  });

  it("Thompson 도 최적 arm 으로 수렴한다", () => {
    const rng = seeded(7);
    const b = new ContextualBandit("thompson", Math.SQRT2, rng);
    const arms = ["a", "b"];
    const truth: Record<string, number> = { a: 0.8, b: 0.2 };
    for (let i = 0; i < 400; i++) {
      const x = b.select("c", arms);
      b.update("c", x, rng() < truth[x] ? 1 : 0);
    }
    expect(b.ranking("c")[0].arm).toBe("a");
  });

  it("상황(context)별로 독립적으로 학습한다", () => {
    const rng = seeded(1);
    const b = new ContextualBandit("ucb1", Math.SQRT2, rng);
    for (let i = 0; i < 300; i++) {
      const a1 = b.select("ctxA", ["x", "y"]);
      b.update("ctxA", a1, a1 === "x" ? 1 : 0); // A 에서는 x 가 정답
      const a2 = b.select("ctxB", ["x", "y"]);
      b.update("ctxB", a2, a2 === "y" ? 1 : 0); // B 에서는 y 가 정답
    }
    expect(b.ranking("ctxA")[0].arm).toBe("x");
    expect(b.ranking("ctxB")[0].arm).toBe("y");
  });

  it("snapshot/복원이 통계를 보존한다", () => {
    const b = new ContextualBandit("ucb1");
    b.update("s", "a", 1);
    b.update("s", "a", 0);
    const snap = b.snapshot();
    const b2 = ContextualBandit.fromSnapshot(snap);
    expect(b2.value("s", "a")).toBeCloseTo(0.5);
  });

  it("sampleBeta 는 [0,1] 범위", () => {
    const rng = seeded(99);
    for (let i = 0; i < 100; i++) {
      const x = sampleBeta(2, 5, rng);
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThanOrEqual(1);
    }
  });
});
