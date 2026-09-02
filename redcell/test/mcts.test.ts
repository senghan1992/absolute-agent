import { describe, it, expect } from "vitest";
import { GraphLab, buildRandomTree, type GraphSpec } from "../src/explore/graph-lab.js";
import { Mcts } from "../src/explore/mcts.js";

function seeded(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
}

describe("GraphLab", () => {
  it("전이와 막다른 길이 동작한다", () => {
    const spec: GraphSpec = {
      start: "a",
      nodes: {
        a: { actions: { go_b: { next: "b", reward: 0 }, trap: { reward: 0, done: true } } },
        b: { actions: { win: { reward: 1, done: true } } },
      },
    };
    const env = new GraphLab(spec);
    env.reset();
    const r1 = env.step("go_b");
    expect(r1.observation.stateKey).toBe("b");
    const r2 = env.step("win");
    expect(r2.done).toBe(true);
    expect(r2.reward).toBe(1);

    env.reset();
    const trap = env.step("trap");
    expect(trap.done).toBe(true);
    expect(trap.reward).toBe(0); // 막다른 길
  });
});

describe("MCTS", () => {
  it("수제 트리에서 목표 리프로 가는 경로를 찾는다", async () => {
    const spec: GraphSpec = {
      start: "root",
      nodes: {
        root: { actions: { left: { next: "L", reward: 0 }, right: { next: "R", reward: 0 } } },
        L: { actions: { a: { reward: 0, done: true }, b: { next: "LG", reward: 0 } } },
        LG: { actions: { flag: { reward: 1, done: true } } },
        R: { actions: { x: { reward: 0, done: true }, y: { reward: 0, done: true } } },
      },
    };
    const mcts = new Mcts(() => new GraphLab(spec), { iterations: 400, rng: seeded(1) });
    const res = await mcts.search();
    expect(res.solved).toBe(true);
    expect(res.bestReturn).toBe(1);
    expect(res.bestPath).toEqual(["left", "b", "flag"]);
  });

  it("랜덤 미로(깊이3·분기2)에서 목표를 찾아낸다", async () => {
    const { spec, goalPath } = buildRandomTree(3, 2, seeded(123));
    const mcts = new Mcts(() => new GraphLab(spec), { iterations: 600, rng: seeded(7) });
    const res = await mcts.search();
    expect(res.solved).toBe(true);
    expect(res.bestReturn).toBe(1);
    expect(res.bestPath).toEqual(goalPath);
  });

  it("탐색을 늘리면 더 어려운 미로도 푼다(깊이4·분기2)", async () => {
    const { spec } = buildRandomTree(4, 2, seeded(999));
    const mcts = new Mcts(() => new GraphLab(spec), { iterations: 2000, rng: seeded(5) });
    const res = await mcts.search();
    expect(res.solved).toBe(true);
  });
});
