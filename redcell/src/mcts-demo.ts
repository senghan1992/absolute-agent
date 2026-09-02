#!/usr/bin/env tsx
/**
 * MCTS 트리검색 데모: 랜덤 미로에서 목표를 찾아내는 과정을 탐색량별로 비교.
 *   tsx src/mcts-demo.ts [depth] [branching]
 *
 * 탐색 반복(iterations)이 늘수록 더 깊은 미로도 안정적으로 푼다.
 */

import { GraphLab, buildRandomTree } from "./explore/graph-lab.js";
import { Mcts } from "./explore/mcts.js";

function seeded(seed: number): () => number {
  let s = seed >>> 0;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 0xffffffff;
}

async function main(): Promise<void> {
  const depth = Number(process.argv[2] ?? 5);
  const branching = Number(process.argv[3] ?? 3);
  const { spec, goalPath } = buildRandomTree(depth, branching, seeded(2026));
  const leaves = branching ** depth;

  console.log(`\n=== MCTS 트리검색 데모 ===`);
  console.log(`미로: 깊이 ${depth}, 분기 ${branching} → 리프 ${leaves}개 중 목표 1개(숨김)`);
  console.log(`무작위로 찍으면 성공확률 ≈ ${(100 / leaves).toFixed(2)}%\n`);
  console.log("반복(iter)   해결   경로리턴   루트방문");

  for (const iters of [50, 200, 800, 3000]) {
    const mcts = new Mcts(() => new GraphLab(spec), { iterations: iters, rng: seeded(42) });
    const res = await mcts.search();
    console.log(
      `${String(iters).padStart(6)}      ${res.solved ? "✅" : "❌"}     ${res.bestReturn.toFixed(2).padStart(5)}      ${res.rootVisits}`,
    );
    if (res.solved) {
      console.log(`             찾은 경로: ${res.bestPath.join(" → ")}`);
      console.log(`             실제 목표: ${goalPath.join(" → ")} ${arrEq(res.bestPath, goalPath) ? "(일치)" : ""}`);
      break;
    }
  }
  console.log();
}

function arrEq(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

main().catch((e) => {
  console.error("MCTS 데모 오류:", (e as Error).message);
  process.exit(1);
});
