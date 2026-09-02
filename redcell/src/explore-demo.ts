#!/usr/bin/env tsx
/**
 * 자기발전 데모: MockWebLab 를 반복 공략하며 학습곡선을 출력.
 *   tsx src/explore-demo.ts [episodes] [ucb1|thompson]
 *
 * 초반에는 이것저것 시도(스텝 많음, 실패 잦음)하다가,
 * 에피소드가 쌓일수록 정답 체인(recon→find_admin→sqli_probe→dump_flag)에
 * 빠르게 수렴하는 것을 확인할 수 있다(= 스스로 발전).
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { ContextualBandit, type Policy } from "./explore/bandit.js";
import { Explorer, learningCurve } from "./explore/explorer.js";
import { MockWebLab } from "./explore/env.js";
import { SkillMemory } from "./memory/skill-memory.js";

async function main(): Promise<void> {
  const episodes = Number(process.argv[2] ?? 60);
  const policy = (process.argv[3] as Policy) ?? "ucb1";
  const root = path.dirname(fileURLToPath(import.meta.url));

  const bandit = new ContextualBandit(policy);
  const memory = new SkillMemory(path.join(root, "..", "knowledge", "playbooks"));
  await memory.load();

  const explorer = new Explorer(bandit, { maxSteps: 40, memory });
  const results = await explorer.run(() => new MockWebLab(), episodes);
  const curve = learningCurve(results, 10);

  console.log(`\n=== 자기발전 데모 (policy=${policy}, episodes=${episodes}) ===`);
  console.log(`정답 체인은 숨겨져 있음. 에이전트가 스스로 찾아 학습.\n`);
  console.log("ep   성공률(최근10)  평균스텝(최근10)  막대");
  for (const c of curve) {
    if (c.episode % 5 !== 0 && c.episode !== 1 && c.episode !== episodes) continue;
    const bar = "█".repeat(Math.round(c.successRate * 20));
    console.log(
      `${String(c.episode).padStart(3)}   ${(c.successRate * 100).toFixed(0).padStart(3)}%          ` +
        `${c.avgSteps.toFixed(1).padStart(5)}          ${bar}`,
    );
  }

  const first10 = results.slice(0, 10);
  const last10 = results.slice(-10);
  const avg = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
  console.log(`\n초반 10회 평균 스텝: ${avg(first10.map((r) => r.steps)).toFixed(1)}`);
  console.log(`후반 10회 평균 스텝: ${avg(last10.map((r) => r.steps)).toFixed(1)}`);
  console.log(`후반 10회 성공률: ${(last10.filter((r) => r.success).length / 10 * 100).toFixed(0)}%`);

  console.log(`\n학습된 전략표(상황 → 최적 액션):`);
  for (const ctx of ["s0:unknown", "s1:recon-done", "s2:admin-found", "s3:sqli-open"]) {
    const top = bandit.ranking(ctx)[0];
    if (top) console.log(`  ${ctx.padEnd(16)} → ${top.arm.padEnd(14)} (가치 ${top.value.toFixed(2)}, ${top.pulls}회)`);
  }
  console.log();
}

main().catch((e) => {
  console.error("데모 오류:", (e as Error).message);
  process.exit(1);
});
