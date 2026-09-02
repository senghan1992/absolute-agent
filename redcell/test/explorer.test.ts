import { describe, it, expect } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ContextualBandit } from "../src/explore/bandit.js";
import { Explorer, learningCurve, type StrategyProposer } from "../src/explore/explorer.js";
import { MockWebLab } from "../src/explore/env.js";
import { SkillMemory } from "../src/memory/skill-memory.js";

function seeded(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
}

describe("Explorer 자기발전", () => {
  it("에피소드를 반복할수록 스텝수가 줄고 성공률이 오른다", async () => {
    const bandit = new ContextualBandit("ucb1", Math.SQRT2, seeded(123));
    const explorer = new Explorer(bandit, { maxSteps: 40 });
    const results = await explorer.run(() => new MockWebLab(), 80);

    const first10 = results.slice(0, 10);
    const last10 = results.slice(-10);
    const avgSteps = (rs: typeof results) => rs.reduce((a, r) => a + r.steps, 0) / rs.length;

    // 학습: 후반이 초반보다 확실히 적은 스텝으로 해결
    expect(avgSteps(last10)).toBeLessThan(avgSteps(first10));
    // 정답 체인은 4스텝. 후반엔 거의 최적(<=7)으로 수렴
    expect(avgSteps(last10)).toBeLessThanOrEqual(7);
    // 후반 성공률 100%
    expect(last10.every((r) => r.success)).toBe(true);
  });

  it("학습된 전략표가 정답 체인과 일치한다", async () => {
    const bandit = new ContextualBandit("ucb1", Math.SQRT2, seeded(5));
    const explorer = new Explorer(bandit, { maxSteps: 40 });
    await explorer.run(() => new MockWebLab(), 60);

    expect(bandit.ranking("s0:unknown")[0].arm).toBe("recon");
    expect(bandit.ranking("s1:recon-done")[0].arm).toBe("find_admin");
    expect(bandit.ranking("s2:admin-found")[0].arm).toBe("sqli_probe");
    expect(bandit.ranking("s3:sqli-open")[0].arm).toBe("dump_flag");
  });

  it("성공 경로를 SkillMemory 에 distill 한다", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-explore-"));
    const memory = new SkillMemory(dir);
    await memory.load();
    const bandit = new ContextualBandit("ucb1", Math.SQRT2, seeded(9));
    const explorer = new Explorer(bandit, { maxSteps: 40, memory });

    await explorer.run(() => new MockWebLab(), 15);
    expect(memory.all().length).toBeGreaterThan(0);
    expect(memory.all().some((p) => p.tags?.includes("self-improved"))).toBe(true);
  });

  it("proposer(반성)로 새 전략을 주입할 수 있다", async () => {
    // available 에서 정답을 숨기고, proposer 만이 정답을 제공하는 변형 환경
    class HiddenLab extends MockWebLab {
      step(action: string) {
        return super.step(action);
      }
      reset() {
        const o = super.reset();
        return { ...o, available: o.available.filter((a) => a !== "recon") };
      }
    }
    const proposer: StrategyProposer = {
      propose: () => ["recon"], // 반성 시 정답 전략 제안
    };
    const bandit = new ContextualBandit("ucb1", Math.SQRT2, seeded(3));
    const explorer = new Explorer(bandit, { maxSteps: 60, proposer, reflectAfter: 2 });
    const res = await explorer.runEpisode(new HiddenLab());
    // recon 이 available 에 없어도 반성으로 찾아내 진행했는지
    expect(res.path.some((p) => p.action === "recon")).toBe(true);
  });

  it("learningCurve 는 이동평균을 계산한다", () => {
    const fake = Array.from({ length: 20 }, (_, i) => ({
      success: i >= 10,
      steps: 20 - i,
      totalReward: 0,
      path: [],
    }));
    const curve = learningCurve(fake as any, 5);
    expect(curve.length).toBe(20);
    expect(curve[19].successRate).toBe(1); // 마지막 5개 전부 성공
  });
});
