/**
 * RealTargetEnv — 실제(운영자 인가) 대상을 LabEnv 로 감싸는 어댑터.
 *
 * 시뮬레이션에서 학습한 Explorer 를 그대로 실대상에 붙일 수 있게 한다.
 * 상태(stateKey)는 현재까지의 fingerprint 서명으로 만든다 → 밴딧이
 * "이런 스택엔 이 전략" 을 상황별로 학습한다.
 *
 * 액션 = 툴 이름. step() 은 툴을 실행하되, 실행 전 ScopeGuard 를 통과해야 한다
 * (운영자가 authorization.yaml 로 통제하는 지점). 통과 못하면 강한 감점 + 종료 없음.
 *
 * 보상 성형(reward shaping):
 *   +1.0  심각(High/Critical) 발견 → 목표 달성으로 done
 *   +0.5  유의미(low/medium) 발견
 *   +0.3  새로운 fingerprint 사실 획득(정보 진전)
 *   -0.2  scope 차단(하면 안 되는 시도)
 *   -0.05 아무 진전 없음
 */

import type { LabEnv, Observation, StepResult } from "./env.js";
import type { ScopeGuard, Target } from "../scope/scope-guard.js";
import type { ToolBox } from "../core/types.js";
import type { Fingerprint } from "../memory/skill-memory.js";

const SEV_REWARD: Record<string, number> = { critical: 1, high: 1, medium: 0.5, low: 0.5, info: 0 };

export class RealTargetEnv implements LabEnv {
  name: string;
  steps = 0;
  private fp: Fingerprint = {};
  private seenFacts = new Set<string>();
  private foundHigh = false;

  constructor(
    private readonly guard: ScopeGuard,
    private readonly tools: ToolBox,
    private readonly target: Target,
    private readonly maxSteps = 30,
  ) {
    this.name = `real:${target.host}${target.port ? ":" + target.port : ""}`;
  }

  reset(): Observation {
    this.steps = 0;
    this.fp = {};
    this.seenFacts.clear();
    this.foundHigh = false;
    return this.observe();
  }

  private stateKey(): string {
    const parts = [this.fp.service ?? "?", this.fp.version ?? "?", ...(this.fp.tech ?? []).slice().sort()];
    return `fp:${parts.join("/")}`;
  }

  private observe(): Observation {
    return {
      stateKey: this.stateKey(),
      description: `${this.name} — ${this.fp.service ?? "미탐색"}${this.fp.version ? " " + this.fp.version : ""}`,
      available: this.tools.list().map((t) => t.name),
      facts: [...this.seenFacts],
    };
  }

  async step(action: string): Promise<StepResult> {
    this.steps += 1;
    const tool = this.tools.get(action);
    if (!tool) {
      return { observation: this.observe(), reward: -0.1, done: false, info: { error: "unknown tool" } };
    }

    // 운영자 통제 지점: scope 게이트.
    const decision = this.guard.check({ ...this.target, intent: tool.intent });
    if (!decision.allowed) {
      return { observation: this.observe(), reward: -0.2, done: false, info: { blocked: decision.reason } };
    }

    const res = await tool.run({}, { target: this.target, rps: this.guard.requestsPerSecond });

    // fingerprint 진전 계산.
    let novelty = 0;
    if (res.fingerprint) {
      const before = this.seenFacts.size;
      if (res.fingerprint.service && !this.fp.service) this.fp.service = res.fingerprint.service;
      if (res.fingerprint.version && !this.fp.version) this.fp.version = res.fingerprint.version;
      this.fp.tech = dedupe([...(this.fp.tech ?? []), ...(res.fingerprint.tech ?? [])]);
      for (const f of res.fingerprint.indicators ?? []) this.seenFacts.add(f);
      novelty = this.seenFacts.size - before;
    }

    const d = res.data as { severity?: string } | undefined;
    const sev = d?.severity ?? "info";
    let reward = SEV_REWARD[sev] ?? 0;
    if (reward === 0 && novelty > 0) reward = 0.3;
    if (reward === 0) reward = -0.05;

    const done = reward >= 1 || this.foundHigh || this.steps >= this.maxSteps;
    if (reward >= 1) this.foundHigh = true;

    return { observation: this.observe(), reward, done, info: { summary: res.summary, severity: sev, novelty } };
  }
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs.map((x) => x.trim()).filter(Boolean))];
}
