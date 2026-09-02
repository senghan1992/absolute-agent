/**
 * ContextualBandit — "어떤 상황에서 어떤 전략이 통하는가"를 학습.
 *
 * 탐색(exploration) vs 활용(exploitation) 균형이 자기발전의 핵심이다.
 * - context: 상황 키(예: fingerprint 서명 + phase). 상황마다 별도로 학습한다.
 * - arm: 전략 id. 아직 안 써본 arm 은 우선적으로 시도(정보 획득).
 * - reward: [0,1]. 진전이 있었는가/성공했는가의 신호.
 *
 * 두 정책 지원:
 *  - UCB1: mean + c·sqrt(ln N / n). 결정론적, 이론적 후회 경계.
 *  - Thompson(Beta): 성공/실패로 Beta 사후분포에서 샘플링. 확률적, 실전서 강함.
 */

export type Policy = "ucb1" | "thompson";

export interface ArmStats {
  pulls: number;
  rewardSum: number; // reward 누적(평균 계산용)
  successes: number; // Thompson 용(reward 를 성공확률로 취급해 누적)
  failures: number;
}

function emptyArm(): ArmStats {
  return { pulls: 0, rewardSum: 0, successes: 0, failures: 0 };
}

export interface BanditSnapshot {
  [context: string]: { [arm: string]: ArmStats };
}

export class ContextualBandit {
  private table = new Map<string, Map<string, ArmStats>>();

  constructor(
    private readonly policy: Policy = "ucb1",
    private readonly c = Math.SQRT2, // UCB 탐색 계수
    private readonly rng: () => number = Math.random,
  ) {}

  private ctx(context: string): Map<string, ArmStats> {
    let m = this.table.get(context);
    if (!m) {
      m = new Map();
      this.table.set(context, m);
    }
    return m;
  }

  private arm(context: string, armId: string): ArmStats {
    const m = this.ctx(context);
    let a = m.get(armId);
    if (!a) {
      a = emptyArm();
      m.set(armId, a);
    }
    return a;
  }

  /** 주어진 상황에서 후보 arm 중 하나를 선택 */
  select(context: string, arms: string[]): string {
    if (arms.length === 0) throw new Error("bandit.select: 후보 arm 이 없습니다");
    if (arms.length === 1) return arms[0];

    // 안 써본 arm 이 있으면 그것부터(정보 획득 우선).
    const unseen = arms.filter((a) => this.arm(context, a).pulls === 0);
    if (unseen.length > 0) return unseen[Math.floor(this.rng() * unseen.length)];

    return this.policy === "thompson" ? this.selectThompson(context, arms) : this.selectUcb(context, arms);
  }

  private selectUcb(context: string, arms: string[]): string {
    const total = arms.reduce((s, a) => s + this.arm(context, a).pulls, 0);
    const lnN = Math.log(Math.max(1, total));
    let best = arms[0];
    let bestScore = -Infinity;
    for (const a of arms) {
      const st = this.arm(context, a);
      const mean = st.rewardSum / st.pulls;
      const bonus = this.c * Math.sqrt(lnN / st.pulls);
      const score = mean + bonus;
      if (score > bestScore) {
        bestScore = score;
        best = a;
      }
    }
    return best;
  }

  private selectThompson(context: string, arms: string[]): string {
    let best = arms[0];
    let bestSample = -Infinity;
    for (const a of arms) {
      const st = this.arm(context, a);
      const sample = sampleBeta(st.successes + 1, st.failures + 1, this.rng);
      if (sample > bestSample) {
        bestSample = sample;
        best = a;
      }
    }
    return best;
  }

  /** 시도 결과를 반영. reward 는 [0,1] 로 clamp 된다. */
  update(context: string, armId: string, reward: number): void {
    const r = Math.max(0, Math.min(1, reward));
    const st = this.arm(context, armId);
    st.pulls += 1;
    st.rewardSum += r;
    st.successes += r;
    st.failures += 1 - r;
  }

  /** 현재 추정 가치(평균 reward). 미시도는 undefined. */
  value(context: string, armId: string): number | undefined {
    const st = this.ctx(context).get(armId);
    return st && st.pulls > 0 ? st.rewardSum / st.pulls : undefined;
  }

  /** 상황별 arm 순위(가치 내림차순) — 학습된 전략표 확인용 */
  ranking(context: string): Array<{ arm: string; value: number; pulls: number }> {
    const m = this.ctx(context);
    return [...m.entries()]
      .map(([arm, st]) => ({ arm, value: st.pulls ? st.rewardSum / st.pulls : 0, pulls: st.pulls }))
      .sort((a, b) => b.value - a.value);
  }

  snapshot(): BanditSnapshot {
    const out: BanditSnapshot = {};
    for (const [ctx, m] of this.table) {
      out[ctx] = {};
      for (const [arm, st] of m) out[ctx][arm] = { ...st };
    }
    return out;
  }

  static fromSnapshot(snap: BanditSnapshot, policy: Policy = "ucb1", c?: number, rng?: () => number): ContextualBandit {
    const b = new ContextualBandit(policy, c, rng);
    for (const ctx of Object.keys(snap)) {
      const m = b.ctx(ctx);
      for (const arm of Object.keys(snap[ctx])) m.set(arm, { ...snap[ctx][arm] });
    }
    return b;
  }
}

/** Beta(α,β) 샘플링 — 두 Gamma 샘플의 비. Thompson sampling 용. */
export function sampleBeta(alpha: number, beta: number, rng: () => number): number {
  const x = sampleGamma(alpha, rng);
  const y = sampleGamma(beta, rng);
  return x / (x + y);
}

/** Marsaglia–Tsang Gamma(shape,1) 샘플러 */
function sampleGamma(shape: number, rng: () => number): number {
  if (shape < 1) {
    // Boost: Gamma(shape) = Gamma(shape+1) * U^(1/shape)
    return sampleGamma(shape + 1, rng) * Math.pow(rng() || 1e-12, 1 / shape);
  }
  const d = shape - 1 / 3;
  const c = 1 / Math.sqrt(9 * d);
  for (;;) {
    let x: number;
    let v: number;
    do {
      x = gaussian(rng);
      v = 1 + c * x;
    } while (v <= 0);
    v = v * v * v;
    const u = rng();
    if (u < 1 - 0.0331 * x * x * x * x) return d * v;
    if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
  }
}

/** Box–Muller 표준정규 샘플 */
function gaussian(rng: () => number): number {
  let u = 0;
  let v = 0;
  while (u === 0) u = rng();
  while (v === 0) v = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}
