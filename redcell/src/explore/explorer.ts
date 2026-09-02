/**
 * Explorer — "스스로 이것저것 시도하며 알맞은 방법을 찾고, 발전하는" 엔진.
 *
 * 한 에피소드:
 *   reset → [관측 → 전략선택(bandit) → 실행(env) → 보상반영 → 기록] 반복 → done
 *
 * 학습이 일어나는 세 축:
 *   1) 에피소드 내 탐색: 같은 상태에서 실패한 액션은 tabu 로 걸어 다른 방법을 시도.
 *   2) 에피소드 간 학습: ContextualBandit 이 "상황별로 뭐가 통했는지"를 누적 →
 *      반복할수록 정답 경로로 더 빨리 수렴(= 자기발전).
 *   3) 반성(reflect): 막히면 StrategyProposer 로 새 전략을 생성해 행동공간 자체를 확장.
 *   성공 시 경로를 SkillMemory 에 distill 하여 재사용 가능한 playbook 으로 저장.
 */

import { ContextualBandit } from "./bandit.js";
import type { LabEnv, Observation } from "./env.js";
import type { SkillMemory, Fingerprint } from "../memory/skill-memory.js";

export interface StrategyProposer {
  /** 현재 관측/이력을 보고 새로 시도할 전략 후보를 제안(모델 연결 지점) */
  propose(obs: Observation, history: StepRecord[]): Promise<string[]> | string[];
}

export interface StepRecord {
  stateKey: string;
  action: string;
  reward: number;
  done: boolean;
}

export interface EpisodeResult {
  success: boolean;
  steps: number;
  totalReward: number;
  path: StepRecord[];
  flag?: string;
}

export interface ExplorerOpts {
  maxSteps?: number;
  memory?: SkillMemory;
  proposer?: StrategyProposer;
  /** 반성을 트리거하기 전 무진전 허용 스텝 */
  reflectAfter?: number;
}

export class Explorer {
  constructor(
    private readonly bandit: ContextualBandit,
    private readonly opts: ExplorerOpts = {},
  ) {}

  async runEpisode(env: LabEnv): Promise<EpisodeResult> {
    const maxSteps = this.opts.maxSteps ?? 40;
    const reflectAfter = this.opts.reflectAfter ?? 4;

    let obs = env.reset();
    const path: StepRecord[] = [];
    const tabu = new Map<string, Set<string>>(); // 에피소드 내 상태별 실패 액션
    const extraArms = new Map<string, Set<string>>(); // reflect 로 추가된 전략
    let totalReward = 0;
    let flag: string | undefined;
    let sinceProgress = 0;

    for (let i = 0; i < maxSteps; i++) {
      const banned = tabu.get(obs.stateKey) ?? new Set();
      let arms = [...obs.available, ...(extraArms.get(obs.stateKey) ?? [])].filter((a) => !banned.has(a));

      // 막다른 길: 이 상태의 모든 알려진 액션이 실패했다.
      if (arms.length === 0) {
        const fresh = await this.reflect(obs, path, extraArms);
        arms = fresh.filter((a) => !banned.has(a));
        if (arms.length === 0) {
          // 반성으로도 새 수가 없으면 tabu 를 풀어 재시도(포기하지 않음).
          tabu.set(obs.stateKey, new Set());
          arms = [...obs.available];
        }
      }

      const action = this.bandit.select(obs.stateKey, arms);
      const res = await env.step(action);
      const banditReward = res.reward > 0 ? res.reward : 0; // 진전=양수 보상만 성공신호로
      this.bandit.update(obs.stateKey, action, banditReward);

      const rec: StepRecord = { stateKey: obs.stateKey, action, reward: res.reward, done: res.done };
      path.push(rec);
      totalReward += res.reward;

      if (res.reward <= 0) {
        // 이번 에피소드에서 이 상태-액션은 실패 → 다른 방법 시도.
        if (!tabu.has(obs.stateKey)) tabu.set(obs.stateKey, new Set());
        tabu.get(obs.stateKey)!.add(action);
        sinceProgress += 1;
      } else {
        sinceProgress = 0;
      }

      if (res.done) {
        flag = res.info.flag as string | undefined;
        break;
      }

      // 오래 무진전이면 미리 반성해서 새 전략 확보.
      if (sinceProgress >= reflectAfter) {
        const fresh = await this.reflect(obs, path, extraArms);
        void fresh;
        sinceProgress = 0;
      }

      obs = res.observation;
    }

    const success = path.length > 0 && path[path.length - 1].done;
    if (success && this.opts.memory) await this.distill(path);

    return { success, steps: env.steps, totalReward, path, flag };
  }

  /** 여러 에피소드 실행 → 에피소드별 지표(학습곡선 관찰용) */
  async run(makeEnv: () => LabEnv, episodes: number): Promise<EpisodeResult[]> {
    const results: EpisodeResult[] = [];
    for (let e = 0; e < episodes; e++) {
      results.push(await this.runEpisode(makeEnv()));
    }
    return results;
  }

  /** 반성: proposer 가 있으면 새 전략을 받아 extraArms 에 축적 */
  private async reflect(obs: Observation, history: StepRecord[], extraArms: Map<string, Set<string>>): Promise<string[]> {
    if (!this.opts.proposer) return [...obs.available];
    const proposed = await this.opts.proposer.propose(obs, history);
    const set = extraArms.get(obs.stateKey) ?? new Set<string>();
    for (const p of proposed) set.add(p);
    extraArms.set(obs.stateKey, set);
    return [...new Set([...obs.available, ...set])];
  }

  /** 성공 경로 → playbook. 정답 액션 체인만 추려 저장(오답 스텝 제외). */
  private async distill(path: StepRecord[]): Promise<void> {
    const wins = path.filter((p) => p.reward > 0);
    if (wins.length === 0) return;
    const fp: Fingerprint = { service: "http", tech: ["sim"], indicators: wins.map((w) => w.stateKey) };
    await this.opts.memory!.distill({
      title: `탐색으로 발견한 공략 체인 (${wins.map((w) => w.action).join("→")})`,
      phase: "exploit",
      match: fp,
      steps: wins.map((w) => ({ action: w.action, expect: `${w.stateKey} 진행` })),
      tags: ["explored", "self-improved"],
    });
  }
}

/** 성공률/평균 스텝을 이동평균으로 요약(학습곡선) */
export function learningCurve(results: EpisodeResult[], window = 10): Array<{ episode: number; successRate: number; avgSteps: number }> {
  const out: Array<{ episode: number; successRate: number; avgSteps: number }> = [];
  for (let i = 0; i < results.length; i++) {
    const lo = Math.max(0, i - window + 1);
    const slice = results.slice(lo, i + 1);
    const succ = slice.filter((r) => r.success).length / slice.length;
    const steps = slice.reduce((s, r) => s + r.steps, 0) / slice.length;
    out.push({ episode: i + 1, successRate: succ, avgSteps: steps });
  }
  return out;
}
