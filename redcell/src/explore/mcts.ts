/**
 * MCTS (Monte Carlo Tree Search, UCT) — 상태가 전이하는 환경에서의 트리검색 계획.
 *
 * 밴딧이 "한 상태에서 최적 액션"을 배운다면, MCTS 는 "여러 수 앞을 내다보고
 * 최적 경로"를 찾는다. 막다른 길로 빠지면 자연스럽게 그 가지의 가치가 낮아져
 * 다른 가지를 더 탐색한다(= 백트래킹).
 *
 * 환경은 undo 가 안 되므로, 매 반복마다 reset 후 루트부터 액션 경로를 재생(replay)한다.
 * (모델/실대상 대신 시뮬레이션 계획에 적합; env.step 은 sync/async 모두 지원)
 *
 * 4단계: 선택(UCT) → 확장 → 시뮬레이션(rollout) → 역전파.
 */

import type { LabEnv, Observation } from "./env.js";

class MctsNode {
  visits = 0;
  value = 0; // 이 노드를 지나간 에피소드 리턴의 합
  children = new Map<string, MctsNode>();
  untried: string[];
  terminal = false;

  constructor(
    readonly stateKey: string,
    readonly parent: MctsNode | null,
    readonly actionFromParent: string | null,
    available: string[],
  ) {
    this.untried = [...available];
  }

  get mean(): number {
    return this.visits > 0 ? this.value / this.visits : 0;
  }
}

export interface MctsOpts {
  iterations?: number;
  cExplore?: number; // UCT 탐색 계수
  rolloutDepth?: number;
  rng?: () => number;
}

export interface MctsResult {
  bestPath: string[]; // 루트에서 목표까지 추천 액션열(방문수 기준 greedy)
  bestReturn: number; // 그 경로의 실제 리턴
  rootVisits: number;
  solved: boolean;
}

export class Mcts {
  private iterations: number;
  private c: number;
  private rolloutDepth: number;
  private rng: () => number;

  constructor(
    private readonly makeEnv: () => LabEnv,
    opts: MctsOpts = {},
  ) {
    this.iterations = opts.iterations ?? 500;
    this.c = opts.cExplore ?? Math.SQRT2;
    this.rolloutDepth = opts.rolloutDepth ?? 20;
    this.rng = opts.rng ?? Math.random;
  }

  async search(): Promise<MctsResult> {
    const rootEnv = this.makeEnv();
    const rootObs = rootEnv.reset();
    const root = new MctsNode(rootObs.stateKey, null, null, rootObs.available);

    for (let i = 0; i < this.iterations; i++) {
      const env = this.makeEnv();
      env.reset();
      let node = root;
      let ret = 0;
      let done = false;

      // 1) 선택: 완전 확장 + 비종단 노드를 UCT 로 내려간다(경로 재생).
      while (node.untried.length === 0 && node.children.size > 0 && !node.terminal) {
        const [action, child] = this.uctSelect(node);
        const res = await env.step(action);
        ret += res.reward;
        node = child;
        if (res.done) {
          done = true;
          break;
        }
      }

      // 2) 확장: 미시도 액션이 있으면 하나 펼친다.
      if (!done && !node.terminal && node.untried.length > 0) {
        const action = node.untried[Math.floor(this.rng() * node.untried.length)];
        const res = await env.step(action);
        ret += res.reward;
        node.untried = node.untried.filter((a) => a !== action);
        const child = new MctsNode(res.observation.stateKey, node, action, res.observation.available);
        child.terminal = res.done;
        node.children.set(action, child);
        node = child;
        done = res.done;

        // 3) 시뮬레이션(rollout): 무작위 정책으로 종단/깊이한계까지.
        if (!done) ret += await this.rollout(env, res.observation);
      }

      // 4) 역전파.
      this.backprop(node, ret);
    }

    return this.extractBest(root);
  }

  private uctSelect(node: MctsNode): [string, MctsNode] {
    const lnN = Math.log(Math.max(1, node.visits));
    let best: [string, MctsNode] | null = null;
    let bestScore = -Infinity;
    for (const [action, child] of node.children) {
      const exploit = child.mean;
      const explore = this.c * Math.sqrt(lnN / Math.max(1, child.visits));
      const score = exploit + explore;
      if (score > bestScore) {
        bestScore = score;
        best = [action, child];
      }
    }
    return best!;
  }

  private async rollout(env: LabEnv, obs: Observation): Promise<number> {
    let ret = 0;
    let cur = obs;
    for (let d = 0; d < this.rolloutDepth; d++) {
      if (cur.available.length === 0) break;
      const action = cur.available[Math.floor(this.rng() * cur.available.length)];
      const res = await env.step(action);
      ret += res.reward;
      if (res.done) break;
      cur = res.observation;
    }
    return ret;
  }

  private backprop(leaf: MctsNode, ret: number): void {
    let n: MctsNode | null = leaf;
    while (n) {
      n.visits += 1;
      n.value += ret;
      n = n.parent;
    }
  }

  /** 방문수 기준 greedy 로 루트→리프 경로를 추출하고, 실제로 재생해 리턴 확인. */
  private async extractBest(root: MctsNode): Promise<MctsResult> {
    const path: string[] = [];
    let node = root;
    while (node.children.size > 0) {
      let best: [string, MctsNode] | null = null;
      for (const entry of node.children) {
        if (!best || entry[1].visits > best[1].visits) best = entry;
      }
      if (!best) break;
      path.push(best[0]);
      node = best[1];
      if (node.terminal) break;
    }

    // 실제 재생으로 리턴/성공여부 확정.
    const env = this.makeEnv();
    env.reset();
    let bestReturn = 0;
    let solved = false;
    for (const a of path) {
      const res = await env.step(a);
      bestReturn += res.reward;
      if (res.done) {
        solved = res.reward > 0;
        break;
      }
    }
    return { bestPath: path, bestReturn, rootVisits: root.visits, solved };
  }
}
