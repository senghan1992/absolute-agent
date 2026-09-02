/**
 * GraphLab — 상태가 실제로 전이(transition)하는 그래프 환경.
 *
 * MockWebLab 는 오답 시 제자리였지만, 여기선 오답이 다른 상태(막다른 길 포함)로
 * 데려간다. 즉 "잘못된 경로로 빠졌다가 되돌아와야" 하는 상황이 생겨 백트래킹/트리검색이
 * 의미를 갖는다. 에이전트는 reset 으로만 되돌아갈 수 있다(실제 침투처럼 undo 불가).
 */

import type { LabEnv, Observation, StepResult } from "./env.js";

export interface Transition {
  next?: string; // 도달 상태(없으면 제자리)
  reward: number;
  done?: boolean; // true 면 에피소드 종료(성공 또는 막다른 길)
}

export interface GraphNode {
  desc?: string;
  facts?: string[];
  actions: Record<string, Transition>;
}

export interface GraphSpec {
  start: string;
  nodes: Record<string, GraphNode>;
}

export class GraphLab implements LabEnv {
  name = "graph-lab";
  steps = 0;
  private cur: string;

  constructor(private readonly spec: GraphSpec) {
    this.cur = spec.start;
  }

  reset(): Observation {
    this.steps = 0;
    this.cur = this.spec.start;
    return this.observe();
  }

  private observe(): Observation {
    const node = this.spec.nodes[this.cur];
    return {
      stateKey: this.cur,
      description: node?.desc ?? this.cur,
      available: node ? Object.keys(node.actions) : [],
      facts: node?.facts ?? [],
    };
  }

  step(action: string): StepResult {
    this.steps += 1;
    const node = this.spec.nodes[this.cur];
    const trans = node?.actions[action];
    if (!trans) {
      return { observation: this.observe(), reward: -0.1, done: false, info: { invalid: action } };
    }
    if (trans.next && this.spec.nodes[trans.next]) this.cur = trans.next;
    return {
      observation: this.observe(),
      reward: trans.reward,
      done: !!trans.done,
      info: { to: this.cur, done: !!trans.done },
    };
  }
}

/**
 * 랜덤 트리 미로 생성기: 깊이 depth, 분기 branching.
 * 정확히 하나의 리프만 목표(reward 1, done). 나머지 리프는 막다른 길(reward 0, done).
 * 시드로 재현 가능. MCTS 가 목표 리프로 가는 경로를 찾아내는지 검증하는 용도.
 */
export function buildRandomTree(depth: number, branching: number, rng: () => number): { spec: GraphSpec; goalPath: string[] } {
  const nodes: Record<string, GraphNode> = {};
  const goalPath: string[] = [];
  let goalNode = "n0";

  const build = (id: string, d: number, onGoalPath: boolean): void => {
    if (d === depth) {
      // 리프
      nodes[id] = { desc: `leaf ${id}`, actions: {} };
      if (onGoalPath) goalNode = id;
      return;
    }
    const goalChild = onGoalPath ? Math.floor(rng() * branching) : -1;
    const actions: Record<string, Transition> = {};
    for (let b = 0; b < branching; b++) {
      const childId = `${id}_${b}`;
      const isGoalEdge = b === goalChild;
      const isLeaf = d + 1 === depth;
      if (isLeaf && !isGoalEdge && !onGoalPath) {
        // 목표경로 밖 리프로 가는 엣지: 막다른 길
      }
      actions[`act_${b}`] = {
        next: childId,
        reward: 0,
        done: false,
      };
      if (isGoalEdge) goalPath.push(`act_${b}`);
      build(childId, d + 1, onGoalPath && isGoalEdge);
    }
    nodes[id] = { desc: `node ${id} (depth ${d})`, actions };
  };

  build("n0", 0, true);

  // 리프들의 보상 확정: 목표 리프는 성공, 나머지 리프는 막다른 길.
  for (const [id, node] of Object.entries(nodes)) {
    if (Object.keys(node.actions).length === 0) {
      // 리프에 도달하는 엣지의 보상/done 을 부모에서 설정해야 하므로, 여기선 표시만.
    }
    for (const [act, tr] of Object.entries(node.actions)) {
      const child = tr.next!;
      const childIsLeaf = child && Object.keys(nodes[child]?.actions ?? {}).length === 0;
      if (childIsLeaf) {
        if (child === goalNode) {
          tr.reward = 1;
          tr.done = true;
        } else {
          tr.reward = 0; // 막다른 길
          tr.done = true;
        }
      }
    }
  }

  return { spec: { start: "n0", nodes }, goalPath };
}
