/**
 * RedCell 코어 인터페이스.
 *
 * RedCell 는 특정 런타임에 묶이지 않는다. 아래 두 어댑터만 구현하면
 * prime-agent(런타임/모델) 위에서도, 완전 독립 실행으로도 동작한다.
 *   - ModelAdapter : LLM 추론(계획/판단)
 *   - ToolBox      : 실제 관측/행동(모두 ScopeGuard 를 통과해야 함)
 */

import type { Fingerprint, Phase, Playbook } from "../memory/skill-memory.js";
import type { Target } from "../scope/scope-guard.js";

export interface ModelAdapter {
  /** 자연어 프롬프트 → 텍스트(JSON 등) 응답. prime-agent 의 모델 계층에 연결. */
  complete(input: { system: string; prompt: string; json?: boolean }): Promise<string>;
}

export interface ToolResult {
  ok: boolean;
  summary: string;
  data?: unknown;
  /** 관측에서 갱신된 fingerprint 정보(있으면 병합) */
  fingerprint?: Fingerprint;
}

export interface ToolContext {
  target: Target;
  /** 인가된 요청 속도(RPS). 툴은 이 값을 반드시 준수해야 한다. */
  rps: number;
}

export interface Tool {
  name: string;
  description: string;
  /** 이 툴이 수행하는 액션의 성격. ScopeGuard 판정에 사용. */
  intent: NonNullable<Target["intent"]>;
  run(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult>;
}

export interface ToolBox {
  get(name: string): Tool | undefined;
  list(): Tool[];
}

/** 한 phase 에서 모델이 제안하는 하나의 액션 */
export interface ProposedAction {
  tool: string;
  args: Record<string, unknown>;
  rationale: string;
  /** 어떤 playbook 을 근거로 삼았는지(자기발전 추적용) */
  fromPlaybook?: string;
}

export interface EngagementFinding {
  phase: Phase;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  detail: string;
  evidence?: string;
}

export interface EngagementLog {
  target: Target;
  fingerprint: Fingerprint;
  findings: EngagementFinding[];
  usedPlaybooks: string[];
  distilled: Playbook[];
  transcript: string[];
}
