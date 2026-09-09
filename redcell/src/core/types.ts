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
  /**
   * 이 어댑터가 "신뢰되는" 코드 생성원인가(선택). 오프라인 결정적 MockCoder 처럼 외부
   * 입력(대상 응답)에 영향받지 않는 어댑터만 true. 라이브 LLM 은 false/미설정(신뢰불가).
   * pyrun 의 OS 격리 정책이 이 값으로 fail-closed 여부를 정한다.
   */
  trusted?: boolean;
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
  /**
   * 인증 컨텍스트(선택). 인가된 계정의 세션/토큰을 요청에 실어 "로그인 뒤" 표면까지
   * 점검할 수 있게 한다. 값은 요청에 그대로 병합될 HTTP 헤더 맵이다.
   * (authorization.yaml 의 credentials 에서 구성되며, 실행 중 발견한 크리덴셜로 확장될 수 있다)
   */
  auth?: Record<string, string>;
  /** 프록시 URL(예: http://127.0.0.1:8080). Burp/ZAP 로 트래픽을 태워 수동 검증. */
  proxy?: string;
  /** 쿠키 jar(로그인 세션 유지). 지정 시 Set-Cookie 저장 + Cookie 재전송. */
  jar?: import("../net/http-client.js").CookieJar;
  /**
   * 연결 시점 IP 검증(선택). 호스트명이 실제 해석된 IP 로 연결되기 전에 호출돼, 내부/사설 IP·
   * DNS rebinding 을 차단한다. 보통 ScopeGuard.checkResolvedIp 로 구성되어 주입된다.
   */
  validateIp?: (hostname: string, ip: string) => boolean;
  /**
   * 산출물 저장 디렉터리(목표 에이전트 전용). download_file/write_output 툴이
   * 이 디렉터리 아래에만 파일을 쓴다(경로 조작 차단). 지정되지 않으면 두 툴은 거부된다.
   */
  resultsDir?: string;
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
  /**
   * 예상 영향/피해 반경(blast radius) — "이 취약점으로 공격자가 실제로 어디까지 갈 수 있고
   * 그 피해가 어느 정도인가"를 방어자 관점에서 서술. 툴이 data.impact 로 직접 제공하거나,
   * 없으면 리포트가 취약점 유형별 기본 영향으로 보강한다. (비파괴 원칙: 실제 피해를 내지 않고 서술만)
   */
  impact?: string;
}

/**
 * 게이트 판정 — "이 대상을 오픈해도 되는가"를 세 값으로만 표현한다.
 *   - clean        : 검사한 표면에서 유의미 취약점 미발견 + 커버리지 충분(그래도 전체 안전 보장은 아님).
 *   - findings     : 취약점 발견 → 게이트 실패.
 *   - inconclusive : 대상 미도달/커버리지 불충분 → "통과"로 간주하면 안 됨(거짓 안전 방지).
 */
export type GateVerdict = "clean" | "findings" | "inconclusive";

/**
 * 커버리지 — "얼마나 봤는가"를 정량화해 '발견 0'과 '안 봄'을 구분한다.
 * 게이트가 clean 을 선언하려면 이 값들이 충분해야 한다(불충분 시 inconclusive).
 */
export interface Coverage {
  /** 대상이 HTTP 응답을 한 번이라도 돌려줬는가(연결 실패/타임아웃이면 false). */
  reachable: boolean;
  /** 실제 실행된 서로 다른 툴 수. */
  toolsRun: number;
  /** 시도 대상이었던 총 툴 수. */
  toolsTotal: number;
  /** 정찰로 발견한 엔드포인트 수(공격 표면 크기). */
  endpointsDiscovered: number;
  /** 인증 표면을 점검했는가(자격증명/세션 보유). false 면 "로그인 뒤"는 미검사. */
  authScanned: boolean;
  /**
   * 실제로 검사된 익스플로잇 계열 툴 이름(측정된 취약점 계열).
   * "실행"이 아니라 "대상 표면에 도달해 응답을 관측"한 것만 센다 — 연결 실패/타임아웃으로
   * 대상에 닿지 못한 툴은 해당 취약점 계열을 검사했다고 볼 수 없으므로 제외한다(거짓 커버리지 방지).
   */
  vulnClassesTested: string[];
  /** 연결 실패/타임아웃으로 실패한 요청 수. */
  requestErrors: number;
  /** 결정적 전수(--full) 모드였는가(재현성 보장 여부). */
  deterministic: boolean;
}

export interface EngagementLog {
  target: Target;
  fingerprint: Fingerprint;
  findings: EngagementFinding[];
  usedPlaybooks: string[];
  distilled: Playbook[];
  transcript: string[];
  /** 게이트 커버리지(있으면 리포트에 판정/커버리지 섹션 출력). */
  coverage?: Coverage;
  /** 게이트 판정. */
  verdict?: GateVerdict;
  /** 판정 사유(사람이 읽는 한 줄). */
  verdictReason?: string;
}
