/**
 * harden — 시스템 오픈(출시) 전 취약점 사전 진단 + 강화(보안) 권고 모듈.
 *
 * 두 가지 입력을 받는다.
 *  1. 텍스트(문장/파일)로 설명된 시스템 — `describeSystem` 이 성분/포트/플래그를 결정적으로 추출.
 *  2. (선택) --url: ScopeGuard 가 승인한 대상에 대한 읽기 전용 크로스체크(live recon).
 *
 * 지식 베이스(내장 하드닝 규칙)로 평가하고, routes 의 planRoutes 로 타협(attack) 시나리오를
 * 도출하며, "출시 게이트" 판정(PASS/FAIL)을 내려 리포트(markdown/html/json)로 남긴다.
 *
 * 원칙: 결정적(오프라인 가능) · 비파괴(읽기 전용) · ScopeGuard 경유(인가 필수, fail-closed).
 */
import type { AttackRoute } from "../assault/routes.js";
import type { EngagementFinding as EF } from "../core/types.js";
import type { Fingerprint } from "../memory/skill-memory.js";

/** 시스템에 포함된 것으로 파악된 구성 요소(컴포넌트) 하나. */
export interface ComponentRef {
  /** 정규화된 키: "gitlab", "redis", "mqtt", … */
  key: string;
  /** 원문에서 발견된 이름(표기 그대로). */
  label: string;
  /** 버전을 명시했으면 마저. */
  version?: string;
}

/**
 * 텍스트 설명에서 결정적으로 추출한 시스템 프로필.
 * 정규식 스캔 기반이므로 hallucination 이 없는 것이 보장이며, 추출 못한 항목은 "확인 필요"로 남는다.
 */
export interface SystemProfile {
  /** 시스템 이름(명시하면 그 값, 없으면 "system"). */
  name: string;
  /** 원문(추적용). */
  raw: string;
  /** 인식된 구성 요소. */
  components: ComponentRef[];
  /** 명시한 포트 + 구성 요소별 기본 포트(추론 포함). */
  ports: number[];
  /** 감지된 속성: no-auth, has-mfa, no-mfa, default-creds, debug, exposed, internal, cloud,
 *   container, mobile, no-tls, http-only, admin, secrets-in-code … */
  flags: string[];
  /** 결정적으로 판단하지 못한 원문 단서들(리포트의 "확인 필요" 섹션). */
  notes: string[];
}

/** 강화 권고(발견) 하나. 리포트의 1회고(행동) 단위가 된다. */
export interface HardeningFinding {
  /** 규칙 id(예: "H-07"). 프로필 평가는 H-xx, live 크로스체크는 LV-xx. */
  id: string;
  severity: EF["severity"];
  source: "profile" | "live";
  /** 관련 구성 요소 키(redis, gitlab …). */
  component?: string;
  /** 취약점/위험(무엇이 안 되는지). */
  risk: string;
  /** 공격자 관점의 시나리오(어디까지 갈 수 있는지) — 방어자에게 "왜"를 보여준다. */
  attack: string;
  /** 방어자 관점의 조치(어떻게 고칠지). 리포트의 "권고" 문단. */
  fix: string;
  detail?: string;
  cwe?: string;
  effort?: "low" | "medium" | "high";
}

/** 선택적 live 크로스체크 결과. */
export interface LiveReconResult {
  url: string;
  host: string;
  port: number;
  reachable: boolean;
  /** 읽기 전용 툴에서 나온 발견들(원문 그대로). */
  findings: EF[];
  /** 툴별 요약(추적용). */
  toolSummaries: string[];
  /** 수집된 지문(툴 run 동안 머지된 서비스/버전/OS/기술 스택). */
  fingerprint: Fingerprint;
  /** 미도달 사유(도달 불가 시 리포트가 표기). */
  reason?: string;
}

export type HardenVerdict = "PASS" | "PASS_WITH_RISKS" | "FAIL" | "INCONCLUSIVE";

export interface GateResult {
  verdict: HardenVerdict;
  reason: string;
  counts: Record<EF["severity"], number>;
}

export interface HardeningReport {
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  profile: SystemProfile;
  live?: LiveReconResult;
  findings: HardeningFinding[];
  /** 타협 시나리오(공격 경로) — profile+live 발견을 capability 로 매핑해 도출. */
  routes: AttackRoute[];
  gate: GateResult;
  transcript: string[];
}

/** runHarden 옵션. */
export interface HardenOptions {
  /** 텍스트 설명(문장 하나부터 수문까지), 또는 프로필 파일 경로(.json/텍스트). */
  description?: string;
  /** 시스템 이름(없으면 "system"). */
  name?: string;
  /** live 크로스체크 URL(http/https). 없으면 오프라인(설명서 기준) 평가만. */
  url?: string;
  /** 인가 파일. url 이 있으면 필수 — ScopeGuard 경유(최종 인가 판정). */
  authFile?: string;
  /** 인증 세션(선택). */
  auth?: Record<string, string>;
  proxy?: string;
  /** 쿠키(선택). 쉼표 구분 k=v ... — live cross-check 에 세션 쿠키를 태울 때. */
  cookie?: string;
  /** 출력 디렉터리. 기본 ~/.redcell/harden/<ts>. */
  outDir?: string;
  /** 리포트 기본 이름. 기본 hardn-<시스템명>. */
  reportName?: string;
  /** 실행 로그를 담을 배열(리포트의 실행기록 섹션). */
  transcript?: string[];
}

export interface HardenResult {
  report: HardeningReport;
  /** 파일 이름: [md, json] 경로들 */
  files: string[];
  /** 게이트 판정 코드: 0=PASS/PASS_WITH_RISKS, 1=FAIL, 4=INCONCLUSIVE(대상 미도달) */
  exitCode: number;
}
