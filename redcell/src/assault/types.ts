/**
 * assault — URL 기반 자율 공격 캠페인 타입.
 *
 * 한 줄의 URL 을 받아 정찰 → 열거 → 익스플로잇 → 증거 수집 → AI 해석 → 전투보고 까지
 * 자동으로 이어지는 파이프라인(redcell assault --url <URL>)의 도메인 모델.
 *
 * 설계 원칙:
 *   - "증거(evidence)"는 공격자가 실제로 탈취할 수 있는 정보의 **샘플 증명**이다.
 *     (노출된 .env, IDOR 문서, GraphQL 스키마 등) — 전량 덤프가 아니라 cap+redact 된
 *     노출 증거를 모아 [탈취 가능 정보 매니페스트]로 보여준다.
 *   - 모든 요청은 ScopeGuard 브로커를 경유하고, 판정은 "게이트"가 아니라 "전투 보고"로
 *     남는다(assault 는 판정이 아니라 침투 성공 증거와 방어 권고를 만든다).
 */

import type { Phase, Fingerprint } from "../memory/skill-memory.js";
import type { Coverage, GateVerdict, EngagementFinding } from "../core/types.js";

export type AssaultStage = "recon" | "enumerate" | "exploit" | "evidence" | "analysis";

export type StageStatus = "pending" | "running" | "done" | "skipped" | "error";

/** URL 에서 해석한 공격 대상. */
export interface AssaultTarget {
  /** 원본 URL(사용자 입력). */
  url: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  /** 원래 경로(첫 시드 엔드포인트). */
  path: string;
}

/** 툴 1회 실행 결과(파이프라인 로그 단위). */
export interface ToolOutcome {
  tool: string;
  stage: Exclude<Phase, "report">;
  ok: boolean;
  summary: string;
  durationMs: number;
  /** 툴이 낸 발견(EngagementFinding 후보). */
  finding?: Pick<EngagementFinding, "severity" | "title" | "detail" | "evidence">;
  /** 툴의 상세 데이터(evidence 추출에 사용). */
  data?: Record<string, unknown>;
  /** 툴의 fingerprint 지표(evidence 추출에 사용). */
  fp?: { indicators?: string[]; tech?: string[] };
  /** 실행 오류 메시지(있으면). */
  error?: string;
}

export type EvidenceCategory =
  | "secret"    // 자격증명/키/토큰
  | "pii"       // 개인정보(계정/레코드/문서)
  | "schema"    // API/DB 스키마 노출
  | "config"    // 설정/요청 추적/디버그 노출
  | "backup"    // 백업/소스/아카이브 파일
  | "error"     // DB/스택 오류 문자열(내부 정보 누설)
  | "endpoint"  // 비인가 접근 가능한 관리/민감 엔드포인트
  | "exploit";  // 익스플로잇 실증(XSS/SSTI/SSRF/LFI/리다이렉트/XXE PoC)

/** 탈취 가능 정보 매니페스트의 한 항목. */
export interface EvidenceItem {
  id: string;
  category: EvidenceCategory;
  /** 사람이 읽는 제목(예: "DB 자격증명 포함 .env 노출"). */
  label: string;
  /** 발견 툴 이름. */
  source: string;
  /** 위치(경로/URL/파일). */
  target: string;
  severity: EngagementFinding["severity"];
  /** 증거 샘플(redact + cap 적용됨). */
  sample: string;
  /** redaction 적용 여부. */
  redacted: boolean;
  /** 발견된 노출 항목 수(있으면). */
  itemCount?: number;
  /** 공격자 관점 설명: "왜 탈취 가능한가 / 무엇이 얻어지는가". */
  attack: string;
  /** 검증 엔진 결과 — "가능성"인지 "실증"인지(proof 포함, 마스킹 적용됨). */
  verification?: import("./verify.js").Verification;
}

/** 공격 경로 — "이 서비스는 이렇게 뚫린다" 체인. */
export interface AttackPath {
  id: string;
  /** 요약 제목(예: "환경변수 노출 → DB 자격증명 탈취"). */
  label: string;
  severity: EngagementFinding["severity"];
  /** 단계별 체인. */
  chain: string[];
  /** 관련 증거 항목 id. */
  evidenceRefs: string[];
  /** ai: 사고 모델이 생성 / deterministic: 규칙 합성. */
  source: "ai" | "deterministic";
}

/** 방어 권고 한 항목. */
export interface DefenseItem {
  severity: EngagementFinding["severity"];
  /** 대응 조치 제목. */
  control: string;
  detail: string;
}

/** 능력 기반 다단계 공격 루트(공격 경로 플래너 산출). */
export type AttackRoute = import("./routes.js").AttackRoute;

/** assault 실행의 최종 산출물(전투 보고). */
export interface AssaultReport {
  target: AssaultTarget;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  /** 단계별 요약. */
  stages: Partial<Record<AssaultStage, { status: StageStatus; durationMs: number; toolsRun: number; findings: number }>>;
  /** 툴 실행 로그(타임라인 순). */
  outcomes: ToolOutcome[];
  /** 통합 발견 목록(심각도순). */
  findings: EngagementFinding[];
  coverage: Coverage;
  verdict: GateVerdict;
  verdictReason: string;
  /** 탈취 가능 정보 매니페스트. */
  exposed: EvidenceItem[];
  /** 공격 경로. */
  attackPaths: AttackPath[];
  /** 능력 기반 다단계 공격 루트(공격 경로 플래너). */
  attackRoutes: AttackRoute[];
  /** 방어 권고. */
  defense: DefenseItem[];
  /** 실행 요약 내러티브(ai 또는 결정적 합성). */
  narrative: string;
  /** 원문 전사(요청/응답 로그). */
  transcript: string[];
  meta: {
    command: string;
    model: string;
    authPath: string;
    authKind: string;
    aiAnalyzed: boolean;
    fullExposure: boolean;
    redact: boolean;
  };
}
