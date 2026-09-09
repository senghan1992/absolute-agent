/**
 * 공격 경로 플래너 — 발견을 "능력(capability)"으로 승격해 다단계 공격 루트를 합성한다.
 *
 * 해커는 발견을 끝으로 보지 않는다. "파일 읽기가 되면 → 설정에서 자격증명을 찾고 →
 * 그 자격증명으로 로그인하고 → 관리자 기능을 쓴다"처럼 능력을 연결해 목표(왕관)까지
 * 경로를 만든다. 이 모듈은 그 사고를 그래프로 코드화한다:
 *
 *   1) 능력 추출   — 발견(툴 제목)·증거(분류)에서 공격자가 가진 힘을 식별한다.
 *   2) 체인 규칙   — 능력 → 능력 전이(어떻게, 무엇을 시도할지, 막는 법)의 결정적 지식.
 *   3) 경로 열거   — 보유 능력에서 시작해 왕관 목표까지의 단순 경로를 DFS 로 열거한다.
 *   4) 랭킹       — 목표 심각도 × 경로 길이(짧고 직접적일수록 먼저).
 *
 * 결과는 "지금까지 발견만 나열하던 리포트"를 "공격자의 다음 수까지 예측하는 침투 지도"로
 * 바꾼다 — 방어자에게는 우선순위(어디를 끊을지), 공격자에게는 체크리스트가 된다.
 * 모든 규칙은 비파괴 서술이며 실제 실행은 하지 않는다(계획 전용).
 */

import type { EngagementFinding } from "../core/types.js";
import type { EvidenceItem } from "./types.js";

/** 공격자 능력 — 발견을 행동력으로 번역한 것. */
export type Capability =
  | "code-exec" // 서버에서 코드/명령 실행
  | "file-read" // 서버 파일 열람
  | "creds" // 자격증명 확보
  | "db-access" // DB 조회/조작
  | "session-hijack" // 사용자/관리자 세션 탈취
  | "admin-access" // 관리자 기능 접근
  | "internal-net" // 내부망·클라우드 메타데이터 접근
  | "traffic-hijack" // 트래픽/응답 납치(캐시 오염·스머글링)
  | "auth-bypass" // 인증 논리 우회
  | "data-exfil"; // 대량 데이터 유출

export const CAPABILITY_KO: Record<Capability, string> = {
  "code-exec": "코드/명령 실행",
  "file-read": "서버 파일 열람",
  creds: "자격증명 확보",
  "db-access": "DB 접근",
  "session-hijack": "세션 탈취",
  "admin-access": "관리자 기능 접근",
  "internal-net": "내부망 접근",
  "traffic-hijack": "트래픽 납치",
  "auth-bypass": "인증 우회",
  "data-exfil": "대량 데이터 유출",
};

/** 왕관 목표 — 공격 경로의 종착점. */
const GOALS: Record<Capability, { label: string; severity: "critical" | "high" }> = {
  "code-exec": { label: "서버 완전 장악(RCE)", severity: "critical" },
  "admin-access": { label: "관리자 권한 장악", severity: "critical" },
  "traffic-hijack": { label: "불특정 다수 사용자 피해(트래픽 납치)", severity: "critical" },
  "session-hijack": { label: "사용자 세션 장악", severity: "high" },
  creds: { label: "자격증명 장악", severity: "high" },
  "data-exfil": { label: "전체 데이터 유출", severity: "high" },
  "file-read": { label: "서버 파일 장악", severity: "high" },
  "db-access": { label: "데이터베이스 장악", severity: "high" },
  "internal-net": { label: "내부망 침투", severity: "high" },
  "auth-bypass": { label: "인증 체계 무력화", severity: "high" },
};

export interface RouteStep {
  from: Capability;
  to: Capability;
  /** 근거가 된 발견(툴 제목). */
  via: string;
  /** 다음 수 — 공격자가 시도할 행동(비파괴 서술). */
  how: string;
  /** 이 전이를 끊는 방어. */
  defense: string;
}

export interface AttackRoute {
  id: string;
  /** 종착 목표(왕관). */
  goal: string;
  goalSeverity: "critical" | "high";
  /** 시작 능력(이미 확보된 것). */
  entry: Capability;
  steps: RouteStep[];
  /** 목표 도달 시 피해 반경. */
  impact: string;
}

// ── 1) 능력 추출 ──────────────────────────────────────────────────────────────

/** 발견 제목/증거에서 능력을 식별하는 규칙(우리 툴의 안정적 제목 문구 기반). */
const CAP_RULES: Array<{ cap: Capability; re: RegExp }> = [
  { cap: "code-exec", re: /명령 실행|Command Injection|템플릿 인젝션|SSTI|업로드 실증|Unrestricted Upload|python_exec|역직렬화|deserialize/i },
  { cap: "file-read", re: /경로 조작|Path Traversal|LFI|백업|소스|아카이브/i },
  { cap: "creds", re: /자격증명|시크릿|크리덴셜|Secret|메타데이터|IAM|자격증명 재사용/i },
  { cap: "db-access", re: /SQL|NoSQL|DB 오류/i },
  { cap: "session-hijack", re: /XSS|쿠키|세션|캐시 기만/i },
  { cap: "admin-access", re: /접근통제|IDOR|관리|Broken Access/i },
  { cap: "internal-net", re: /SSRF|내부/i },
  { cap: "traffic-hijack", re: /캐시 포이즈닝|스머글링|Smuggling|CRLF|호스트 헤더/i },
  { cap: "auth-bypass", re: /JWT|NoSQL (?:Injection|우회)|논리|logic|비밀번호 재설정/i },
  { cap: "data-exfil", re: /개인정보|사적 데이터|대량|개인 레코드/i },
];

/** 발견+증거 → 능력별 근거(첫 발견 제목). 이미 '실증'인 발견을 우선한다. */
export function capabilitiesOf(findings: EngagementFinding[], exposed: EvidenceItem[]): Map<Capability, string> {
  const caps = new Map<Capability, string>();
  const put = (cap: Capability, via: string) => {
    if (!caps.has(cap)) caps.set(cap, via);
  };
  for (const f of findings) {
    if (f.severity === "info") continue;
    const text = `${f.title} ${f.detail ?? ""}`;
    for (const r of CAP_RULES) {
      if (r.re.test(text)) put(r.cap, f.title);
    }
  }
  for (const e of exposed) {
    if (e.category === "secret") put("creds", e.label);
    if (e.category === "backup") put("file-read", e.label);
    if (e.category === "config") put("file-read", e.label);
    if (e.category === "pii") put("data-exfil", e.label);
    if (e.category === "schema") put("db-access", e.label);
  }
  return caps;
}

// ── 2) 체인 규칙 — 능력 전이 지식(공격자 플레이북) ─────────────────────────────

interface ChainRule {
  from: Capability;
  /** 추가 전제 능력(이것들도 있어야 전이 가능). */
  requires?: Capability[];
  to: Capability;
  how: string;
  defense: string;
}

const CHAIN_RULES: ChainRule[] = [
  {
    from: "file-read",
    to: "creds",
    how: "열람 가능한 경로에서 설정·소스·환경파일(.env, config, .git)을 읽어 자격증명을 수집한다",
    defense: "시크릿을 코드/문서에서 분리해 시크릿 매니저로 주입하고, 파일 서빙을 화이트리스트로 제한한다",
  },
  {
    from: "creds",
    to: "session-hijack",
    how: "확보한 자격증명으로 로그인해 정상 세션을 획득한다(자격증명 재사용)",
    defense: "유출 의심 자격증명 전량 로테이션 + MFA/이상 로그인 탐지",
  },
  {
    from: "db-access",
    to: "creds",
    how: "DB 조회 권한으로 사용자 테이블·토큰·비밀번호 해시를 덤프한다",
    defense: "DB 계정 최소권한 분리, 민감 컬럼 암호화, 해시는 느린 KDF 사용",
  },
  {
    from: "internal-net",
    to: "creds",
    how: "클라우드 메타데이터(169.254.169.254)에 접근해 IAM 임시 자격증명을 요청한다",
    defense: "IMDSv2(토큰 필수) 강제, 메타데이터 주소로의 서버측 요청 차단",
  },
  {
    from: "internal-net",
    to: "admin-access",
    how: "내부망의 관리 콘솔·API 를 탐색해 인증 없이 열린 인터페이스를 찾는다",
    defense: "내부망 세그멘테이션(관리 평면 분리), 내부 서비스도 인증 강제",
  },
  {
    from: "session-hijack",
    to: "admin-access",
    how: "탈취한 세션으로 관리자 전용 기능을 호출한다(수준 재검증 없는 경우 성공)",
    defense: "민감 기능에 단계별 재인증(step-up auth), 관리자 세션 분리",
  },
  {
    from: "auth-bypass",
    to: "admin-access",
    how: "우회된 인증(토큰 위조·연산자 주입·논리 결함)으로 관리 기능에 직접 접근한다",
    defense: "서버측 인가 검증을 모든 기능에 강제, 인증 로직 통합 테스트",
  },
  {
    from: "admin-access",
    to: "file-read",
    how: "관리자 파일 관리·백업·로그 조회 기능을 통해 서버 파일에 접근한다",
    defense: "관리 기능의 파일 접근을 화이트리스트로 제한, 감사 로깅",
  },
  {
    from: "code-exec",
    to: "internal-net",
    how: "장악한 서버에서 내부망 포트를 탐색하고 인접 서비스로 횡이동한다",
    defense: "아웃바운드 이그레스 정책, 워크로드 간 네트워크 세그멘테이션",
  },
  {
    from: "code-exec",
    to: "creds",
    how: "서버 환경변수·설정 파일·메모리에서 자격증명을 회수한다",
    defense: "프로세스 최소권한, 시크릿 매니저 단기 토큰, 키 로테이션",
  },
  {
    from: "traffic-hijack",
    to: "session-hijack",
    how: "오염된 캐시/응답에 스크립트를 심어 방문자의 세션 쿠키를 수집한다",
    defense: "캐시 키 정규화(모호 헤더 제외), CSP, 쿠키 HttpOnly/Secure",
  },
  {
    from: "traffic-hijack",
    to: "creds",
    how: "납치한 응답에 가짜 로그인 폼을 서빙해 자격증명을 수확한다",
    defense: "캐시/프록시 정규화, 서브리소스 무결성(SRI), 콘텐츠 모니터링",
  },
  {
    from: "file-read",
    requires: ["code-exec"],
    to: "creds",
    how: "코드 실행으로 보호된 위치의 자격증명까지 직접 읽는다",
    defense: "프로세스 권한 분리로 파일 열람과 실행 능력을 동시에 주지 않는다",
  },
  {
    from: "db-access",
    to: "data-exfil",
    how: "DB 조회로 전체 사용자 레코드를 반복 추출한다(블라인드/UNION 확장)",
    defense: "행 수준 이상 접근 탐지, 쿼리 레이트 제한, 최소권한",
  },
  {
    from: "admin-access",
    to: "data-exfil",
    how: "관리자 내보내기/목록 기능으로 전체 데이터를 한 번에 내보낸다",
    defense: "대량 export 승인 절차, 비정상 접근 알림",
  },
  {
    from: "session-hijack",
    to: "data-exfil",
    how: "탈취 세션으로 개인 페이지·API 를 순회 수집한다",
    defense: "계정별 이상 행동 탐지, 세션 무효화 버튼 제공",
  },
];

const MAX_DEPTH = 4;

// ── 3) 경로 열거 ──────────────────────────────────────────────────────────────

/** 보유 능력에서 왕관까지의 단순 경로를 DFS 열거(깊이 ≤ 4, 능력 반복 없음). */
export function planRoutes(findings: EngagementFinding[], exposed: EvidenceItem[]): AttackRoute[] {
  const caps = capabilitiesOf(findings, exposed);
  if (caps.size === 0) return [];
  const routes: AttackRoute[] = [];
  let n = 0;

  const dfs = (current: Capability, possessed: Set<Capability>, steps: RouteStep[], entry: Capability): void => {
    if (steps.length >= MAX_DEPTH) return;
    for (const rule of CHAIN_RULES) {
      if (rule.from !== current) continue;
      if (rule.requires && !rule.requires.every((r) => possessed.has(r) || r === current)) continue;
      if (steps.some((s) => s.to === rule.to)) continue; // 단순 경로
      const step: RouteStep = { from: rule.from, to: rule.to, via: caps.get(rule.from) ?? caps.get(current) ?? rule.from, how: rule.how, defense: rule.defense };
      const next = [...steps, step];
      const reached = new Set([...possessed, rule.to]);
      // 왕관 도달(트래픽 납치·코드 실행·관리자) 또는 심화 대상이면 경로 확정.
      if (isCrown(rule.to)) {
        n++;
        routes.push({
          id: `r${n}`,
          goal: GOALS[rule.to].label,
          goalSeverity: GOALS[rule.to].severity,
          entry,
          steps: next,
          impact: impactOf(rule.to),
        });
      }
      dfs(rule.to, reached, next, entry);
    }
  };

  for (const [cap, via] of caps) {
    // 보유 능력 자체가 왕관이면 0단계 경로로 확정한다(스머글링 = 트래픽 납치 능력 확보 등).
    if (isCrown(cap)) {
      n++;
      routes.push({
        id: `r${n}`,
        goal: GOALS[cap].label,
        goalSeverity: GOALS[cap].severity,
        entry: cap,
        steps: [],
        impact: impactOf(cap),
      });
    }
    void via;
    dfs(cap, new Set([cap]), [], cap);
  }

  // 랭킹: critical 목표 우선 → 경로가 짧을수록 우선 → id 순(결정적).
  routes.sort((a, b) => {
    const g = (r: AttackRoute) => (r.goalSeverity === "critical" ? 0 : 1);
    return g(a) - g(b) || a.steps.length - b.steps.length || a.id.localeCompare(b.id);
  });
  return routes.slice(0, 12);
}

function isCrown(cap: Capability): boolean {
  return cap === "code-exec" || cap === "admin-access" || cap === "traffic-hijack" || cap === "data-exfil";
}

function impactOf(goal: Capability): string {
  switch (goal) {
    case "code-exec":
      return "서버에서 임의 명령 실행 — 전체 데이터·내부망·배포 파이프라인까지 노출";
    case "admin-access":
      return "관리자 기능 장악 — 사용자 통제·데이터 내보내기·설정 위변조 가능";
    case "traffic-hijack":
      return "캐시/응답을 통한 불특정 다수 사용자 공격 — 세션 탈취·피싱·악성코드 배포";
    case "data-exfil":
      return "서비스 전체 개인정보/기록 유출 — 규제 위반·신뢰 붕괴";
    default:
      return "능력 확대로 추가 침투 경로 활성화";
  }
}

/** 리포트용 — 능력 보유 현황 + 다음 수 요약. */
export function routeSummary(routes: AttackRoute[], findings: EngagementFinding[], exposed: EvidenceItem[]): string[] {
  const caps = capabilitiesOf(findings, exposed);
  const lines: string[] = [];
  lines.push(`보유 능력: ${[...caps.keys()].map((c) => CAPABILITY_KO[c]).join(", ") || "없음"}`);
  if (routes.length === 0) {
    lines.push("합성 가능한 다단계 경로 없음 — 발견이 단독으로 끝나거나 왕관까지 연결 규칙이 없다.");
    return lines;
  }
  lines.push(`왕관 경로 ${routes.length}건 — 최우선: ${routes[0].goal} (${routes[0].entry ? CAPABILITY_KO[routes[0].entry] : "?"} → ${routes[0].steps.map((s) => CAPABILITY_KO[s.to]).join(" → ")})`);
  const nextMoves = [...new Set(routes.flatMap((r) => r.steps.slice(0, 1).map((s) => s.how)))].slice(0, 3);
  for (const m of nextMoves) lines.push(`다음 수: ${m}`);
  return lines;
}
