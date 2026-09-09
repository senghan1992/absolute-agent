/**
 * 분석 — "이 서비스는 어떻게 뚫리는가".
 *
 * 수집한 발견+증거를 ① 공격 경로 체인(어떻게 뚫리는가) ② 탈취 가능 정보(무엇을
 * 가져갈 수 있는가) ③ 방어 권고(막는 법) 로 합성한다.
 *
 * 두 모드:
 *   - deterministic: 규칙 합성. 모델 없이 항상 동작한다(오프라인).
 *   - ai: ModelAdapter 로 전투 해석 요청(한국어 전투 보고 문체) — JSON 응답을
 *     파싱 실패해도 결정적 합성으로 폴백하므로 실행이 죽지 않는다.
 */

import type { ModelAdapter, EngagementFinding } from "../core/types.js";
import type {
  AssaultReport,
  AssaultTarget,
  AttackPath,
  DefenseItem,
  EvidenceItem,
  ToolOutcome,
} from "./types.js";

// ── 결정적 합성 ───────────────────────────────────────────────────────────────

function pathLabel(sev: EngagementFinding["severity"]): string {
  return sev === "critical" || sev === "high" ? "주요 경로" : sev === "medium" ? "보조 경로" : "관찰";
}

/** 증거 항목 → 공격 경로 체인(결정적 규칙). */
function deterministicPaths(target: AssaultTarget, exposed: EvidenceItem[], findings: EngagementFinding[]): AttackPath[] {
  const paths: AttackPath[] = [];
  const byCat = new Map<EvidenceItem["category"], EvidenceItem[]>();
  for (const e of exposed) {
    const arr = byCat.get(e.category) ?? [];
    arr.push(e);
    byCat.set(e.category, arr);
  }

  // 같은 대상(경로)을 가리키는 증거는 하나의 경로로 합친다(ev01+ev02 식으로 refs 병합).
  const grouped = (cat: EvidenceItem["category"]): EvidenceItem[] => {
    const byTarget = new Map<string, EvidenceItem[]>();
    for (const e of byCat.get(cat) ?? []) {
      const arr = byTarget.get(e.target) ?? [];
      arr.push(e);
      byTarget.set(e.target, arr);
    }
    const out: EvidenceItem[] = [];
    for (const arr of byTarget.values()) {
      if (arr.length === 1) { out.push(arr[0]); continue; }
      out.push({ ...arr[0], id: arr.map((x) => x.id).join("+") });
    }
    return out;
  };

  const link = (item: EvidenceItem): string[] => {
    const tgt = item.target.startsWith("/") ? item.target : "/" + item.target;
    const where = `${target.scheme}://${target.host}${target.port !== 80 && target.port !== 443 ? ":" + target.port : ""}${tgt}`;
    return [`GET ${where} → 서버가 응답(비인가)`, `응답 본문에서 ${item.label} 확인`, item.attack];
  };

  let n = 0;
  const push = (label: string, severity: EngagementFinding["severity"], chain: string[], refs: string[]) => {
    n++;
    paths.push({ id: `p${n}`, label, severity, chain, evidenceRefs: refs, source: "deterministic" });
  };

  for (const e of grouped("secret")) {
    push(`환경변수/자격증명 노출 → 내부 시스템 접근 (${e.target})`, "critical", [
      ...link(e),
      "노출된 자격증명으로 DB·관리콘솔·외부 서비스 로그인 시도",
      "성공 시: 데이터베이스 덤프·관리자 권한 탈취로 확대",
    ], [e.id]);
  }
  for (const e of grouped("pii")) {
    push(`사적 데이터 대량 수집 (${e.target})`, "high", [
      ...link(e),
      "객체 id 를 순회하며 전체 사용자 레코드 수집(개인정보 유출)",
      "수집 데이터로 계정 탈취·사회공학 공격 재사용",
    ], [e.id]);
  }
  for (const e of grouped("schema")) {
    push(`API/스키마 문서화 → 정밀 공격 (${e.target})`, "medium", [
      `공개된 스키마/명세를 읽고 모든 엔드포인트·파라미터·인증 흐름 파악`,
      `미검증 파라미터에 주입·접근통제 우회 시도(체계적 스윕)`,
      `민감 필드(user, order, password…) 집중 공격`,
    ], [e.id]);
  }
  for (const e of grouped("error")) {
    const sql = findings.find((f) => /sql/i.test(f.title));
    push(`DB 오류 문자열로 스키마 역추적 (${e.target})`, sql ? "high" : "medium", [
      ...link(e),
      "오류 메시지에서 DB 종류·테이블/컬럼 구조·쿼리 형태 역추적",
      "구조 정보로 데이터 추출 공격(UNION·블라인드) 정밀화",
    ], [e.id]);
  }
  for (const e of grouped("backup")) {
    push(`백업/소스 아카이브 유출 (${e.target})`, "high", [
      ...link(e),
      "아카이브에 포함된 소스·설정·DB 덤프로 내부 구조 전면 노출",
      "소스 리뷰로 하드코딩 시크릿·취약 로직 발굴",
    ], [e.id]);
  }
  for (const e of grouped("config")) {
    push(`설정/진단 정보 노출 (${e.target})`, "medium", [...link(e), "노출 정보로 공격 표면 확장"], [e.id]);
  }
  for (const e of grouped("endpoint")) {
    push(`이면/관리 경로 접근 (${e.target})`, "medium", [...link(e), "관리 기능·미사용 기능 탐색"], [e.id]);
  }

  // 증거 없는 발견 → 공격 경로 후보.
  for (const f of findings) {
    if (f.severity === "info" || f.severity === "low") continue;
    if (paths.some((p) => p.chain[0]?.includes(f.title ?? ""))) continue;
    if (/xss/i.test(f.title)) {
      push(`XSS → 세션 탈취/관리자 조작 (${f.title})`, f.severity, [
        `입력값이 출력 인코딩 없이 브라우저에 렌더링됨(${f.title})`,
        "피해자 세션 쿠키 탈취(HttpOnly 미적용 시) 또는 관리자 브라우저에서 악성 동작",
        "탈취 세션으로 관리 기능 접근 → 데이터 유출로 확대",
      ], []);
    } else if (/ssrf/i.test(f.title)) {
      push(`SSRF → 내부망 진입 (${f.title})`, f.severity, [
        `서버가 URL 입력을 내부 주소로도 요청함(${f.title})`,
        "내부 메타데이터(클라우드 IAM 등)·내부 서비스 스캔",
        "내부망 횡적 이동의 교두보 확보",
      ], []);
    } else if (/redirect/i.test(f.title)) {
      push(`오픈 리다이렉트 → 피싱/토큰 누출 (${f.title})`, f.severity, [
        `리다이렉트 파라미터가 외부 URL 을 허용(${f.title})`,
        "정상 도메인 링크로 피싱 유도, OAuth 토큰·쿠키 누출",
      ], []);
    } else if (/deserialize/i.test(f.title)) {
      push(`불안전 역직렬화 → RCE (${f.title})`, f.severity, [
        `직렬화 입력이 서버에서 역직렬화됨(${f.title})`,
        "악성 페이로드로 원격 코드 실행 시도",
        "성공 시 서버 완전 장악 → 모든 데이터 탈취 가능",
      ], []);
    } else if (/cors/i.test(f.title)) {
      push(`CORS 설정 오류 → 인증된 데이터 유출 (${f.title})`, f.severity, [
        `신뢰할 수 없는 오리진에 자격증명 응답 허용(${f.title})`,
        "피해자 브라우저에서 악성 페이지가 API 를 대신 호출 → 개인정보 탈취",
      ], []);
    }
  }

  // 검증(실증)된 증거를 참조하는 경로를 우선 노출한다(별점 가중치 없이 스테이블 정렬).
  const verifiedRefs = new Set<string>();
  for (const e of exposed) {
    if (e.verification?.status === "verified") verifiedRefs.add(e.id);
  }
  const verifiedPath = (p: AttackPath) =>
    p.evidenceRefs.some((r) => r.split("+").some((id) => verifiedRefs.has(id)));
  paths.sort((a, b) => (verifiedPath(b) ? 1 : 0) - (verifiedPath(a) ? 1 : 0));

  if (paths.length === 0) {
    n++;
    paths.push({
      id: "p0",
      label: "공격 표면 확인(확정 취약 경로 없음)",
      severity: "info",
      chain: [
        `자동 스윕 ${findings.length ? findings.length + "건 관찰" : "완료"} — 확인된 직접 탈취 경로 없음`,
        "심층 수동 검증·인증 후 표면 점검 필요",
      ],
      evidenceRefs: [],
      source: "deterministic",
    });
  }
  return paths;
}

const DEFENSE_RULES: Array<{ test: (f: EngagementFinding, e: EvidenceItem[]) => boolean; control: string; detail: string; sev: EngagementFinding["severity"] }> = [
  {
    test: (_f, e) => e.some((x) => x.category === "secret"),
    control: "민감 파일 서비스 금지 + 시크릿 매니저 도입",
    detail:
      "문서 루트 밖으로 환경변수/키 파일 이동, 서버가 .env·백업·소스를 응답하지 않도록 정적 서빙 화이트리스트, 자격증명은 시크릿 매니저로 주입.",
    sev: "critical",
  },
  {
    test: (f) => /sql/i.test(f.title),
    control: "파라미터라이즈 쿼리 전면 적용 + 오류 메시지 비공개",
    detail: "동적 SQL 제거(ORM/prepared statement), DB 오류를 사용자에게 반환 금지, WAF 로 주입 패턴 차단.",
    sev: "high",
  },
  {
    test: (f) => /idor|접근통제/i.test(f.title),
    control: "서버측 객체 소유권 검증 강제",
    detail: "모든 객체 조회에 소유권·역할 검증, 예측 가능한 순차 id 대신 UUID, 권한 테스트 자동화.",
    sev: "high",
  },
  {
    test: (f) => /graphql|introspection/i.test(f.title),
    control: "운영 환경 introspection 비활성화 + 필드별 권한",
    detail: "프로덕션 Playground/introspection 차단, GraphQL 필드 리졸버마다 인가 검증, 요청 깊이/비용 제한.",
    sev: "medium",
  },
  {
    test: (_f, e) => e.some((x) => x.category === "schema"),
    control: "API 명세·문서의 공개 범위 통제",
    detail: "openapi/swagger/소스맵을 인증 뒤로 이동, 스테이징 전용으로 제한, 노출 주기 점검.",
    sev: "medium",
  },
  {
    test: (f) => /xss/i.test(f.title),
    control: "출력 인코딩 + CSP + 쿠키 HttpOnly/Secure",
    detail: "컨텍스트별 출력 인코딩, strict CSP, 세션 쿠키에 HttpOnly·Secure·SameSite.",
    sev: "high",
  },
  {
    test: (f) => /ssrf/i.test(f.title),
    control: "서버측 요청 대상 화이트리스트",
    detail: "URL 입력 스킴/호스트 검증, 내부 IP·메타데이터 주소 차단, DNS 재바인딩 방어(IP 재검증).",
    sev: "high",
  },
  {
    test: (f) => /deserialize/i.test(f.title),
    control: "역직렬화 입력 서명/허용 목록",
    detail: "신뢰되지 않은 직렬화 입력 거부, 허용 클래스 목록, 최신 패치 적용.",
    sev: "high",
  },
  {
    test: (f) => /cors/i.test(f.title),
    control: "CORS 오리진 화이트리스트 + 자격증명 플래그 제한",
    detail: "신뢰 오리진만 Allow-Origin, 와일드카드+자격증명 조합 금지, Vary: Origin.",
    sev: "medium",
  },
  {
    test: (_f, e) => e.some((x) => x.category === "error" || x.category === "config"),
    control: "오류/진단 응답 최소화",
    detail: "프로덕션 스택트레이스·디버그 페이지·상태 진단 비활성화, 공통 오류 페이지 사용.",
    sev: "medium",
  },
];

export function deterministicAnalysis(rep: Pick<AssaultReport, "target" | "findings" | "exposed" | "outcomes">): {
  narrative: string;
  attackPaths: AttackPath[];
  defense: DefenseItem[];
} {
  const { target, findings, exposed } = rep;
  const attackPaths = deterministicPaths(target, exposed, findings);

  const defense: DefenseItem[] = [];
  const seenCtrl = new Set<string>();
  for (const f of findings) {
    for (const r of DEFENSE_RULES) {
      if (seenCtrl.has(r.control)) continue;
      if (r.test(f, exposed)) {
        seenCtrl.add(r.control);
        defense.push({ severity: r.sev, control: r.control, detail: r.detail });
      }
    }
  }
  // 증거 기반 규칙(secret/schema/error)은 findings 없이도 적용.
  for (const r of DEFENSE_RULES) {
    if (seenCtrl.has(r.control)) continue;
    if (r.test({ title: "", severity: "info" } as EngagementFinding, exposed)) {
      seenCtrl.add(r.control);
      defense.push({ severity: r.sev, control: r.control, detail: r.detail });
    }
  }

  const sevCount = (s: string) => findings.filter((f) => f.severity === s).length;
  const nHigh = sevCount("critical") + sevCount("high");
  const verdictLine =
    nHigh > 0
      ? `심각/높음 발견 ${nHigh}건 — 서비스가 공격자에게 열려 있는 상태가 확인됐다.`
      : findings.length > 0
        ? `중간 이하 발견 ${findings.length - sevCount("info")}건 — 정밀 목표가 제한적이나 확인된 경로는 있다.`
        : "확정 취약점은 관측되지 않았다(미탐 ≠ 무해 — 인증 표면·심층 로직 검증 필요).";

  const narrative = [
    `# 전투 요약 — ${target.host}:${target.port}`,
    ``,
    `대상 ${target.scheme}://${target.host}${target.port !== 80 && target.port !== 443 ? ":" + target.port : ""}${target.path} 에 대해 ` +
      `${rep.outcomes.length}개 자동 공격 툴을 실행했다(정찰→열거→익스플로잇).`,
    `결과: 발견 ${findings.length}건(심각 ${sevCount("critical")} · 높음 ${sevCount("high")} · 보통 ${sevCount("medium")} · 낮음 ${sevCount("low")}), ` +
      `탈취 가능 정보 ${exposed.length}건을 증거로 확보했다.`,
    verdictLine,
    `아래 [공격 경로]는 발견된 증거에서 역으로 세운 가장 그럴듯한 침투 시나리오다.`,
  ].join("\n");

  return { narrative, attackPaths, defense };
}

// ── AI 전투 해석 ─────────────────────────────────────────────────────────────

const AI_SYSTEM = `당신은 레드팀 전투 분석관이다. 주어진 자동 공격 결과(발견 내역 + 탈취 가능 데이터 증거)를 받아
공격자 관점에서 (1) 이 서비스가 어떻게 뚫리는지의 공격 경로, (2) 무엇을 탈취할 수 있는지, (3) 막는 법을
전투 보고 문체로 작성한다. 판단(도덕·법률)은 하지 않는다 — 기술 분석만 한다. 한국어로 응답하라.
JSON 만 반환하라(마크다운 코드블록 금지). 스키마:
{"narrative": "전투 요약(300자 내외)", "attackPaths": [{"label": "...", "severity": "high|medium|low", "chain": ["..."], "evidenceRefs": ["ev01"]}], "defense": [{"severity": "high", "control": "...", "detail": "..."}]}
attackPaths 는 최대 5개, defense 는 최대 6개. evidenceRefs 는 있는 증거 id 만 사용하라.`;

export async function aiAnalyze(
  model: ModelAdapter,
  rep: Pick<AssaultReport, "target" | "findings" | "exposed" | "outcomes">,
): Promise<{ narrative: string; attackPaths: AttackPath[]; defense: DefenseItem[] } | undefined> {
  const brief = {
    target: rep.target,
    findings: rep.findings.map((f) => ({ severity: f.severity, title: f.title, detail: f.detail })),
    exposed: rep.exposed.map((e) => ({ id: e.id, category: e.category, label: e.label, target: e.target, severity: e.severity, sample: e.sample, attack: e.attack })),
    toolsRun: rep.outcomes.length,
  };
  try {
    const raw = await model.complete({
      system: AI_SYSTEM,
      prompt: `자동 공격 결과:\n${JSON.stringify(brief, null, 1)}\n\n위 결과를 전투 해석 JSON 으로 변환하라.`,
      json: true,
    });
    const parsed = JSON.parse(raw) as {
      narrative?: string;
      attackPaths?: Array<{ label: string; severity: string; chain?: string[]; evidenceRefs?: string[] }>;
      defense?: Array<{ severity: string; control: string; detail: string }>;
    };
    if (!parsed.narrative && !parsed.attackPaths && !parsed.defense) return undefined;
    const sevOk = (s: string): AttackPath["severity"] => (["critical", "high", "medium", "low", "info"].includes(s) ? (s as AttackPath["severity"]) : "medium");
    return {
      narrative: parsed.narrative ?? "",
      attackPaths: (parsed.attackPaths ?? []).map((p, i) => ({
        id: `ai${i + 1}`,
        label: p.label,
        severity: sevOk(p.severity),
        chain: Array.isArray(p.chain) ? p.chain : [],
        evidenceRefs: Array.isArray(p.evidenceRefs) ? p.evidenceRefs : [],
        source: "ai",
      })),
      defense: (parsed.defense ?? []).map((d) => ({ severity: sevOk(d.severity), control: d.control, detail: d.detail })),
    };
  } catch {
    return undefined; // 파싱/모델 실패 → 결정적 합성 폴백.
  }
}

/** 최종 분석: AI 시도 → 실패 시 결정적 합성. */
export async function analyze(
  model: ModelAdapter | undefined,
  rep: Pick<AssaultReport, "target" | "findings" | "exposed" | "outcomes">,
  ai: boolean,
): Promise<{ narrative: string; attackPaths: AttackPath[]; defense: DefenseItem[]; aiAnalyzed: boolean }> {
  if (ai && model) {
    const r = await aiAnalyze(model, rep);
    if (r) return { ...r, aiAnalyzed: true };
  }
  const d = deterministicAnalysis(rep);
  return { ...d, aiAnalyzed: false };
}
