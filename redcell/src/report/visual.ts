/**
 * visual — 초보자용 "상황판(situation board)".
 *
 * 보안 신입·비전문 개발자·비개발 PM 이 결과를 보고 스스로 판단할 수 있도록, 전문 용어 대신
 * 쉬운 말과 CLI 그림(가로줄·화살표·막대)으로 결과를 시각화한다. 상세 Markdown 리포트
 * 위에 얹어 "무슨 일이 / 얼마나 위험 / 언제까지 누가 무엇을" 을 한눈에 보여준다.
 *
 * 색 없이 문자만으로 그리므로 어떤 터미널·로그에서도 동일하게 보인다.
 *
 * 설계 근거: 초보자 3인(보안 신입/웹 개발자/비개발 PM) 사용성 테스트 피드백 반영.
 *   - 제목은 한글 우선(영문 병기)  - 유형별 고유 설명(복붙 금지)  - 조치 기한·담당 표기
 *   - "위치"는 공격당한 파일이 아니라 취약 엔드포인트로  - 게이트 통과 조건 명시
 *   - 근거 줄은 '개발자 전달용'으로 표시하고, 핵심은 사람 말 한 줄로 별도 제공.
 */

import type { EngagementLog, EngagementFinding } from "../core/types.js";
import type { WaivedFinding } from "./provenance.js";

const W = 64; // 가로줄 폭
const SEV_LABEL: Record<EngagementFinding["severity"], string> = {
  critical: "심각",
  high: "높음",
  medium: "보통",
  low: "낮음",
  info: "참고",
};
const SEV_ICON: Record<EngagementFinding["severity"], string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};
/** 심각도별 권장 처리 기한(초보자가 일정·보고 판단을 할 수 있게). */
const SEV_SLA: Record<EngagementFinding["severity"], string> = {
  critical: "24시간 내(최우선)",
  high: "이번 주 내",
  medium: "이번 달 내",
  low: "여유 있을 때",
  info: "참고",
};

export interface VisualOptions {
  waived?: WaivedFinding[];
}

export function toVisualBoard(log: EngagementLog, opts: VisualOptions = {}): string {
  const L: string[] = [];
  const rule = (ch = "─") => ch.repeat(W);
  const heading = (title: string) => `${"━".repeat(3)} ${title} ${"━".repeat(Math.max(3, W - 5 - dispWidth(title)))}`;

  const t = log.target;
  const actionable = log.findings.filter((f) => f.severity !== "info");

  // ── 헤더 ────────────────────────────────────────────────────────────────
  L.push("");
  L.push("┌" + rule("─") + "┐");
  L.push("│" + center("RedCell 진단 결과 · 초보자 상황판", W) + "│");
  L.push("└" + rule("─") + "┘");
  L.push(`  대상 서버 : ${t.host}${t.port ? ":" + t.port : ""}`);
  L.push(`  사용 기술 : ${techLine(log)}`);
  L.push("");

  // ── 한눈에 보기(신호등) ───────────────────────────────────────────────────
  L.push(heading("한눈에 보기"));
  for (const line of verdictView(log, actionable)) L.push("  " + line);
  L.push("");

  // ── 공격 경로 지도(킬체인) ─────────────────────────────────────────────────
  L.push(heading("공격자는 이렇게 들어옵니다 (공격 경로)"));
  for (const line of killChain(log, actionable)) L.push("  " + line);
  L.push("");

  // ── 위험도 막대 ────────────────────────────────────────────────────────────
  L.push(heading("위험도 한눈에 (막대 길이 = 건수, 위험도는 색으로)"));
  for (const line of severityBars(log.findings)) L.push("  " + line);
  L.push("");

  // ── 발견 카드(쉬운 설명) ──────────────────────────────────────────────────
  if (actionable.length > 0) {
    L.push(heading("무엇이 문제인가요? (급한 것부터)"));
    const sorted = [...actionable].sort((a, b) => rankOf(b.severity) - rankOf(a.severity));
    sorted.forEach((f, i) => {
      for (const line of findingCard(f, i + 1)) L.push("  " + line);
      L.push("");
    });
  } else {
    L.push(heading("무엇이 문제인가요?"));
    L.push("  검사한 범위에서 악용 가능한 문제를 찾지 못했습니다.");
    L.push("  (단, 이 검사는 전체 안전을 보장하지 않습니다 — 아래 '주의' 참고)");
    L.push("");
  }

  // ── 수용된 위험(waiver) ────────────────────────────────────────────────────
  if (opts.waived && opts.waived.length > 0) {
    L.push(heading("이미 '알고 넘어가기로' 결정한 문제 (승인됨)"));
    for (const w of opts.waived) {
      L.push(`  ${SEV_ICON[w.finding.severity]} ${classify(w.finding.title).ko}`);
      L.push(`     └ 승인: ${w.waiver.approved_by} · 기한: ${w.waiver.expires}`);
    }
    L.push("  ※ 사라진 게 아니라 담당자가 책임지고 수용한 항목입니다.");
    L.push("");
  }

  // ── 다음 할 일 ────────────────────────────────────────────────────────────
  L.push(heading("그래서, 지금 무엇을 하면 되나요?"));
  for (const line of nextSteps(log, actionable)) L.push("  " + line);
  L.push("");

  // ── 범례 ──────────────────────────────────────────────────────────────────
  L.push(rule("┄"));
  L.push("  위험도 색: 🔴 심각(당장)  🟠 높음(이번 주)  🟡 보통(이번 달)  🔵 낮음");
  L.push("  '확인된 근거' 줄은 개발자 전달용입니다 — 비개발자는 그 윗줄까지만 봐도 됩니다.");
  L.push("  이 상황판 아래에는 전문가용 상세 리포트가 이어집니다.");
  L.push(rule("┄"));
  return L.join("\n");
}

/** 사용 기술 한 줄 — 서비스와 버전을 붙여 읽기 쉽게(nginx 1.18.0 / php ...). */
function techLine(log: EngagementLog): string {
  const fp = log.fingerprint;
  const head = [fp.service, fp.version].filter(Boolean).join(" ");
  const parts = [head, ...(fp.tech ?? [])].filter(Boolean);
  return parts.length ? parts.join(" / ") : "확인 안 됨";
}

// ── 신호등 판정 ───────────────────────────────────────────────────────────────
function verdictView(log: EngagementLog, actionable: EngagementFinding[]): string[] {
  const highPlus = actionable.filter((f) => f.severity === "critical" || f.severity === "high").length;
  if (log.verdict === "inconclusive") {
    return [
      "🟡 판단 보류 — 아직 '안전하다'고 말할 수 없습니다.",
      `   이유: ${log.verdictReason ?? "검사를 끝까지 수행하지 못했습니다."}`,
      "   → 대상이 켜져 있는지, 접속 정보가 맞는지 확인 후 다시 검사하세요.",
    ];
  }
  if (actionable.length > 0) {
    const sev = highPlus > 0 ? "🔴 위험" : "🟡 주의";
    return [
      `${sev} — 지금 이대로 서비스를 열면 안 됩니다.`,
      `   공격에 악용될 수 있는 문제 ${actionable.length}건${highPlus > 0 ? ` (그중 심각·높음 ${highPlus}건)` : ""}.`,
      `   경영진 보고용 한 줄: "${execSummary(actionable)}"`,
      `   오픈(게이트 통과) 조건: 심각·높음 0건. 지금 ${highPlus}건 남음.`,
      "   → 아래 문제를 '급한 것부터(심각→높음)' 고친 뒤 다시 검사하세요.",
    ];
  }
  return [
    "🟢 양호 — 검사한 범위에서는 악용 가능한 문제를 못 찾았습니다.",
    "   다만 이건 '검사한 부분만' 깨끗하다는 뜻입니다(전체 보증 아님).",
    "   → 아래 '주의' 항목의 수동 점검을 함께 진행하세요.",
  ];
}

/** 발견 유형을 근거로 비전문가·경영진용 위험 한 줄을 조립(사실에 없는 피해는 지어내지 않음). */
function execSummary(actionable: EngagementFinding[]): string {
  const cats = new Set(actionable.map((f) => classify(f.title).cat));
  const parts: string[] = [];
  if (cats.has("rce")) parts.push("외부 공격자가 서버를 통째로 장악");
  if (cats.has("sql")) parts.push("데이터베이스 전체 유출");
  if (cats.has("access")) parts.push("로그인 없이 고객 데이터 열람");
  if (cats.has("secret")) parts.push("노출된 열쇠로 시스템 침입");
  if (parts.length === 0) parts.push("공격자가 추가 침투의 발판을 확보");
  return `${parts.slice(0, 2).join("·")}할 수 있는 상태. 오픈 시 사고 위험이 큽니다.`;
}

// ── 공격 경로(킬체인) 다이어그램 ────────────────────────────────────────────────
function killChain(log: EngagementLog, actionable: EngagementFinding[]): string[] {
  const endpoints = (log.fingerprint.indicators ?? []).filter((i) => /^endpoint /.test(i)).length;
  const breach = actionable.some((f) => f.phase === "exploit" || f.phase === "enumerate");
  const own = actionable.some((f) => f.severity === "critical" || f.severity === "high");

  // 공격자가 각 단계에 '도달했는가'를 표시(✓=우리 점검 성공 과 헷갈리지 않게 '도달/막힘' 단어 사용).
  const breachWord = breach ? "▶ 공격 통함" : "□ 막힘";
  const ownWord = own ? "▶ 도달 가능" : "□ 차단";
  return [
    "정찰(살펴보기)   ──▶   문 열기(약점 악용)   ──▶   장악(내부 장악)",
    `  ▶ 점검 완료          ${breachWord}            ${ownWord}`,
    "  서버·경로 파악        발견한 약점으로 침투        데이터·계정·서버 탈취",
    "",
    `  이 서버에서 입구(경로) ${endpoints}곳을 확인했고, 아래 ${actionable.length}건의 문제가 나왔습니다.`,
    own
      ? "  ⚠ '장악' 단계까지 도달 가능 — 공격자가 실제로 내부를 차지할 수 있습니다."
      : breach
        ? "  ⚠ '문 열기' 단계 문제 발견 — 방치하면 장악으로 이어질 수 있습니다."
        : "  □ 침투로 이어질 결정적 약점은 확인되지 않았습니다.",
  ];
}

// ── 위험도 막대 ────────────────────────────────────────────────────────────────
function severityBars(findings: EngagementFinding[]): string[] {
  const order: EngagementFinding["severity"][] = ["critical", "high", "medium", "low"];
  const counts = order.map((s) => findings.filter((f) => f.severity === s).length);
  const max = Math.max(1, ...counts);
  const barMax = 24;
  return order.map((s, i) => {
    const n = counts[i];
    const len = n === 0 ? 0 : Math.max(1, Math.round((n / max) * barMax));
    const bar = n === 0 ? "·" : "█".repeat(len);
    const label = `${SEV_ICON[s]} ${SEV_LABEL[s]}`;
    return `${padDisp(label, 8)} │ ${padDisp(bar, barMax)} ${n}건`;
  });
}

// ── 발견 카드(쉬운 설명) ─────────────────────────────────────────────────────
function findingCard(f: EngagementFinding, idx: number): string[] {
  const k = classify(f.title);
  const where = whereFrom(f);
  const proof = plainProof(f);
  return [
    `[${idx}] ${SEV_ICON[f.severity]} ${SEV_LABEL[f.severity]} · ${k.ko}${where ? `   (위치: ${where})` : ""}`,
    `      쉽게 말하면 : ${k.simple}`,
    `      왜 위험한가 : ${k.why}`,
    `      어떻게 막나  : ${k.fix}`,
    `      조치 기한·담당: ${SEV_ICON[f.severity]} ${SEV_SLA[f.severity]} · ${k.owner}`,
    ...(proof ? [`      실제 확인    : ${proof}`] : []),
    ...(f.evidence ? [`      확인된 근거(개발자 전달용): ${clip(f.evidence, 96)}`] : []),
  ];
}

// ── 다음 할 일 ────────────────────────────────────────────────────────────────
function nextSteps(log: EngagementLog, actionable: EngagementFinding[]): string[] {
  const out: string[] = [];
  if (log.verdict === "inconclusive") {
    out.push("1) 대상 서버가 실행 중이고 주소·포트가 맞는지 확인하세요.");
    out.push("2) 로그인이 필요한 서비스면 인가된 테스트 계정을 설정하고 다시 검사하세요.");
    return out;
  }
  if (actionable.length > 0) {
    const highPlus = actionable.filter((f) => f.severity === "critical" || f.severity === "high").length;
    const top = [...actionable].sort((a, b) => rankOf(b.severity) - rankOf(a.severity)).slice(0, 3);
    top.forEach((f, i) => {
      const k = classify(f.title);
      out.push(`${i + 1}) [${SEV_LABEL[f.severity]}] ${k.ko} → ${k.fix}`);
      out.push(`   └ 담당: ${k.owner} · 기한: ${SEV_SLA[f.severity]}`);
    });
    out.push(`${top.length + 1}) 위를 포함해 심각·높음 ${highPlus}건을 모두 없애면 게이트 통과(오픈 가능).`);
    out.push(`${top.length + 2}) 고친 뒤 같은 명령으로 다시 검사해 문제가 사라졌는지 확인하세요.`);
    return out;
  }
  out.push("이 도구가 못 보는 곳은 사람이 봐야 합니다:");
  out.push("  • 로그인 이후 화면·권한(내 것이 아닌 데이터가 보이는지)");
  out.push("  • 결제·쿠폰 같은 '업무 규칙' 악용, 저장형 XSS");
  out.push("  • 사용 중인 라이브러리의 알려진 취약점(의존성 점검, SCA)");
  return out;
}

// ── 유형 분류(한글명·쉬운설명·담당) ────────────────────────────────────────────
type Cat = "rce" | "sql" | "access" | "secret" | "other";
interface VulnInfo {
  ko: string; // 한글 우선 제목(영문 병기)
  cat: Cat; // 경영진 요약용 대분류
  simple: string;
  why: string;
  fix: string;
  owner: string; // 조치 담당(초보자가 티켓을 어디로 넘길지)
}
const OWNER = {
  code: "개발팀(코드 수정)",
  infra: "인프라/서버 설정",
  secops: "보안팀(키 즉시 폐기)",
  identity: "백엔드(인증·토큰)",
};

/**
 * 발견 제목을 유형으로 분류한다. ⚠️ 순서가 중요: 구체 유형을 먼저 판정해야
 * "노출/명령" 같은 넓은 단어가 엉뚱한 유형으로 새지 않는다. 유형마다 고유 설명을 준다(복붙 금지).
 */
function classify(title: string): VulnInfo {
  const t = title.toLowerCase();
  const has = (...keys: string[]) => keys.some((k) => t.includes(k));

  if (has("ssti", "template", "템플릿"))
    return {
      ko: "서버 템플릿 주입 (SSTI)",
      cat: "rce",
      simple: "입력값이 서버의 화면 '틀(템플릿)'에 그대로 들어가 계산식·코드로 실행됩니다.",
      why: "표현식을 통해 서버 명령까지 실행 → 서버를 통째로 장악할 수 있습니다.",
      fix: "사용자 입력을 템플릿 문자열로 렌더링하지 말고 '데이터'로만 전달하세요(템플릿 엔진 안전 모드).",
      owner: OWNER.code,
    };
  if (has("command", "커맨드", "명령", "rce", "code execution"))
    return {
      ko: "서버 명령어 실행 (OS Command Injection)",
      cat: "rce",
      simple: "입력값이 서버에서 진짜 '시스템 명령어'로 실행됩니다.",
      why: "공격자가 서버에서 임의 프로그램을 실행 → 서버 장악(root 실행 확인 시 최악).",
      fix: "쉘을 거치지 말고 인자 배열로 실행(exec)하고, 세미콜론·파이프 같은 쉘 특수문자를 차단하세요.",
      owner: OWNER.code,
    };
  if (has("deserial", "역직렬"))
    return {
      ko: "안전하지 않은 역직렬화 (Insecure Deserialization)",
      cat: "rce",
      simple: "외부에서 받은 데이터를 그대로 객체로 복원하다 악성 코드가 실행됩니다.",
      why: "조작된 데이터로 서버에서 임의 코드가 실행 → 서버 장악.",
      fix: "신뢰할 수 없는 데이터를 역직렬화하지 말고, 허용 타입 화이트리스트·서명 검증을 쓰세요.",
      owner: OWNER.code,
    };
  if (has("stored xss", "저장형 xss"))
    return {
      ko: "저장형 스크립트 삽입 (Stored XSS)",
      cat: "other",
      simple: "게시판·댓글 같은 곳에 저장된 내용이 다른 사용자 화면에서 '스크립트'로 실행됩니다.",
      why: "여러 사용자에게 반복 실행돼 세션 탈취·계정 탈취·악성 확산으로 이어집니다.",
      fix: "저장할 때와 출력할 때 모두 이스케이프하고, CSP 를 켜고, 입력 길이·종류를 제한하세요.",
      owner: OWNER.code,
    };
  if (has("nosql"))
    return {
      ko: "NoSQL 인젝션 (NoSQL Injection)",
      cat: "other",
      simple: "아이디·검색어 같은 값에 연산자($ne/$regex)를 넣으면 인증·검색 조건을 우회합니다.",
      why: "아이디/비밀번호 없이 로그인하거나 비밀 데이터 조건을 무력화할 수 있습니다.",
      fix: "사용자 입력을 쿼리 연산자로 해석하지 말고 값을 화이트리스트로 검증·타입을 고정하세요.",
      owner: OWNER.code,
    };
  if (has("crlf", "헤더 분할"))
    return {
      ko: "CRLF 헤더 분할 (Header Injection)",
      cat: "other",
      simple: "입력값의 줄바꿈(%0d%0a)이 응답 헤더에 그대로 들어가 새 헤더를 만들 수 있습니다.",
      why: "Set-Cookie 주입(세션 고정)·캐시 오염·리다이렉트 조작으로 이어집니다.",
      fix: "입력값에서 CR/LF(%0d%0a)를 제거하거나 인코딩하고 헤더 값 생성을 금지하세요.",
      owner: OWNER.code,
    };
  if (has("프로토타입 오염"))
    return {
      ko: "프로토타입 오염 (Prototype Pollution)",
      cat: "other",
      simple: "JSON 객체를 합칠 때 __proto__ 같은 키를 심으면 객체 '기본값'을 오염시킵니다.",
      why: "서버 로직·설정이 오염돼 권한 상승·RCE 로 확대될 수 있는 깊은 결함입니다.",
      fix: "병합 시 __proto__/constructor/prototype 키를 차단하고 깊은 복사를 금지(객체 키 화이트리스트)하세요.",
      owner: OWNER.code,
    };
  if (has("업로드"))
    return {
      ko: "안전하지 않은 파일 업로드 (Unrestricted Upload)",
      cat: "rce",
      simple: "파일 종류 제한 없이 아무 파일이나 올릴 수 있습니다.",
      why: "악성 스크립트를 올려 서버에서 실행시킬 수 있습니다.",
      fix: "확장자·MIME 화이트리스트, 실행 불가 경로 저장, 파일명 무작위화를 적용하세요.",
      owner: OWNER.code,
    };
  if (has("경쟁 조건", "race"))
    return {
      ko: "경쟁 조건 (Race Condition)",
      cat: "other",
      simple: "동시 요청을 쏘면 상태 확인과 변경 사이에 '틈'이 생겨 두 번 반영됩니다.",
      why: "잔액·재고·쿠폰을 두 번 쓰거나 무한 적립으로 금전 피해가 납니다.",
      fix: "상태 변경을 DB 트랜잭션·원자적 연산(INCR/DECR)·유일 제약으로 묶고 재시도별 멱등키를 쓰세요.",
      owner: OWNER.code,
    };
  if (has("sql"))
    return {
      ko: "SQL 주입 (SQL Injection)",
      cat: "sql",
      simple: "검색창·주소값에 특수한 문장을 넣으면 그게 DB 명령처럼 실행됩니다.",
      why: "회원 이메일·비밀번호 등 DB 전체를 통째로 빼갈 수 있습니다.",
      fix: "입력을 쿼리에 직접 붙이지 말고 '파라미터 바인딩(Prepared Statement)'을 쓰세요.",
      owner: OWNER.code,
    };
  if (has("xss"))
    return {
      ko: "스크립트 삽입 (XSS)",
      cat: "other",
      simple: "입력한 내용이 다른 사용자 화면에서 그대로 '스크립트'로 실행됩니다.",
      why: "접속자 세션·쿠키를 훔쳐 계정을 가로챌 수 있습니다.",
      fix: "화면에 출력할 때 HTML 특수문자를 이스케이프하고, CSP 헤더를 켜세요.",
      owner: OWNER.code,
    };
  if (has("traversal", "lfi", "경로 조작", "파일 포함"))
    return {
      ko: "경로 조작·파일 열람 (Path Traversal / LFI)",
      cat: "secret",
      simple: "파일 이름 자리에 ../ 같은 걸 넣어 서버의 다른 파일을 열어봅니다.",
      why: "설정 파일·비밀번호 파일·소스코드가 노출돼 추가 침투에 쓰입니다.",
      fix: "파일 경로를 사용자 입력으로 만들지 말고, 정해진 목록에서만 고르게 하세요.",
      owner: OWNER.code,
    };
  if (has("ssrf"))
    return {
      ko: "서버 위조 요청 (SSRF)",
      cat: "secret",
      simple: "서버가 대신 요청을 보내게 만들어 내부망·클라우드 정보를 꺼냅니다.",
      why: "외부에서 못 보던 내부 서비스·클라우드 열쇠(임시 자격증명)를 훔칩니다.",
      fix: "서버가 외부 주소로 요청하는 기능은 대상 주소를 화이트리스트로 제한하세요.",
      owner: OWNER.code,
    };
  if (has("redirect"))
    return {
      ko: "열린 리다이렉트 (Open Redirect)",
      cat: "other",
      simple: "링크의 이동 주소를 공격자가 원하는 외부 사이트로 바꿀 수 있습니다.",
      why: "진짜 사이트처럼 보이는 가짜 로그인(피싱)으로 유도됩니다.",
      fix: "이동 주소를 허용된 내부 목록으로 제한하세요(임의 URL 금지).",
      owner: OWNER.code,
    };
  if (has("xxe"))
    return {
      ko: "XML 외부 개체 주입 (XXE)",
      cat: "secret",
      simple: "XML 안에 넣은 지시로 서버가 내부 파일을 읽거나 요청을 보냅니다.",
      why: "내부 파일 노출·SSRF·서비스 거부로 이어집니다.",
      fix: "XML 파서에서 외부 엔티티(DTD) 처리를 꺼세요.",
      owner: OWNER.code,
    };
  if (has("jwt"))
    return {
      ko: "약한 로그인 토큰 (JWT)",
      cat: "access",
      simple: "로그인 토큰이 약하게 만들어져 위조가 가능합니다.",
      why: "공격자가 관리자 토큰을 만들어 아무 계정이나 사칭합니다.",
      fix: "강한 무작위 비밀키로 서명하고 만료시간을 두며 alg=none 을 막으세요.",
      owner: OWNER.identity,
    };
  if (has("csrf"))
    return {
      ko: "요청 위조 (CSRF)",
      cat: "other",
      simple: "사용자가 모르는 사이에 그 사람 권한으로 요청이 나갑니다.",
      why: "피해자 몰래 송금·비밀번호 변경 같은 행동을 시킬 수 있습니다.",
      fix: "상태를 바꾸는 요청에는 CSRF 토큰(1회용 값) 확인을 넣으세요.",
      owner: OWNER.code,
    };
  if (has("cors"))
    return {
      ko: "느슨한 교차출처 설정 (CORS)",
      cat: "other",
      simple: "다른 사이트가 로그인된 사용자를 통해 이 API 를 마음대로 호출합니다.",
      why: "악성 사이트가 피해자 세션으로 데이터를 가져갑니다.",
      fix: "허용 출처(Origin)를 고정 목록으로 제한하고, 자격증명 허용을 남발하지 마세요.",
      owner: OWNER.code,
    };
  if (has("idor", "접근통제", "접근 통제", "access control", "권한", "인증 없", "인증없", "무인증", "unauth", "broken access"))
    return {
      ko: "권한 없는 접근 (IDOR / Broken Access Control)",
      cat: "access",
      simple: "로그인/권한 확인 없이 남의 데이터·관리 기능에 그냥 접근됩니다(주소 번호만 바꿔도 열림).",
      why: "다른 사용자 개인정보를 대량으로 열람·변조하거나 관리 기능을 쓸 수 있습니다.",
      fix: "요청마다 서버에서 '로그인했는지 + 이 자원의 주인/권한자인지'를 반드시 확인하세요.",
      owner: OWNER.code,
    };
  if (has("api", "명세", "graphql", "introspection", "swagger", "openapi"))
    return {
      ko: "API 설계도·관리 경로 노출 (API/Schema Exposure)",
      cat: "other",
      simple: "API 설계도(명세)나 GraphQL 스키마·관리 경로가 외부에 그대로 공개돼 있습니다.",
      why: "공격자에게 '어디를 어떻게 공격할지' 지도를 그려주는 셈입니다.",
      fix: "운영 환경에서는 API 문서·GraphQL introspection·관리 경로 공개를 끄고 인증을 거세요.",
      owner: OWNER.infra,
    };
  // 민감 '경로' 노출은 .env 파일 노출보다 먼저 판정한다("민감 경로 노출 (/admin, /.env)"
  // 처럼 제목에 .env 가 끼어 있어도 '경로' 유형이면 경로로 분류되게).
  if (has("경로 노출", "민감 경로", "디렉터리", "디렉토리", "listing", "경로 나열"))
    return {
      ko: "민감 경로 노출 (Sensitive Path Exposure)",
      cat: "other",
      simple: "관리자 페이지·설정 경로처럼 숨겨야 할 주소가 외부에서 그대로 열립니다.",
      why: "공격자가 관리 기능·내부 정보로 가는 지름길을 얻습니다.",
      fix: "불필요한 관리/설정 경로는 외부 접근을 막고, 필요하면 인증·IP 제한을 거세요.",
      owner: OWNER.infra,
    };
  if (has(".env", "secret", "시크릿", "credential", "자격증명", "비밀번호", "api key", "apikey", "토큰 노출", "backup", "백업"))
    return {
      ko: "비밀·자격증명 파일 노출 (Secret Exposure)",
      cat: "secret",
      simple: "비밀번호·API 키 같은 '열쇠'가 담긴 파일이 외부에 그대로 보입니다.",
      why: "노출된 열쇠로 시스템·클라우드·DB 에 바로 로그인당할 수 있습니다.",
      fix: "해당 파일을 웹에서 제거하고, 노출된 열쇠·토큰은 즉시 폐기·재발급하세요.",
      owner: OWNER.secops,
    };
  if (has("trace", "xst"))
    return {
      ko: "TRACE 메서드 활성 (XST)",
      cat: "other",
      simple: "TRACE 라는 진단용 요청 방식이 켜져 있어, 보낸 요청을 그대로 되돌려줍니다.",
      why: "브라우저가 숨긴 쿠키·인증정보를 우회로 빼내는 데 악용됩니다(XST).",
      fix: "웹서버(nginx/Apache)에서 TRACE 메서드를 끄고, 필요한 요청 방식만 허용하세요.",
      owner: OWNER.infra,
    };
  if (has("method", "메서드", "put", "delete"))
    return {
      ko: "위험한 요청 메서드 허용 (Dangerous HTTP Method)",
      cat: "other",
      simple: "PUT·DELETE 같은 '변경/삭제' 요청 방식이 열려 있습니다.",
      why: "콘텐츠를 몰래 바꾸거나 지울 수 있습니다.",
      fix: "필요한 방식(GET/POST 등)만 허용하고 나머지는 막으세요.",
      owner: OWNER.infra,
    };
  if (has("host"))
    return {
      ko: "Host 헤더 조작 (Host Header Injection)",
      cat: "other",
      simple: "요청의 Host 값을 조작해 서버가 만드는 링크를 바꿀 수 있습니다.",
      why: "비밀번호 재설정 링크가 공격자 주소로 바뀌어 계정을 탈취합니다.",
      fix: "링크 생성에 요청 Host 를 쓰지 말고 서버 설정값을 쓰세요.",
      owner: OWNER.code,
    };
  if (has("pollution", "오염"))
    return {
      ko: "파라미터 오염 (HTTP Parameter Pollution)",
      cat: "other",
      simple: "같은 이름의 파라미터를 여러 개 넣어 서버 해석을 헷갈리게 합니다.",
      why: "접근통제·필터(WAF)를 우회하는 발판이 됩니다.",
      fix: "중복 파라미터 처리 규칙을 고정하고 입력을 엄격히 검증하세요.",
      owner: OWNER.code,
    };
  if (has("헤더", "header"))
    return {
      ko: "보안 헤더 누락 (Missing Security Headers)",
      cat: "other",
      simple: "브라우저를 보호하는 보안 헤더가 빠져 있습니다.",
      why: "클릭재킹·MIME 스니핑 등 기본 방어가 없어 다른 공격이 쉬워집니다.",
      fix: "CSP·X-Frame-Options·X-Content-Type-Options·HSTS 헤더를 추가하세요.",
      owner: OWNER.infra,
    };
  if (has("쿠키", "cookie"))
    return {
      ko: "취약한 세션 쿠키 설정 (Insecure Cookie)",
      cat: "other",
      simple: "세션 쿠키에 보호 옵션(HttpOnly·Secure)이 빠져 있습니다.",
      why: "스크립트나 평문 통신으로 세션이 탈취되기 쉽습니다.",
      fix: "쿠키에 HttpOnly·Secure·SameSite 옵션을 켜세요.",
      owner: OWNER.code,
    };
  return {
    ko: `기타 보안 이상 (${title})`,
    cat: "other",
    simple: "정상 동작에서 벗어난 신호가 관측됐습니다.",
    why: "그 자체로 위험하거나 다른 공격의 발판이 될 수 있습니다.",
    fix: "해당 기능의 입력 검증·접근통제를 점검하고 최신 패치를 적용하세요.",
    owner: OWNER.code,
  };
}

// ── 근거를 사람 말 한 줄로(초보자가 '진짜 뚫렸다'를 알 수 있게) ─────────────────
function plainProof(f: EngagementFinding): string | undefined {
  const e = f.evidence ?? "";
  if (/uid=0\(root\)/.test(e)) return "이미 서버 최고권한(root)으로 명령이 실행됨 — 가장 위험합니다.";
  if (/root:x:0:0/.test(e)) return "서버의 시스템 계정 목록(/etc/passwd)이 실제로 읽혔습니다.";
  if (/169\.254\.169\.254/.test(e)) return "클라우드 내부 관리 주소(메타데이터) 접근 신호가 확인됐습니다.";
  if (/평가되어|산술식|\{\{\s*\d+\s*\*/.test(e)) return "서버가 입력한 계산식을 실제로 계산해 돌려줬습니다(코드 실행 신호).";
  if (/서명 재현 성공|위조 가능/.test(e)) return "약한 비밀키로 로그인 토큰 위조가 실제로 재현됐습니다.";
  return undefined;
}

// ── 유틸 ──────────────────────────────────────────────────────────────────────
function rankOf(s: EngagementFinding["severity"]): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s];
}
/**
 * 취약 '엔드포인트'를 찾는다. 툴 근거의 `path=<경로>` 를 최우선으로 쓴다.
 * (공격당해 노출된 파일 /etc/passwd·169.254… 를 위치로 오표기하지 않도록 그런 경로는 배제.)
 */
function whereFrom(f: EngagementFinding): string {
  const ev = f.evidence ?? "";
  const param = /param=([^),\s]+)/i.exec(f.title)?.[1];
  // 1순위: 근거의 path= 표기(툴이 명시한 실제 공격 대상 경로).
  let epath = /\bpath=(\/[^\s,)]+)/i.exec(ev)?.[1];
  // 2순위: 근거 첫머리의 (/foo …) 또는 "GET /foo" 형태 — 단, 탈취 대상 파일은 제외.
  if (!epath) {
    const cand = /(?:^|[\s(])(\/[\w./:-]+)/.exec(ev)?.[1];
    if (cand && !EXFIL_PATH.test(cand)) epath = cand;
  }
  const parts = [epath, param ? `입력값 '${param}'` : undefined].filter(Boolean);
  return parts.join(" 의 ");
}
/** '위치'로 쓰면 안 되는(공격으로 노출된 시스템 파일·클라우드 주소) 경로 패턴. */
const EXFIL_PATH = /(?:\/etc\/|\/proc\/|\/root\/|passwd|shadow|\/windows\/|\/latest\/meta-data|169\.254)/i;

function clip(s: string, n: number): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? one.slice(0, n - 1) + "…" : one;
}
/** 표시폭(한글·전각 2, 그 외 1) 계산 — 정렬용. */
function dispWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += /[ᄀ-ᅟ⺀-꓏가-힣豈-﫿︰-﹏＀-｠￠-￦]/.test(ch) ? 2 : 1;
  return w;
}
function padDisp(s: string, width: number): string {
  const pad = width - dispWidth(s);
  return pad > 0 ? s + " ".repeat(pad) : s;
}
function center(s: string, width: number): string {
  const total = width - dispWidth(s);
  if (total <= 0) return s;
  const left = Math.floor(total / 2);
  return " ".repeat(left) + s + " ".repeat(total - left);
}
