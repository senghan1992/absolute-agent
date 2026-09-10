// mock.js — 브라우저 프리뷰용 Tauri 백엔드 목(mock).
//
// 실제 Tauri 앱에서는 window.__TAURI__ 가 이미 주입되어 있으므로 이 파일은 아무 일도
// 하지 않는다(inert). 순수 브라우저(file:// 또는 정적 서버)로 열면, invoke/event 를
// 흉내 내는 인메모리 백엔드를 설치해 디자인·흐름을 그대로 확인할 수 있게 한다.
// 세션 실행은 실제 redcell 대신 실시간 스트리밍을 시뮬레이션한다.

(function () {
  if (window.__TAURI__) return; // 실제 Tauri 환경 → 목 미설치

  const nowIso = () => new Date().toISOString();
  const uid = () => "s_" + Math.random().toString(36).slice(2, 10);

  // ── 이벤트 리스너 레지스트리 ────────────────────────────────────────────────
  const listeners = {}; // name -> [cb]
  const timers = {}; // sessionId -> setInterval 핸들(실행 중 스트림)
  function emit(name, payload) {
    (listeners[name] || []).forEach((cb) => { try { cb({ payload }); } catch (e) { console.error(e); } });
  }

  // ── 샘플 데이터 ──────────────────────────────────────────────────────────────
  function demoEvents() {
    // 완료된 예시 engagement 의 이벤트 스트림(캡처 테이블/발견/인텔이 즉시 채워지도록)
    const t0 = Date.now() - 120000;
    const raw = [
      { type: "note", text: "[sys] [model] anthropic:claude-opus-5" },
      { type: "note", text: "[sys] [scope] config/authorization.yaml" },
      { type: "authorized", text: "[인가] 대상 demo.vulnlab.local:8080 인가 확인됨 (local-lab-training). — 목표: 웹 취약점 정찰 및 방어 권고", target: { host: "demo.vulnlab.local", port: 8080 }, goal: "웹 취약점 정찰 및 방어 권고" },
      { type: "phase", text: "[phase] recon 시작", phase: "recon" },
      { type: "action", phase: "recon", tool: "http_probe", rationale: "응답 헤더로 기술스택 핑거프린팅", args: { path: "/" }, text: "[recon] → http_probe({\"path\":\"/\"}) · 응답 헤더로 기술스택 핑거프린팅" },
      { type: "tool_result", phase: "recon", tool: "http_probe", ok: true, summary: "200 · nginx/1.24.0 · X-Powered-By: PHP/8.1.2", text: "[recon] http_probe: 200 · nginx/1.24.0 · X-Powered-By: PHP/8.1.2" },
      { type: "action", phase: "recon", tool: "header_audit", rationale: "보안 헤더 누락 점검", args: {}, text: "[recon] → header_audit({}) · 보안 헤더 누락 점검" },
      { type: "tool_result", phase: "recon", tool: "header_audit", ok: true, summary: "CSP·HSTS·X-Frame-Options 누락", severity: "medium", text: "[recon] header_audit: CSP·HSTS·X-Frame-Options 누락" },
      { type: "finding", text: "[발견] (medium) 보안 헤더 누락", finding: { phase: "recon", severity: "medium", title: "보안 헤더 누락 (CSP, HSTS, X-Frame-Options)", detail: "클릭재킹·프로토콜 다운그레이드·XSS 완화 헤더가 없습니다.", evidence: "response headers: (no) Content-Security-Policy / Strict-Transport-Security / X-Frame-Options" } },
      { type: "phase", text: "[phase] enumerate 시작", phase: "enumerate" },
      { type: "action", phase: "enumerate", tool: "dir_enum", rationale: "흔한 경로 열거", args: { wordlist: "common" }, text: "[enumerate] → dir_enum({\"wordlist\":\"common\"}) · 흔한 경로 열거" },
      { type: "tool_result", phase: "enumerate", tool: "dir_enum", ok: true, summary: "/login, /admin(302), /api, /uploads(403)", text: "[enumerate] dir_enum: /login, /admin(302), /api, /uploads(403)" },
      { type: "phase", text: "[phase] exploit 시작", phase: "exploit" },
      { type: "action", phase: "exploit", tool: "sqli_probe", rationale: "로그인 파라미터 SQLi 신호 탐지", args: { path: "/login", param: "user" }, text: "[exploit] → sqli_probe({\"path\":\"/login\",\"param\":\"user\"}) · 로그인 파라미터 SQLi 신호 탐지" },
      { type: "tool_result", phase: "exploit", tool: "sqli_probe", ok: true, summary: "SQLi 신호 탐지: param 'user' 에서 DB 오류 시그니처", severity: "high", text: "[exploit] sqli_probe: SQLi 신호 탐지: param 'user' 에서 DB 오류 시그니처" },
      { type: "finding", text: "[발견] (high) SQL Injection 신호", finding: { phase: "exploit", severity: "high", title: "SQL Injection 취약점 신호 (param=user)", detail: "오류유발 입력('\\'')에서 DB 오류가 응답에 노출되었습니다. error-based SQLi 가능성.", evidence: "You have an error in your SQL syntax; check the manual ... near '''" } },
      { type: "distilled", id: "pb_learned_01", title: "[학습] http — SQL Injection 취약점 신호 (param=user)", text: "[자기발전] 새 playbook 저장: [학습] http — SQL Injection 신호 (id=pb_learned_01)" },
      { type: "phase", text: "[phase] post 시작", phase: "post" },
      { type: "note", text: "[post] 모델이 이 단계 종료를 선언." },
      { type: "done", text: "[완료] engagement 종료.", log: {
        target: { host: "demo.vulnlab.local", port: 8080 },
        fingerprint: { service: "http", version: "nginx/1.24.0", os: "linux", tech: ["nginx", "PHP/8.1.2", "MySQL"], indicators: ["error-based sqli", "param user", "X-Powered-By"] },
        findings: [
          { phase: "recon", severity: "medium", title: "보안 헤더 누락 (CSP, HSTS, X-Frame-Options)", detail: "클릭재킹·프로토콜 다운그레이드·XSS 완화 헤더가 없습니다.", evidence: "response headers: (no) Content-Security-Policy / Strict-Transport-Security / X-Frame-Options" },
          { phase: "exploit", severity: "high", title: "SQL Injection 취약점 신호 (param=user)", detail: "오류유발 입력에서 DB 오류가 응답에 노출되었습니다.", evidence: "You have an error in your SQL syntax ... near '''" },
        ],
        usedPlaybooks: ["pb_seed_http_recon"],
        distilled: [{ id: "pb_learned_01", title: "[학습] http — SQL Injection 신호 (param=user)" }],
        transcript: [],
      } },
    ];
    return raw.map((e, i) => Object.assign({ _seq: i, _ts: t0 + i * 1400 }, e));
  }

  const sampleSession = {
    id: uid(),
    name: "vulnlab-web",
    host: "demo.vulnlab.local",
    port: 8080,
    goal: "웹 취약점 정찰 및 방어 권고",
    provider: "anthropic",
    mode: "prime",
    status: "done",
    created_at: nowIso(),
    updated_at: nowIso(),
    chat: [
      { role: "user", content: "이 대상 웹 취약점을 찾아서 방어책까지 정리해줘.", ts: nowIso() },
      { role: "assistant", content: "이해했습니다. demo.vulnlab.local:8080 에 대해 방법을 강구합니다 — 왼쪽 라이브 캡처에서 진행을 확인하세요.", ts: nowIso() },
      { role: "assistant", content: "완료 — 발견 2건 (medium:1, high:1). ‘다음 단계’ 탭에 권고를 정리했습니다.", ts: nowIso() },
    ],
    events: demoEvents(),
  };

  // ── 서비스 진단 모드 샘플: 검증 배지 + 시뮬레이션 플레이어까지 모두 넣은 리포트 ──
  const DIAG_DEMO_REPORT = `# 서비스 진단 리포트 — 데모몰 쇼핑몰

## 0. 한눈에 보기

| 루트 | 위험도 | 공격 방법 | 탈취 정보 | 보완 요약 |
|---|---|---|---|---|
| 1. 로그인 SQL 주입 → 관리자 탈취 | [치명] | \`' OR '1'='1\` 로 인증 우회 | 관리자 세션 · 회원 개인정보 | 파라미터라이즈 쿼리 + WAF |
| 2. 주문 조회 IDOR | [높음] | 인접 주문 id 순회 | 타인 주문·결제 정보 | 리소스 소유권 검사 |
| 3. 세션 쿠키 보안 플래그 누락 | [낮음] | XSS 연계 시 세션 탈취 | 세션 토큰 | HttpOnly·Secure·SameSite |

## 1. 진단 범위 및 가정

- 기술 스택: PHP/8.1 + MySQL, nginx (설명 기반 — [가정])
- 진단 경계: 설명 기반 판단 + 진입점 일부 실측 ([실증]), 파괴적 동작은 미수행

## 2. 공격 표면 (Attack Surface)

- 인증·세션: /login 폼, SESSION 쿠키
- 입력 처리: /search?q, /api/orders/<id>
- 데이터 흐름: 주문·회원·결제 API (/api/orders, /api/me)

## 3. 창의적 공격 루트 (위험도 순)

### 루트 1. 로그인 SQL 주입으로 관리자 권한 탈취 [치명]
 위험도: 치명
 진입점: /login POST 폼 (user, pass 파라미터)
 공격 흐름: 공격자 → /login 로그인 폼 → (SQL 주입 = 입력값으로 DB 질의를 조작) → 인증 우회 → (관리자 세션 탈취) → 전체 회원 개인정보 열람
 탈취 정보: 관리자 세션 토큰, 회원 이메일 주소, 비밀번호 해시, 배송지 주소
 공격 방법: user 값에 \`' OR '1'='1' -- \` 주입 → WHERE 절을 항상 참으로 만들어 관리자 계정으로 로그인
 영향: 관리자 계정 전체 장악 — 회원 개인정보·주문·결제 내역 전수 유출
 시뮬레이션:
 1. /login 의 id 입력창에 \`admin' OR '1'='1' -- \` 입력 후 로그인 클릭 → 302 리다이렉트 + Set-Cookie: SESSION=adm_9f2c… 발급
 2. SESSION 쿠키로 GET /admin/orders 호출 → 200 · 회원 주문 1,248건이 담긴 JSON 응답
 3. 응답 본문에서 이메일·배송지·카드 뒤 4자리 확인 → 전체 회원 데이터 유출 확정
 검증: [실증] web_fetch 로 /login 실측 — 악성 입력에 DB 오류 메시지 노출 확인, 관리자 쿠키 발급 응답 원문 확보
 보완: Prepared statement(PDO bindValue)로 전환하고 아이디/비번 분리 검증. 오류 메시지는 로그로만. WAF 차단 규칙 추가.

### 루트 2. 주문 조회 IDOR — 인증 없는 타인 주문 열람 [높음]
 위험도: 높음
 진입점: GET /api/orders/<id> (쿠키 없이 접근 가능)
 공격 흐름: 공격자 → GET /api/orders/1000
 → (IDOR = 인접 번호 조회로 접근통제 우회) → 타인 주문 응답 수신
 → (결제 정보 노출) → 카드 정보·배송지 열람
 탈취 정보: 타인 주문 내역, 결제 카드 정보, 배송지 주소
 공격 방법: 쿠키 없이 /api/orders/1000~1003 을 순회 — 인접 id 가 서로 다른 응답을 반환하는지 확인
 영향: 고객 주문·개인정보 대량 노출 — 신뢰도 및 민감정보 유출
 시뮬레이션:
 1. 브라우저에서 세션 쿠키 삭제 후 GET /api/orders/1000 → 200 · 다른 고객의 주문 JSON 반환
 2. id 를 1001, 1002, 1003 … 으로 순회 → 매번 서로 다른 고객의 주문·카드 정보 응답
 3. 마지막 주문에 은행 계좌번호 포함 확인 → 결제 정보 노출 범위 확정
 검증: [징후] 무인증 200 이 확인되고 응답에 주문번호·주소 필드가 관찰되나, 완전한 개인정보 원문은 부분 마스킹 상태
 보완: 소유권 검사(현재 세션의 사용자 id 와 리소스 소유자 id 비교) 후 응답. 인증 게이트를 API 라우트에 공통 적용.

### 루트 3. 세션 쿠키 보안 플래그 누락 [낮음]
 위험도: 낮음
 진입점: 로그인 응답의 Set-Cookie: SESSION=…
 공격 흐름: 공격자 → (XSS 또는 네트워크 도청) → 쿠키 원문 획득 → 세션 하이재킹
 탈취 정보: 세션 토큰
 공격 방법: 응답 헤더에서 Set-Cookie 검사 — HttpOnly/Secure/SameSite 플래그 유무 확인
 영향: XSS 나 도청과 조합될 때 세션 탈취 — 단독 위험은 낮음
 검증: [가정] 실측 불가 — 로그인 응답이 내부 네트워크에 있어 헤더 원문을 확보하지 못함 (다음 진단에서 확인 필요)
 보완: Set-Cookie 에 HttpOnly·Secure·SameSite=Lax 추가. 세션 토큰은 로테이션 정책 적용.

## 4. 개선·보완 권고 (우선순위)

- [P0] SQL 주입 — 위험도 [치명] · 파라미터라이즈 쿼리 전면 적용 · 검증: 루트 1 재현 요청으로 확인
- [P1] IDOR — 위험도 [높음] · 소유권 검사 공통 미들웨어 · 검증: 순회 스크립트 재실행
- [P2] 쿠키 플래그 — 위험도 [낮음] · 헤더 설정 · 검증: 응답 헤더 점검

## 5. 실측 확인

- /login 폼 존재·악성 입력 오류 노출 → [실증] (루트 1)
- /api/orders/<id> 무인증 응답 → [징후] (루트 2) — 전체 원문은 redaction
- 미확인: HTTPS 강제 여부, 비밀번호 정책
`.trim();

  const sampleDiagSession = {
    id: uid(),
    name: "데모몰-진단",
    host: "demo.vulnlab.local",
    port: 8080,
    goal: "쇼핑몰 서비스 보안 진단해줘",
    provider: "anthropic",
    mode: "prime",
    diag: true,
    status: "done",
    created_at: nowIso(),
    updated_at: nowIso(),
    chat: [
      { role: "user", content: "쇼핑몰 서비스 보안 진단해줘", ts: nowIso() },
      { role: "assistant", content: "진단 완료 — 공격 루트 3건(치명 1 · 높음 1 · 낮음 1)을 찾았습니다. 결과 탭에서 흐름·시뮬레이션·검증 상태를 확인하세요.", ts: nowIso() },
    ],
    events: [
      { type: "note", text: "[sys] [model] anthropic:claude-opus-5" },
      { type: "note", text: "[sys] 진단 모드 시작 — DIAG_METHOD 주입" },
      { type: "text_end", text: DIAG_DEMO_REPORT },
    ].map((e, i) => Object.assign({ _seq: i, _ts: Date.now() - 60000 + i * 2000 }, e)),
  };

  const store = { sessions: [sampleSession, sampleDiagSession], settings: { redcell_dir: "(preview)", auth_path: "", default_provider: "" } };
  const findById = (id) => store.sessions.find((s) => s.id === id);
  const clone = (o) => JSON.parse(JSON.stringify(o));

  // ── 인가 목록(ip-list) mock — localStorage 로 브라우저 새로고침에도 유지 ───────
  const AUTH_KEY = "redcell-auth-mock";
  const defaultAuth = () => ({
    path: "~/.redcell/authorization.list (preview)",
    allows: ["127.0.0.1", "10.13.37.0/24", "*.vulnlab.local"],
    denies: ["10.13.37.1"],
    until: null,
    ports: null,
  });
  let mockAuth = null;
  const getAuth = () => {
    if (mockAuth) return mockAuth;
    try { mockAuth = JSON.parse(localStorage.getItem(AUTH_KEY) || "null") || defaultAuth(); }
    catch { mockAuth = defaultAuth(); }
    return mockAuth;
  };
  const saveAuth = () => { try { localStorage.setItem(AUTH_KEY, JSON.stringify(mockAuth)); } catch (e) {} };
  // 엔진(ip-list.ts)과 같은 대상 검증(브라우저 미리보기용 근사)
  const HOSTNAME_TARGET = /^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
  const assertTarget = (t) => {
    const v = t.trim();
    if (!v) throw new Error("대상을 입력하세요 (IP / CIDR / 도메인)");
    if (v.startsWith("!")) throw new Error("add 에는 ! 접두사를 쓰지 마세요. 제외는 토글을 사용하세요.");
    if (v.includes("/")) {
      const [ip, bits] = v.split("/");
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || !/^\d{1,2}$/.test(bits) || Number(bits) > 32 || ip.split(".").some((o) => Number(o) > 255)) {
        throw new Error(`잘못된 CIDR: '${v}' — IPv4/CIDR 형식(예: 10.0.0.0/24)이어야 합니다.`);
      }
      return;
    }
    const isIpLike = /^[\d.]+$/.test(v) || /:/.test(v);
    if (isIpLike) {
      const isIp4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(v) && v.split(".").every((o) => Number(o) <= 255);
      if (!isIp4 && !/^[0-9a-fA-F:]+$/.test(v.split("%")[0])) {
        throw new Error(`잘못된 IP: '${v}'`);
      }
      return;
    }
    if (!HOSTNAME_TARGET.test(v)) {
      throw new Error(`인식할 수 없는 대상: '${v}' — IP, CIDR(10.0.0.0/24), 또는 도메인(*.example.com)만 허용합니다.`);
    }
  };
  const authResult = () => clone({
    ...getAuth(),
    yaml: false, empty: false, error: null, warn: null,
    default_path: "~/.redcell/authorization.list",
  });
  // host 입력(URL 허용)을 인가 대상으로 정규화 — Rust auth::normalize_host 와 동일 규칙
  const mockNormalizeHost = (raw) => {
    const v = String(raw || "").trim();
    if (!v) return v;
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)) {
      try {
        const u = new URL(v);
        return (u.hostname || "").replace(/^\[|\]$/g, "");
      } catch { return v; }
    }
    const m = /^(.+):(\d{1,5})$/.exec(v);
    if (m && !m[1].includes(":")) return m[1];
    return v;
  };

  // 목표 문구가 "backend API·정보 수집"을 향하는지(엔진 MockModel 과 동일 기준).
  const API_INTENT = /(\bapi\b|엔드포인트|endpoint|백엔드|backend|정보|목록|수집|제출|submission|평가|evaluation|채점|score|점수|랭킹|ranking)/i;

  const preamble = (session, target) => [
    { type: "note", text: `[sys] [model] ${session.provider || "미지정"}` },
    { type: "note", text: "[sys] [scope] config/authorization.yaml" },
    { type: "authorized", text: `[인가] 대상 ${session.host}:${session.port || ""} 인가 확인됨 (local-lab-training). — 목표: ${session.goal || "정찰"}`, target, goal: session.goal },
  ];

  // 웹 취약점 발산 흐름: 한 방법에 갇히지 않고 여러 공격 벡터를 번갈아 시도한다.
  // (일부는 빗나가고 일부는 적중 — 창의적 다각 접근을 그대로 보여준다.)
  function vulnSeq(session, target) {
    const fHeader = { phase: "recon", severity: "medium", title: "보안 헤더 누락 (CSP, HSTS, X-Frame-Options)", detail: "클릭재킹·다운그레이드·XSS 완화 헤더가 없습니다.", evidence: "no CSP / HSTS / X-Frame-Options" };
    const fCookie = { phase: "recon", severity: "medium", title: "세션 쿠키 HttpOnly 누락", detail: "PHPSESSID 에 HttpOnly/SameSite 플래그가 없어 XSS 로 세션 탈취 표면이 넓습니다.", evidence: "Set-Cookie: PHPSESSID=… (no HttpOnly/Secure/SameSite)" };
    const fSecret = { phase: "enumerate", severity: "high", title: "민감 파일 노출 (.env 환경설정)", detail: ".env 가 공개되어 앱 키·DB 비밀번호가 노출됩니다.", evidence: "/.env → APP_KEY=…; DB_PASSWORD=…" };
    const fCors = { phase: "enumerate", severity: "medium", title: "CORS 설정 오류 — 임의 Origin 반사", detail: "임의 Origin 을 반사해 교차출처 데이터 접근 표면이 있습니다.", evidence: "ACAO 가 요청 Origin 반사" };
    const fSqli = { phase: "exploit", severity: "high", title: "SQL Injection 신호 (param=id)", detail: "오류유발 입력에서 DB 오류가 노출됩니다.", evidence: "You have an error in your SQL syntax ... near '''" };
    const fIdor = { phase: "exploit", severity: "high", title: "IDOR / 접근통제 미흡 (/api/orders/<id>)", detail: "인증 없이 인접 id 의 타인 주문을 열람할 수 있습니다.", evidence: "무인증으로 id 1000,1001,1002 가 서로 다른 응답 반환" };
    const fSsti = { phase: "exploit", severity: "high", title: "Server-Side Template Injection (param=name)", detail: "템플릿 문법의 산술식이 서버에서 평가되어 결과가 반환됩니다. RCE 로 이어질 수 있습니다.", evidence: "산술식 {{7919*7331}} 이 서버에서 평가되어 58054189 노출 (path=/greet)" };
    const fCmdi = { phase: "exploit", severity: "high", title: "OS Command Injection (param=host)", detail: "구분자로 붙인 무해 명령의 출력이 응답에 노출됩니다.", evidence: "주입 `;id` 로 uid=33(www-data) gid=33(www-data) 노출 (path=/ping)" };
    return [
      ...preamble(session, target),
      { type: "phase", text: "[phase] recon 시작", phase: "recon" },
      { type: "action", phase: "recon", tool: "http_probe", rationale: "기술스택 핑거프린팅", args: { path: "/" }, text: "[recon] → http_probe({\"path\":\"/\"}) · 기술스택 핑거프린팅" },
      { type: "tool_result", phase: "recon", tool: "http_probe", ok: true, summary: "200 · nginx · X-Powered-By: PHP/8.1", text: "[recon] http_probe: 200 · nginx · X-Powered-By: PHP/8.1" },
      { type: "action", phase: "recon", tool: "header_audit", rationale: "보안 헤더 점검", args: {}, text: "[recon] → header_audit({}) · 보안 헤더 점검" },
      { type: "tool_result", phase: "recon", tool: "header_audit", ok: true, severity: "medium", summary: "CSP·HSTS·X-Frame-Options 누락", text: "[recon] header_audit: CSP·HSTS·X-Frame-Options 누락" },
      { type: "finding", text: "[발견] (medium) 보안 헤더 누락", finding: fHeader },
      { type: "action", phase: "recon", tool: "cookie_audit", rationale: "세션 쿠키 플래그 점검", args: { path: "/" }, text: "[recon] → cookie_audit({\"path\":\"/\"}) · 세션 쿠키 플래그 점검" },
      { type: "tool_result", phase: "recon", tool: "cookie_audit", ok: true, severity: "medium", summary: "PHPSESSID HttpOnly/SameSite 누락", text: "[recon] cookie_audit: PHPSESSID HttpOnly/SameSite 누락" },
      { type: "finding", text: "[발견] (medium) 세션 쿠키 HttpOnly 누락", finding: fCookie },
      { type: "action", phase: "recon", tool: "waf_detect", rationale: "WAF 식별 → 이후 페이로드 우회 변형 유도", args: {}, text: "[recon] → waf_detect({}) · WAF/방화벽 식별" },
      { type: "tool_result", phase: "recon", tool: "waf_detect", ok: true, severity: "info", summary: "WAF 감지: cloudflare (cf-ray)", text: "[recon] waf_detect: WAF 감지: cloudflare (cf-ray) → 우회 변형 활성화" },
      { type: "action", phase: "recon", tool: "crawl", rationale: "링크·폼을 따라 실제 엔드포인트·파라미터 수집", args: { path: "/" }, text: "[recon] → crawl({\"path\":\"/\"}) · 공격 표면 수집" },
      { type: "tool_result", phase: "recon", tool: "crawl", ok: true, severity: "info", summary: "엔드포인트 4개 수집: /greet?name, /ping?host, /item?id, /search?q", text: "[recon] crawl: 엔드포인트 4개 수집(/greet?name, /ping?host, /item?id, /search?q)" },
      { type: "phase", text: "[phase] enumerate 시작", phase: "enumerate" },
      { type: "action", phase: "enumerate", tool: "dir_enum", rationale: "경로 열거", args: {}, text: "[enumerate] → dir_enum({}) · 경로 열거" },
      { type: "tool_result", phase: "enumerate", tool: "dir_enum", ok: true, summary: "/login, /admin, /api/orders/1000", text: "[enumerate] dir_enum: /login, /admin, /api/orders/1000" },
      { type: "action", phase: "enumerate", tool: "secret_scan", rationale: "노출 비밀·백업 파일 스캔", args: {}, text: "[enumerate] → secret_scan({}) · 노출 비밀·백업 파일 스캔" },
      { type: "tool_result", phase: "enumerate", tool: "secret_scan", ok: true, severity: "high", summary: "노출 파일 1건: /.env", text: "[enumerate] secret_scan: 노출 파일 1건: /.env" },
      { type: "finding", text: "[발견] (high) 민감 파일 노출 (.env)", finding: fSecret },
      { type: "tool_result", phase: "enumerate", tool: "secret_scan", ok: true, summary: "[체이닝] secret_scan 노출 자격증명 재사용: .env 의 ACCESS_TOKEN → Authorization: Bearer 로 이후 요청에 재사용", text: "[체이닝] secret_scan 노출 자격증명 재사용: .env 의 ACCESS_TOKEN → Authorization: Bearer" },
      { type: "action", phase: "enumerate", tool: "cors_audit", rationale: "CORS 신뢰정책 점검", args: { path: "/api/orders/1000" }, text: "[enumerate] → cors_audit({\"path\":\"/api/orders/1000\"}) · CORS 신뢰정책 점검" },
      { type: "tool_result", phase: "enumerate", tool: "cors_audit", ok: true, severity: "medium", summary: "임의 Origin 반사", text: "[enumerate] cors_audit: 임의 Origin 반사" },
      { type: "finding", text: "[발견] (medium) CORS 설정 오류", finding: fCors },
      { type: "phase", text: "[phase] exploit 시작", phase: "exploit" },
      { type: "action", phase: "exploit", tool: "xss_probe", rationale: "반사형 XSS 탐지(무해 마커)", args: { path: "/search", param: "q" }, text: "[exploit] → xss_probe({\"path\":\"/search\",\"param\":\"q\"}) · 반사형 XSS 탐지" },
      { type: "tool_result", phase: "exploit", tool: "xss_probe", ok: false, summary: "반사형 XSS 미탐지 — 입력이 이스케이프됨", text: "[exploit] xss_probe: 반사형 XSS 미탐지 — 입력이 이스케이프됨" },
      { type: "action", phase: "exploit", tool: "path_traversal", rationale: "경로 조작·LFI 시도", args: { path: "/download", param: "file" }, text: "[exploit] → path_traversal({\"path\":\"/download\",\"param\":\"file\"}) · 경로 조작·LFI 시도" },
      { type: "tool_result", phase: "exploit", tool: "path_traversal", ok: false, summary: "LFI 미탐지 — 다른 벡터로 전환", text: "[exploit] path_traversal: LFI 미탐지 — 다른 벡터로 전환" },
      { type: "action", phase: "exploit", tool: "sqli_probe", rationale: "SQLi 신호 탐지", args: { path: "/item", param: "id" }, text: "[exploit] → sqli_probe({\"path\":\"/item\",\"param\":\"id\"}) · SQLi 신호 탐지" },
      { type: "tool_result", phase: "exploit", tool: "sqli_probe", ok: true, severity: "high", summary: "SQLi 신호 탐지: param 'id'", text: "[exploit] sqli_probe: SQLi 신호 탐지: param 'id'" },
      { type: "finding", text: "[발견] (high) SQL Injection 신호", finding: fSqli },
      { type: "action", phase: "exploit", tool: "ssti_probe", rationale: "크롤이 찾은 /greet?name 에 템플릿 산술식 주입", args: { paths: ["/greet"], params: ["name"] }, text: "[exploit] → ssti_probe({\"paths\":[\"/greet\"],\"params\":[\"name\"]}) · 서버측 템플릿 인젝션 탐지" },
      { type: "tool_result", phase: "exploit", tool: "ssti_probe", ok: true, severity: "high", summary: "SSTI 신호: /greet 의 param 'name' 산술 평가", text: "[exploit] ssti_probe: SSTI 신호: /greet 의 param 'name' 에서 템플릿 산술 평가(7919*7331=58054189)" },
      { type: "finding", text: "[발견] (high) Server-Side Template Injection", finding: fSsti },
      { type: "action", phase: "exploit", tool: "cmdi_probe", rationale: "크롤이 찾은 /ping?host 에 구분자+무해명령 주입", args: { paths: ["/ping"], params: ["host"] }, text: "[exploit] → cmdi_probe({\"paths\":[\"/ping\"],\"params\":[\"host\"]}) · OS 커맨드 인젝션 탐지" },
      { type: "tool_result", phase: "exploit", tool: "cmdi_probe", ok: true, severity: "high", summary: "OS 커맨드 인젝션 확인: /ping 의 param 'host' 로 unix `id` 실행", text: "[exploit] cmdi_probe: OS 커맨드 인젝션 확인: /ping 의 param 'host' 로 unix `id` 실행" },
      { type: "finding", text: "[발견] (high) OS Command Injection", finding: fCmdi },
      { type: "action", phase: "exploit", tool: "idor_probe", rationale: "IDOR·접근통제 점검", args: { path: "/api/orders/1000" }, text: "[exploit] → idor_probe({\"path\":\"/api/orders/1000\"}) · IDOR·접근통제 점검" },
      { type: "tool_result", phase: "exploit", tool: "idor_probe", ok: true, severity: "high", summary: "IDOR 신호: 무인증 인접 id 열람", text: "[exploit] idor_probe: IDOR 신호: 무인증 인접 id 열람" },
      { type: "finding", text: "[발견] (high) IDOR / 접근통제 미흡", finding: fIdor },
      { type: "phase", text: "[phase] post 시작", phase: "post" },
      { type: "note", text: "[post] 모델이 이 단계 종료를 선언." },
      { type: "distilled", id: "pb_learned_web", title: "[학습] http — 다각 웹 취약점(.env·SQLi·SSTI·CMDI·IDOR)", text: "[자기발전] 새 playbook 저장: [학습] http — 다각 웹 취약점 (id=pb_learned_web)" },
      { type: "done", text: "[완료] engagement 종료.", log: {
        target,
        fingerprint: { service: "http", version: "nginx", os: "linux", tech: ["nginx", "PHP/8.1"], indicators: ["waf:cloudflare", "exposed /.env", "error-based sqli param id", "ssti /greet?name", "cmdi /ping?host", "idor /api/orders/<id>", "cors reflect"] },
        findings: [fHeader, fCookie, fSecret, fCors, fSqli, fSsti, fCmdi, fIdor],
        usedPlaybooks: ["pb_seed_http_recon"],
        distilled: [{ id: "pb_learned_web", title: "[학습] http — 다각 웹 취약점(.env·SQLi·SSTI·CMDI·IDOR)" }],
        transcript: [],
      } },
    ];
  }

  // backend API 발견 → 노출 정보 확인 흐름(공모전 제출/평가 API 등).
  function apiSeq(session, target) {
    const eps = ["/api/submissions", "/api/evaluations/summary", "/api/admin/users", "/api/scores"];
    const findApi = { phase: "recon", severity: "medium", title: "API 명세 노출 (/openapi.json)", detail: "openapi.json 이 공개되어 backend API 표면이 문서화되어 있습니다.", evidence: "endpoint /api/submissions; endpoint /api/evaluations/summary; endpoint /api/admin/users; endpoint /api/scores; descriptor /openapi.json (200, openapi)" };
    const findExposure = { phase: "enumerate", severity: "high", title: "인증 없는 민감정보 노출 (/api/admin/users)", detail: "인증 없이 접근되는 엔드포인트가 이메일·비밀번호를 반환합니다.", evidence: "/api/submissions → 200 records=2 fields=id,team,title,score | /api/admin/users → 200 records=1 fields=id,email,password 민감=email,password" };
    return [
      ...preamble(session, target),
      { type: "phase", text: "[phase] recon 시작", phase: "recon" },
      { type: "action", phase: "recon", tool: "http_probe", rationale: "기술스택·프런트엔드 파악", args: { path: "/" }, text: "[recon] → http_probe({\"path\":\"/\"}) · 기술스택·프런트엔드 파악" },
      { type: "tool_result", phase: "recon", tool: "http_probe", ok: true, summary: "200 · SPA(app.js) 감지", text: "[recon] http_probe: 200 · SPA(app.js) 감지" },
      { type: "action", phase: "recon", tool: "api_discover", rationale: "프런트엔드가 호출하는 backend API 엔드포인트 발견", args: { path: "/" }, text: "[recon] → api_discover({\"path\":\"/\"}) · backend API 발견" },
      { type: "tool_result", phase: "recon", tool: "api_discover", ok: true, severity: "medium", summary: "엔드포인트 4개, 서술자 1개(openapi.json)", text: "[recon] api_discover: 엔드포인트 4개, 서술자 1개(openapi.json)" },
      { type: "finding", text: "[발견] (medium) API 명세 노출 (/openapi.json)", finding: findApi },
      { type: "phase", text: "[phase] enumerate 시작", phase: "enumerate" },
      { type: "action", phase: "enumerate", tool: "api_probe", rationale: "발견된 엔드포인트의 노출 데이터/민감정보 확인(읽기 전용)", args: { paths: eps }, text: `[enumerate] → api_probe({"paths":${JSON.stringify(eps)}}) · 노출 정보 확인` },
      { type: "tool_result", phase: "enumerate", tool: "api_probe", ok: true, severity: "high", summary: "데이터 노출 2건 (민감 1)", text: "[enumerate] api_probe: 데이터 노출 2건 (민감 1)" },
      { type: "finding", text: "[발견] (high) 인증 없는 민감정보 노출 (/api/admin/users)", finding: findExposure },
      { type: "phase", text: "[phase] post 시작", phase: "post" },
      { type: "note", text: "[post] 모델이 이 단계 종료를 선언." },
      { type: "done", text: "[완료] engagement 종료.", log: {
        target,
        fingerprint: { service: "http", tech: ["spa"], indicators: eps.map((e) => `endpoint ${e}`).concat("descriptor /openapi.json (200, openapi)") },
        findings: [findApi, findExposure],
        usedPlaybooks: ["pb_seed_http_recon"], distilled: [], transcript: [],
      } },
    ];
  }

  // ── 시뮬레이션 스트림(실행) ──────────────────────────────────────────────────
  // 목표에 따라 두 흐름 중 하나를 재생한다:
  //   · 정보 수집형(공모전 제출/평가 API 발견) → API 디스커버리 흐름
  //   · 그 외(취약점 정찰)                     → 웹 취약점 흐름
  function simulate(session) {
    const target = { host: session.host, port: session.port };
    const isDiag = session.diag || /진단|점검해줘|개선점|보안 검토/.test(session.goal || "");
    const seq = isDiag ? [] : (API_INTENT.test(session.goal || "") ? apiSeq(session, target) : vulnSeq(session, target));

    session.events = [];
    session.status = "running";
    emit("engagement-status", { sessionId: session.id, status: "running" });

    let i = 0;
    const timer = setInterval(() => {
      if (i >= seq.length) { clearInterval(timer); delete timers[session.id]; return; }
      const ev = Object.assign({ _seq: session.events.length, _ts: Date.now() }, seq[i]);
      session.events.push(ev);
      session.updated_at = nowIso();
      emit("engagement-event", { sessionId: session.id, event: ev });
      if (ev.type === "done") {
        clearInterval(timer); delete timers[session.id];
        // 진단 모드: 흐름 시뮬레이션 후 최종 리포트를 결과 탭으로 방출
        if (isDiag) {
          const rep = Object.assign({ _seq: session.events.length, _ts: Date.now() }, { type: "text_end", text: DIAG_DEMO_REPORT });
          session.events.push(rep);
          emit("engagement-event", { sessionId: session.id, event: rep });
        }
        session.status = "done";
        emit("engagement-status", { sessionId: session.id, status: "done" });
      }
      i++;
    }, 550);
    timers[session.id] = timer;
  }

  // 실행 중지: 스트림 타이머를 멈추고 상태를 stopped 로 마감한다.
  function stopSim(session) {
    const timer = timers[session.id];
    if (timer) { clearInterval(timer); delete timers[session.id]; }
    if (session.status !== "running") return;
    const ev = { _seq: session.events.length, _ts: Date.now(), type: "note", text: "[중지] 사용자가 실행을 중지했습니다." };
    session.events.push(ev);
    session.status = "stopped";
    session.updated_at = nowIso();
    emit("engagement-event", { sessionId: session.id, event: ev });
    emit("engagement-status", { sessionId: session.id, status: "stopped" });
  }

  // ── invoke 라우터 ────────────────────────────────────────────────────────────
  async function invoke(cmd, args = {}) {
    switch (cmd) {
      case "get_settings": return clone(store.settings);
      case "save_settings": store.settings = clone(args.settings); return clone(store.settings);
      case "list_sessions": return clone(store.sessions).sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
      case "get_session": { const s = findById(args.id); return s ? clone(s) : null; }
      case "create_session": {
        const s = { id: uid(), name: args.name && args.name.trim() ? args.name : "session-" + Math.random().toString(36).slice(2, 6),
          host: args.host || "127.0.0.1", port: args.port ?? null, goal: args.goal || "", provider: args.provider || "", mode: "prime",
          status: "idle", created_at: nowIso(), updated_at: nowIso(), chat: [], events: [] };
        store.sessions.unshift(s); return clone(s);
      }
      case "update_session": {
        const s = findById(args.id); if (!s) return null;
        Object.assign(s, { name: args.name, host: args.host, port: args.port, goal: args.goal, provider: args.provider, updated_at: nowIso() });
        if (args.mode) s.mode = args.mode;
        return clone(s);
      }
      case "delete_session": store.sessions = store.sessions.filter((s) => s.id !== args.id); return null;
      case "append_chat": {
        const s = findById(args.id); if (!s) return null;
        s.chat.push({ role: args.role, content: args.content, ts: nowIso() }); s.updated_at = nowIso();
        return clone(s);
      }
      case "start_engagement": { const s = findById(args.id); if (s) simulate(s); return null; }
      case "stop_engagement": { const s = findById(args.id); if (s) stopSim(s); return null; }
      case "list_auth": return authResult();
      case "get_providers": return [
        { name: "anthropic", kind: "anthropic", note: "Claude 공식 API", default_model: "claude-opus-5", env_keys: [], base_url: "https://api.anthropic.com/v1", ready_env: false, needs_base: false },
        { name: "openai", kind: "openai-compat", note: "GPT 공식 API", default_model: "gpt-5.4", env_keys: ["OPENAI_API_KEY"], base_url: "https://api.openai.com/v1", ready_env: false, needs_base: false },
        { name: "openrouter", kind: "openai-compat", note: "다수 모델 게이트웨이 — 무료 모델은 :free 접미사", default_model: "moonshotai/kimi-k2.6", env_keys: [], base_url: "https://openrouter.ai/api/v1", ready_env: false, needs_base: false },
        { name: "prime-inference", kind: "openai-compat", note: "Prime Intellect inference", default_model: "z-ai/glm-5.2", env_keys: [], base_url: "https://api.pinference.ai/api/v1", ready_env: false, needs_base: false },
        { name: "groq", kind: "openai-compat", note: "고속 추론", default_model: "openai/gpt-oss-120b", env_keys: [], base_url: "https://api.groq.com/openai/v1", ready_env: false, needs_base: false },
        { name: "cerebras", kind: "openai-compat", note: "Cerebras 초고속 추론", default_model: "gpt-oss-120b", env_keys: [], base_url: "https://api.cerebras.ai/v1", ready_env: false, needs_base: false },
        { name: "xai", kind: "openai-compat", note: "xAI Grok", default_model: "grok-4.20-0309-reasoning", env_keys: [], base_url: "https://api.x.ai/v1", ready_env: false, needs_base: false },
        { name: "deepseek", kind: "openai-compat", note: "DeepSeek", default_model: "deepseek-v4-pro", env_keys: [], base_url: "https://api.deepseek.com", ready_env: false, needs_base: false },
        { name: "mistral", kind: "openai-compat", note: "Mistral AI", default_model: "devstral-medium-latest", env_keys: [], base_url: "https://api.mistral.ai/v1", ready_env: false, needs_base: false },
        { name: "moonshotai", kind: "openai-compat", note: "Moonshot Kimi", default_model: "kimi-k2.6", env_keys: [], base_url: "https://api.moonshot.ai/v1", ready_env: false, needs_base: false },
        { name: "zai", kind: "openai-compat", note: "Z.ai GLM", default_model: "glm-5.1", env_keys: [], base_url: "https://api.z.ai/api/coding/paas/v4", ready_env: false, needs_base: false },
        { name: "ollama", kind: "openai-compat", note: "로컬/원격 ollama 서버 (키 불필요)", default_model: "llama3.1", env_keys: [], base_url: "http://localhost:11434/v1", ready_env: false, needs_base: true },
        { name: "custom", kind: "openai-compat", note: "임의 OpenAI 호환 엔드포인트", default_model: "", env_keys: [], base_url: "", ready_env: false, needs_base: true },
      ];
      case "test_provider": return new Promise((res) => setTimeout(() => res("OK 200 (preview — 실제 연결은 데스크톱에서 확인)"), 350));
      case "add_auth": {
        const a = getAuth();
        assertTarget(args.target);
        const list = args.deny ? a.denies : a.allows;
        if (!list.includes(args.target.trim())) list.push(args.target.trim());
        saveAuth();
        return authResult();
      }
      case "remove_auth": {
        const a = getAuth();
        a.allows = a.allows.filter((x) => x !== args.target);
        a.denies = a.denies.filter((x) => x !== args.target);
        saveAuth();
        return authResult();
      }
      case "auth_ensure": {
        const norm = mockNormalizeHost(args.host);
        assertTarget(norm);
        const a = getAuth();
        if (a.allows.includes(norm)) {
          return { added: false, existed: true, host: norm, path: a.path, yaml: false, reason: null };
        }
        a.allows.push(norm);
        saveAuth();
        return { added: true, existed: false, host: norm, path: a.path, yaml: false, reason: null };
      }
      default: console.warn("mock invoke: 알 수 없는 명령", cmd); return null;
    }
  }

  async function listen(name, cb) {
    (listeners[name] = listeners[name] || []).push(cb);
    return () => { listeners[name] = (listeners[name] || []).filter((f) => f !== cb); };
  }

  window.__TAURI__ = { core: { invoke }, event: { listen } };
  console.info("%cRedCell preview mock 활성화 — 브라우저 미리보기 모드", "color:#6d6afe;font-weight:bold");
})();
