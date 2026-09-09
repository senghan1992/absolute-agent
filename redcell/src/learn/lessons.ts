/**
 * learn — 초보자 해킹 학습 카탈로그.
 *
 * "해킹은 허들이 높다"를 부수는 레이어. 각 강의는 인가된 로컬 랩(labs/)에서
 * 실제 취약점을 하나씩 뚫어보는 안내 투어다:
 *
 *   이야기(왜 위험한가) → 공격 그림(어떻게 흘러가는가) → 단계 실습(직접 실행) →
 *   관찰 포인트(무엇을 봐야 하나) → 퀴즈(이해 확인) → 방어법(막는 법) → 더 읽기
 *
 * 모든 강의는 labs/ 의 로컬 랩에서만 동작한다(외부 대상 불가 — ScopeGuard 원칙 동일).
 */

export interface LearnStep {
  /** 단계 제목. */
  title: string;
  /** 이 단계에서 무엇을 왜 하는가(초보자용 설명). */
  explain: string;
  /** 실행할 툴(없으면 설명만 하는 단계). */
  tool?: string;
  /** 툴 인자. */
  args?: Record<string, unknown>;
  /** 성공 판정 — finding 제목에 포함돼야 할 문자열. */
  expectFinding?: string;
  /** 성공 판정 — 증거/요약에 포함돼야 할 문자열(또는 목록 = 전부 포함). */
  expectContains?: string | string[];
  /** 이 단계에서 무엇을 봐야 하는가(실행 후 해설). */
  observe: string;
}

export interface Quiz {
  q: string;
  options: string[];
  /** 정답 인덱스. */
  answer: number;
  explain: string;
}

export interface Lesson {
  id: string;
  title: string;
  /** 취약점 클래스(OWASP 계열). */
  klass: string;
  level: "입문" | "중급";
  /** 미션 시나리오(스토리텔링). */
  story: string;
  /** ASCII 공격 흐름 그림. */
  diagram: string;
  lab: { start: string[]; port: number };
  /** 인증된 표면 강의용 테스트 세션 쿠키(선택). */
  cookie?: string;
  steps: LearnStep[];
  quiz: Quiz[];
  defense: string;
  /** 더 읽을 자료. */
  link: string;
}

/** 강의 카탈로그 — labs/ 의 로컬 랩과 1:1 대응. */
export const LESSONS: Lesson[] = [
  {
    id: "sql-injection",
    title: "SQL 인젝션 — 로그인 창의 뒷문",
    klass: "SQLi (OWASP A03)",
    level: "입문",
    story:
      "쇼핑몰 검색창에 아무 단어나 넣는데, 서버가 그 단어를 **SQL 문에 그대로 갖다 붙인다면?** " +
      "공격자는 검색어 자리에 SQL 코드를 끼워 넣어 데이터베이스가 '원래 하지 말아야 할 질문'까지 답하게 만든다. " +
      "이 강의에서는 UNION SELECT 로 데이터베이스가 스스로 다른 테이블의 값을 내놓게 만들어 본다.",
    diagram: [
      "공격자                          서버                       데이터베이스",
      "  │  검색어: x' UNION SELECT      │                            │",
      "  ├──────────────────────────────▶│  SQL = ...UNION SELECT...  │",
      "  │                               ├───────────────────────────▶│",
      "  │                               │   ◀── 다른 테이블의 값! ─────┤",
      "  │◀──────────────────────────────┤                            │",
      "  ▼  (비밀 데이터가 검색 결과에)                                   ",
    ].join("\n"),
    lab: { start: ["node", "labs/vuln-union/server.cjs"], port: 18089 },
    steps: [
      {
        title: "1. 정찰 — 대상이 무엇으로 만들어졌는지 본다",
        explain: "해킹의 첫 단계는 항상 관찰이다. 서버 헤더·응답 형태로 기술 스택을 파악하면 이후 공격의 힌트가 된다.",
        tool: "http_probe",
        args: { path: "/" },
        observe: "응답 헤더의 server, x-powered-by, 쿠키 이름 등이 힌트다. 200 이면 대상이 살아 있다는 뜻.",
      },
      {
        title: "2. 주입 — 검색어에 SQL 조각을 넣어본다",
        explain: "검색 파라미터에 작은따옴표를 넣어 SQL 문법이 깨지는지 본다. DB 오류가 그대로 출력되면 서버가 우리 입력을 SQL 로 실행하고 있다는 강력한 증거다.",
        tool: "sqli_probe",
        args: { path: "/search", param: "q" },
        expectFinding: "SQL Injection",
        observe: "오류 기반 신호(MySQL/SQLSTATE 등)가 보이면 주입점 확정. 이것이 '뒷문'을 찾은 순간이다.",
      },
      {
        title: "3. 실증 — UNION SELECT 로 실제 데이터를 꺼낸다",
        explain: "UNION SELECT 는 원래 쿼리 결과에 우리가 고른 열을 덧붙이는 SQL 기능이다. 컬럼 수를 맞춰 넣으면 다른 테이블의 값을 검색 결과에 그대로 볼 수 있다. RedCell 은 DB 버전 문자열을 실제로 꺼내와 착취를 증명한다.",
        observe: "증거에 'UNION 실증'과 DB 엔진 버전이 나오면 검증된 착취(verified)다. 이제 이 서비스의 DB 는 공격자가 질문하는 대로 답한다.",
      },
    ],
    quiz: [
      {
        q: "SQL 인젝션의 근본 원인은?",
        options: ["비밀번호가 짧아서", "사용자 입력이 SQL 코드와 섞여 실행되어서", "서버가 느려서"],
        answer: 1,
        explain: "입력과 코드가 섞이는 것이 핵심이다. 해결책은 입력을 문자열로만 취급하는 파라미터라이즈드 쿼리( prepared statement ).",
      },
      {
        q: "UNION SELECT 로 할 수 있는 것은?",
        options: ["서버 재시작", "원래 질문 결과에 다른 SELECT 결과를 덧붙여 보기", "방화벽 끄기"],
        answer: 1,
        explain: "UNION 은 결과 집합을 합친다. 컬럼 수/타입만 맞추면 다른 테이블 데이터도 같은 화면에 나온다.",
      },
    ],
    defense: "모든 쿼리를 파라미터라이즈드 쿼리(ORM/prepared statement)로 작성하고, DB 오류를 사용자에게 노출하지 않는다. 계정은 최소권한으로 분리한다.",
    link: "https://portswigger.net/web-security/sql-injection",
  },
  {
    id: "idor",
    title: "IDOR — 남의 우편물 열어보기",
    klass: "접근통제 (OWASP A01)",
    level: "입문",
    story:
      "택배 조회 URL 이 /orders/1001 처럼 **순번으로 되어 있고, 서버가 '이 주문이 네 것인지' 확인하지 않는다면?** " +
      "1001 을 1002 로 바꾸는 것만으로 남의 주문이 보인다. 가장 흔하고 가장 치명적인 권한 결함이다.",
    diagram: [
      "공격자              서버(소유권 검증 없음)        데이터",
      "  │ GET /orders/1001   │                            ",
      "  ├───────────────────▶│ 내 주문 1001 반환  (정상)     ",
      "  │ GET /orders/1002   │                            ",
      "  ├───────────────────▶│ 누구 것인지 안 물어봄!        ",
      "  │◀───── 남의 주문 ────┤◀── 1002 레코드 ──────────────",
    ].join("\n"),
    lab: { start: ["node", "labs/vuln-idor/server.cjs"], port: 18090 },
    steps: [
      {
        title: "1. 정찰 — API 모양을 살펴본다",
        explain: "숫자 id 를 쓰는 엔드포인트(/api/orders/1001 등)는 IDOR 의 전형적인 표적이다. 크롤과 API 탐색으로 표면을 그려낸다.",
        tool: "http_probe",
        args: { path: "/api/orders/1001" },
        observe: "인증 없이 200 이면 이미 수상하다. 정상 서비스라면 최소한 로그인을 요구해야 한다.",
      },
      {
        title: "2. 실증 — 인접 id 로 사적 레코드를 열람한다",
        explain: "내 id(1001) 대신 1002 를 요청한다. 서버가 소유권을 검증하지 않으면 타인의 개인 레코드가 그대로 응답으로 온다. RedCell 은 서로 다른 사적 레코드가 나오는지 확인해 오탐을 막는다(공개 카탈로그는 발견으로 세지 않는다).",
        tool: "idor_probe",
        args: { path: "/api/orders/1001" },
        expectFinding: "IDOR",
        observe: "증거에 사적 필드(이름/이메일/주소 등)와 서로 다른 레코드가 확인되면 검증된 착취다. 숫자만 바꿨을 뿐인데 남의 데이터를 봤다.",
      },
    ],
    quiz: [
      {
        q: "IDOR 를 막는 올바른 방법은?",
        options: ["id 를 숨긴다", "서버가 매 요청마다 '이 객체의 소유자인지' 검증한다", "id 를 10자리로 늘린다"],
        answer: 1,
        explain: "소유권 검증(객체 수준 인가)이 답이다. UUID 로 바꾸는 것은 추측만 어렵게 할 뿐, 검증 없으면 IDOR 는 그대로다.",
      },
    ],
    defense: "모든 객체 조회에 서버측 소유권·역할 검증을 강제한다. 예측 가능한 순차 id 는 UUID 로 대체하고, 권한 테스트를 CI 에 넣는다.",
    link: "https://portswigger.net/web-security/access-control",
  },
  {
    id: "xss",
    title: "XSS — 방문자 브라우저에서 도는 내 코드",
    klass: "XSS (OWASP A03)",
    level: "입문",
    story:
      "검색어가 결과 화면에 그대로 다시 보인다면, **<script> 도 그대로 보일 수 있다.** " +
      "서버가 이스케이프 없이 출력하면 공격자의 코드가 피해자의 브라우저에서 실행된다. " +
      "쿠키 훔치기, 가짜 화면 보여주기 등 무엇이든 가능해진다.",
    diagram: [
      "공격자                       서버                     피해자 브라우저",
      "  │ /?q=<script>…</script>    │                          ",
      "  ├──────────────────────────▶│ 이스케이프 없이 그대로 출력 │",
      "  │                           ├─────────────────────────▶│",
      "  │                           │        <script> 실행! ◀───┤",
      "  │◀── (피해자 쿠키 등 탈취) ────────────────────────────┤",
    ].join("\n"),
    lab: { start: ["node", "labs/vuln-xss/server.cjs"], port: 18093 },
    steps: [
      {
        title: "1. 반사 관찰 — 입력이 화면에 되돌아오는가",
        explain: "XSS 의 전제는 '내 입력이 다른 사람(또는 나)의 화면에서 HTML/JS 로 살아나는 것'. 크롤이 파라미터를 찾고, 툴이 실행 가능한 문맥인지 확인한다.",
        tool: "xss_probe",
        args: { path: "/", param: "q" },
        expectFinding: "Reflected XSS",
        observe: "증거에 '실행 가능 문맥'이 나오면 단순 반사가 아니라 진짜 실행 지점이다. CSP 헤더가 없다면 방어막도 없다는 뜻.",
      },
      {
        title: "2. 피해 시뮬레이션 — 무엇이 가능해지나",
        explain: "실제 공격에서는 이 지점에 세션 쿠키를 공격자 서버로 보내는 스크립트를 심는다. RedCell 은 무해 마커로만 실증한다(실제 탈취는 하지 않는다).",
        observe: "쿠키에 HttpOnly 가 없다면 document.cookie 로 세션 탈취가 가능하다. cookie_audit 결과를 함께 보라.",
      },
    ],
    quiz: [
      {
        q: "XSS 를 막는 3종 세트는?",
        options: ["방화벽, 백신, 로그", "출력 인코딩, CSP, 쿠키 HttpOnly", "HTTPS, 긴 비밀번호, 2FA"],
        answer: 1,
        explain: "출력 인코딩(문맥별)이 근본, CSP 가 실수의 마지막 안전망, HttpOnly 가 쿠키 탈취를 막는다.",
      },
    ],
    defense: "문맥별 출력 인코딩 + strict CSP + 세션 쿠키에 HttpOnly·Secure·SameSite. 프론트엔드 프레임워크의 기본 이스케이프를 끄지 않는다.",
    link: "https://portswigger.net/web-security/cross-site-scripting",
  },
  {
    id: "request-smuggling",
    title: "요청 밀반입 — 프록시의 눈을 속이기",
    klass: "Request Smuggling (중급)",
    level: "중급",
    story:
      "요청의 길이는 두 가지 방법(Content-Length 와 Transfer-Encoding)으로 표현할 수 있다. " +
      "앞단 프록시와 뒷단 서버가 **서로 다른 방법을 믿으면**, 요청의 경계가 어긋나고 " +
      "공격자의 '한 요청'이 뒷단에서는 '두 요청'이 된다. 이렇게 몰래 끼워 넣은 두 번째 요청으로 " +
      "캐시를 오염시키거나 다른 사용자의 요청을 가로챈다.",
    diagram: [
      "공격자        프론트(CL 믿음)           백엔드(TE 믿음)",
      "  │ 모호한 요청    │                        │",
      "  ├──────────────▶│ CL 만큼 잘라 전달        │",
      "  │               ├───────────────────────▶│ TE 로 해석 → 잔여 바이트가",
      "  │               │                        │    다음 요청의 시작이 됨!",
      "  │               │   다른 사용자의 요청 ◀───┤ ← 오염된 연결로 흡수됨",
    ].join("\n"),
    lab: { start: ["node", "labs/vuln-smuggle/server.cjs"], port: 18113 },
    steps: [
      {
        title: "1. 관찰 — 프레이밍 모호성 차등",
        explain: "RedCell 은 실제 밀반입(다른 사용자까지 위험)을 하지 않고, 모호한 요청에 서버가 '대기'하는지 관찰한다. CL-우선 파서는 부족한 바이트를 기다리고(스톨), TE-우선 파서는 즉시 답한다. 이 차등이 파서 불일치의 증거다.",
        tool: "smuggle_probe",
        args: { path: "/" },
        expectFinding: "HTTP Request Smuggling",
        observe: "baseline 은 빠른데 모호 요청에서만 응답이 없으면(스톨), 이 서버 체인은 요청 경계를 다르게 해석한다. 실전에서는 여기에 밀반입 페이로드가 얹힌다.",
      },
      {
        title: "2. 왜 위험한가 — 연결 오염",
        explain: "스톨이 확인됐다는 건 파서가 어긋난다는 것. 실제 공격에선 이 어긋남으로 다른 사용자의 요청 앞부분에 내 요청을 붙여 '가로챈다'. 캐시 오염·인증 우회로 이어진다.",
        observe: "RedCell 은 잔여 바이트를 보내지 않으므로 이 검증 자체는 누구에게도 피해가 없다. '관찰만으로 확정'이 안전한 검증의 모범이다.",
      },
    ],
    quiz: [
      {
        q: "스머글링 탐지를 위험 없이 하려면?",
        options: ["실제로 밀반입해 본다", "잔여 바이트 없이 '대기 차등'만 관찰한다", "포트를 닫아 본다"],
        answer: 1,
        explain: "밀반입은 다른 사용자의 연결을 망가뜨릴 수 있다. CL/TE 불일치가 만드는 '응답 대기'만 관찰하면 안전하게 확정할 수 있다.",
      },
    ],
    defense: "프레이밍 헤더 정규화: CL+TE 동시 수신 시 거부, 중복 CL 거부, TE 값은 chunked 만 허용. 프록시와 백엔드의 파서 버전을 통일한다.",
    link: "https://portswigger.net/web-security/request-smuggling",
  },
  {
    id: "cache-deception",
    title: "캐시 기만 — 개인 페이지를 '정적 파일'로 위장하기",
    klass: "Cache Deception (중급)",
    level: "중급",
    story:
      "캐시는 보통 '정적 파일(.css/.js)'만 공개 저장한다. 그런데 /profile/rc.css 처럼 **개인 페이지 뒤에 정적 확장자만 붙이면** " +
      "서버는 개인 페이지를 주고, 캐시는 '정적 파일'로 착각하고 저장한다. " +
      "공격자가 그 URL 을 피해자에게 클릭시키면 캐시에 피해자의 개인정보가 저장되고, 공격자는 같은 URL 로 그걸 꺼내 본다.",
    diagram: [
      "공격자        캐시           서버            피해자",
      "  │ /profile/rc.css 링크 클릭 유도 ──────────────▶│",
      "  │                 │◀── 개인 페이지(캐시 저장!) ──┤",
      "  ├───────────────▶│ hit! 피해자 개인정보 반환     │",
      "  │◀── 타인의 이메일/이름 ─┤                       ",
    ].join("\n"),
    lab: { start: ["node", "labs/vuln-cache-deception/server.cjs"], port: 18114, },
    cookie: "sid=sid-lee-2026",
    steps: [
      {
        title: "1. 기준 — 개인 페이지는 로그인 뒤에만 보인다",
        explain: "캐시 기만은 '인증된 표면'의 결함이다. RedCell 에 테스트 세션을 주면 로그인 뒤 페이지까지 점검한다. 먼저 /profile 이 세션 없이는 차단되는지 확인한다 — 이 차등이 있어야 캐시 기만이 성립한다(차단이 없으면 그건 그냥 접근통제 결함).",
        observe: "세션 있음=개인 정보, 세션 없음=로그인 리다이렉트. 정상이다.",
      },
      {
        title: "2. 위장 — 정적 확장자를 붙여 요청한다",
        explain: "/profile/rc1234.css 를 세션으로 요청한다. 서버가 접미사를 무시하고 개인 페이지를 주면, 캐시는 이 응답을 '정적 파일'로 저장한다.",
        observe: "같은 개인 본문이 접미사 경로에서도 나오면 서버는 경로 끝의 .css 를 신경 쓰지 않는 것이다.",
      },
      {
        title: "3. 실증 — 세션 없이 같은 URL 을 요청한다",
        explain: "결정적 단계. 세션 없이 /profile/rc1234.css 를 요청했을 때 피해자의 개인 본문이 나오면, 캐시가 개인 데이터를 공개 저장했다는 실증이다. RedCell 은 무작위 접미사를 써서 자기 데이터만 다루므로 누구에게도 피해가 없다.",
        tool: "cache_deception_probe",
        args: { path: "/profile" },
        expectFinding: "웹 캐시 기만",
        observe: "'무인증 요청에 개인 본문 반환'이 증거로 나오면 검증된 착취다. 이 URL 을 다른 사용자가 클릭하게 만들면 그 사람의 정보도 같은 방식으로 캐시에 쌓인다.",
      },
    ],
    quiz: [
      {
        q: "캐시 기만의 핵심 착각은?",
        options: ["캐시가 개인 페이지를 정적 파일로 착각해 공개 저장하는 것", "서버가 너무 빨라서", "쿠키가 없어서"],
        answer: 0,
        explain: "'확장자가 정적이면 공개 자원'이라는 캐시 규칙과 개인 데이터 응답의 조합이 문제다.",
      },
    ],
    defense: "캐시 규칙에서 개인 페이지 경로를 정적 대상에서 제외하고, 응답에 Cache-Control: private/no-store 를 명시한다. 인증이 필요한 경로에는 확장자를 붙여도 캐시하지 않는다.",
    link: "https://portswigger.net/web-security/web-cache-deception",
  },
  {
    id: "jwt-forgery",
    title: "JWT 위조 — 신분증을 스스로 찍어내기",
    klass: "JWT (인증)",
    level: "중급",
    story:
      "JWT 는 '서버가 서명한 신분증'이다. 그런데 서명 검증을 건너뛰거나 서명 키가 약하면, " +
      "**공격자가 신분증을 스스로 찍어낼 수 있다.** alg=none(서명 없음)으로 바꿔 보내거나, " +
      "사전에 찾은 약한 키로 role=admin 을 새로 서명하면 관리자가 된다.",
    diagram: [
      "공격자                        서버(검증 허점)",
      "  │ 토큰 획득(정상 로그인)       │",
      "  │ header: {alg: \"none\"} 으로 조작 또는 약한 키로 재서명(role=admin)",
      "  ├───────────────────────────▶│ 서명 검증 생략/약한 키 통과!",
      "  │◀── \"role\":\"admin\" 로 인식 ──┤",
      "  ▼  관리자 기능 접근",
    ].join("\n"),
    lab: { start: ["node", "labs/vuln-jwt/server.cjs"], port: 18115 },
    steps: [
      {
        title: "1. 토큰 관찰 — 신분증을 손에 넣는다",
        explain: "정상 로그인으로 발급된 JWT 를 관찰한다. JWT 는 점(.)으로 구분된 header.payload.signature 세 조각이고, 앞 두 조각은 base64url 로 누구나 읽을 수 있다.",
        observe: "jwt_audit 이 alg, exp, 민감 클레임을 정적 분석한다. 여기서 alg=none 이나 약한 키 징후가 나오면 다음 단계로 간다.",
      },
      {
        title: "2. 위조와 실증 — 서버가 받아주는지 확인한다",
        explain: "RedCell 은 두 가지 위조 변형을 만든다: ① alg=none(서명 제거) ② 약한 시크릿으로 role=admin 재서명. 그리고 무토큰/원본/위조 세 요청을 비교해 서버가 위조 토큰을 유효 세션으로 받아들이는지 실증한다(오탐 방지를 위해 인증 경계가 없는 엔드포인트는 스킵).",
        tool: "jwt_attack",
        args: { paths: ["/login?user=admin", "/api/me"] },
        expectFinding: "JWT 위조 실증",
        observe: "증거에 '위조 토큰이 유효 세션으로 수용'과 role=admin 특권 신호가 나오면 인증 체계가 무력화된 것이다. 이제 임의 계정 사칭이 가능하다.",
      },
    ],
    quiz: [
      {
        q: "alg=none 공격이 성립하는 이유는?",
        options: ["none 을 서명 없는 토큰으로 해석하는 파서가 있어서", "JWT 가 느려서", "쿠키가 작아서"],
        answer: 0,
        explain: "'받은 alg 를 그대로 믿고 검증하는' 구현이 있으면 none=서명 없음 통과가 된다. 해법은 alg 를 서버가 고정(allowlist)하는 것.",
      },
      {
        q: "약한 HMAC 시크릿의 위험은?",
        options: ["토큰이 길어진다", "사전 대입으로 시크릿을 찾아 임의 토큰 재서명이 가능하다", "속도가 느려진다"],
        answer: 1,
        explain: "HMAC 키를 알면 원하는 클레임(role=admin)을 넣어 정당한 서명으로 찍어낼 수 있다. 시크릿은 충분한 엔트로피(≥256비트)로.",
      },
    ],
    defense: "검증 라이브러리 API 사용(수동 파싱 금지), alg 화이트리스트 고정(none/혼합 거부), 충분한 엔트로피의 시크릿, kid/jku 등 헤더 파라미터 검증, 짧은 만료.",
    link: "https://portswigger.net/web-security/jwt",
  },
];

export function lessonById(id: string): Lesson | undefined {
  return LESSONS.find((l) => l.id === id);
}
