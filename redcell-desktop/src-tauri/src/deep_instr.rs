//! 심층 진단 지시문 생성기 — 워커 정의·역할 프롬프트·병합/추적 지시문 조립.
//!
//! LLM 에 보내는 텍스트를 만드는 순수 로직만 모은다(네트워크·프로세스·상태 없음).
//! 워커 5분야 지시문, P0 증거 주입 후 병합 지시문, 추적 라운드 지시문이 여기 있다.

/// 서비스 진단 역할 + 실측 정찰 지시 (단일 진단·심층 collector 공용 토대).
pub const DIAG_ROLE: &str = r#"# RedCell 서비스 진단 — 시니어 해커 멘토

당신은 10년차 시니어 해커다. 지금 주니어 해커를 가르치듯, 이 서비스에서
**실제로 해킹이 어떻게 가능한지** 시나리오 단위로 보여주고, 각 시나리오마다
"왜 가능한지(원리)"와 "어떻게 막는지(구체적 코드·설정)"를 함께 설명한다.
독자는 해킹을 모르는 서비스 담당자 + 주니어 보안 담당자다.

대상 URL 이 주어졌으면 보고서를 쓰기 전에 **반드시** 아래 실측 정찰을 먼저
수행하고, 확보한 실제 응답·헤더·상태로 서비스 모델을 세운다.
(P0 자동 스윕 증거([P-###])가 함께 주어지면 그것을 우선 사용하고, 빈틈만
아래 순서로 보완한다 — 이미 커버된 항목의 재프로브는 시간 낭비다.)

## 실측 정찰 순서 (URL 이 주어진 경우 — 보고서 작성 전 반드시)
모든 요청은 web_fetch, 비파괴 GET/HEAD 로만 한다:
① 홈페이지 GET + 응답 헤더 — 기술스택·서버·보안 헤더 점검
   (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
   X-Content-Type-Options, Referrer-Policy, Server, X-Powered-By)
② 쿠키 플래그 (HttpOnly/Secure/SameSite) 점검
③ 홈페이지의 링크·폼·스크립트·JS 번들에서 엔드포인트·파라미터·API 수집(공격 표면)
④ 흔한 민감/설계 경로를 각각 한 번씩 프로브: /robots.txt, /.well-known/security.txt,
   /sitemap.xml, /openapi.json, /swagger, /admin, /login, /api, /health, /.env,
   /.git/HEAD, /config, /favicon.ico, /server-status
⑤ 리다이렉트·HTTPS 강제·응답 코드(200/301/302/403/404/500)로 배포·접근통제 정황 파악
⑥ JS 번들·openapi 문서에서 API 키·토큰·내부 URL 같은 비밀 문자열 탐색
정찰에서 실제로 본 것을 근거로만 단정하고, 못 본 것은 [가정] 으로 표기한다."#;

/// 리포트 형식 + 집필 원칙 (단일 진단·심층 collector 공용).
pub const REPORT_SPEC: &str = r#"## 리포트 형식 (Markdown, 아래 구조를 지킨다 — UI 가 자동 시각화한다)
# <서비스명> 진단 리포트
## 0. 한눈에 보기 (맨 앞 요약 표)
  3줄 요약: 비전문가도 이해하는 "그래서 뭐가 위험한가" 3줄 (등급·최대 피해·급한 조치)
  | 루트 | 위험도 | 공격 방법 | 탈취 정보 | 보완 요약 |
  (각 시나리오를 한 행으로 — 비전문가도 표 하나로 전체 그림을 본다)
  P0 자동 스윕 요약 1줄: "자동 스윕 N개 프로브·M건 발견" + 심각도 분포.
  (시나리오에는 관련 증거 ID를 [P-###] 형태로 반드시 인용한다)
## 1. 진단 범위 및 가정
  - 기술 스택·아키텍처 추정 (설명에 없는 부분은 [가정] 으로 표시)
  - 진단 경계: 설명 기반 판단 vs 실측 확인
## 2. 공격 표면 (Attack Surface)
  인증·세션·권한 / 입력 처리 / 데이터 흐름 / 외부 연동 / 배포·설정 / 비즈니스 로직
  각 표면의 노출 경로와 진입점(예상 엔드포인트·함수·플로우)
## 3. 공격 시나리오 (위험도 순 — 시니어가 주니어에게 가르치듯 구체적으로)
  각 시나리오는 **반드시 아래 고정 형식**으로 작성한다 — UI 가 '공격 흐름
  다이어그램'·'단계 시뮬레이션'·'멘토 노트'·'탈취 정보 태그'로 시각화하므로
  라벨 줄을 정확히 지켜라:

  ### 루트 1. <공격 시나리오 이름> [높음]
  위험도: 높음                  (치명|높음|중간|낮음 중 하나)
  진입점: <공격자가 처음 닿는 지점 — URL/엔드포인트/화면/파일 등>
  공격 흐름: 공격자 → <진입점> → (<취약점/공격 기법>) → <중간 결과> → (<탈취>) → <최종 피해>
             예: 공격자 → 로그인 폼 → (SQL 주입) → 인증 우회 → (관리자 세션 탈취) →
             전체 사용자 개인정보 열람
             (→ 로 구분된 단계들. 취약점 단계는 ( ) 로, 정보 유출 단계도 ( ) 로 표기)
  탈취 정보: 이메일 주소, 비밀번호 해시, 세션 토큰, 결제 카드 정보
             (쉼표로 구분 — 무엇이 새는지 구체적일수록 좋음)
  공격 방법: 구체적 기법·페이로드 예시·도구 (주니어가 따라 할 수 있을 정도로)
  멘토 노트: 왜 이 공격이 가능한지 원리 설명 — 주니어를 가르치듯 쉽게, 2~4문장
             (예: "로그인 입력값을 SQL 문장에 그대로 이어붙이면, 공격자의 입력이
             코드가 된다. 그래서 참이 되는 조건을 넣으면 비밀번호 없이도 …")
  증거: 실제 확인한 응답·헤더·본문 발췌 1~3줄 (원문 그대로, 민감값은 뒤 4자리만)
  영향: 비즈니스 영향 (한 줄 — "결국 무엇이 어떻게 새는가")
  시뮬레이션: (UI 가 '이렇게 하면 → 이렇게 된다' 단계 재생 플레이어로 시각화)
    1. <공격자 행동 — 요청·페이로드·조작> → <시스템 결과/응답>
    2. <다음 행동> → <다음 결과>
    (숫자 번호 + '→' 한 쌍으로 2~4단계. 행동은 주니어가 따라 할 수 있을 만큼
    구체적으로 — 예: "id 에 ' OR '1'='1 입력 후 로그인 클릭 → 관리자 쿠키 발급 응답")
  검증: [실증] <어떻게 확인했는지 — web_fetch 실측 응답 근거>
        [징후] <부분 확인·정황 — 헤더, 설정, 오류 노출 등>
        [가정] <설명 기반 추론 — 실측 불가 사유>
        [실증]은 P0 증거 + P1 재확인(verify-*)이 있거나 직접 재현에 성공했을 때만 사용한다.
        (셋 중 하나만. URL 이 주어졌으면 핵심 루트는 실측 재현을 시도해 [실증]으로
        올리고, 재현 실패 시 [가정]으로 유지한다. 게으른 추측 금지)
  보완: 미리 막는 방법 — 복붙 가능한 코드·설정 예시를 포함해 2~5줄
        (코드·설정·프로세스 수준, 우회 가능성과 한계 포함)

  참고할 공격 기법 pool (여기서 뽑지 말고 서비스에 맞게 창의적으로 조합하라):
  주입류(SQLi·NoSQLi·명령·SSRF·SSTI·LDAP/XPath·CRLF·HPP·CSTI), 인증·세션(JWT·
  OAuth/OIDC·쿠키·토큰), 권한(IDOR·BOLA·수평/수직 상승), 파일 업로드·경로,
  XXE·역직렬화, 레이스 컨디션, 캐시 오염·기만, 요청 스머글링, Host 헤더 오염,
  GraphQL introspection·API 남용, 비즈니스 로직 남용(할인·쿼터·순서·상태),
  AI/LLM(프롬프트 주입·시스템 프롬프트 유출·RAG 오염·에이전트 도구 남용·과권한 키),
  개인정보 노출, 유니코드·인코딩 우회, 체인 공격(XSS→CSRF→관리자 권한 등)
## 4. 개선·보완 권고 (우선순위)
  각 항목: **우선순위(P0~P3) · 문제 · 구체적 보완 방법(복붙 가능한 코드·설정 포함) ·
  검증 방법**
## 5. 실측 확인 (URL 이 주어진 경우) — 정밀 검증 단계
  먼저 P0 자동 스윕 결과(프로브 수·발견 수·심각도 분포)를 3~5줄로 요약하고,
  각 시나리오의 검증 항목에 관련 증거 ID([P-###])를 명시한다. P0 증거와
  모순되는 시나리오는 삭제하거나 [가정]으로 강등한다.
  `verify-*`(P1 재확인 확정)와 `auth-inject`(로그인 injection 시도 결과) 발견이
  있으면 반드시 대응 시나리오로 작성한다 — 시도가 있었는데 리포트에서 빠지면 안 된다.
  위험도 높음/치명 시나리오는 반드시 web_fetch 로 **재현을 시도**하고(요청·응답·
  헤더·쿠키를 실제로 확인), 각 시나리오의 검증 상태를 갱신한다:
  - 재현 성공 → [실증] 으로 상향 (근거: 실제 응답 원문 기재)
  - 부분 확인(오류 노출·헤더·설정 파일 등) → [징후]
  - 재현 불가/미시도 → [가정] 유지 (어떤 시도를 했는지 기재)
  재현 동작은 비파괴(읽기·폼 검증 정도)로 제한하고, 실측 전후의 차이와 남은 미확인
  항목을 정리한다.

## 집필 원칙
- **비전문가 친화**: 시나리오마다 "결국 무엇이 어떻게 새는가"를 흐름·탈취 정보로
  한눈에 보이게 한다. 전문 용어는 괄호로 풀어 쓴다(예: (SQL 주입 = 입력값으로
  DB 질의를 조작)).
- **멘토링**: 모든 시나리오에 멘토 노트(왜 가능한지 원리)를 붙인다 — 리포트를 읽은
  주니어가 다음엔 스스로 찾을 수 있어야 한다.
- **창의성**: 잘 알려진 취약점뿐 아니라 조합·비즈니스 로직·운영 방식에서 나오는
  공격 시나리오를 발굴한다. 공격자 관점에서 "실제로 어떻게 성공하는가"를 구체적으로.
- **보완 중심**: 모든 공격 시나리오마다 반드시 "미리 막는 방법"을 복붙 가능한 수준으로
  제시한다 — 진단 리포트가 곧 개선 지침이 되도록.
- **정밀 검증**: 추측(가정)과 실측(실증)을 절대 섞지 않는다. 근거 없이 단정하거나
  위험도를 부풀리지 말 것 — 증거가 부족하면 [징후]나 [가정]으로 정직하게 낮춘다.
  검증 상태가 [실증]인 시나리오만 "확인된 취약점"으로 표현한다.
- 로컬 컴퓨터 파일은 조사하지 말 것. 웹 실측은 반드시 web_fetch 툴로만."#;

/// 정밀 진단 분야 정의 — prime-agent builder(factory) 패턴의 워커/섹션에 대응.
/// 각 분야는 독립 pi 세션으로 동시에 실행되고, 병합 단계에서 결과를 합친다.
pub struct DeepWorkerDef {
    pub id: &'static str,    // pi 세션 접미사 + 이벤트 태그
    pub label: &'static str, // UI 칩·로그 표시 (쉬운 이름)
    pub title: &'static str, // 담당 분야
    pub brief: &'static str, // 워커 전용 임무 지시
}
pub const DEEP_WORKERS: &[DeepWorkerDef] = &[
    DeepWorkerDef {
        id: "w1",
        label: "구조 살펴보기",
        title: "표면 정찰",
        brief: "홈페이지·헤더·쿠키·TLS·리다이렉트·민감 경로(/robots.txt, /.well-known/security.txt, /sitemap.xml, /openapi.json, /swagger, /admin, /login, /api, /health, /.env, /.git/HEAD, /server-status)를 비파괴 GET/HEAD 로 전수 조사하고, 링크·폼·스크립트·JS 번들에서 엔드포인트·파라미터·API 를 수집한다. REST·GraphQL(/graphql introspection)·WebSocket·gRPC·LLM API(/v1/models·/api/tags) 표면을 빠짐없이 지도화하고, 보안 헤더·쿠키 플래그 누락을 빠짐없이 기록한다.",
    },
    DeepWorkerDef {
        id: "w2",
        label: "입력값 점검",
        title: "주입 공격",
        brief: "수집된 엔드포인트·파라미터에 SQL 주입·XSS(반사형, 무해 마커)·SSTI·SSRF·OS 명령 주입·경로 조작·NoSQL 연산자·LDAP/XPath·CRLF 헤더 주입·HPP 신호를 비파괴 프로브로 탐지한다. 오류 메시지 노출·산술 평가·응답 헤더 반영 같은 신호를 증거 원문과 함께 기록한다. 파괴적 페이로드·대량 요청·시간 지연(time-based) 프로브는 금지. P0 증거(ssti-/ssrf-/crlf-/nosql-/graphql-/host-header/cache-poison)가 있으면 재프로브 대신 인용하고 빈틈만 보완한다. 단, P0 증거에 danger-write(쓰기 검증)가 있으면 그 결과를 인용해 체인 시나리오(웹셸 경로·정리 여부 포함)를 작성한다.",
    },
    DeepWorkerDef {
        id: "w3",
        label: "로그인·권한 점검",
        title: "인증·세션·권한",
        brief: "로그인·회원가입·토큰(JWT/쿠키/OAuth/OIDC) 흐름을 분석한다: 세션 고정·예측 가능성, 로그아웃 무효화, 탈취 시 영향, 무차별 대입 방어(레이트리밋·잠금), JWT 위험 클레임(kid/jku/x5u)·OAuth redirect_uri·state 누락, IDOR·수평/수직 권한 상승 신호를 비파괴 범위에서 확인하고 기록한다. 로그인 쿠키가 적용된 실행이면 비로그인 가정 시나리오를 쓰지 말고 P0 인증 증거를 우선 인용한다. P0 증거에 danger-creds(기본자격)·danger-idor(인접 확정)가 있으면 인용해 권한 탈취 체인을 작성한다(비밀번호 원문은 절대 복기하지 마라).",
    },
    DeepWorkerDef {
        id: "w4",
        label: "정보 노출 점검",
        title: "노출·설정 오류",
        brief: "노출된 비밀·설정 오류를 찾는다: /.env·백업 파일·설정 파일, /.git, JS 번들·openapi 문서 속 API 키·토큰(LLM API 키 포함)·내부 URL, 디버그·관리자 페이지, CORS 와일드카드·null Origin, 상세 오류 스택 노출, 역직렬화 blob·ViewState, 탭내빙·CSP 우회 지점. P0의 upload-surface(업로드 폼)·methods(쓰기 메서드)·method-override·deserialize-sig·tabnabbing·csp-analysis 증거를 인용해 설정 보완안(실제 업로드·PUT 발송 없이)을 제시한다. 발견 원문(민감값 마스킹)을 증거로 기록한다.",
    },
    DeepWorkerDef {
        id: "w5",
        label: "기능 오용 점검",
        title: "비즈니스 로직",
        brief: "서비스 설명과 실제 화면·API 흐름을 대조해 비즈니스 로직 남용 포인트를 발굴한다: 가격·할인·쿼터·순서·상태 전이 조작, 레이스 컨디션 가능 지점, 권한 단계 건너뛰기, 악용 가능한 정상 기능. AI/LLM 연동이 보이면(챗봇·요약·검색·에이전트·/v1/*·API 키) 프롬프트 주입(직접·간접)·시스템 프롬프트 유출·RAG 오염·에이전트 도구 남용·과권한 API 키 시나리오도 비파괴 범위에서 발굴한다. 각 포인트마다 악용 시나리오 초안을 기록한다.",
    },
];

/// 워커 구조화 발견 파일명 — findings-<worker-id>.json (id 는 영숫자·`-` 만).
pub fn findings_filename(worker_id: &str) -> String {
    let safe: String = worker_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    format!("findings-{safe}.json")
}

/// 구조화 발견 스키마 블록 — {PATH} 에 절대경로를 채워 워커·추적 지시문에 붙인다.
/// 텍스트 출력과 동일 내용을 JSON 으로도 저장하게 해 collector 병합의 1차 입력으로 쓴다.
pub fn findings_save_block(findings_path: &str, rewrite: bool) -> String {
    if findings_path.trim().is_empty() {
        return String::new();
    }
    let mode = if rewrite { "추가분을 반영해 전체를 덮어쓰기로 갱신" } else { "새로 저장" };
    format!(
        r#"## 구조화 저장 (필수 — 텍스트 출력과 별개)
위 발견과 동일한 내용을 아래 JSON 배열로 `{path}` 절대경로에 {mode}한다
(prime: edit.run / pi: write·edit 툴. 상대경로 금지 — 이 경로 그대로 쓴다):
[{{"severity":"치명|높음|중간|낮음|정보","title":"...","detail":"한 줄 설명","evidence":"응답·헤더 발췌 또는 [가정]","target":"URL·엔드포인트","p0_ids":["P-001"]}}]
규칙: severity 는 5값 중 하나만, evidence 민감값 마스킹, 발견 없으면 [] 빈 배열."#,
        path = findings_path.trim(),
        mode = mode,
    )
}

/// 정밀 진단 분야용 지시문 — 독립 세션에서 한 분야만 깊게 파고든다.
/// `findings_path` 가 비어 있지 않으면 구조화 저장 블록을 덧붙인다.
pub fn deep_worker_instruction(
    def: &DeepWorkerDef,
    target: &str,
    goal: &str,
    https_hint: &str,
    mem: &str,
    findings_path: &str,
) -> String {
    format!(
        r#"# RedCell 정밀 진단 워커 — {label} ({title})

당신은 시니어 해커 팀의 '{title}' 담당 전문가다. 아래 대상을 맡은 분야에서만
깊게 파고들어 발견 사항을 정리한다. 다른 워커가 다른 분야를 동시에 맡고 있으니
네 분야 외에는 손대지 마라.

대상 사이트(인가됨): {target}
{https_hint}
서비스 설명: {goal}

## 임무
{brief}

## 규칙
- 모든 웹 조회는 web_fetch 툴로, 비파괴 GET/HEAD(폼 검증 정도의 POST 허용)로만.
- 실제로 확인한 것만 증거(응답·헤더·본문 발췌, 민감값은 뒤 4자리만)와 함께 기록.
- 못 본 것은 [가정] 으로 표기하고 단정하지 마라.
- 이 컴퓨터의 파일 시스템(bash/read/edit/write)은 조사 대상이 아니다.
{mem}
## 출력 형식 (반드시 지킨다 — 병합 단계에서 합친다)
## 워커 발견 ({label} {title})
- [치명|높음|중간|낮음|정보] <발견 제목> — <한 줄 설명> / 근거: <증거 발췌 또는 [가정]>
(발견마다 한 줄, 최대 12줄. 발견이 없으면 "- [정보] 이상 없음 — <확인한 범위>" 한 줄)
{save_block}"#,
        label = def.label,
        title = def.title,
        target = target,
        https_hint = https_hint,
        goal = if goal.trim().is_empty() { "(설명 없음 — 실측으로 파악)" } else { goal.trim() },
        brief = def.brief,
        mem = mem,
        save_block = findings_save_block(findings_path, false),
    )
}

/// 정밀 진단 병합자용 지시문 — 분야별 발견을 결과 리포트로 fan-in.
/// `kind` 는 리포트 종별 ("1차 리포트" | "최종 리포트") — 역할 문구와 H1 에 반영된다.
pub fn deep_merge_instruction(target: &str, goal: &str, outputs: &str, mem: &str, kind: &str) -> String {
    let spec = REPORT_SPEC.replacen("# <서비스명> 진단 리포트", &format!("# <서비스명> {kind}"), 1);
    format!(
        r#"{DIAG_ROLE}

당신은 정밀 진단의 {kind} 작성자(병합 담당)다. 5명의 분야별 워커가 같은
대상을 동시에 진단한 결과(아래)가 주어졌다. 이를 병합·검증해 {kind} 1개를
작성한다.

대상 사이트(인가됨): {target}

## 서비스 설명

{goal}

## 워커 발견 (5개 분야 — 중복 제거하고 병합할 것)

{outputs}
{mem}
## 병합 규칙
1. 중복 발견은 하나로 합치고, 서로 연결되는 발견은 체인 시나리오(XSS→세션 탈취→
   관리자 권한 등)로 엮는다 — 단일 발견 나열이 아니라 **공격 시나리오**가 주인공이다.
2. 위험도 높음/치명 후보는 web_fetch 로 비파괴 재현을 시도해 [실증]/[징후]로
   확정한다. 재현 못 하면 [가정]으로 정직하게 둔다.
3. 워커가 놓친 분야가 보이면 최대 2개 시나리오까지만 보강하고, 보강분은
   반드시 [가정] 으로 표기한다. P0 증거([P-###])와 모순되는 시나리오는
   쓰지 말고, 근거 없는 고위험 단정은 금지한다.
4. `## 기계 대조 결과` 블록이 있으면 반드시 반영한다: 불일치 [실증] 은 [징후] 로
   강등하고, 존재하지 않는 [P-###] 인용(기계 판정 목록)은 삭제한다.
   대조 결과를 무시하고 [실증] 을 유지하는 것은 금지한다.
5. 아래 리포트 형식·집필 원칙을 정확히 지킨다.

{spec}"#,
        target = target,
        goal = if goal.trim().is_empty() { "(설명 없음 — 워커 실측 기반)" } else { goal.trim() },
        outputs = outputs,
        mem = mem,
    )
}

/// 문자열 뒤쪽 cap 자만 남긴다 — 누적 로그는 앞이 아니라 뒤(최신 발견)가 중요하므로
/// 앞부분을 잘라낸다. 잘린 앞부분이 있으면 머리말로 알린다.
/// 기계 대조용 증거 주장 — (루트/발견 제목, URL, 증거 발췌).
/// 하네스가 URL 을 재요청해 발췌 출현을 확인한다 ([실증] 자기채점의 기계망).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceClaim {
    pub route: String,
    pub url: String,
    pub excerpt: String,
}

/// 주장 추출 상한 (대조 요청 폭증 방지).
pub const VERIFY_CLAIM_CAP: usize = 12;

fn clean_url_token(tok: &str) -> String {
    tok.trim_matches(|c: char| matches!(c, '"' | '\'' | ')' | ']' | '>' | ',' | ';' | '.' | '`' | '*'))
        .to_string()
}

fn first_url_in(text: &str) -> Option<String> {
    for tok in text.split_whitespace() {
        let t = clean_url_token(tok);
        if t.starts_with("http://") || t.starts_with("https://") {
            if t.len() > 12 {
                return Some(t);
            }
        }
    }
    None
}

fn clean_excerpt(raw: &str) -> String {
    raw.replace("**", "").replace('`', "").replace('"', "").trim().to_string()
}

/// 증거 주장 추출 — 병합 리포트의 `### 루트` 섹션 + 워커 `## 발견` 불릿을 모두 처리.
/// 발췌에 [가정] 이 있으면 제외 (가정은 대조 대상이 아니다). URL 없는 주장은 제외.
pub fn extract_evidence_claims(text: &str) -> Vec<EvidenceClaim> {
    let mut out: Vec<EvidenceClaim> = Vec::new();
    // 병합 형식: ### 루트 섹션 단위.
    let mut sections: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("### 루트") {
            if !cur.trim().is_empty() {
                sections.push(std::mem::take(&mut cur));
            }
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        sections.push(cur);
    }
    for sec in &sections {
        if out.len() >= VERIFY_CLAIM_CAP {
            break;
        }
        let route = sec.lines().next().unwrap_or("").trim().trim_start_matches('#').trim().to_string();
        // [실증] 없는 섹션은 스킵 (가정·징후만이면 대조 무의미).
        if !sec.contains("[실증]") {
            continue;
        }
        let Some(url) = first_url_in(sec) else { continue };
        let mut excerpt = String::new();
        for line in sec.lines() {
            if let Some(pos) = line.find("증거:") {
                let e = clean_excerpt(&line[pos + "증거:".len()..]);
                if !e.contains("[가정]") && e.chars().count() >= 20 {
                    excerpt = e;
                    break;
                }
            }
        }
        if excerpt.is_empty() {
            continue;
        }
        if out.iter().any(|c: &EvidenceClaim| c.url == url) {
            continue;
        }
        out.push(EvidenceClaim { route, url, excerpt });
    }
    // 워커 형식: "- [등급] 제목 — 설명 / 근거: ..." 불릿.
    for line in text.lines() {
        if out.len() >= VERIFY_CLAIM_CAP {
            break;
        }
        let t = line.trim();
        if !t.starts_with("- [") && !t.starts_with("* [") {
            continue;
        }
        if t.contains("[가정]") && !t.contains("[실증]") {
            continue;
        }
        let Some(rpos) = t.find("/ 근거:") else { continue };
        let excerpt = clean_excerpt(&t[rpos + "/ 근거:".len()..]);
        if excerpt.chars().count() < 20 {
            continue;
        }
        let head = &t[..rpos];
        let Some(url) = first_url_in(head) else { continue };
        if out.iter().any(|c: &EvidenceClaim| c.url == url) {
            continue;
        }
        let route: String = head.chars().take(80).collect();
        out.push(EvidenceClaim { route, url, excerpt });
    }
    out
}

/// [P-###] 인용 추출 (수동 스캔 — regex 불필요).
pub fn extract_p_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i + 7 <= b.len() {
        if &b[i..i + 3] == b"[P-" && b[i + 3].is_ascii_digit() && b[i + 4].is_ascii_digit() && b[i + 5].is_ascii_digit() && b[i + 6] == b']' {
            out.push(text[i..i + 7].to_string());
            i += 7;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 존재하지 않는 P-ID 인용 검출 — 환각 증거의 기계 판정.
pub fn unknown_p_ids(text: &str, valid: &std::collections::HashSet<String>) -> Vec<String> {
    extract_p_ids(text).into_iter().filter(|id| !valid.contains(id)).collect()
}

fn norm_ws_lower(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// 발췌 출현 판정 — 공백 정규화·대소문자 무시, 앞 60자 출현이면 참.
/// 20자 미만 발췌는 false (호출자가 Skipped 처리).
pub fn excerpt_matches(body: &str, headers: &str, excerpt: &str) -> bool {
    let need = norm_ws_lower(excerpt);
    if need.chars().count() < 20 {
        return false;
    }
    let key: String = need.chars().take(60).collect();
    norm_ws_lower(body).contains(&key) || norm_ws_lower(headers).contains(&key)
}

pub fn tail_chars(s: &str, cap: usize) -> String {
    let n = s.chars().count();
    if n <= cap {
        return s.to_string();
    }
    let tail: String = s.chars().skip(n - cap).collect();
    format!("…(앞부분 {}자 생략 — 최신 발견 위주)\n{tail}", n - cap)
}

/// 워커 출력 병합 — collector 입력용. 분야당 6000자로 절단하고 빈 워커는
/// 플레이스홀더로 채운다. 1차·최종 병합이 같은 규칙을 쓰도록 공용화.
/// 누적분은 뒤쪽(최신 차수)을 남긴다 — 앞쪽 절단은 새 발견을 버리게 된다.
/// (combined, 내용 있는 워커 수) 반환.
pub fn combine_worker_outputs(accum: &std::collections::HashMap<String, String>, rounds_run: u32) -> (String, usize) {
    let mut combined = String::new();
    let mut ok_n = 0;
    let span = if rounds_run <= 1 { "1차".to_string() } else { format!("1~{rounds_run}차 누적") };
    for def in DEEP_WORKERS {
        let wid = def.id;
        let body = accum.get(wid).map(|s| s.trim()).unwrap_or("");
        if !body.is_empty() {
            ok_n += 1;
        }
        let body = if body.is_empty() {
            "(이 분야는 결과를 내지 못했습니다 — 최종 리포트에서 해당 분야를 보강할 것)".to_string()
        } else {
            tail_chars(body, COMBINE_WORKER_CAP)
        };
        combined.push_str(&format!("\n\n--- {} ({wid}) [{span}] ---\n{body}", def.label));
    }
    (combined, ok_n)
}

/// 1차 리포트 병합 지시문 — 같은 본문에 1차 단계 고지만 덧붙인다.
pub fn early_merge_instruction(base: String) -> String {
    format!("{base}\n\n주: 이는 1차 확인 직후의 1차 리포트 병합이다. 서두에 '1차 확인 기반의 1차 리포트이며, 추가 확인이 뒤에서 계속되어 최종 리포트로 바뀔 수 있음'을 한 줄로 명시하라. 확정할 수 없는 것은 [가정]·[징후]로 정직하게 구분하라.")
}

/// 정밀 진단 추가 확인 상한 (1차 + 추가 2회 = 최대 3차).
/// 1차 리포트가 먼저 나가고, 새로 찾은 게 없으면 조기 수렴해 최종 리포트로 간다.
pub const DEEP_MAX_ROUNDS: u32 = 3;
/// 추가 확인 지시문에 넣는 자가 이전 결과 발췌 상한 (문자, 뒤쪽 우선).
pub const DEEP_FOLLOWUP_TRUNC: usize = 2000;
/// collector 입력용 워커 출력 상한 (분야당 문자, 뒤쪽 우선).
pub const COMBINE_WORKER_CAP: usize = 6000;

/// 워커 출력에서 발견 키 추출 — `[등급] 제목` 줄을 정규화해 순서 유지 중복 제거.
/// 수렴 판정(신규 발견 수) + 교차 단서 전달에 쓴다.
/// `##` 소제목은 매 라운드 새로 찍혀 신규로 오판되므로 세지 않는다.
/// "추가 발견 없음/이상 없음" 같은 무발견 보고도 발견이 아니므로 제외한다 —
/// 안 그러면 매 라운드 신규로 잡혀 수렴 판정이 무력화된다.
pub fn extract_finding_keys(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.contains("추가 발견 없음") || t.contains("이상 없음") {
            continue;
        }
        let is_bullet = t.starts_with("- [")
            || t.starts_with("* [")
            || t.contains("[치명]")
            || t.contains("[높음]")
            || t.contains("[중간]")
            || t.contains("[낮음]");
        if !is_bullet {
            continue;
        }
        let norm: String = t
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '#' | '*' | '/' | ':' | '(' | ')'))
            .take(80)
            .collect();
        if norm.chars().count() >= 8 && !out.contains(&norm) {
            out.push(norm);
        }
    }
    out
}

/// 추가 확인 지시문 — 자가 이전 결과 + 타 워커 단서를 물고 추가 발견만 노린다.
pub fn deep_followup_instruction(
    def: &DeepWorkerDef,
    round: u32,
    own_prior: &str,
    cross: &str,
    target: &str,
    findings_path: &str,
) -> String {
    let own = tail_chars(own_prior.trim(), DEEP_FOLLOWUP_TRUNC);
    format!(
        r###"# RedCell 정밀 진단 추가 확인 {round}차 — {label} ({title})

너는 같은 대상을 계속 파고 있는 '{title}' 담당 전문가다. 이전 턴의 대화·P0 증거는
그대로 이어진다. 새로 실측·추론해서 **추가 발견만** 보고한다. 이미 보고한 것은
반복하지 마라.

대상 사이트(인가됨): {target}

## 네 이전 보고 (요약 — 반복 금지)
{own}

## 다른 분야의 단서 (네 분야와 엮일 수 있음)
{cross}

## 확인 규칙
- 위 단서 중 네 분야와 연결되는 것을 우선 확인하고, 네 이전 보고의 [가정] 은
  web_fetch 비파괴 재현으로 [실증]/[징후] 승격을 시도한다.
- 그래도 새 게 없으면 "- [정보] 추가 발견 없음 — <확인한 범위>" 한 줄만.
- 출력 형식: "## 추가 발견 ({label})" + 발견마다 "- [등급] 제목 — 설명 / 근거: …"
  (최대 8줄)
{save_block}"###,
        round = round,
        label = def.label,
        title = def.title,
        target = target,
        own = if own.trim().is_empty() { "(이전 보고 없음)" } else { own.trim() },
        cross = if cross.trim().is_empty() { "(단서 없음)" } else { cross.trim() },
        save_block = findings_save_block(findings_path, true),
    )
}
