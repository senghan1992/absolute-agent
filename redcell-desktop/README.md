# RedCell Desktop 🖥️🛡️

RedCell 인가 레이어로 감싼 **prime-agent(pi) 데스크톱 셸**. ChatGPT 데스크톱 앱처럼
세션별 대화를 관리하고, CLI 를 어려워하는 일반인도 **URL 하나 넣고 대화로 지시**하면
prime-agent 가 그 대상에서 작업(조사·정보 수집·파일 추출·정리)을 수행한다.

```
┌──────────────────────────────────────────────────────────────────┐
│  RedCell   [세션1] [세션2*]                        + 새 세션  ⚙     │  ← 세션 탭
├───────────────────────────────────────────┬──────────────────────┤
│  host/URL  [axhack.lge.com] : [port]  ▶    │  대화 (오른쪽 패널)     │
│  ┌ pi 터미널(라이브 캡처) ──────────────┐   │  user: 하반기 1차 합격자  │
│  │ [sys] 인가 게이트: RedCell 확장 로드  │   │        목록 파일로 뽑아줘 │
│  │ 하반기 합격자 페이지를 찾았습니다…      │   │  asst: …수행 중…       │
│  │ 📄 /합격자명단.xlsx 저장 완료          │   │    (입력) [보내기]      │
│  └────────────────────────────────────┘   │                        │
└───────────────────────────────────────────┴──────────────────────┘
```

- **URL 입력 + 프로바이더 선택** — 위에 대상 `host / URL : port`, LLM 프로바이더
  드롭다운(`custom` 등 — 키·base URL·모델은 ⚙ 설정의 카드에서 연결), 실행 버튼만 있다
  (엔진 모드/공격 방법 선택 같은 해킹 전용 컨트롤은 제거). 실행 시 **자동 인가**: URL +
  DNS 해석된 실제 IP 를 `~/.redcell/authorization.list` 에 추가해 사내망 대상도 즉시
  통과한다. 🛡 패널에서 제거 가능.
- **우측 패널에서 지시** — "하반기 1차 합격자 목록을 파일로 뽑아줘" 처럼 평범한 말로
  지시하면 prime-agent(pi)가 그 대상에서 알아서 수행하고, 결과물(파일 등)을 만들어 준다.
  같은 세션에서 이어서 지시하면 **대화가 이어진다**(pi `--session-id` 연속 대화).
- **첫 화면 온보딩** — 세션이 없으면 URL 입력 화면이 먼저 뜬다. URL + 프로바이더만
  고르고 **[심층 진단 시작]** 을 누르면 세션 생성·자동 인가·심층 진단이 한 번에 실행된다.
- **P0 자동 스윕(결정적 대량 프로브)** — LLM이 움직이기 전에 Rust 엔진이 수백 건의
  읽기 전용 프로브(민감 경로 130여 종·보안 헤더·쿠키 플래그·CORS·허용 메서드·TRACE·
  HTTPS 대조·JS 비밀 스캔·무해 반사/XSS 마커·SQL 오류 지문·오픈 리다이렉트)를
  수십 초 안에 실행한다. 결과는 증거 ID(`[P-###]`)와 함께 `sessions/probe-<id>.json`에
  저장되고, 진행은 워커 보드의 **P0·스윕 칩**으로 확인한다. 스윕 산출물은 리포트
  품질의 근거로 그대로 전달된다 — 각 증거에 **CVSS 3.1 벡터·점수·CWE**가 붙고,
  **점검 커버리지 원장**(공격 클래스 × 표면 × covered/finding/deferred/out_of_scope/
  blocked), **미검증 인계 항목**(무엇을 왜 못 했는지 · 다음 단계), **탐지된 기술 스택
  인벤토리**(버전·근거)가 함께 LLM 에 주어진다 — 리포트의 등급·점수·한계 섹션이
  추측이 아니라 실측 원장에서 나온다.
- **TLS 계층 검사** — 인증서 **만료일**(DER/X.509 최소 파서를 직접 구현해 판독 — 외부
  라이브러리 추가 없이), 협상된 **TLS 버전**(1.2 미만이면 high), **약한 암호군**,
  **자체 서명·호스트명 불일치·알 수 없는 발급자**까지 판정한다. 스킴 대조만 하던
  과거와 달리 「서버 인증서 상태」까지 리포트에 실린다.
- **그 밖의 최근 보강** — 로그인·인증 API 응답의 **Cache-Control no-store 누락**
  (민감 응답이 CDN에 캐시되는 문제), 외부 CDN 스크립트의 **무결성(SRI) 누락**,
  preflight **Access-Control-Max-Age** 과다, WSDL·SOAP 엔드포인트와 백업 확장자 변형,
  업로드 폼의 accept/enctype 표면, 그리고 **로그아웃 후 세션 무효화**(동일 쿠키
  재사용 검사 — 파괴적 동의 기반에서만, 자기 세션 한정).
- **인증 스윕 + 로그인 injection 시도** — 상단 **쿠키** 란에 로그인 후 복사한 세션
  쿠키를 붙여넣으면(저장되는 것은 이 세션의 스윕용 값뿐, 비밀번호 저장·자동 로그인
  없음) 인증 영역까지 스윕한다(`P0 스윕(인증)`). 로그인 폼이 있으면 존재하지 않는
  계정 + 고정 무해 페이로드로 baseline→SQLi 2종→레이트리밋 시도(`auth-inject`)를
  실행하고 결과(우회 성공/차단/내성)를 시나리오 리포트에 녹인다.
- **SPA 렌더 + P1 검증 루프** — 헤드리스 Chromium이 있으면 JS 렌더 DOM을 확보해
  정적 HTML에 없는 폼·파라미터·스크립트까지 수집하고(없으면 정적 파싱으로 우아하게
  진행), P1 패스에서 XSS 재반사·SQLi Boolean 차분·리다이렉트 제2호스트·민감 경로
  재확인으로 1차 발견을 검증(`verify-*`, 요약의 `검증 N건`)한다. `[실증]`은 P0+P1
  확정 또는 직접 재현에만 붙는다.
- **반복 agentic loop** — 1차 워커 실행 후 신규 발견이 있으면 동일 세션에서 최대
  2회 추적 라운드를 돈다. 각 워커는 자기 이전 보고 + 타 워커 교차 단서를 물고
  `[가정]` 승격·연계 추적을 시도하고, 신규 발견이 0건이면 수렴 종료한다(결정적
  상한 3라운드, 라운드별 `추적 라운드 N 시작/종료` 노트, collector 는 전 라운드
  누적본을 병합).
- **인증우회 퍼징(`auth-bypass`, 읽기 전용)** — 세션 쿠키가 JWT 형태면 오프라인
  해석(alg=none 즉시 high, exp 없음 info) 후 **본인 세션만** 변조·재전송해서
  alg=none·서명 제거 위조 수락 여부를 판정한다(GET 4회). 인증 필요 후보 경로
  10종은 쿠키 유무 차분으로 게이트 누락을 찾고(무쿠키 200은 노출 medium/low),
  응답 내 JWT 하드코딩은 마스킹 스캔한다. 기본자격 대입·타인 ID 인접 순회는
  파괴적 진단 동의 시에만 열리는 별도 프로브(`danger-*`)로 분리돼 있다.
- **쓰기계열 탐지형 진단(무발송)** — PUT/DELETE/PATCH·업로드 전송은 절대 하지 않고,
  OPTIONS Allow 판독(`methods`, PUT/DELETE는 medium)·업로드 폼 표면 식별
  (`upload-surface`, action·필드명 + 보완 권고)·`_method` 오버라이드 힌트
  (`method-override`)까지 탐지·권고한다. W4 워커가 증거를 인용해 설정 보완안을
  리포트에 녹인다.
- **파괴적 진단(명시 동의 모달)** — 기본 읽기 전용 경계를 넘어서는 3종 프로브는
  세션 헤더의 **[파괴적]** 버튼 → 동의 모달(대상 표시 + 항목별 위험 + 체크박스
  확인)에서 동의해야 열린다(세션별, 버튼 재클릭으로 즉시 철회, 동의 시각 감사
  기록). 동의 시 P0가 `danger-creds`(기본자격 5종, 잠금 신호 즉시 중단·비밀번호
  마스킹) · `danger-idor`(본인 세션 인접 ±2, 1건 확정 시 중단·증거 마스킹) ·
  `danger-write`(무해 마커 1건 PUT→GET→DELETE 정리, 잔여 시 경로 보고)를 실행하고,
  요약에 `(파괴적 동의)`가 붙는다. 미동의 시 각 프로브는 fail-closed 로 빈 반환한다.
- **파괴적 지시 가드레일(동적)** — Agent 패널 자유 지시문도 실행 전에 `risk.rs`
  가이드라인으로 평가한다. 등급별 처리: Safe(읽기·조회·추출·리포트·진단) 진행 ·
  Caution(대량 스캔·조회) 주의 노트 후 진행 · High(파일·설정·서비스·배포·업로드·
  DB 쓰기·공격 실행) 모달 동의 필요 · Critical(DB 삭제·포맷·셧다운·전체 kill)
  모달 동의 필요(강한 경고). 모달에는 등급·근거·예상 영향·복구 가능 여부·
  서비스 중단/데이터 손실 플래그를 표시하고, 체크박스 확인 시 세션 동의를 받아
  자동 재시도한다. 부정 표현("~하지 마", "don't")과 단어 경계로 오탐을 억제하고,
  "파일로 뽑아줘" 같은 조회 지시는 모달 없이 진행된다.
- **심층 진단([진단 시작] 원클릭)** — **host/URL 만 넣고 [진단 시작] 을 누르면** P0 스윕
  증거 위에서 5개 분야 워커(정찰·주입·인증·노출·로직)가 **독립 세션으로 동시에** 파고들고,
  collector 가 하나로 병합해 **공격 시나리오 리포트**(prime-agent builder/fan-in 패턴)를
  발행한다. 시나리오는 P0 증거 ID를 인용해야 하며, 모순되면 삭제·강등된다.
  진행은 라이브 뷰 상단 **워커 보드 칩**으로 확인한다. 단일 턴 진단은 우측 Agent 지시로도 가능.
- **대화형 진단도 심층과 같은 표준** — 채팅창에 “이 사이트 보안 진단해줘” 처럼 지시하면
  백엔드가 **진단 의도**를 판별해(강한 신호 우선 · 일반 작업 지시·부정 표현 배제) 세션을
  진단 모드로 승격한다(영속 저장). 그 결과 채팅 경로도 **리포트 표준(REPORT_SPEC) +
  P0 자동 스윕 증거 + 기계 대조 + 리포트 표식 + 자동 저장**을 모두 받는다 —
  “깊게/정밀” 같은 표현이면 다섯 분야 병렬 **심층 진단**으로 자동 라우팅된다.
  승격 사유는 진행 화면에 한 줄로 남는다(왜 표준 진단으로 바뀌었는지 사용자가 안다).
- **위험도 과대평가 자동 감사(신뢰 장치)** — 리포트가 주장한 위험도를 그 루트가 인용한
  P0 실측 근거의 최대 심각도와 기계 대조한다. 근거가 medium 인데 ‘치명’이라 쓰면
  **[심각도 과대]** 로 잡아 강등을 지시하고, 반대로 위험을 숨긴 **[심각도 과소]** 도
  지적한다(근거 없는 P-ID 인용은 기존대로 환각으로 삭제). 머신 대조 결과는 병합
  프롬프트에 **[심각도 대조]** 절로 들어가므로 최종 리포트의 등급도 자동으로 내려간다.
- **서비스 진단 리포트(시니어 멘토 스타일)** — 에이전트가 먼저 **실측 정찰**(web_fetch 로 홈페이지·보안
  헤더·쿠키·엔드포인트·민감 경로 robots.txt/.well-known/openapi/.env 등을 실제 조회)로
  서비스를 파악한 뒤, 취약점과 **대비해야 할 공격 시나리오 + 미리 막는 방법**을 리포트로
  작성한다. 서비스 설명을 함께 붙여넣으면 더 정밀해진다. 리포트 형식: ① 한눈에 보기 요약 표
  ② 진단 범위·가정(미점검 영역 포함) ③ **위험도 판정 기준(CVSS 3.1 루브릭)** ④ 공격 표면
  ⑤ 창의적 공격 루트 ⑥ 보완 권고(P0~P3·영향·노력·완료기준) ⑦ 실측 결과 ⑧ 확인된 보안 통제
  ⑨ 한계·미검증 영역 + 부록(재현 절차·참고 기준).
  잘 알려진 취약점뿐 아니라 조합·비즈니스 로직·운영 방식의 루트를 발굴하고, 모든 루트에
  "미리 막는 방법"을 제시한다. 리포트는 결과 탭에서 시각화된다 — **공격 흐름 화살표 다이어그램**
  (공격자→진입점→(취약점 빨강)→중간 결과→(탈취 노랑)→최종 피해), **단계 시뮬레이션
  플레이어**(루트마다 "공격자 행동 → 시스템 결과" 단계가 재생 버튼/한 단계씩/진행
  바와 함께 "이렇게 하면 → 이렇게 된다"로 재생), **검증 상태 배지**([실증] 초록 -
  web_fetch 실측 확인 / [징후] 노랑 - 부분 확인 / [가정] 회색 - 설명 기반 추론,
  추측과 실측을 섞지 않는 정밀 검증 원칙), 탈취 정보 태그, 위험도 배지([치명]/[높음]/
  [중간]/[낮음]/[P0~P3]), **객관 지표 칸(CVSS 벡터·점수 · CWE · OWASP)** — 엔진이
  산출한 값을 그대로 인용하고 LLM 이 임의 재계산하지 않는다, 한눈에 보기 요약 표, 카드별
  왼쪽 위험도 액센트 색, 그리고
  **보고서 상단 요약 헤더**(위험도 등급 A~F · 위험지수 0~10 · 루트/치명·높음·중간·낮음 카운트 ·
  검증 상태 실증/징후/가정 카운트 · **최고 위험 루트 이름** · 등급 판정 근거 한 줄).
  등급은 **평균이 아니라 규칙 기반**이다 — "직접 확인된 치명 1건"이 다른 추측 항목에
  묻혀 '안전' 으로 표시되는 사고를 막기 위해 확인된 치명·높음이 등급의 하한이 된다
  (A 이상 없음 / B 중간 이하 / C 추정 높음·확인 중간 / D 추정 치명·확인 높음 / F 확인 치명).
  진단 리포트는 **루트별 카드로 분할**되어(요약·범위 / **해야 할 일** / 루트 1·2·3… /
  직접 확인 / 잘 되고 있는 / 한계 / 부록) 상단
  **「루트 보기」 위험도 필터**(전체·치명·높음·중간·낮음)로 원하는 루트만 볼 수 있다.
  **‘해야 할 일’ 카드는 루트보다 앞에 놓인다** — 비전문가는 “무엇을 해야 하지?” 를
  먼저 봐야 하기 때문이고, 요약 카드에도 **지금 해야 할 일 3가지**(P0/P1 우선순위)를
  클릭 가능한 항목으로 노출한다.
  요약 헤더의 **[MD 저장]**·**[HTML 저장]**·**[복사]** 로 전체 리포트를 Markdown(.md)
  또는 **자체 완성형 HTML(.html — 검증 배지·공격 흐름·시나리오 정적 목록 포함)** 파일로
  저장하거나 클립보드에 복사할 수 있다(앱 데이터 `reports/` 폴더). 저장·복사본 맨 위에는
  **표지 블록**(대상·점검일·등급·위험지수·발견 분포·검증 상태 분포)이 붙어 파일이
  스스로를 설명한다.
- **검사(검증) 도구** — `bash tools/quality.sh` 한 번으로 Rust 테스트(엔진·프롬프트·하네스)
  + Rust 빌드 + UI 단위 테스트(등급 회귀) + Playwright UI 스모크를 모두 돌리고 판정한다.
  `tools/shot.py` 는 결과 탭을 캡처해 정보 구조를 눈으로 검수하게 하고,
  `tools/integrate_lane.sh` 는 격리 워크트리에서 작업한 변경분을 메인에 반영한다.
- **진단 이력 대시보드(topbar ▦ 버튼)** — 세션·대상별 진단 결과 요약(보안 등급 A~F ·
  위험도 카운트 · 검증 상태)을 한 화면으로 보여준다. 카드를 클릭하면 해당 세션의 전체
  결과로 이동한다. 실측은 항상 비파괴(GET/HEAD) 이고 scope(인가) 를 강제하며,
  인가 범위 밖 대상·파괴적 재현은 하지 않는다.
- **결과 탭(좌측 상단 "결과")** — 에이전트가 정리한 마크다운 결과를 표·제목·코드 블록
  등으로 **렌더링**해서 보여준다(의존성 없는 안전한 자체 렌더러, HTML 이스케이프 처리).
  라이브 터미널 탭과 전환해 보면서 진행/결과를 나란히 확인할 수 있다.
- **안전** — 모든 tool_call 은 RedCell 인가 게이트(ScopeGuard, `authorization.list`)를
  거친다. 인가되지 않은 호스트는 시도조차 못 한다(fail-closed).

## 동작 원리

이 앱은 **pi-coding-agent(1.4.0) / prime-agent(0.10)를 감싼 표시/세션 계층**이다.
공격력을 새로 만들지 않는다. 세션의 `engine` 값에 따라 실행 엔진이 갈린다.

```
redcell-desktop (Tauri, Rust)
   ├─ start_engagement(session) ──▶ pi --mode json -e <redcell 확장> --session-id …
   │                                 또는 prime-agent --mode json --print … --skill … --session-dir …
   └─ start_deep_diagnosis(session) ──▶ 워커 5개 병렬 (rc-…-w1…w5 / prime-sessions/<id>/w1…)
                                           + collector fan-in (…-merge)
        │                             (pi: -e 확장 사전 차단 / prime: 스킬+반응형 킬게이트)
        └─ JSON 이벤트 스트림 ◀────────┘  → 워커 보드 + 라이브 캡처 + 시나리오 리포트
```

엔진 기준: pi CLI 진입점은 정식 번들(`dist/bundle/cli.js`, 구 `dist/cli.js` 폴백 유지),
이벤트는 pi 1.4 json 프로토콜(`text_delta`·`tool_execution_start/end`·`message_end.stopReason`·
`agent_settled`)로 파싱한다. prime-agent(Rust 하네스)는 라이브러리 임베딩을 제공하지 않아
직접 실행 엔진으로도 쓴다 — 세션마다 `pi`/`prime-agent` 를 고른다(상단 셀렉트·첫 화면).
`detect_engines` 로 설치 상태·버전을 감지해 설정 화면과 첫 화면에 표시한다.

```
pi 엔진 (기본)          node <pi dist/bundle/cli.js> --mode json -e <redcell 확장> --session-id …
prime-agent 엔진        prime-agent --mode json --print … --skill <스코프 스킬> --session-dir …
```

- **pi**: RedCell 확장을 `-e` 로 명시 로드 — `tool_call` 훅이 호출 **전에** 인가를 검사해
  차단한다(사전 차단). 방법론은 `before_agent_start` 로 시스템 프롬프트에 주입한다(pi 1.4 방식).
- **prime-agent(Rust 하네스 직접 실행)**: 확장 훅이 없으므로 4중 방어로 scope 를 강제한다.
  ① 실행마다 인가 목록을 채운 스코프 스킬(`SKILL.md`)을 `--skill` 로 주입,
  ② **선행 차단**(Linux): `LD_PRELOAD` egress 필터(`netfilter`, `connect`/`getaddrinfo`
  후킹)가 인가 밖 연결·DNS 를 호출 전에 차단 — 위반 호출의 첫 실행 자체가 나가지
  못한다(차단 기록은 `sessions/netfilter-<id>.log`, pi 엔진에도 동일 적용),
  ③ JSON 스트림의 `tool_execution_start` 를 볼 때마다 호스트를 판정하고 위반이면
  프로세스를 즉시 kill (반응형 킬게이트 — `[차단]` 노트 + 상태 `error`),
  ④ 읽기 전용 태스킹(웹 조회는 `python_repl`+urllib GET/HEAD 만 — prime-agent 에는
  `web_fetch` 이 없다). 세션 연속대화는 `--session-dir` + `--continue` 로 유지된다.
  선행 차단은 `cargo build` 시 자동 생성되는 `libredcell_netfilter.so` 를 바이너리 옆에
  두고 활성화되며, 허용 집합 = 인가 목록 + 세션 대상 + LLM API 호스트, `!` 제외가
  우선한다. 비-Linux·`.so` 부재 시에는 기존 방어(훅/킬게이트)로 폴백하고 노트로 명시한다.
- **정직한 한계(잔여)**: 정식 YAML 인가를 쓸 때는 데스크톱이 scope 를 해석할 수 없어
  반응형 킬게이트 대신 선행 차단(세션 대상 단일 호스트 + LLM API)으로 강제하고 경고를
  띄운다. 정적 링킹 자식 프로세스(Go 바이너리 등)는 `LD_PRELOAD` 가 안 먹으므로
  스킬·킬게이트 층이 커버한다.
- 모델 설정: pi 는 `~/.pi/agent/models.json`, prime-agent 는 `~/.prime/agent/models.json`
  (동일 스키마 — custom/ollama 는 앱이 자동 병합). `--provider/--model/--api-key` 규칙 동일.

### prime-agent 설치

```sh
git clone https://github.com/PrimeIntellect-ai/prime-agent && cd prime-agent
cargo build --release -p pa-cli
install -m 0755 target/release/prime-agent /usr/local/bin/prime-agent
# 또는 REDCELL_PRIME_BIN=/경로/prime-agent 로 바이너리 직접 지정
```

심층 진단의 병렬 워커+병합(builder)·진단 메모리(harness) 구조도 prime-agent 패턴을
따른다. 진단 메모리는 앱 데이터 `memory.json`(전역+대상별)에 누적되며 진단 지시문에
자동 주입된다.

- 엔진은 전부 형제 프로젝트 [`../redcell`](../redcell) 의 `prime-agent/extension.ts`
  (인가 게이트 + 인가 대상 전용 툴) + pi CLI 다.
- 해킹 고정 템플릿(PTES 단계 강제 등)은 제거 — 대상이 인가되어 있으면 사용자가 시킨
  무엇이든 자유롭게 수행한다(범용 지시가 더 좋은 결과를 낸다).

## 사전 요구
- Rust + Cargo, `cargo-tauri` (`cargo install tauri-cli`)
- Node.js + **pi CLI 전역 설치**: `npm i -g @earendil-works/pi-coding-agent`
- Linux: `webkit2gtk-4.1`, `libsoup-3.0` 등 Tauri v2 시스템 의존성

## 실행

### Windows
1. **pi CLI 설치(필수)**: PowerShell 에서
   ```powershell
   npm i -g @earendil-works/pi-coding-agent
   ```
2. 프로젝트 폴더로 이동해 실행:
   ```powershell
   cd redcell-desktop\src-tauri
   cargo tauri dev
   ```
   앱이 pi 를 찾는 대표 위치(`%APPDATA%\npm\node_modules`, `%ProgramFiles%\nodejs`,
   nvm-windows `%APPDATA%\nvm`, pnpm `%LOCALAPPDATA%\pnpm`, `npm root -g`, PATH 위
   `pi.cmd`)를 자동 탐색한다. 못 찾으면 에러 메시지에 검색한 후보 전체와
   `USERPROFILE`/PATH 상태가 표시된다. 특수 위치에 설치했다면 `REDCELL_PI_DIR`
   환경변수로 pi 패키지 디렉터리를 직접 지정할 수도 있다.

### Linux / macOS

```bash
cd redcell-desktop/src-tauri
cargo tauri dev          # 개발 실행 (창이 뜸)
# 또는 백엔드만 컴파일 검증:
cargo build
```

앱을 처음 열면 `⚙ 설정`에서 **redcell 경로**를 확인/지정한다(기본 자동 탐색).
`⚙ 설정 > 프로바이더`에서 LLM API 키를 등록한다(Claude/GPT/OpenRouter 등).

**custom / ollama 프로바이더** — API 키·base URL·모델명을 앱에서 저장하면, 실행 시
자동으로 pi 의 `~/.pi/agent/models.json`(Windows: `%USERPROFILE%\.pi\agent\models.json`)에
병합 기록하고 `--api-key`/`--model` 로 전달한다. 기존 파일의 다른 프로바이더 설정은
보존되며, pi 가 인식하지 못하는 `custom` 프로바이더로 인한
"Unknown provider / No API key found" 오류가 나지 않는다. 키를 안 쓰는 로컬 서버
(vLLM·Ollama)도 모델명만 지정하면 동작한다(placeholder 키 자동 기록).

## 검증

## CLI 단독 실행 (P0 스윕)

데스크톱 없이 터미널에서 바로 실측할 수 있다 (인가된 대상에만 사용):

```bash
cd redcell-desktop/src-tauri
cargo run --bin sweep -- <host|URL> [--port N] [--cookie "a=b"] [--danger] [--json] [--timeout S]
# 예: cargo run --bin sweep -- 127.0.0.1 --port 8080 --danger
```

`--danger` 는 파괴적 동의 모달과 동일 (기본자격·IDOR 인접·쓰기검증).

## 검증

```bash
cd redcell-desktop/src-tauri
cargo test --workspace      # 백엔드 + netfilter (단위·스텁 실측·LD_PRELOAD 통합)

cd redcell-desktop
./preview.sh                # UI 프리뷰 (http://localhost:5173)
cd .verify && npm run setup # 최초 1회 (playwright, 브라우저 DL 생략)
npm run all                 # report-ui + deep-ui (인증 스윕·추적 라운드 포함)
```

## 세션 데이터 위치
- Linux: `~/.local/share/dev.redcell.desktop/sessions/*.json`
- macOS: `~/Library/Application Support/dev.redcell.desktop/sessions/*.json`

## 라이선스
MIT. 인가된 대상에 한해 사용한다.