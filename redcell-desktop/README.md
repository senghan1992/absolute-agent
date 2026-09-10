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
- **서비스 진단 모드(상단 '서비스 진단' 토글 / **[진단] 원클릭)** — **host/URL 만 넣고
  [진단] 을 눌러도** 에이전트가 먼저 **실측 정찰**(web_fetch + recon_list 로 홈페이지·보안
  헤더·쿠키·엔드포인트·민감 경로 robots.txt/.well-known/openapi/.env 등을 실제 조회)로
  서비스를 파악한 뒤, 취약점과 **대비해야 할 공격 시나리오 + 미리 막는 방법**을 리포트로
  작성한다. 서비스 설명을 함께 붙여넣으면 더 정밀해진다. 리포트 형식: ① 한눈에 보기 요약 표
  ② 진단 범위·가정 ③ 공격 표면 ④ 창의적 공격 루트 ⑤ 보완 권고(P0~P3) ⑥ 실측 결과.
  잘 알려진 취약점뿐 아니라 조합·비즈니스 로직·운영 방식의 루트를 발굴하고, 모든 루트에
  "미리 막는 방법"을 제시한다. 리포트는 결과 탭에서 시각화된다 — **공격 흐름 화살표 다이어그램**
  (공격자→진입점→(취약점 빨강)→중간 결과→(탈취 노랑)→최종 피해), **단계 시뮬레이션
  플레이어**(루트마다 "공격자 행동 → 시스템 결과" 단계가 재생 버튼/한 단계씩/진행
  바와 함께 "이렇게 하면 → 이렇게 된다"로 재생), **검증 상태 배지**([실증] 초록 -
  web_fetch 실측 확인 / [징후] 노랑 - 부분 확인 / [가정] 회색 - 설명 기반 추론,
  추측과 실측을 섞지 않는 정밀 검증 원칙), 탈취 정보 태그, 위험도 배지([치명]/[높음]/
  [중간]/[낮음]/[P0~P3]), 한눈에 보기 요약 표, 카드별 왼쪽 위험도 액센트 색, 그리고
  **보고서 상단 요약 헤더**(위험도 등급 A~F · 루트/치명·높음·중간·낮음 카운트 ·
  검증 상태 실증/징후/가정 카운트, **검증(실증/징후/가정) 상태를 반영해 등급 산정**).
  진단 리포트는 **루트별 카드로 분할**되어(요약·범위 / 루트 1·2·3… / 권고·실측) 상단
  **「루트 보기」 위험도 필터**(전체·치명·높음·중간·낮음)로 원하는 루트만 볼 수 있다.
  요약 헤더의 **[MD 저장]**·**[HTML 저장]**·**[복사]** 로 전체 리포트를 Markdown(.md)
  또는 **자체 완성형 HTML(.html — 검증 배지·공격 흐름·시나리오 정적 목록 포함)** 파일로
  저장하거나 클립보드에 복사할 수 있다(앱 데이터 `reports/` 폴더).
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

이 앱은 **prime-agent(pi)를 감싼 표시/세션 계층**이다. 공격력을 새로 만들지 않는다.

```
redcell-desktop (Tauri, Rust)
   └─ start_engagement(session) ──▶ pi CLI (--mode json -e <redcell 확장> --session-id …)
        │                             (REDCELL_GATE=1 — 모든 툴 호출을 인가 목록으로 검사)
        └─ NDJSON 이벤트 스트림 ◀─────┘  → 좌측 pi 터미널 + 우측 대화 패널
```

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

## 세션 데이터 위치
- Linux: `~/.local/share/dev.redcell.desktop/sessions/*.json`
- macOS: `~/Library/Application Support/dev.redcell.desktop/sessions/*.json`

## 라이선스
MIT. 인가된 대상에 한해 사용한다.