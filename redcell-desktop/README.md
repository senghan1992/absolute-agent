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

- **URL 입력** — 위에 대상 `host / URL : port`를 넣는 것만 남았다(공격 방법/엔진 모드
  선택 같은 해킹 전용 컨트롤은 제거). 실행 시 **자동 인가**: URL + DNS 해석된 실제 IP 를
  `~/.redcell/authorization.list` 에 추가해 사내망 대상도 즉시 통과한다. 🛡 패널에서 제거 가능.
- **우측 패널에서 지시** — "하반기 1차 합격자 목록을 파일로 뽑아줘" 처럼 평범한 말로
  지시하면 prime-agent(pi)가 그 대상에서 알아서 수행하고, 결과물(파일 등)을 만들어 준다.
  같은 세션에서 이어서 지시하면 **대화가 이어진다**(pi `--session-id` 연속 대화).
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

```bash
cd redcell-desktop/src-tauri
cargo tauri dev          # 개발 실행 (창이 뜸)
# 또는 백엔드만 컴파일 검증:
cargo build
```

앱을 처음 열면 `⚙ 설정`에서 **redcell 경로**를 확인/지정한다(기본 자동 탐색).
`⚙ 설정 > 프로바이더`에서 LLM API 키를 등록한다(Claude/GPT/OpenRouter 등).

## 세션 데이터 위치
- Linux: `~/.local/share/dev.redcell.desktop/sessions/*.json`
- macOS: `~/Library/Application Support/dev.redcell.desktop/sessions/*.json`

## 라이선스
MIT. 인가된 대상에 한해 사용한다.