# RedCell Desktop 🖥️🛡️

RedCell 엔진을 감싸는 **Rust(Tauri v2) 데스크톱 앱**. ChatGPT 데스크톱 앱처럼
**세션별로** engagement 를 관리하고, 대화형으로 흘러가 찾기 어려웠던 로그를
구조화된 패널로 보여준다.

```
┌────────────────────────────────────────────────────────────────────┐
│  RedCell   [세션1] [세션2*] [세션3]              + 새 세션    ⚙       │  ← 세션 탭
├─────────────────────────────────────────────┬──────────────────────┤
│  세션 헤더: host / port / provider / 목표  ▶실행│  대화 (오른쪽 패널)     │
│  ┌ 핵심 발견 · 실행 로그 · 핑거프린트 · 다음단계 ┐│  user: 웹 취약점 정찰   │
│                                               │  asst: 실행합니다…      │
│  [발견] (high) SQL Injection 신호             │  asst: 완료 — 발견 2건  │
│  [recon] http_probe: 200 nginx …             │                        │
│  (좌측 메인 패널 — 실시간 스트리밍)             │  [목표 입력…] [보내기]  │
└─────────────────────────────────────────────┴──────────────────────┘
```

- **오른쪽 대화 패널**에 목표를 입력하면 세션이 실행된다.
- **왼쪽 메인 패널**에 로그·발견·핑거프린트가 실시간으로 쌓이고,
  `다음 단계` 탭이 발견 내용에 맞춰 후속 작업을 제안한다.
- **상단바 🛡 버튼(인가 대상 관리)** — 인가 목록(ip-list)의 허용/제외 대상을 UI 에서
  확인·추가·제거한다. `~/.redcell/authorization.list`(또는 설정된 auth 경로)를 관리하며,
  `run`/`pyrun` 은 이 목록을 자동 우선 감지한다.
- **세션 헤더의 host 란**에 IP·도메인·URL(`http://host:port/path` 형식도 가능)을 넣고
  실행하면 **인가 목록에 자동 추가**된다. 이때 DNS 해석된 **실제 IP 도 함께 허용**한다 —
  사내망 호스트(예: `axhack.lge.com` → `10.x.x.x`)처럼 사설 대역으로 해석되는 대상도
  그대로 실행된다(ScopeGuard 의 연결시점 IP 검증 통과). 추가된 대상은 🛡 패널에서 바로
  제거할 수 있다.
- **tools 모드는 목표 지향 자율 루프로 실행된다** — prime-agent(pi) 처럼 횟수 제한 없이
  스스로 판단하며 돌아다닌다: 모델이 종료를 선언하면 한 번 추궁해 소득을 끌어내고,
  발견·수집 목록이 늘지 않으면 다음 단계로 넘어가고, 단계가 끝나도 남은 소득이 있으면
  단계 구분 없이 계속 추격한다. (무한 루프 방지용 비상 브레이크: 총 액션 150 · 20분.)
  엔드포인트·민감 경로·포트·헤더 목록을 빠짐없이 수집하며(크롤 24 페이지 · dir_enum 110+
  단어), 부작용성 프로브(race/upload/logic 등)까지 전부 돌리려면 **최대 공격(`--max`)**
  체크박스를 쓴다.
- **작업형 목표도 그대로 입력하면 된다** — 대화창에 "하반기 1차 합격자 목록 리스트 파일로
  뽑아줘" 처럼 작업을 지시하고 실행하면, 엔진이 자동으로 **목표 에이전트**로 전환해
  페이지를 읽고 링크를 따라가 파일을 내려받고 정리해 **실제 파일**로 만들어 낸다
  (산출물: `~/.redcell/results/<host>-…` — 실행 로그에 `[산출물] 경로` 가 표시된다).
  취약점 스캔 키워드가 없는 작업 지시는 자동 감지되며, 강제하려면 `--task`/`--scan`.
- 세션은 앱 데이터 폴더에 JSON 으로 저장되어 언제든 다시 열람 가능하다.

## 동작 원리

이 앱은 **표시/세션 관리 계층**이다. 공격력을 새로 만들지 않는다.
세션 실행 시 형제 프로젝트 [`../redcell`](../redcell) 의 CLI 를
스폰하고, stdout 의 NDJSON 이벤트를 파싱해 UI 로 스트리밍한다.
모든 액션은 redcell 의 `ScopeGuard`(authorization.yaml)를 그대로 통과하므로,
**인가된 대상만** 다뤄진다.

엔진 모드는 3가지로 정리돼 있다:

- **tools** — 고정 툴박스 자율 에이전트(`run --ndjson`, 기본값)
- **python(코드실행)** — absolute-agent(`pyrun`, 코드 작성→실행 반복)
- **prime-agent(pi)** — pi CLI 직접 실행(대화형, 같은 인가 목록 적용)

```
redcell-desktop (Tauri, Rust)
   └─ start_engagement(session) ─┐
                                 ├─ spawn: npx tsx src/cli.ts run --host … --ndjson
   ┌─ NDJSON 이벤트 스트림 ◀──────┘
   └─ engagement-event / engagement-status → 프론트엔드 패널 갱신
```

## 사전 요구
- Rust + Cargo, `cargo-tauri` (`cargo install tauri-cli`)
- Node.js (redcell CLI 실행용 — `npx tsx`)
- Linux: `webkit2gtk-4.1`, `libsoup-3.0` 등 Tauri v2 시스템 의존성
- 형제 폴더에 빌드 가능한 `redcell` (`cd ../redcell && npm install`)

## 실행

```bash
cd redcell-desktop/src-tauri
cargo tauri dev          # 개발 실행 (창이 뜸)
# 또는 백엔드만 컴파일 검증:
cargo build
```

앱을 처음 열면 `⚙ 설정`에서 **redcell 경로**를 확인/지정한다(기본은 자동 탐색).
`authorization.yaml` 경로를 지정하지 않으면 redcell 의 기본 탐색 규칙을 따른다.

## 세션 데이터 위치
- Linux: `~/.local/share/dev.redcell.desktop/sessions/*.json`
- macOS: `~/Library/Application Support/dev.redcell.desktop/sessions/*.json`

## 라이선스
MIT. 인가된 보안 테스트·교육 목적으로만 사용한다.
