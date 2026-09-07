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
  바로 추가·제거한다. `~/.redcell/authorization.list`(또는 설정된 auth 경로)를 관리하며,
  `run`/`pyrun` 은 이 목록을 자동 우선 감지한다. 추가한 IP 는 즉시 인가된 대상이 된다.
- 세션은 앱 데이터 폴더에 JSON 으로 저장되어 언제든 다시 열람 가능하다.

## 동작 원리

이 앱은 **표시/세션 관리 계층**이다. 공격력을 새로 만들지 않는다.
세션 실행 시 형제 프로젝트 [`../redcell`](../redcell) 의 CLI 를
`run --ndjson` 으로 스폰하고, stdout 의 NDJSON 이벤트를 파싱해 UI 로 스트리밍한다.
모든 액션은 redcell 의 `ScopeGuard`(authorization.yaml)를 그대로 통과하므로,
**인가된 대상만** 다뤄진다.

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
