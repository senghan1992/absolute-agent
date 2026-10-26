# redcell-tui — 터미널 코딩-에이전트형 셸

`redcell` (인자 없음) 또는 `redcell tui`로 실행되는 터미널 UI.
Muse Code / Claude Code / Codex 같은 대화형 터미널 도구 형태로,
데스크톱과 같은 엔진을 터미널에서 다룬다.

## 실행

```bash
cd redcell-tui && cargo build --release
cd ../redcell && npx tsx src/cli.ts        # → TUI 실행
# 또는 직접: ./target/release/redcell-tui
```

TUI 바이너리 탐색 순서: `REDCELL_TUI_BIN` → 형제 `redcell-tui/target/{release,debug}` → PATH.

## 기본 흐름

1. 시작 화면에서 `/setup`으로 대상 URL·세션을 설정 (`Ctrl+S` 저장)
2. `/sweep`으로 기본 점검 → 완료 후 리포트 표시 (`Esc`로 닫기)
3. 대화형 작업이 필요하면 `/providers`로 AI 연결 (API 키/OAuth, 선택 사항)
4. 입력창에서 추가 지시 전송 → 기존 risk 평가·동의 절차 → agent 실행

첫 실행과 새 세션은 모달을 강제로 열지 않습니다. 시작 안내와 `/` 메뉴에서
필요한 설정부터 고를 수 있으며, 연결 마법사도 언제든 건너뛸 수 있습니다.
대상이 없는 빈 입력창에서 `Enter`를 누르면 URL 빠른 시작 창을 엽니다.
이 창은 URL 입력 후 `Enter`로 즉시 기본 점검을 시작하므로, 대상만 저장하려면
`/setup`을 사용하세요.

## 화면 구성

- 상단: 세션·실행 상태 / 대상·AI 연결을 분리해 표시. 동의 상태는 우측에 고정
- 시작 안내: 대상 설정·AI 연결·도움말의 다음 동작을 제시
- 로그·대화: P0/agent/sys/채팅을 시각순 병합 (`PgUp/Dn` 스크롤)
- 상태줄: 실행 중 작업·오류/안내 메시지·현재 입력에 맞는 단축키
- 입력창: 한글 표시 폭 기준 자동 줄바꿈, 최대 5줄 표시·커서 따라 스크롤
- 명령어 메뉴: 입력창 **아래**에 별도 공간을 확보해 로그/입력을 덮지 않음

작은 터미널에서는 헤더·메뉴를 축소하고 팝업 여백을 줄입니다. 폼은 선택한
필드가 항상 보이도록 스크롤됩니다 (최소 24×8, 권장 80×24 이상).

## 키·명령 (F키 없음 — 전부 `/`)

`/`를 치면 입력창 아래에 명령어 메뉴가 뜹니다 (`↑↓` 선택 · `Tab` 완성 ·
`Enter` 실행 · `Esc` 닫기). 이름·별칭뿐 아니라 `/설정`, `/세션`, `/연결`처럼
한국어 설명으로도 검색할 수 있습니다. 선택 위치/전체 개수를 표시하며 목록
끝에서 처음으로 순환합니다. 검색 결과가 없으면 검색어 변경 안내를 표시합니다.

`/say`처럼 필수 인자가 있는 명령은 먼저 명령어만 완성한 뒤 인자를
받습니다. 인자 입력 중에는 메뉴를 접고, 알 수 없는 명령은 오타 제안과 함께
입력창에 남겨 바로 수정할 수 있게 합니다.

| 명령 | 동작 |
|---|---|
| `/sweep` | P0 스윕 실행 |
| `/stop` | 실행 중지 (agent kill + 스윕 즉시 중단) |
| `/setup` | 대상 설정 (URL·포트·provider·model·쿠키) |
| `/providers` | LLM 연결 (미설정 시 마법사 · 설정 후 목록·키·기본값) |
| `/danger` | 파괴적 동의 모달 / 철회 |
| `/findings` | 점검 결과 (심각도별 건수·상세 · 스윕 후 리포트는 자동 표시) |
| `/sessions` | 세션 관리 (전환·생성 `n` · 이름변경 `r` · 삭제 `d`, 확인 후) |
| `/say` · `/clear` | 메모 · 로그 지움 |
| `/help` · `/quit` | 도움말 · 종료 |
| Esc | 메뉴 닫기 · 입력 지움 · 입력이 비었으면 실행 중단 |
| Ctrl+P | 명령어 메뉴 열기 (다시 누르거나 Esc로 원래 초안 복원) |
| ↑ / ↓ | 이전 입력 탐색·초안 복원 (여러 줄에서는 줄 사이 이동 우선) |
| Alt+Enter | 줄바꿈 (지원 터미널에서는 Shift+Enter도 가능) |
| Ctrl+A / Ctrl+E | 입력 처음 / 끝으로 이동 |
| Ctrl+U / Ctrl+W | 커서 앞부분 / 앞 단어 삭제 |
| Ctrl+S | 대상·프로바이더 폼 즉시 저장 |
| Ctrl+C | 작업 중지 / 입력 취소 (앱은 유지) |
| Ctrl+Q | 종료 |
| PgUp / PgDn | 로그 스크롤 |

붙여넣기는 bracketed paste로 한 번에 입력하며, 여러 줄이나 `/` 명령을
붙여넣어도 자동 실행하지 않습니다. 폼의 API 키·URL·이름에도 붙여넣을 수
있고, 키는 계속 마스킹됩니다. 입력 이력은 최근 사용자 대화에서 복원하며,
슬래시 명령 이력은 실행 중 메모리에만 보관합니다.

실행 중 상태줄에 스피너 + 단계 + 진행 바 + 경과(`P0 병렬 프로브 ████░░ 49/229 · 3초 · Esc 중단`)가 표시된다.

## LLM 연결 (pi-agent 스타일)

`/providers`로 연결합니다 (미설정 시 마법사 자동 진입, `/login`·`/onboard`도 같은 화면):
환영 → 프로바이더 선택 → 인증 방식
(API 키 직접 입력 / OAuth 토큰 붙여넣기 / pi-agent 에서 가져오기) →
키 입력·검증 → 기본값 지정. 설정 후에는 `/providers`가 연결 목록을 엽니다.

- `/providers` 목록: `●` 사용가능 · `◐` 연결됐으나 모델/baseUrl 보완 필요 · `○` 미연결
- `/providers` 편집(`e`): `auth` 필드에서 `api_key`/`oauth` 전환 (anthropic OAuth는 Bearer 경로)
- pi-agent(`~/.pi/agent/auth.json`)에 같은 이름 자격증명이 있으면 가져오기 제공
- 키 검증은 best-effort (GET `…/models`, 실패해도 강제 저장 가능)

## 엔진 (데스크톱과 공유)

- `engine::probes` — P0 스윕 소스를 그대로 include (규칙 drift 없음)
- `engine::risk` — 지시문 가드레일 동일 규칙 (Safe/Caution/High/Critical)
- `scope` — 실행 전 인가 사전 검사 (TS ScopeGuard 와 동일 fail-closed 규칙)
- Agent 실행은 `redcell run` 자식 프로세스 스트리밍

### 스윕 → agent 연결 (정찰→공격 자동화)

P0 스윕 결과는 agent 실행에 자동 반영된다:

- `--target-map` — 발견된 경로·파라미터·ID 경로를 TS 인젝션 툴 인자로 주입
  (수동 재입력 없이 스윕이 찾은 표면 전체를 공격 툴이 스윕). 파일은
  `~/.local/share/redcell-tui/target-map.json` (0600) 에 보관
- goal 보강 — 상위 발견(critical/high/medium 최대 5건) 요약이 목표 텍스트에
  덧붙어 모델이 스윕 근거에서 출발
- 종료코드 안내 — agent 가 scope 차단(3)·도달 불가(4) 로 끝나면 다음 행동
  (`redcell auth add <host>` 등) 을 즉시 제안

## 안전·보안

- 스윕·agent 실행 전 `~/.redcell/authorization.list` 를 검사한다
  (deny 우선 · CIDR/와일드카드 · `until:` 유효기간 · `ports:` 제한).
  파일이 없으면 차단(fail-closed) — 정식 YAML 인가가 있으면 TS 판정에 위임
- 세션·프로바이더·target-map 파일은 temp(0600) 기록 후 원자적 치환 —
  쿠키·API 키·증거가 세계Readable 로 노출되는 창이 없음
- API 키 검증은 평문 http 엔드포인트로 전송하지 않는다 (localhost 게이트웨이 제외)
- agent 중지는 프로세스 그룹 전체를 종료해 npx/node/headless-chrome 고아를 남기지 않는다
- 중단된 이전 스윕의 늦은 결과는 세대 번호로 폐기 (신규 스윕 오염 방지)

## 저장소 (데스크톱과 독립)

- 세션: `~/.local/share/redcell-tui/sessions/*.json` (`XDG_DATA_HOME` 준수)
- LLM: redcell 본체와 공유 — `~/.redcell/config.json`(기본값),
  `~/.redcell/providers.json`(키·baseUrl·모델, `REDCELL_HOME` 준수)

## 검증

```bash
cargo test -- --test-threads=1   # 단위·UI 회귀·기존 엔진 스위트
cargo build --release
python3 tests/smoke_tui.py --output /tmp/redcell-tui-screens
```

실제 실행 검증은 `tmux`가 필요합니다. 임시 HOME·설정·세션과 전용 tmux 소켓을
사용해 메뉴 검색, 인자 편집, 이력/초안 복원, 붙여넣기, 창 크기 변경,
폼 저장·마법사 건너뛰기를 확인합니다. 외부 대상 진단이나 AI 호출은 하지
않으며, 화면 캡처를 `--output` 디렉터리에 저장합니다.
