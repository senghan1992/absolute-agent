# REDFORGE — 터미널 기반 자율 보안점검 에이전트

`redcell-desktop` 과 별개인, **CLI(터미널) 에서 동작하는** 최강의 점검 도구.
prime-agent 처럼 **파이썬 인터프리터를 직접 붙여서** 코드를 하나씩 직접 실행하면서
공격하고, 동시에 **고속 병렬 스톰 엔진**으로 초당 수백 번 변이를 시도한다.

목적은 단순히 "뚫는 것" 이 아니라, **발견된 약점을 운영자가 고칠 수 있게 하는 것**이다.
모든 발견에는 근거·재현 절차·보완(수정) 포인트가 붙는다.

---

## 1. 구성 (4 계층)

```
┌─────────────────────────────────────────────────────────────────┐
│ TUI (ratatui)  콘솔 · 커널 · 스톰 · 발견 · 리포트 탭             │
├─────────────────────────────────────────────────────────────────┤
│ AGENT  LLM 자율 루프 (Anthropic / OpenAI 호환)                  │
│        도구: python · storm · recon · finding · note · finish   │
├─────────────────────────────────────────────────────────────────┤
│ KERNEL  파이썬 영속 인터프리터 (JSON Lines 프로토콜)             │
│         forge 툴킷 · 네임스페이스 유지 · SIGALRM 타임아웃        │
│         ★ 소켓 후킹으로 인가 밖 연결 차단 (fail-closed)         │
├─────────────────────────────────────────────────────────────────┤
│ PROBES  IDOR · 가격/수량 변조 (의미론적 상태 검증)          │
│ STORM   고속 병렬 퍼징 · 기준선 대비 응답 분류 · 이상 탐지       │
│         300~400 req/s (로컬 실측) · 인가 RPS 상한 강제          │
└─────────────────────────────────────────────────────────────────┘
        ▲
        └── SCOPE  인가 게이트: ~/.redcell/authorization.yaml
            (없으면 차단 · deny 우선 · 기간/포트/RPS 제한)
```

| 모듈 | 파일 | 역할 |
| --- | --- | --- |
| 인가 게이트 | `src/scope.rs`, `src/yaml.rs` | 모든 트래픽의 단일 관문. YAML 서브셋 파서 포함 |
| 파이썬 커널 | `src/kernel.rs`, `py/forge_kernel.py` | 영속 인터프리터 브리지 + 샌드박스 툴킷 |
| 스톰 엔진 | `src/storm.rs`, `src/signals.rs` | 고속 퍼징 · 응답 서명 · 이상/신호 탐지 |
| 정찰 | `src/recon.rs` | 링크·폼·API 경로 추출, 기술 스택 지문 |
| 논리 프로브 | `src/probes/` | IDOR·가격변조 탐지 (스톰과 다른 축) |
| 자율 에이전트 | `src/agent.rs`, `src/providers.rs` | 도구 호출 루프, 프로바이더 관리 |
| 리포트 | `src/report.rs` | 심각도·근거·재현·보완 포인트 |
| 기억 | `src/memory.rs` | 지문별 성공 전술 축적 (자기발전) |
| TUI | `src/tui.rs` | 대시보드 · 커널 편집기 · 스톰 게이지 |

---

## 2. 빌드 · 실행

```bash
cd redcell-tui/forge
cargo build --release          # ./target/release/forge

./target/release/forge                       # TUI (기본)
./target/release/forge doctor                # 환경 점검
./target/release/forge scope --host 127.0.0.1 --port 8099
./target/release/forge kernel --code "print(1+1)"
./target/release/forge storm --target "http://127.0.0.1:8099/api/item?id=1" --max 200
```

### 비대화형 사용

```bash
# 1) 환경 확인 (파이썬·인가·프로바이더·커널)
forge doctor

# 2) 인가 판정 (fail-closed 확인)
forge scope --host 127.0.0.1 --port 8099     # ✔ 인가됨
forge scope --host example.com               # ✖ 인가 대상이 아닙니다 (exit 3)

# 3) 파이썬 커널 1회 실행 (영속 네임스페이스)
forge kernel --scope ~/.redcell/authorization.yaml --base http://127.0.0.1:8099 \
  --code "r = forge.get('/api/user?id=2'); print(r['status'], r['body'][:200])"

# 4) 스톰 실행 + JSON/Markdown 리포트
forge storm --scope ~/.redcell/authorization.yaml \
  --target "http://127.0.0.1:8099/api/item?id=1" --max 200 --concurrency 32 --json

# 5) IDOR 탐지 (id 를 바꿔가며 다른 주체의 리소스 접근 확인)
forge idor --scope ~/.redcell/authorization.yaml \
  --target "http://127.0.0.1:8099/api/user?id=1" --param id --spread 3

# 6) 가격/수량 변조 탐지 (0·음수·대값 주입 후 합계 반응 확인)
forge tamper --scope ~/.redcell/authorization.yaml \
  --target "http://127.0.0.1:8099/checkout?price=10&qty=2" --param price --method GET
```

---

## 3. 인가 (Authorization) — 없으면 아무것도 못 한다

`~/.redcell/authorization.yaml` (또는 `--scope` 경로). redcell 의 기존 규약과 같은 형태다.

```yaml
engagement:
  name: "my-lab"
  authorized_from: "2026-01-01"
  authorized_until: "2026-12-31"
scope:
  allow:
    - host: "127.0.0.1"
    - cidr: "10.13.37.0/24"
    - domain: "*.vulnlab.local"
  deny:
    - host: "10.13.37.1"          # deny 가 allow 를 이긴다
ports:
  allow_tcp: [80, 443, 8099]
limits:
  max_requests_per_second: 200   # 스톰 전체에 강제
```

강제 규칙:

1. **파일 부재 → 전 기능 차단** (fail-closed)
2. `deny` > `allow`
3. `authorized_until` 지난 즉시 차단 / `authorized_from` 전 차단
4. `ports.allow_tcp` 에 없는 포트 차단
5. `max_requests_per_second` 을 스톰 엔진이 그대로 적용

게이트는 **두 곳**에서 동작한다:
- Rust 스톰 엔진 — 요청 전 검사
- 파이썬 커널 — `socket.getaddrinfo` / `socket.connect` 후킹.
  LLM 이 `urllib`/`requests`/`httpx` 무엇을 쓰든 인가 밖 호스트로는 **소켓 레벨에서** 막힌다.

```
$ forge kernel --code "import urllib.request; urllib.request.urlopen('http://example.com')"
blocked -> ScopeError example.com 는 인가 대상이 아닙니다.
```

---

## 4. TUI

| 탭 | 내용 |
| --- | --- |
| 콘솔 | 명령 출력·에이전트 대화·도구 호출 로그 (색 구분) |
| 커널 | 파이썬 코드 편집기 + 실행 결과. **타이핑 = 코드 편집**, `Ctrl+R` 또는 `Ctrl+Enter` = 실행 |
| 스톰 | 진행 게이지(요청/총, req/s) + 이상 응답 목록 |
| 발견 | 기록된 취약점 (심각도별 색) |
| 리포트 | Markdown 리포트 미리보기 · `/report` 로 저장 |

### 키

| 키 | 동작 |
| --- | --- |
| `Ctrl+P` | 명령 팔레트 (한글 검색 가능) |
| `Tab` | 탭 전환 |
| `Ctrl+R` / `Ctrl+Enter` | 커널 코드 실행 |
| `Ctrl+C` | 작업 중지 (작업 없으면 종료) |
| `Ctrl+Q` | 종료 |
| `Esc` | 입력 지움 / 팔레트 닫기 |

### 명령

| 명령 | 동작 |
| --- | --- |
| `/target <url>` | 대상 설정 |
| `/scope` | 인가 상태 표시 |
| `/providers` | LLM 연결 상태 |
| `/recon` | 정찰 — 엔드포인트·지문 추출 |
| `/storm` | 정찰 후 스톕 실행 (진행 게이지 실시간) |
| `/idor <param>` | IDOR 탐지 (`/idor id`) |
| `/tamper <param>` | 가격/수량 변조 탐지 (`/tamper price`) |
| `/autopilot <목표>` | **자율 점검 실행** (LLM 이 커널·스톰을 직접 구동) |
| `/findings` `/report` | 발견 보기 · 리포트 생성/저장 |
| `/stop` `/clear` `/help` `/quit` | 기타 |

입력창에 일반 문장을 넣으면 **그 목표(goal)** 로 자율 에이전트가 실행된다.

---

## 5. 파이썬 커널 (prime-agent 스타일)

- 커널 스크립트는 `include_str!` 로 **바이너리에 내장** → 실행 시 임시 파일로 기록되어 실행.
- 네임스페이스가 유지되므로 변수를 누적하며 여러 단계를 이어서 실행한다.
- 마지막 표현식의 값이 결과로 반환되고, `print()` 출력이 그대로 캡처된다.
- `SIGALRM` 기반 타임아웃 — 무한 루프도 끊긴다.
- `subprocess`/`os.system`/파일쓰기 차단, 쓰기는 실행 디렉터리 안에서만 가능.

커널 안에서 쓰는 툴킷:

```python
forge.set_base("http://127.0.0.1:8099")
r = forge.get("/api/user?id=2")            # 스코프 검사 후 요청
print(r["status"], r["body"][:200])
forge.analyze(r)["signals"]                # 오류·스택·유출 신호
forge.diff(r1, r2)                         # 응답 차이
forge.mutate(["1"])                        # 경계값·인코딩 변이 생성
forge.burst("GET", "/api/item?id=1", ["1","2'","3 OR 1=1"])   # 병렬
forge.note("관찰") / forge.finding("제목", severity="high")
```

---

## 6. 스톰 엔진 — 정확도가 핵심

단순히 빠르게 때리는 것은 의미가 없다. **오탐 없는 신호**를 내야 한다.

1. **기준선 수집** — 원본 값으로 N회 요청해 기준 서명(status + 정규화 해시)을 만든다.
2. **변이 주입** — 페이로드 코퍼스(약 100종: 경계값·SQLi·XSS·SSTI·경로이탈·CMDi·프로토콜)를 병렬로 주입.
3. **정규화 비교** — 응답에 반사된 페이로드와 원래 값을 **제거 집합**으로 지운 뒤 구조만 비교.
   (숫자·UUID·타임스탬프 정규화까지叠加 → 동적 콘텐츠 오탐 제거)
4. **신호 탐지** — SQL 오류·스택트레이스·디버그 노출·시크릿·내부 IP·XSS/CMDi 마커 등을 분류하고
   심각도별 권고 문구를 붙인다.
5. **이상 집계** — 같은 이상은 묶어 "반복 N회" 로 강등/확정.

실측(로컬 랩): **385 req/s**, 150건 중 실제 SQLi 페이로드 5건 + XSS 반사 1건만 탐지.
---

## 6-1. 논리 프로브 — IDOR / 가격 변조

스톰은 '값을 바꿔 응답이 달라지는가'를 본다. 프로브는 그와 다른 축 —
**의미론적 상태** — 를 다룬다.

### IDOR (`src/probes/idor.rs`)

1. 기준선 요청 → 응답에서 **식별자 집합** 추출 (메일·이름·계정 등 PII 필드)
2. 기준값 주변(±spread)과 존재하지 않는 값으로 요청
3. **식별자 집합이 실제로 달라졌는지** 로 판정
   - 달라짐 + 기준선에 PII 있음 → `Confirmed` (high) — 남의 리소스 노출 확정
   - 달라짐 + PII 판별 불가 → `Suspected` (medium) — 수동 확인 필요
   - 내용은 같고 일부 값만 404 → `Enumerable` (low) — 존재 경계 노출
   - 전부 403/404 → `None` — 소유자 검증이 동작함

단순히 본문이 id 를 반사하는 공개 카탈로그는 **취약점으로 잡지 않는다**
(식별자가 안 바뀌면 `Confirmed` 가 아니다). 값을 아예 무시하는 엔드포인트는
존재 경계도 없으므로 열거 신호조차 만들지 않는다.

### 가격/수량 변조 (`src/probes/tamper.rs`)

1. 기준선 요청 → 응답의 금액 필드 추출 (`total`, `grand_total`, `price` 등, JSON + HTML)
2. `0 / -1 / 0.01 / 1 / 999999999 / 2147483648 / -2147483649` 등 주입
3. 합계 반응을 두 모델로 판정
   - **곱셈형**: `합계 = 단가 × 수량` → 기준합계 × (변조/원래)
   - **가산형**: `합계 = 원래합계 + (변조 − 원래)`
   - 관측 합계가 둘 중 하나를 따라가면 → `FollowedTamper` (변조값 ≤ 0 이면 critical)
   - 단가 필드가 변조값을 그대로 되풀이하면 → `Reflected` (high)
   - 합계가 기준선과 동일하면 → `Recalculated` (안전)
   - 4xx/5xx 면 → `Rejected` (안전)

JSON 본문을 보낼 때 **숫자 타입을 보존**한다(숫자 필드는 숫자로) — 서버가
문자열/숫자를 구분하는 경우 거짓 양성을 만들지 않기 위해.

두 프로브 모두 인가 게이트·RPS 상한을 지키고, 결과는 `report::Finding` 으로
변환되어 리포트에 근거·재현 절차·보완 포인트와 함께 담긴다.


---

## 7. 자율 에이전트

LLM(Anthropic Messages API 또는 OpenAI 호환 Chat Completions) 이 아래 도구를 호출하며
스스로 점검 루프를 돌린다.

| 도구 | 입력 | 동작 |
| --- | --- | --- |
| `python` | `code` | 커널에서 코드 실행 (결과가 관찰로 돌아온다) |
| `storm` | `url, params, payloads` | 고속 변이 스윕 → 이상 목록 |
| `idor` | `url, param` | IDOR 탐지 → 다른 주체 리소스 접근 확인 |
| `tamper` | `url, param, values` | 가격/수량 변조 탐지 → 서버 신뢰도 확인 |
| `recon` | `url` | 표면·지문 추출 |
| `finding` | `title, severity, ...` | 발견 기록 (리포트에 반영) |
| `note` | `text` | 중간 관찰 (다음 턴 컨텍스트에 포함) |
| `finish` | `summary` | 종료 |

- 시스템 프롬프트에 방법론(정찰→열거→익스플로잇→증거→보고), 최소 영향 원칙,
  **파괴적/DoS 금지**, 근거 없는 추측 금지가 포함된다.
- 성공한 전술은 `~/.local/share/forge/memory.json` 에 지문별로 축적되고,
  다음 라운드 프롬프트에 "먼저 재사용"으로 주입된다 (자기발전).

프로바이더는 redcell 저장소를 공유한다:
`~/.redcell/config.json` (기본 프로바이더·모델) + `~/.redcell/providers.json` (키·baseUrl).
`ANTHROPIC_API_KEY` 등 환경변수도 `envKeys` 로 지정하면 사용된다.

---

## 8. 리포트 — 보완 포인트를 남기는 것이 목적

`forge/README` 의 `/report` 또는 CLI 실행 후 `~/.local/share/forge/runs/reports/` 에 저장된다.

각 발견에 붙는 것:

- 심각도 (critical/high/medium/low)
- 근거 (실제 응답 발췌)
- **재현 절차**
- **보완(수정) 포인트** — 신호별로 구체적 권고
  (예: SQL 오류 → 프리페어드 스테이트먼트 + 오류 메시지 분리, 스택 트레이스 → 디버그 비활성화 + 일반화 응답)

---

## 9. 검증

```bash
cd redcell-tui/forge
cargo test -- --test-threads=1        # 단위 48 + 통합 9
python3 tests/smoke_tui.py --output /tmp/forge-screens
```

- 단위(48): YAML 파서·인가 판정·RPS 제한·응답 정규화·신호 탐지·기억·리포트·커널 프로토콜·
  **IDOR 판정 6종·변조 판정 5종·금액 필드 추출·파라미터 교체(타입 보존)**
- 통합(probes, 6): 취약/안전 엔드포인트가 함께 있는 모의 서버로
  '취약한 것만 잡히고 안전한 것은 잡히지 않는지' 검증
- 통합(agent, 3): **모의 모델 서버**로 python→storm→finding→finish 루프와
  **에이전트가 idor 도구를 직접 호출하는 경로**까지 검증
- 스모크: tmux 로 실제 화면을 띄워 헤더·팔레트·명령·스톰 게이지·탭 전환을 검증

---

## 10. 확장

- 새 스캔 모듈: `src/storm.rs` 의 `send_with_client` 에 분기 추가
- 새 도구: `src/agent.rs` 의 `tool_specs()` + `run_tool()` 에 추가
- 새 신호: `src/signals.rs` 의 `PATTERNS` + `remediation()` 에 추가
- 커널 기능: `py/forge_kernel.py` 의 `Toolkit` 클래스에 메서드 추가
  (바이너리에 내嵌되어 함께 배포된다)
