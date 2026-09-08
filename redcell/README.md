# RedCell 🛡️

**자기발전형(self-improving) 화이트해커 훈련 에이전트** — [prime-agent](https://github.com/PrimeIntellect-ai/prime-agent) 위에 얹는 확장.

RedCell 는 "잘 뚫는 법"을 **합법적인 인가 환경**(CTF, 취약점 실습랩, 본인 소유 VM)에서
학습하고, 성공한 공략 전술을 스스로 축적해 다음엔 더 빠르게 뚫도록 발전한다.
prime-agent 의 자기발전 패러다임(Continual Harness)을 보안 도메인에 이식한 것이다.

> ⚠️ **RedCell 는 인가 없이는 동작하지 않는다.** `authorization.yaml`(또는 간단 IP 목록
> `~/.redcell/authorization.list` — `redcell auth add`) 에 명시적으로 허용된 대상만 다루며,
> prime-agent 의 `tool_call` 훅에서 scope 밖 요청은 자동 차단된다.
> 권한 없는 실제 서비스를 대상으로 사용하는 것은 불법이며, 이 도구의 목적이 아니다.
> 자세한 내용은 [`labs/README.md`](labs/README.md) 참조.

## 데스크톱 패널 = prime-agent 셸

`redcell-desktop` 의 모드 선택에서 `prime(pi)` 를 고르면 패널이 곧바로 prime-agent(pi) 를
실행한다(`pi -e <redcell/prime-agent/index.ts> --mode json --session-id rc-… -p "<지시문>"`) —
지시문에 인가된 대상 URL 을 붙여 보내고, pi 의 bash/웹 툴이 자유롭게 조사한 결과를
그대로 스트리밍한다. RedCell 확장은 **`-e` 로 명시 로드**되므로 이 패널 세션에서만
모든 tool_call 을 인가 목록으로 게이팅한다 — 전역 설치가 없어 다른 곳의 pi 에는
전혀 영향이 없다.

## RLM 모드 (`rlm`) — 재귀 언어 모델(Recursive Language Model) 방식 에이전트

[RLM(arXiv 2512.24601)](https://arxiv.org/abs/2512.24601) 패러다임을 엔진 안에 이식한 모드다
(prime-agent 는 이 RLM 위에 지어진 harness — 패널의 `rlm(재귀 REPL)` 모드가 이것):

1. **영구 Python REPL** — JSON 툴콜 대신 모델이 코드를 쓰고, 같은 파이썬 프로세스 globals 에
   계속 실행된다. 변수와 `ctx`(prompt-as-a-variable)가 스텝을 넘어 유지된다.
2. **재귀 서브콜** — 파이썬에서 `rlm('하위 작업', 8)` 호출 시 하위 에이전트가 실행되고 **값으로** 답이
   돌아온다(프로그래매틱 subagent calling). 깊이 상한(기본 3)·공유 요청 예산(기본 240).
3. **자기발전 기억** — `rc.memo('키','내용')` 로 배운 전략을 `~/.redcell/memories/<호스트>.md` 에
   남기고, 다음 실행 시작 시 `ctx.memories`+프롬프트로 재주입된다(continual harness).
4. **FINAL: 계약** — `print('FINAL: ...')` 로 최종 답을 내면 그 텍스트가 이 에이전트(와 재귀 값)의 답이 된다.

```bash
redcell rlm --host 127.0.0.1 --port 8080 \
  --goal "관리자 세션 탈취 경로를 찾아라" --provider anthropic
# --depth 3  재귀 깊이 상한  ·  --budget 240  전체 요청 예산  ·  --mem <파일>  기억 파일
```

안전은 엔진과 동일하다: 모든 대상 통신은 ReplSession 브로커(ScopeGuard·공유 예산·RPS·
비파괴)를 통과하고, 재귀 하위 에이전트도 같은 게이트를 공유한다.

### 라이브 데스크톱 패널 (`--panel`) — 학습 과정을 눈으로

```bash
redcell run --host 127.0.0.1 --port 8080 --panel        # run 도 지원
redcell rlm  --host 127.0.0.1 --port 8080 --panel        # rlm 권장(recall/reward/verify)
# --panel-port <n>  포트 지정(기본 5173, 0=임의)
```

`--panel` 을 주면 CLI 가 로컬 HTTP 패널(`http://127.0.0.1:<port>`)을 띄운다. 브라우저에서
이벤트 타임라인(recall/action/reward/distilled/reflect/verify/finding)과 통계 카드(누적 보상
스파크라인 포함)가 실시간으로 갱신된다. 외부 CDN/네트워크를 전혀 쓰지 않는 셀프컨테인드
HTML + SSE 라서 오프라인에서도 동작하고, CLI 종료와 함께 패널도 닫힌다.

## 무엇이 "자기발전"인가 — 탐색 엔진이 핵심

RedCell 의 심장은 **스스로 여러 방법을 시도하고, 결과로 배우고, 발전하는 탐색 엔진**이다.
정답 경로를 모르는 상태에서 이것저것 시도하다가, 통하는 전략을 학습해 다음엔 더 빨리 해결한다.

```
관측 → 전략 생성/선택(bandit) → 실행 → 보상 → 학습(값 갱신) → 막히면 반성/백트래킹 → 성공 시 distill
```

세 축으로 발전한다:
1. **에피소드 내 탐색** — 같은 상태에서 실패한 방법은 tabu 처리하고 다른 방법을 시도.
2. **에피소드 간 학습** — `ContextualBandit`(UCB1/Thompson)이 "상황별로 뭐가 통했는지"를 누적 →
   반복할수록 정답 경로로 수렴.
3. **반성(reflect)** — 막히면 모델이 새 전략을 생성해 **행동공간 자체를 확장**.

### 직접 보기 (숨겨진 공략 체인을 스스로 발견)

```bash
npm run explore            # 밴딧 기반: 반복하며 최적 전략 학습(학습곡선 출력)
npm run mcts               # MCTS 트리검색: 깊은 미로에서 목표 경로 탐색
```
```
[explore] 초반 10회 평균 스텝: 13.6  →  후반 10회 평균 스텝: 6.7 (최적 4)
[mcts]    리프 243개(무작위 0.41%) 미로를 800 반복만에 정확한 경로로 해결
```

**두 가지 탐색 전략**을 상황에 맞게 쓴다:
- **밴딧(`Explorer`)** — "한 상태에서 최적 액션"을 반복 경험으로 학습(에피소드 간 발전).
- **MCTS(`Mcts`)** — 상태가 전이하고 막다른 길이 있는 환경에서 "여러 수 앞 최적 경로"를 트리검색.
  잘못된 가지의 가치가 낮아져 자연스럽게 백트래킹한다.

같은 `Explorer` 가 시뮬레이션(`MockWebLab`)과 실대상(`RealTargetEnv`, 운영자 인가)에서 동일하게 돈다.
실전에서는 이 학습이 prime-agent 의 harness 메모리(`/refine`)에도 축적되어 이후 세션 프롬프트에 재주입된다.

## CLI (prime-agent 스타일)

`redcell` 은 서브커맨드로 동작한다. 로컬에서는 `npx tsx src/cli.ts <cmd>`,
설치 후에는 `redcell <cmd>` (`npm link` 또는 `bin/redcell`).

```bash
redcell providers          # 연결 가능한 프로바이더 + 자격증명 상태(✅/—)
redcell models             # 프로바이더별 기본 모델
redcell scope              # 인가(scope) 상태
redcell run --host 127.0.0.1 --port 8080 --goal "웹 취약점 정찰"
redcell pyrun --host 127.0.0.1 --port 8080 --goal "id 파라미터 취약점"  # absolute-agent(코드 작성→실행 반복)
redcell config set defaultProvider anthropic
redcell explore  |  redcell mcts     # 자기발전/트리검색 데모
redcell help
```

### 사용자 정의 프로바이더 (custom providers)

자체(vLLM·Ollama·LM Studio 등 OpenAI 호환 서버, 또는 Anthropic 호환 게이트웨이) 엔드포인트를
코드 수정 없이 등록하고 `--provider <이름>` 으로 바로 연결한다. 기존 환경변수 방식의 익명
`custom` 항목(`REDCELL_OPENAI_BASE_URL`/`REDCELL_MODEL`/`REDCELL_OPENAI_API_KEY`)은 그대로 유지된다.

```bash
# 등록 — 이름은 영문/숫자/._- 1~40자
redcell providers add my-llm   --base-url http://127.0.0.1:8000/v1 \          # OpenAI 호환(기본) / anthropic 호환은 --kind anthropic
  --api-key-env MY_LLM_KEY \                     # 키를 담은 env 변수명(여러 개는 콤마). env 를 못 찾으면 --api-key 리터럴 사용
  --default-model llama-3.3-70b \                # --model 미지정 시 기본값
  --header "X-Tag: redcell" \                    # 추가 헤더(여러 개는 콤마)
  --note "로컬 vLLM"

redcell providers            # 목록 — 사용자 정의 항목도 ✅/— 자격증명 상태 표시
redcell providers rm my-llm  # 삭제(빌트인은 삭제 불가)
redcell providers add my-llm --base-url ...       # 같은 이름 재등록 = 교체

# 연결 — 빌트인과 동일한 경로
redcell run --host 127.0.0.1 --port 8080 --provider my-llm
redcell config set defaultProvider my-llm        # 기본 프로바이더로 지정
```

저장 위치는 `~/.redcell/providers.json`(`REDCELL_HOME` 변경 시 함께 이동, 소유자 전용 600 권한).
빌트인과 같은 이름으로 등록하면 사용자 정의 정의가 우선한다. `--kind anthropic` 프로바이더는
`baseUrl`은 선택이며, `--api-key-env`/`--api-key` 인증을 그대로 쓴다(oauth 토큰은 미지원).

### 간단 인가: 내가 입력한 IP = 인가 (ip-list)

정식 Rules of Engagement(YAML) 작성을 부담스러워할 때, **IP 목록 한 장**으로 시작한다.
사람(운영자)이 직접 목록을 관리하고, 목록에 있는 대상만 인가된다:

```bash
redcell auth add 10.13.37.5            # 허용 IP 추가 (CIDR·도메인도 가능)
redcell auth add 10.13.37.0/24
redcell auth add 10.13.37.1 --deny     # 제외 — deny 가 항상 allow 를 이긴다
redcell auth rm 10.13.37.5             # 제거
redcell auth list                      # 현재 목록 확인
```

기본 파일은 `~/.redcell/authorization.list`(`--auth <파일>` 로 변경)이며, `run`/`pyrun`/`scope`는
`authorization.yaml`보다 **ip-list 를 우선** 감지한다. 직접 편집도 가능(한 줄에 하나):

```
# 주석
10.13.37.5
10.13.37.0/24
*.vulnlab.local          # 와일드카드 도메인
!10.13.37.1              # 제외 (allow 에 있어도 최우선 차단)
until: 2027-12-31        # (선택) 유효기간 — 없으면 실행 시점 +365일
ports: 80,443,8080       # (선택) 허용 포트 — 없으면 전체
```

안전 기본값은 그대로 유지된다: 파괴/DoS 차단, RPS 기본 제한, 내부대역 측면이동 차단,
DNS rebinding 차단, 감사 추적, deny>allow. 정식 게이트(waiver·서명·직무분리)가 필요할 때만
기존 `authorization.yaml`을 쓰면 된다.

### absolute-agent 모드 (`pyrun`) — 에이전트가 파이썬을 스스로 써서 공략 (prime-agent RLM)

고정 툴박스에서 고르는 대신, **모델이 파이썬 코드를 직접 작성 → 실행 → 결과 관찰 →
다른 방법 모색**을 반복하며 대상을 공략한다(발산·백트래킹). 한 방법에 갇히지 않고
관점을 바꿔 새 코드를 쓴다. 이것이 이 프로젝트의 근본 — 해킹에 특화된 나만의 에이전트다.

임의 코드 실행이지만 안전은 **구조적으로(safe-by-construction)** 보장한다:

- **모든 대상 HTTP 는 로컬 브로커(127.0.0.1, 1회용 토큰) 경유** → 요청 직전
  `ScopeGuard.check` 재확인(우회 불가) + 기존 `httpRequest`/`RateLimiter`(RPS) 재사용.
- **정적 위험 스캔**: 실행 전 파괴적/우회 패턴(rmtree·os.remove·raw socket·requests·
  urllib·subprocess·ctypes·절대경로 쓰기 등)을 차단 — 걸리면 코드를 아예 실행하지 않는다.
- **in-process AST 허용목록 샌드박스**: 정규식이 놓치는 난독화·인트로스펙션 탈출(동적 import·
  문자열 경유 속성접근·프레임 워킹 등)을 실행 시점에 차단.
- **OS 레벨 격리(fail-closed)**: pyrun 코드는 **LLM 이 작성**하고 그 LLM 은 **대상 응답을
  컨텍스트로 삼는다**(프롬프트 인젝션 경로) → 신뢰불가 코드로 취급한다. AST 샌드박스가 탈출돼도
  호스트가 털리지 않도록 **동작이 검증된 OS 격리 백엔드(bubblewrap)** 안에서만 실행한다.
  백엔드가 없으면 신뢰불가(라이브 모델) 코드 실행을 **거부**한다(`--isolation required`, 기본값).
  `--isolation best-effort` 는 경고 후 샌드박스만으로, `off` 는 신뢰되는 오프라인 코드(MockCoder)에
  한해 강제하지 않는다.
- **연결 시점 IP 검증(DNS rebinding/SSRF 차단)**: 호스트명은 해석된 IP 를 `ScopeGuard.checkResolvedIp`
  로 검증한 뒤 그 IP 로 직접 연결(TOCTOU 제거). 내부/사설/링크로컬(메타데이터 169.254.169.254 등)·
  재바인딩은 차단. 리다이렉트는 홉마다 scope 재확인 + 교차출처면 자격증명 제거.
- **격리**: 임시 작업 디렉터리 + 타임아웃(SIGKILL) + 출력 상한 + 요청 예산(폭주 방지).
- **accidental egress fail-closed**: HTTP(S)_PROXY 를 죽은 주소로, `no_proxy` 는 루프백만 →
  실수로 stdlib 로 외부에 나가면 브로커가 아니라 사망한다.

파이썬 쪽은 주입된 `rc` 헬퍼로만 통신한다: `rc.get/post/http(...) → r.status/.headers/.text`,
`rc.tcp(host, port, payload=None) → bytes` 로 인가 대상의 원시 TCP 조사(banner/맞춤 프로토콜)를 할 수 있고
(브로커가 scope 밖 host:port 는 ScopeError 로 차단), 취약 신호는 `rc.finding(title, severity, evidence=, impact=)`,
관찰은 `rc.log(...)`. 문법 오류는 `[구문 오류]` 로, 정책 위반은 `[안전차단]` 으로 구분해 보여주며
에이전트가 스스로 수정·재시도한다.
산출물은 기존 `EngagementLog` 라 리포트·시각 상황판·데스크톱 패널에 그대로 흐른다.
`--provider mock`(오프라인 `MockCoder`) 로 모델 없이도 루프를 재현할 수 있다.

### 다중 프로바이더 (pi agent 참고)

`ModelAdapter` 하나 뒤에 여러 프로바이더를 꽂는다. base URL / env 키 / 기본 모델은
prime-agent(`packages/ai`)의 값을 참고했다. 자격증명(env)이 감지되면 자동 선택된다.

| provider | env | 기본 모델 | kind |
| --- | --- | --- | --- |
| `anthropic` | `ANTHROPIC_API_KEY` / `ANTHROPIC_OAUTH_TOKEN` | `claude-opus-5` | 공식 SDK |
| `openai` | `OPENAI_API_KEY` | `gpt-5.4` | openai-compat |
| `openrouter` | `OPENROUTER_API_KEY` | `moonshotai/kimi-k2.6` | openai-compat |
| `prime-inference` | `PRIME_API_KEY` | `z-ai/glm-5.2` | openai-compat |
| `groq` `cerebras` `xai` `deepseek` `mistral` `moonshotai` `zai` | 각 `*_API_KEY` | (pi 기본값) | openai-compat |
| `ollama` | (불필요) | `--model` 필요 | 로컬 |
| `custom` | `REDCELL_OPENAI_API_KEY` | `REDCELL_OPENAI_BASE_URL`+`REDCELL_MODEL` | 임의 OpenAI 호환 |

```bash
# 자동 선택(자격증명 감지)
export ANTHROPIC_API_KEY=sk-ant-...
redcell run --host 127.0.0.1 --port 8080

# 명시적 선택
redcell run --host 10.13.37.5 --provider openrouter --model moonshotai/kimi-k2.6

# 오프라인 검증(모델 호출 없음)
redcell run --host 127.0.0.1 --port 8080 --provider mock
```

**모델 해석 우선순위**: `--provider/--model` → `~/.redcell/config.json` 기본값 → 자격증명 있는 첫 프로바이더.
새 프로바이더는 `ProviderRegistry.register(spec)` 로 런타임 추가 가능(pi 의 `registerProvider` 취지).

## 핵심 구성요소

| 모듈 | 역할 |
| --- | --- |
| `src/explore/bandit.ts` | **ContextualBandit** — 상황별 탐색/활용 학습(UCB1 · Thompson) |
| `src/explore/explorer.ts` | **Explorer** — 시도·학습·반성·백트래킹·distill 하는 자기발전 루프 |
| `src/explore/mcts.ts` | **Mcts** — UCT 트리검색(전이·막다른 길 환경에서 최적 경로) |
| `src/explore/env.ts` `graph-lab.ts` | **LabEnv** + `MockWebLab`(체인) / `GraphLab`(전이 그래프·랜덤미로) |
| `src/explore/real-env.ts` | **RealTargetEnv** — 실대상을 LabEnv 로 감싸 같은 Explorer 로 구동 |
| `src/explore/model-proposer.ts` | 반성 시 모델이 새 전략을 생성(행동공간 확장) |
| `src/cli.ts` | **CLI** — run/providers/models/scope/explore/mcts/config 서브커맨드 (`bin/redcell`) |
| `src/providers/` | **ProviderRegistry** — 다중 프로바이더(Anthropic·OpenAI호환·로컬), 자격증명 감지 |
| `src/config.ts` | `~/.redcell/config.json` + 모델 해석 우선순위 |
| `src/models/` | **모델 어댑터** — Anthropic(SDK) · OpenAI호환 · Mock |
| `src/memory/` | **SkillMemory** — fingerprint 색인 playbook 저장/recall/distill |
| `src/scope/` | **ScopeGuard** — 운영자가 authorization.yaml 로 통제하는 대상 게이트 |
| `src/core/` | **Orchestrator**(모델 계획) + **AutoPilot**(밴딧 자율, 모델 없음) + **MockModel**(발산형 규칙 플래너) |
| `src/core/payload-forge.ts` | **PayloadForge** — 핑거프린트/WAF 반영 동적 페이로드 생성(주입 통로) |
| `src/core/credential-harvest.ts` | 실행 중 노출된 자격증명 수확 → 이후 요청 재사용(발견 체이닝) |
| `src/tools/` `src/report/` | 32개 다각 공격 표면 툴(아래 표) / Markdown 보고서 + **공격 체인 합성**(`report/chains.ts`) |
| `prime-agent/` | **prime-agent 확장** — 커스텀 툴 + 슬래시 명령 + 방법론 프롬프트 + scope 훅 |
| `skills/pentest-lab/` | prime-agent 마크다운 스킬(방법론 + 자기발전 지침) |
| `knowledge/playbooks/` | 학습된/기본 제공 전술(JSON) |

## 다각 공격 표면 툴 (한 방법에 갇히지 않는다)

RedCell 는 API 정찰에 국한되지 않고 웹/앱을 여러 각도에서 두드린다. 발산형 플래너
(MockModel)와 밴딧 자율 드라이버(AutoPilot)가 **각 단계에서 아직 안 써본 벡터를 우선
골라** 폭넓게 시도한다. 모든 툴은 ScopeGuard 로 인가된 대상에만, RPS 를 지키며,
비파괴적으로 동작한다. 탐지는 상태코드가 아니라 **내용 시그니처** 기반이라 포괄-200
서버에서도 오탐이 적다.

**32개 툴**, 취약점 계열마다 다른 각도로 두드린다:

| 단계 | 툴 | 노리는 것 |
| --- | --- | --- |
| recon | `http_probe` | 응답/헤더로 기술스택 핑거프린팅 |
| recon | `header_audit` | 보안 헤더 누락 |
| recon | `api_discover` | 프런트엔드가 호출하는 backend API 표면 |
| recon | `cookie_audit` | 세션 쿠키 HttpOnly/Secure/SameSite 누락 |
| recon | `waf_detect` | WAF/방화벽 벤더 식별 → 이후 페이로드 우회 변형 유도 |
| recon | `crawl` | 링크·폼을 따라 실제 엔드포인트·파라미터 수집(공격 표면 확장) |
| recon | `jwt_audit` | JWT 정적 분석(alg=none·약한 HMAC 시크릿·exp/민감 클레임) |
| enumerate | `dir_enum` | 숨은 경로/관리자 인터페이스 |
| enumerate | `api_probe` | 엔드포인트 노출 데이터/민감정보(읽기 전용) |
| enumerate | `port_scan` | 노출 서비스 포트 |
| enumerate | `cors_audit` | CORS 신뢰 오설정(Origin 반사+credentials) |
| enumerate | `secret_scan` | 노출된 `.env`/`.git`/백업/자격증명 파일 |
| enumerate | `graphql_probe` | GraphQL introspection 스키마 노출 |
| enumerate | `csrf_audit` | 상태변경 POST 폼의 안티-CSRF 토큰/ SameSite 부재 |
| enumerate | `upload_probe` | 제한 없는 파일 업로드 폼(확장자/MIME accept 부재) |
| enumerate | `http_method_audit` | 위험 HTTP 메서드(PUT/DELETE/PATCH) 노출·TRACE 에코(XST) — 비파괴 |
| enumerate | `host_header_audit` | Host/X-Forwarded-Host 반영(비밀번호 재설정 포이즈닝·캐시 포이즈닝) |
| enumerate | `deserialize_probe` | 쿠키/폼/응답의 직렬화 blob(Java·PHP·pickle·Ruby·ViewState) — 클라이언트 제어 시 잠재 RCE |
| enumerate | `auth_session_probe` | 세션 토큰 예측성(순차·전부숫자·평문 디코딩)·URL 내 세션ID 노출 — 비파괴 |
| exploit | `sqli_probe` | SQL 인젝션 — 오류 기반 + 불리언 블라인드 + 시간 기반 블라인드 |
| exploit | `xss_probe` | 반사형 XSS(미이스케이프 반사, 다중 문맥/우회 변형) |
| exploit | `path_traversal` | 경로 조작/LFI(다중 인코딩 `../etc/passwd`) |
| exploit | `open_redirect` | 외부 canary 로의 오픈 리다이렉트 |
| exploit | `ssrf_probe` | SSRF(내부/클라우드 메타데이터 신호, 반사 오탐 배제) |
| exploit | `idor_probe` | IDOR/접근통제 미흡(무인증 인접 id) |
| exploit | `ssti_probe` | 서버측 템플릿 인젝션(다중 엔진 산술식 평가 신호) |
| exploit | `cmdi_probe` | OS 커맨드 인젝션(무해 정보명령 출력 시그니처) |
| exploit | `xxe_probe` | XXE(안전한 내부 엔티티 확장 신호만, 외부 엔티티 미사용) |
| exploit | `access_control_probe` | 접근통제 미흡/강제 브라우징(관리 기능 무인증 노출) — 읽기 전용 |
| exploit | `param_pollution` | HTTP 파라미터 오염(HPP) — 접근통제/WAF 우회 근거 |
| exploit | `cache_poison_probe` | 웹 캐시 포이즈닝 — 고유 cache-buster 2단계 확인(실사용자 무영향·비파괴) |
| exploit | `logic_probe` | 비즈니스 로직(가격/수량/권한류) 검증 부재 신호 — 읽기 전용·수동확인 |

주입 계열 툴(`xss/sqli/ssti/cmdi/ssrf/lfi/redirect`)은 `crawl` 이 찾은 **여러 경로×파라미터를
발산적으로 스윕**한다. 예: `/tpl→SSTI`, `/ping→CMDI`, `/fetch→SSRF` 를 한 번의 실행에서 각기 탐지.

### 탐지 정확도 벤치마크 (재현율·오탐 측정)

"많이 두드린다"만으로는 부족하다 — **얼마나 정확히 잡고, 얼마나 적게 오탐하는가**가
실전 도구의 신뢰도다. RedCell 은 동일 라우트를 가진 **취약 참조 앱**과 **견고(hardened)
참조 앱** 두 개를 띄우고 21개 취약점 계열을 각 탐지 툴로 채점한다:

- 취약 앱에서 못 잡으면 **False Negative**(놓침) → 재현율 하락
- 견고 앱에서 잡으면 **False Positive**(오탐) → 정밀도 하락

```bash
npm run bench                # 취약/견고 앱 대조, 재현율·정밀도·F1 출력 + 회귀 게이트
```

현재 참조 세트(21개 계열) 기준 **재현율 100% · 오탐 0% · F1 100%**. 이 수치는
`test/bench.test.ts` 가 CI 에서 `재현율 ≥ 90% && 오탐 = 0` 을 강제해 회귀를 막는다.
(이 벤치마크가 실제로 `xss_probe` 의 문맥 오탐 한 건을 잡아내 문맥 인식 판정을 추가했다.)

> ⚠️ **이 "오탐 0%"의 정확한 의미.** 이 수치는 각 툴에 **정답 경로·파라미터를 직접 먹인
> 자기참조 벤치**(`bench/score.ts`)에서 측정한 것이다 — "배선이 맞다면 정확히 판정하는가"를
> 본다. 반면 실제 게이트(`run --full`)는 `crawl`→`deriveArgs` 로 **블라인드로 표면을 배선**하고
> **모든 툴을 스윕**하므로, 자기참조 벤치에 없는 툴(`dir_enum`·`api_discover` 등)까지 관여해
> 오탐 특성이 다르다. 따라서 이 0% 를 "게이트 모드의 실측 오탐률"로 읽으면 안 된다.
> 게이트 모드의 오탐 성향은 아래 `bench:external`(블라인드, 심각 오탐 0) 과, 상태코드/CSP/
> Content-Type 인지 판정(`dir_enum` 401/403=접근통제→info, `api_discover` GraphQL=introspection
> 성공 시에만 노출, `xss_probe` CSP·비-HTML 시 severity 강등)으로 관리한다.

**적대적 미끼(decoy) 케이스**로 벤치마크의 정직성도 지킨다. "취약해 보이지만 정상"인
경로 — 공개 상품 카탈로그(인접 id 가 서로 다른 공개 객체를 반환하나 개인정보 없음),
관리자 로그인 스플래시(제목만 "Admin Dashboard"인 로그인 폼) — 를 넣어, 순진한 판정
(`서로 다른 200 = IDOR`, `헤딩 문구 = 접근통제 우회`)이 오탐하는지 감시한다. 이에 맞춰
`idor_probe` 는 **소유자 귀속/개인정보 신호 + (auth 제공 시) 인증 경계 비교**로, `access_control_probe`
는 **실제 특권 데이터 vs 로그인 폼 구분**으로 재설계되어 미끼를 회피한다.

### 외부 표준 취약앱 블라인드 검증 (`bench:external`) — 자기참조 탈피

위 벤치(`npm run bench`)는 각 툴에 **정답 경로를 직접 먹인다**(자기참조) — "배선이 맞다면
탐지되는가"만 본다. 실전 신뢰도를 주장하려면 **아무 힌트 없이** 얼마나 잡는지 측정해야 한다.
`bench:external` 은 DVWA/OWASP Juice Shop 의 실제 경로·파라미터 이름
(`/vulnerabilities/sqli/?id=`, `/vulnerabilities/exec/?ip=`, `/rest/products/search?q=`,
`/api/Users/:id`, `/redirect?to=` …)을 독립 모델링한 다중 취약 앱에 AutoPilot 을 `--full`
블라인드로 돌린다 — `crawl`(표면 발견) → `deriveArgs`(자동 배선) → 탐지 툴 스윕만으로 공략한다.

```bash
npm run bench:external       # 정답 경로 미제공, 블라인드 재현율 + 정직한 미탐 목록
```

**표면 힌트 주입(`--target-map`, 선택).** 이미 알고 있는 경로·파라미터·툴별 인자가 있으면
JSON 으로 넘겨 자동 배선을 보강할 수 있다(자율 크롤과 병행). 우선순위는
`tools[<tool>]` 직접지정 → 맵의 `paths/params/idPath` 합성표면 `deriveArgs` → 기존 자동 배선:

```bash
redcell run --full --host 127.0.0.1 --port 8080 --target-map surface.json
# surface.json: { "paths": ["/search"], "params": ["q"], "idPath": "/api/users/1",
#                 "tools": { "sqli_probe": { "path": "/login", "param": "user" } } }
```

핵심은 **정직성**이다. 100% 를 조작하지 않는다. 심은 12개 클래스 중 설계상 못 잡는 3개
(저장형 XSS = 단일 요청-응답 반사만 봄 · CSRF = PATH_ONLY 단일경로 배선 한계 · 비즈니스 로직
= 콘텐츠 시그니처 없음)를 "미탐 기대"로 명시하고 실제로 못 잡는지까지 확인한다.

| 지표 | 값 |
| --- | --- |
| 탐지 기대 9개 클래스(블라인드) | **9/9 탐지 · 재현율 100%** |
| 전체 12개 기준 정직 재현율 | **75%** (아키텍처/배선 한계 3개 미탐 포함) |
| 심각(sev≥medium) 오탐 | 0 |

`test/external.test.ts` 가 CI 에서 "탐지 기대 9개 전부 탐지 + 심각 오탐 0 + 심은 한계 3개는
정직 미탐"을 강제한다. 즉 이 검증은 **정찰→공격 자동배선의 실전 회귀 방지**이자, "RedCell 이
못 잡는 계열"을 숫자로 못박는 장치다. ⚠️ 라이브 DVWA/Juice Shop 은 이 환경(도커 없음)에서
띄울 수 없어 재현 가능한 최강의 대체물로 둔다 — 실제 컨테이너가 있으면 같은 AutoPilot 을 그
`host:port` 에 그대로 겨누면 된다.

### 웹 샅샅이 뒤지기 (`osint`) — 원하는 정보 가져오기

"prime-agent 처럼 사이트를 막 뒤져 원하는 정보를 가져와 줘" — 목표를 주면 시드 사이트를
깊이 크롤링하고(같은 오리진 BFS + robots.txt/sitemap.xml 얻어걸림) 이메일·전화·API 경로·
시크릿(api_key/AKIA 등)·기술 스택·HTML 주석·JSON-LD·폼·JS 스크립트를 추출해 목표와
맞는 인텔만 추려 보고한다. 모델이 있으면 frontier 를 보고 "어디를 더 파볼지"를 스스로
정하고(auto 없으면 결정적 전체 다이그):

```bash
redcell auth add example.com        # 인가(운영자 입력 = 인가)
redcell osint --host example.com --goal "고객 지원 이메일과 결제 API 키 수집"
redcell osint --host example.com --auto   # 모델 없이 전체 다이그만(오프라인/빠른 스윔)
```

- 모든 요청은 ScopeGuard(호스트+해석 IP) 경유, 같은 오리진만 따라간다(외부로 안 나감).
- 순수 GET 관측 — 폼 제출·상태변경 없음. 페이지 예산으로 폭주 방지.
- 발견은 보고서 파이프라인(시각 상황판·마크다운·감사)로 흐르고, 목표 키워드 적중 항목은
  medium 으로 마킹(🎯)된다. 데스크톱: 모드 선택에서 `osint(뒤지기)`.

### 칼리 대체식 공격 캠페인 (`--max`) — 다 시도·우회·체이닝

`run --max` 는 모델 주도 계획과 **전수 커버리지**를 결합한 공격 최대 모드다. 운영자가 인가
목록에 넣은 대상이면, 놓친 표면이 없도록 가능한 모든 벡터가 동원된다:

```bash
redcell run --max --host 127.0.0.1 --port 8080 --goal "관리자 세션 탈취 경로 확인"
```

- **모델 계획 → 전수 보강**: 각 phase(recon/enumerate/exploit/post)에서 모델이 고른 액션 이후
  **아직 안 쓴 툴을 전부 1회씩** 추가 실행한다 — 모델이 몰라서/잊어서 놓친 표면까지 뒤진다.
- **opt-in 프로브 전체 활성**: 평소 대상별 승인을 요구하는 `logic_probe`·`cache_poison_probe` 도
  자동으로 켠다(인가 목록 자체가 대상별 동의이므로).
- **python_exec 툴**: 모델이 취약점 심화·정보 추출이 필요하면 파이썬을 직접 작성해 실행한다
  (`rc.get/post/http/tcp`·`rc.finding`). 브로커 ScopeGuard·정적 스캔·AST 샌드박스는 그대로 적용되고,
  파이썬이 낸 발견은 `data.findings` 로 여러 건이 구조화 수집된다.
- **발견 체이닝**: 노출된 쿠키/토큰은 이후 요청에 자동 재사용 → 취약점 → 추가 정보 획득 루트.

안전 계약은 모든 모드와 동일하다: **인가 목록 밖 호스트는 어느 경로로도 못 나간다**
(ScopeGuard 는 요청 직전 매번 재확인 — 툴 요청·브로커 HTTP/TCP·리다이렉트 홉·DNS 해석 IP 전부).
데스크톱에서는 세션 헤더의 `최대 공격` 토글(⚡)로 켠다.

### 릴리스 게이트 모드 (`--full`) — 재현 가능한 관문

RedCell 을 "이 서비스가 RedCell 로 뚫리지 않음을 증빙해야 오픈한다"는 **릴리스 관문**으로
쓰려면 결과가 **재현 가능**해야 한다. 기본(밴딧) 모드는 세션 간 학습을 누적하므로 같은
대상이라도 실행마다 커버리지가 달라질 수 있다(게이트엔 부적합). `--full`(=`--gate`)은 이를
해결한다:

```bash
redcell run --full --host 127.0.0.1 --port 8080 --auth config/authorization.yaml
```

- **결정적 전수** — 밴딧 선택/조기이탈을 쓰지 않고 각 단계의 모든 툴을 등록 순서대로 1회씩
  실행한다. 같은 대상이면 항상 같은 커버리지(밴딧 상태와 무관, `--full` 은 영속 상태를
  로드·저장하지 않음 → 표적 간 오염 제거).
- **도달성 사전 점검** — 대상이 죽어 있으면 스캔을 시작하지 않고 즉시 `inconclusive` 로 끊는다
  (죽은 대상을 오래 grind 하다 '발견 0 = 통과'로 오인하는 것을 방지).
- **커버리지 정직성** — "발견 0"과 "안 봄"을 구분한다. 익스플로잇 계열을 하나도 못 돌렸거나
  **인증 표면을 점검하지 않았으면**(자격증명 없음) clean 이 아니라 `inconclusive` 로 강등한다.
  공개 서비스로 간주하려면 `--allow-unauth` 를 명시해야 한다.
- **종료코드로 판정** — CI 가 자동 판별할 수 있다.

| 판정 | 의미 | 종료코드 |
| --- | --- | --- |
| `clean` | 검사한 표면에서 유의미 취약점 미발견(전체 안전 보장 아님) | 0 |
| `findings` | 취약점 발견 → 오픈 불가 | 2 |
| `inconclusive` | 미도달/커버리지 불충분 → '통과' 아님 | 4 |
| (scope 차단) | 미인가 대상/포트 → 스캔 미수행 | 3 |

> ⚠️ **게이트의 한계 — 필요조건이지 충분조건이 아니다.** `clean` 은 *측정된 계열·표면에
> 한한* 결과다. 저장형/2차 취약점, 비즈니스 로직, 의존성 CVE(SCA), 인증·세션 심층,
> 클라이언트(SPA) 표면은 이 도구의 범위 밖이다. 리포트의 게이트 섹션은 이 면책을 항상 함께
> 출력한다. "RedCell 통과 = 안전"이 아니라 "RedCell 미통과 = 오픈 불가"의 **필요조건 관문**으로
> 쓰고, 수동 펜테스트·SCA·인증/로직 리뷰를 반드시 병행하라.

### 변조탐지 감사 추적 (`audit`) — "무엇을, 어디까지 시도했는가"의 봉쇄 증거

공식 보안팀 툴은 사후에 다툴 수 없는 기록을 남겨야 한다(법적/규정 준수·사고 상관분석).
`run`·`pyrun` 은 기본으로 **append-only + 해시 체인** 감사 추적을 남긴다: 각 항목이 이전
항목의 해시를 품으므로, 중간을 지우거나 고치면 이후 체인이 깨져 검증에서 드러난다.

- **봉쇄 증거** — `ScopeGuard` 의 **모든 allow/deny 판정**(대상·포트·intent·해석 IP)이 기록된다.
  "대상 범위를 절대 벗어나지 않았다"를 증빙한다.
- **내구성** — 항목마다 동기 append(+fsync) → 프로세스가 죽어도 그때까지 기록은 남는다.
- **fail-closed** — 감사 파일을 열 수 없으면(디스크/권한) 실행을 시작하지 않는다. 봉쇄 증거를
  남길 수 없는 상태로 공격성 액션을 하지 않는다. 명시적으로 끄려면 `--no-audit`.

```bash
redcell run --full --host 127.0.0.1 --port 8080 --auth config/authorization.yaml
# → [audit] 감사 추적: ~/.redcell/audit/<engagement>-<ts>-<rand>.jsonl
redcell audit verify ~/.redcell/audit/<...>.jsonl   # 해시 체인·순번 무결성 검증(변조 시 종료코드 2)
```

경로는 `--audit-dir <경로>` 또는 `REDCELL_AUDIT_DIR` 로 지정(기본 `~/.redcell/audit`).

### 피해 반경(blast radius) 보고 — "어디까지, 얼마나 뚫리는가"

탐지에 그치지 않고 **각 발견이 실제로 어떤 피해로 번지는지**를 방어자 언어로 서술한다.
모든 finding 은 `impact`(예상 피해 반경) 필드를 갖고, 리포트의 상세 항목에 "예상 영향(피해
반경)" 으로 출력된다(예: `Host Header Injection → 비밀번호 재설정 링크가 공격자 도메인으로
바뀌어 대량 계정 탈취`). 나아가 **공격 체인 합성**이 낱개 발견을 조합해 상위 위험(예:
`SSRF+메타데이터=클라우드 크리덴셜 탈취`)과 그 영향·방어 우선순위를 제시한다. 모두
비파괴 원칙을 지켜 **실제 피해를 내지 않고 서술만** 한다.

### 초보자 시각 상황판 (ASCII) — 보안 신입·비전문 개발자도 판단 가능

리포트 맨 위에 **문자로 그린 상황판**을 얹는다(색·이미지 없이 `─▶█` 등으로만 그려 어떤
터미널·로그에서도 동일하게 보인다). 보안 신입, 보안이 처음인 개발자, 비개발 PM 세 부류가
결과를 보고 **스스로 판단**할 수 있게 설계했다(초보자 3인 페르소나 사용성 테스트 반영):

- **신호등 판정 + 경영진 한 줄** — 🔴 위험/🟡 주의/🟢 양호 와 "지금 오픈하면 안 됨" 한 문장,
  그리고 `오픈(게이트 통과) 조건: 심각·높음 0건, 지금 N건 남음`.
- **공격 경로 그림** — `정찰 ──▶ 문 열기 ──▶ 장악` 킬체인으로 공격자가 어디까지 도달 가능한지.
- **위험도 막대** — 심각/높음/보통/낮음 건수를 막대로.
- **발견 카드** — 영어 취약점명을 **한글 우선 제목**으로, 유형마다 고유한 `쉽게 말하면 / 왜
  위험한가 / 어떻게 막나`, **조치 기한·담당**(예: `🔴 24시간 내 · 개발팀`), 근거의 사람 말
  요약(예: `이미 root 로 명령 실행됨`). '위치'는 공격당한 파일이 아니라 **취약 엔드포인트**.

```bash
redcell run --full --host 127.0.0.1 --port 8080 --auth config/authorization.yaml
redcell run --full ... --no-visual     # 상황판 끄고 전문가용 상세 리포트만
```

### 발산형 3대 확장

- **동적 페이로드 생성 + 주입 통로 (`PayloadForge`)** — 핑거프린트/WAF 를 반영해 페이로드를
  스택별·우회형으로 생성한다. 플래너(모델/밴딧)가 `args.payloads` 로 커스텀 페이로드를
  직접 주입할 수도 있어, "정해진 페이로드에 갇히지 않는다".
- **인증된 표면 스캔 + 발견 체이닝** — `authorization.yaml` 의 `credentials`(정적 쿠키/토큰)
  또는 `login:`(실제 로그인 플로우 — 인가된 테스트 계정으로 로그인해 세션 쿠키 jar 를 얻고
  응답에서 토큰을 추출)을 모든 요청에 실어 "로그인 뒤" 표면까지 점검한다. 나아가 실행 중
  대상이 흘린 자격증명(`.env` 의 토큰/키 등)을 수확해 이후 요청에 재사용하는 **다단계 침투**를
  수행한다. 모든 트래픽을 Burp/ZAP 로 흘리려면 `--proxy`(또는 `REDCELL_PROXY`)를 쓴다.
- **공격 체인 합성** — 낱개 발견을 조합해 상위 위험 체인을 도출한다(예: `SSRF+메타데이터=클라우드
  크리덴셜 탈취`, `노출 시크릿+API 표면=인증 침투`). 보고서가 방어 우선순위를 제시한다.

```bash
# 모델 없이 밴딧이 스스로 다각 벡터를 발산 탐색(세션 간 학습 누적):
npx tsx src/cli.ts run --host 127.0.0.1 --port 8080 --auto --goal "웹 취약점 자동 탐색"
```

## 빠른 시작 (독립 실행 — 엔진 검증)

```bash
cd redcell
npm install
npm test                     # 299개 테스트: scope(+연결시점 IP검증·rebinding)/메모리/탐색/MCTS/32개 툴/웹벡터/페이로드생성/인증스캔/체이닝/발산플래너/프로바이더/정확도벤치+적대적미끼/탐지심화 FN-트랩/피해반경/정찰→공격 자동배선(+target-map 오버라이드)/중복요청 억제/역직렬화·세션강도·캐시포이즈닝·로직결함 신규툴/scope차단/게이트 신뢰성/서명리포트·waiver·직무분리/변조탐지 감사추적/초보자 시각 상황판/외부 취약앱 블라인드 검증/absolute-agent(pyrun 코드실행 안전·OS격리 fail-closed·scope 강제)/e2e

# 인가 파일 준비 후 로컬 대상에 실행
cp config/authorization.example.yaml config/authorization.yaml
npx tsx src/cli.ts run --host 127.0.0.1 --port 8080 --goal "웹 스택 식별" --provider mock

# 전역 설치(선택): redcell 명령 사용
npm link && redcell providers
```

## prime-agent 에 붙이기 (프로젝트 로컬 — 권장)

```bash
# pi 를 사용하는 프로젝트 디렉터리에서 (기본: 로컬만 설치, 다른 곳의 pi 에 영향 없음)
/path/to/redcell/prime-agent/install.sh .
# → .pi/agent/{extensions/redcell, skills/pentest-lab, redcell/authorization.yaml} 생성
# authorization.yaml 을 본인 권한 대상으로 수정한 뒤:
#   pi -e /path/to/redcell/prime-agent/index.ts    확장 명시 로드(인가 게이트 켜짐, 이 세션만)
#   /scope       인가 상태 확인   /playbooks   학습된 전술 목록

# 경고: --global 로 설치하면 *모든* pi 세션의 툴 호출을 인가 목록으로 검사한다 —
# 다른 프로젝트에서 pi 를 쓸 때 "인가" 차단 메시지가 보이면 다음과 같이 제거:
#   rm "$HOME/.pi/agent/extensions/redcell"   (Windows: Remove-Item "$HOME\.pi\agent\extensions\redcell")
```

확장은 prime-agent 의 문서화된 인터페이스에 정확히 대응한다:
`pi.on("tool_call", …) → {block, reason}`(scope 강제), `pi.registerTool(defineTool(…))`,
`pi.registerCommand(…)`, `pi.appendSystemPrompt(…)`. 자기발전은 prime-agent 의
Continual Harness(`/refine`, auto-refine)를 그대로 사용한다.

## 문서
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — 설계와 prime-agent 매핑
- [`labs/README.md`](labs/README.md) — 합법 실습 환경 구축 및 윤리 규칙

## 라이선스
MIT. 이 도구는 인가된 보안 테스트·교육 목적으로만 제공된다.
