# RedCell 🛡️

**자기발전형(self-improving) 화이트해커 훈련 에이전트** — [prime-agent](https://github.com/PrimeIntellect-ai/prime-agent) 위에 얹는 확장.

RedCell 는 "잘 뚫는 법"을 **합법적인 인가 환경**(CTF, 취약점 실습랩, 본인 소유 VM)에서
학습하고, 성공한 공략 전술을 스스로 축적해 다음엔 더 빠르게 뚫도록 발전한다.
prime-agent 의 자기발전 패러다임(Continual Harness)을 보안 도메인에 이식한 것이다.

> ⚠️ **RedCell 는 인가 없이는 동작하지 않는다.** `authorization.yaml` 에 명시적으로
> 허용된 대상만 다루며, prime-agent 의 `tool_call` 훅에서 scope 밖 요청은 자동 차단된다.
> 권한 없는 실제 서비스를 대상으로 사용하는 것은 불법이며, 이 도구의 목적이 아니다.
> 자세한 내용은 [`labs/README.md`](labs/README.md) 참조.

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
redcell config set defaultProvider anthropic
redcell explore  |  redcell mcts     # 자기발전/트리검색 데모
redcell help
```

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
| `src/core/` | **Orchestrator** — PTES 단계 루프 + 모델/툴 어댑터 |
| `src/tools/` `src/report/` | 툴(`http_probe`·`header_audit`·`dir_enum`·`sqli_probe`) / Markdown 보고서 |
| `prime-agent/` | **prime-agent 확장** — 커스텀 툴 + 슬래시 명령 + 방법론 프롬프트 + scope 훅 |
| `skills/pentest-lab/` | prime-agent 마크다운 스킬(방법론 + 자기발전 지침) |
| `knowledge/playbooks/` | 학습된/기본 제공 전술(JSON) |

## 빠른 시작 (독립 실행 — 엔진 검증)

```bash
cd redcell
npm install
npm test                     # 59개 테스트: scope/메모리/탐색/MCTS/툴/프로바이더/e2e

# 인가 파일 준비 후 로컬 대상에 실행
cp config/authorization.example.yaml config/authorization.yaml
npx tsx src/cli.ts run --host 127.0.0.1 --port 8080 --goal "웹 스택 식별" --provider mock

# 전역 설치(선택): redcell 명령 사용
npm link && redcell providers
```

## prime-agent 에 붙이기 (권장)

```bash
# prime-agent 를 사용하는 프로젝트 디렉터리에서:
/path/to/redcell/prime-agent/install.sh .
# → .prime/agent/{extensions/redcell, skills/pentest-lab, redcell/authorization.yaml} 생성
# authorization.yaml 을 본인 권한 대상으로 수정한 뒤 prime-agent 실행:
#   /scope       인가 상태 확인
#   /playbooks   학습된 전술 목록
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
