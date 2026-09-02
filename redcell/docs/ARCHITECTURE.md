# RedCell 아키텍처

## 설계 목표
1. **인가 강제**가 우회 불가능한 최하층에 있을 것(fail-closed).
2. **자기발전**이 prime-agent 의 네이티브 메커니즘 위에서 일어날 것(재발명 금지).
3. 런타임 독립: prime-agent 위에서도, 단독으로도 같은 엔진이 돌 것.

## 계층 구조

```
┌─────────────────────────────────────────────────────────────┐
│ prime-agent (RLM harness, 모델, ipython 커널, Continual Harness) │
│   └── RedCell 확장 (prime-agent/extension.ts)                    │
│        • tool_call 훅 → ScopeGuard.check() → {block, reason}     │  ← 안전 핵심
│        • registerTool(recon_http)  • /scope /playbooks          │
│        • appendSystemPrompt(화이트해커 방법론)                    │
│   └── skills/pentest-lab (PTES 방법론 + 자기발전 지침)            │
└─────────────────────────────────────────────────────────────┘
                    │ (동일 엔진 재사용)
┌─────────────────────────────────────────────────────────────┐
│ RedCell 엔진 (src/)                                             │
│   ScopeGuard ── Orchestrator ── SkillMemory                    │
│      │             │                │                          │
│   authorization  ToolBox(http_probe) knowledge/playbooks       │
│      .yaml       ModelAdapter        (fingerprint 색인)         │
│                     │                                          │
│                  report(Markdown)                              │
└─────────────────────────────────────────────────────────────┘
```

## 자기발전 루프

| 단계 | 엔진(src) | prime-agent 통합 |
| --- | --- | --- |
| recall | `SkillMemory.recall(fingerprint)` | harness 메모리가 시스템 프롬프트로 재주입 |
| plan | `ModelAdapter.complete()` | RLM 모델(ipython 커널) |
| **gate** | `ScopeGuard.check()` | `tool_call` 훅 `{block,reason}` |
| act | `Tool.run()` | `registerTool` 커스텀 툴 / 커널 |
| observe | fingerprint 병합 | 동일 |
| record | `SkillMemory.record()` | 통계 갱신 |
| distill | `SkillMemory.distill()` | `/refine` → harness `memory`/`skill` 엔트리 |

**왜 두 계층인가?** prime-agent 의 harness 메모리는 자유 텍스트 축적에 강하지만
fingerprint 기반 정밀 검색은 없다. RedCell 의 `SkillMemory` 는 그 위에 얹는
**색인 계층**으로, "이 서비스 지문에 맞는 전술"을 점수순으로 꺼내준다.
(점수 = fingerprint 유사도 × Laplace-smoothed 성공률)

## prime-agent 인터페이스 매핑 (검증된 실제 시그니처)

| RedCell | prime-agent (`@earendil-works/pi-coding-agent`) |
| --- | --- |
| scope 훅 | `pi.on("tool_call", (e,ctx) => {block:true, reason})` |
| 커스텀 툴 | `pi.registerTool(defineTool({ name, parameters: Type.Object(...), execute }))` |
| 슬래시 명령 | `pi.registerCommand(name, { description, handler })` |
| 방법론 주입 | `pi.appendSystemPrompt(text)` |
| 자기발전 | Continual Harness: `RefinementProposal` → `harness_state.json` (kind: memory/skill) |

## 확장 지점
- **새 툴**: `src/tools/` 에 `Tool` 구현 → `DefaultToolBox` 등록 → 확장에서 `registerTool` 로 노출.
  모든 툴은 `intent`(recon/enumerate/exploit/post/destructive/dos)를 선언해야 ScopeGuard 가 판정한다.
- **새 모델**: `ModelAdapter` 구현(예: Anthropic/prime-inference). `MockModel` 을 교체.
- **새 playbook**: `knowledge/playbooks/*.json` 에 seed 추가, 또는 engagement 성공 시 자동 distill.

## 탐색 전략: 밴딧 vs MCTS

두 가지를 환경 특성에 맞게 쓴다.

| | ContextualBandit (`Explorer`) | MCTS (`Mcts`) |
| --- | --- | --- |
| 질문 | "이 상태에서 최적 액션?" | "여러 수 앞을 본 최적 경로?" |
| 학습 단위 | 에피소드 간 누적(상황별 값) | 한 번의 검색 내 트리 성장 |
| 적합 환경 | 상태 반복·재방문 많음(MockWebLab, 실대상) | 상태가 전이하고 막다른 길 존재(GraphLab 미로) |
| 백트래킹 | tabu(에피소드 내) | 낮은 가치 가지 자연 회피 |
| 정책 | UCB1 / Thompson | UCT |

`RealTargetEnv` 는 undo 가 불가하고 요청 비용이 크므로 기본은 밴딧형 `Explorer`.
MCTS 는 시뮬레이션(GraphLab)에서 경로 계획을 세운 뒤 그 계획을 실대상에 적용하는 용도.

## 툴 계층 (intent 기반 게이팅)

모든 툴은 `intent` 를 선언하고, `RealTargetEnv`/Orchestrator/prime-agent 훅이 실행 전
ScopeGuard 로 검사한다. 현재 기본 툴:

| 툴 | intent | 성격 |
| --- | --- | --- |
| `http_probe` | recon | 헤더/본문 핑거프린팅(비파괴) |
| `header_audit` | recon | 보안 헤더 누락 점검(방어 발견) |
| `dir_enum` | enumerate | 흔한 경로 열거(소형 wordlist) |
| `sqli_probe` | exploit | SQLi **탐지만**(오류 시그니처, 추출 없음, 최소영향) |

## 모델 계층 (`src/models/`)

`ModelAdapter` 하나로 추상화. `createModelFromEnv()` 가 자격증명으로 선택:
- **AnthropicModel** — 공식 `@anthropic-ai/sdk`, 기본 `claude-opus-5`, `thinking:{type:"adaptive"}`, `effort` 조절.
- **OpenAICompatModel** — OpenAI 호환 `/chat/completions`(prime-inference `z-ai/glm-5.2` 등). raw fetch.
- **MockModel** — 오프라인 규칙기반(자격증명 없을 때 폴백).

계획(Orchestrator)과 전략생성/반성(ModelStrategyProposer)이 이 어댑터를 공유한다.
