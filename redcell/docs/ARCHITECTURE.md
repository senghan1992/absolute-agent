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


## RLM 모드 — 재귀 언어 모델 에이전트 + 학습 루프

`src/rlm/` 은 prime-agent 의 RLM 패러다임을 엔진 내부로 이식한 계층이다.

```
                      ┌──────────────────────────────────────────────┐
  CLI (src/cli.ts) ──▶│ RlmAgent (src/rlm/rlm-agent.ts)              │
                      │  영구 Python REPL (ReplSession/브로커)          │
                      │   ┌─ rlm('하위작업') → 병렬 자식 REPL (동일 게이트) │
                      │   └─ recall → act → reward → reflect → verify │
                      └──────────────────────────────────────────────┘
                               │ OrchestratorEvent(onEvent)
              ┌────────────────┼─────────────────┐
              ▼                ▼                 ▼
        ndjson(stdout)   LivePanel(SSE)    감사 추적(audit)
```

- **재귀 서브콜**: REPL 프리루드의 `rlm_async(prompt, max_steps, key)`/`rlm_wait(key)` 가
  `##RC_RLM_ASYNC##`/`##RC_RLM_WAIT##` 마커로 브로커를 거쳐 자식 REPL 세션을 병렬 실행하고
  값을 회수한다. 레거시 동기 `rlm()`(`##RC_RLM##`/`##RC_RLM_RESULT##`)은 그대로 유지된다(하위호환).
- **학습 루프**: `recall`(기억 재사용) → `reward`(발견 보상) → `reflect`(전략 반성) →
  `verify`(`achieved/unclear`) → `distill`(harness memory/skill 엔트리). 에피소드 간에
  기억이 쌓여 다음 에피소드의 행동 수가 줄어든다 — `bench/rlbench.ts` 가 이 곡선을 결정적으로 증명한다
  (`npm run bench:rl`, 4개 게이트 통과 시 exit 0).
- **데스크톱 패널** (`--panel`): `src/panel/panel.ts` 의 `LivePanel` 은 이벤트 스트림을
  외부 의존성 0(CDN 없음)의 로컬 HTTP+SSE 패널로 서빙한다. `--ndjson` 과 직교이며,
  내부 이벤트와 사람이 읽는 리포트가 섞이지 않도록 stdout 은 ndjson 전용, 패널 URL/진행은 stderr.
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
| `sqli_probe` | exploit | SQLi 탐지(오류·부울·시간) + 확정 시 **UNION SELECT 버전 값 실증 추출**(읽기 전용) |

## assault 파이프라인 — URL 한 줄 → 전투 보고 (`src/assault/`)

`redcell assault --url <url>` 는 순수 **결정적 오케스트레이션** 파이프라인이다(모델 유무와 무관하게
진행·증거·보고 구조가 고정). 단계별 모듈:

| 모듈 | 역할 |
| --- | --- |
| `url.ts` | URL 파싱(스킴 화이트리스트 http/https, 기본 포트, 호스트 형식 fail-closed) + `--authorize` 인가 기록 |
| `pipeline.ts` | 전체 오케스트레이션: 인가 확인 → 로그인(선택) → recon/exploit 스윕 → 증거 수집 → 분석 → 보고. 모든 요청을 ScopeGuard(도달성·DNS 재바인딩·횡적이동)로 게이팅, 도달 불가면 종료코드 4 |
| `args.ts` | 툴별 공격 인자 생성(자동 URL/파라미터 합성) |
| `evidence.ts` | `ToolOutcome` 의 지표/발견을 "탈취 가능 정보" 매니페스트로 변환. **redaction**(KEY=value·이메일·URL userinfo·토큰 마스킹), 항목별 샘플 cap(기본 1500자), 매니페스트 상한(기본 40), target+label 기준 중복 제거. redaction **전** 원본에 `verify.ts` 검증을 수행해 각 항목에 검증 배지(✅ 실증 / ⚠️ 징후 / ❓ 미확인) 부착 |
| `verify.ts` | 검증 엔진: 원본 증거를 규칙 기반으로 재판독해 "가능성"을 "실증"으로 업그레이드 — 자격증명 키-값, DB 엔진 지문(SQLSTATE/PG::/ORA-), UNION SELECT 실제 데이터 추출(검증된 착취), 서로 다른 사적 레코드(distinct≥2)·민감 필드, introspection 스키마 구조, 실제 본문 확보 vs 경로목록(200 응답) 구분. **exploit 카테고리**: XSS/SSTI/SSRF/LFI/오픈 리다이렉트/XXE 툴 evidence 의 결정적 마커(반사·산술평가·메타데이터·passwd 라인·canary Location·엔티티 확장)로 실증(proof 접두사 `XSS 실증:` 등) — proof 는 항상 마스킹, AI 의존 없이 결정적 |
| `analysis.ts` | 결정적 분석: 증거 → 공격 경로 체인(카테고리별 target 그룹핑으로 중복 제거) + 방어 권고(defense). 모델이 없거나 `--no-ai` 면 이 합성이 항상 실행된다 |
| `report.ts` | `report.md`(전투 보고) / `report.html`(self-contained) / `report.json`(기계 판독) 렌더링 |

**핵심 결정**
- **인가 = URL 자체.** `--authorize` 는 호스트를 `~/.redcell/authorization.list` 에 기록한 뒤에만
  요청을 보낸다. 인가 밖 호스트는 스캔 없이 종료코드 3.
- **재현성.** 같은 대상·같은 옵션이면 툴 순서·분석·보고서가 동일(smoke/e2e 테스트가 고정 포트
  로컬 서버로 검증). AI 분석은 어디까지나 보고서 *해석* 레이어 — 없는 경우 결정적 합성으로 대체.
- **증거 지향.** 찾은 취약점이 "실제로 무엇을 탈취할 수 있는가"를 샘플로 증명하고, 원본 비밀값은
  redaction 으로 보고서 밖으로 새지 않게 한다. `--full-exposure` 으로만 원문이 포함된다.
- **블랙박스 경로 발견.** `--target-map <json>` 으로 아는 경로/파라미터를 주입해 정찰을 보강한다.


## P1 랩 벤치마크 (`bench/lab-bench.ts` + `labs/`)

URL-하나-자동화의 **종단간(엔드투엔드) 점수**: 랩을 기동 → `assault --url` 한 번 →
report.json 을 manifest 기대와 대조해 **해결률(solve rate)** 을 낸다. `bench/bench.ts`(툴별
recall/precision)와 별개의 계층이며, "탐지 → 실증(verified 착취) → 보고" 전체를 한 번에 판정한다.

- **랩 정의**: `labs/<name>/server.cjs`(취약/클린 구현) + `manifest.yaml`(기동 명령, 포트, 정답 조건).
- **해결 판정**(`bench/lab-score.ts`): `findingText` 클래스 발견 && verified 증거(proof 조건 포함) ⇒ solved.
  `clean: true` 랩은 발견 0 + 검증 증거 0 이어야 solved(오탐 FP 통제).
- **러너**: 랩 spawn → 포트 대기 → `REDCELL_HOME` 분리해 assault 실행 → 랩 kill → 채점.
  `--skip-start` 로 **외부 랩**(PortSwigger WSA 등, `source: portswigger`)도 동일 채점.
- **게이트**: 시도한 랩 전부 해결(100%) 이면 exit 0; 아니면 1.
- 실행: `npm run lab-bench` (로컬 5랩: SQLi UNION · IDOR · 자격증명 체이닝 · clean), `--json` 으로 기계판독 출력.
- 랩별 home 디렉터리에 report.json 이 여러 번 쌓이므로 **가장 최근(mtime) report 를 채점**한다.

## P2 다단계 체이닝 (`src/assault/chain.ts`)

evidence 스테이지 직후 실행되는 결정적 체이닝 엔진. 노출 증거(`path /.env (200)` /
`exposed ...` 지표)에서 키-값을 재-fetch 로 파싱해 자격증명 쌍을 만들고, 로그인 폼을 찾아
실제 로그인을 시도한다. 성공 시 **검증된(verified) 체인 증거** `chain-N`(category endpoint,
proof 에 보호자원 응답 포함)과 high finding `자격증명 재사용으로 보호자원 접근 (체이닝)` 을
보고서에 추가한다.

- 자격증명 결합 규칙: `db_user/db_pass`류 → `admin*/admin_pass*`류 → `app_*`류 → DB 공통 → 폴백 교차(dedupe, 최대 8쌍).
- 로그인 폼 탐지: 후보 페이지(base + endpoint/exposed 지표, HTML 스킵 확장자 제외, 12개 한도)에서
  `<form method=post>` + `<input type=password>`(폼 4개 한도).
- 세션 실증: 시도별 **fresh cookie jar**(`newJar()`), 302/200 + Set-Cookie + 보호자원 지표
  (`logout|dashboard|admin|panel|계정|관리자|welcome|profile`) 일치 시 성공. 자격증명 원문은
  증거/보고서에서 마스킹(redaction).
- 오탐 통제: 로그인 실패/리다이렉트가 login 페이지로 복귀하면 실패 처리; 증거·발견은 첫 성공 1건만.
- 파이프라인 배선: evidence 스테이지 내 증거 emit 직후(`runChain(lastCtx, outcomes, ...)`) —
  기존 랩(clean 등)에는 영향 없음(노출 자격증명 없으면 시도 0).


## P2 python_exec 에이전트 (`src/assault/pyagent.ts`)

"absolute-agent 코어"(`src/py/python-agent.ts`, 모델이 코드를 쓰는 루프)의 **결정적 버전**.
LLM 없이도 같은 broker 런타임(`runPython` + rc 헬퍼)으로 블라인드 OS 명령 주입을
탐사·실증한다. 파이프라인 7.5(체이닝) 직후 7.6 스테이지로 배선된다.

- **후보 추출**: 정찰/크롤 지표(`endpoint /path?param=...`)에서 쿼리 파라미터를 가진
  엔드포인트만 값 제거(=`/path?param=`) 후 최대 6개 추출.
- **프로그램 생성**: baseline(정상 값 200 확인) → 주입(`1.1.1.1; echo <마커>;
  cat flag.txt | base64 -w0`, TS 측에서 percent-encoding 선계산 — 파이썬 import 없음) →
  로그 싱크 회수(`/logs?marker=`) → base64 디코드 → 비밀 지표(FLAG/SECRET/PRIVATE KEY) 확인.
- **안전 실행**: `runPython`(broker) 경유. ScopeGuard 인가·AST 허용목록 샌드박스·타임아웃·
  요청 예산·출력 상한이 모두 강제된다. 생성 코드는 `scanDanger` 정적 스캔을 통과해야 한다.
- **FP 통제**: 응답에 무작위 마커가 실제로 나타나고, 디코드 결과에 비밀 지표가 있어야만
  발견(첫 성공 1건 채택). 로그 싱크가 없으면 시도 후 발견 0.
- **검증**: 성공 시 `python-N` 증거(category endpoint, source python, verified proof 에
  탈취 샘플) + high finding `명령 실행으로 서버 파일 탈취 (python_exec 에이전트)`.
- **랩**: `labs/vuln-pyagent` — 모든 요청에 균일 지연(300ms)으로 시간 오라클을 무력화하고
  응답에 출력을 반영하지 않는(블라인드) cmdi + 로그 싱크. 기존 cmdi_probe 로는 탐지 불가,
  python 에이전트(주입→로그 회수 다단계)만 해결한다.

## P3 인간 대결 게이트 (`bench/human-gate.ts`)

동일 랩 셋에서 인간 주니어 펜테스터의 블라인드 결과(동일 report.json/md + meta.json)와
RedCell 산출물을 같은 채점기(lab-score)로 비교해 **recall · FP · 시간 · 문서 품질이 전 랩
동등 이상**인지 판정한다. `--sim` 으로 게이트 자체를 검증(항상 통과). 실제 평가 절차·양식은
`docs/P3-humans-vs-redcell.md`. 2026-09-08 시뮬레이션 5/5 통과.

## 모델 계층 (`src/models/`)

`ModelAdapter` 하나로 추상화. `createModelFromEnv()` 가 자격증명으로 선택:
- **AnthropicModel** — 공식 `@anthropic-ai/sdk`, 기본 `claude-opus-5`, `thinking:{type:"adaptive"}`, `effort` 조절.
- **OpenAICompatModel** — OpenAI 호환 `/chat/completions`(prime-inference `z-ai/glm-5.2` 등). raw fetch.
- **MockModel** — 오프라인 규칙기반(자격증명 없을 때 폴백).

계획(Orchestrator)과 전략생성/반성(ModelStrategyProposer)이 이 어댑터를 공유한다.
