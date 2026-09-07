/**
 * rlm/rlm-agent — RLM(Recursive Language Model) 에이전트.
 *
 * prime-agent/OASYS RLM 패러다임을 RedCell 위에 이식한다:
 *
 *   1) **영구 Python REPL** — JSON 툴콜 대신, 모델이 코드를 작성하면 같은 파이썬
 *      프로세스의 globals 에 계속 실행된다(스텝을 넘어 변수·상태 지속).
 *   2) **prompt-as-a-variable** — REPL 전역 `ctx` 사전: 모델이 ctx_get/ctx_set 으로
 *      맥락(관찰, 중간 결과, 가설)을 코드 변수로 관리한다.
 *   3) **재귀 서브콜 rlm(prompt)** — 파이썬 함수처럼 하위 (R)LM 에이전트를 호출하고,
 *      그 최종 답변을 **값으로** 돌려받는다(프로그래매틱 subagent calling).
 *   4) **자기발전 기억** — rc.memo(key, text) 로 배운 전략을 세션 메모리 파일에 남기고,
 *      다음 실행 시작 시 ctx.memories 로 재주입된다(continual harness).
 *
 * 안전은 엔진과 동일: 모든 대상 통신은 ReplSession 의 BrokerCtx(ScopeGuard·예산·RPS·
 * 비파괴)를 통과하고, 파괴/DoS/scope 밖은 어느 경로(재귀 포함)에서도 차단된다.
 * 모델 재귀 깊이·요청 예산·스텝 수는 상한이 있다.
 */

import type { ScopeGuard, Target } from "../scope/scope-guard.js";
import type { ModelAdapter, EngagementLog, EngagementFinding } from "../core/types.js";
import type { OrchestratorEvent, SessionContext } from "../core/orchestrator.js";
import { ReplSession, type ReplMem, type ReplStepResult } from "../py/broker.js";

export interface RlmAgentOpts {
  /** 모델 재귀 깊이 상한(rlm() 중첩 호출). 기본 3. */
  maxDepth?: number;
  /** 이 에이전트(와 하위)의 코드 스텝 수 상한. 기본 10. */
  maxIterations?: number;
  /** 각 REPL 스텝 타임아웃 ms. 기본 20000. */
  stepTimeoutMs?: number;
  /** 재귀 세션 전체가 공유하는 요청 예산(브로커가 강제). */
  budget?: { used: number; max: number };
  /** 이전 세션에서 학습한 기억(ctx.memories + 시스템 프롬프트 재주입). */
  memories?: string[];
  /** rc.memo() 수집분을 끝에 기록할 파일(markdown). */
  memoryFile?: string;
  /** 실시간 이벤트 훅(Orchestrator 와 동일 형식 → 패널/CLI 가 그대로 소비). */
  onEvent?: (e: OrchestratorEvent) => void;
  /** 로그인/프록시 세션. */
  session?: SessionContext;
  python?: string;
  /** OS 격리 정책(기본 "required" → 데스크톱은 best-effort). */
  isolation?: "required" | "best-effort" | "off";
  /** 코드 생성원 신뢰 여부(MockCoder 등 오프라인). */
  trusted?: boolean;
  /** 재귀 깊이(내부용). */
  depth?: number;
}

/** 한 번의 REPL 스텝 기록(다음 프롬프트에 관측으로 되먹임). */
interface StepRecord {
  code: string;
  rationale: string;
  result: ReplStepResult;
}

const RLM_SYSTEM =
  "너는 RLM(Recursive Language Model) 화이트해커다. 작업을 코드로 분해해 영구 " +
  "Python REPL 에서 실행한다. 핵심 규칙:\n" +
  "1) 대상과의 모든 HTTP 는 `rc` 로만: rc.get(path), rc.post(path, data=/json=), rc.http(method, path_or_url, headers=, body=) " +
  "(응답 r.status/r.headers/r.text/r.json()). 원시 TCP 는 rc.tcp(host, port, payload=None). 쿠키는 호출 간 자동 유지. " +
  "requests/urllib/socket 직접 네트워크는 금지(정적 스캔 + AST 화이트리스트가 실행 자체를 막는다).\n" +
  "2) REPL 은 **영구**다: 변수와 ctx 가 스텝을 넘어 유지된다. 중간 관찰·가설·결과는 ctx_set()/ctx_get() 으로 " +
  "'코드 변수(prompt-as-variable)'로 관리하고 다음 스텝에서 이어 써라.\n" +
  "3) 작업이 크면 **재귀 서브콜**로 분해하라: r = rlm('하위 작업 지시', 8) — 하위 에이전트가 실행되고 " +
  "최종 답변이 값으로 돌아온다(깊이 제한 있음 — 과도한 위임은 삼가고, 부분 문제에만 쓸 것).\n" +
  "4) 통한 전략·재사용할 지식은 rc.memo('키', '내용') 로 기억하라(다음 세션에 재주입됨).\n" +
  "5) 취약 신호 확인 시 rc.finding(title, severity, evidence=, impact=) 로 보고(severity: info|low|medium|high|critical).\n" +
  "6) 인가된 대상이면 공격적으로 파고들어라: 쿠키 위조/토큰 우회, SSRF(인가 호스트 경유), SQLi·XSS·SSTI·경로조작·인증우회·API 남용을 " +
  "실제 페이로드로 시도하되, **scope 밖 호스트·데이터 파괴/변조·DoS(폭주/무한루프)는 금지** — 신호 확인만.\n" +
  "7) 문법(괄호/들여쓰기)을 보내기 전에 스스로 검사하라 — 문법 오류는 실행되지 않고 그대로 반환된다.\n" +
  "8) 목표가 끝나면 최종 답변을 print('FINAL: ...') 로 한 줄에 내라. " +
  "응답은 JSON 하나로만: {\"code\": <python|null>, \"text\": <자유텍스트|null>, \"rationale\": \"<한 줄 근거>\", \"done\": <bool>}.";

export class RlmAgent {
  constructor(
    private readonly guard: ScopeGuard,
    private readonly model: ModelAdapter,
    private readonly opts: RlmAgentOpts = {},
  ) {}

  /** 최종 답변(FINAL: 이후 텍스트) — rlm() 재귀 콜이 돌려받는 값. */
  private finalText = "";

  async run(target: Target, goal: string): Promise<EngagementLog> {
    const depth = this.opts.depth ?? 0;
    const maxIter = this.opts.maxIterations ?? 10;
    const label = depth === 0 ? "rlm" : `rlm↡${"↡".repeat(Math.max(0, depth - 1))}${depth}`;
    const log: EngagementLog = {
      target,
      fingerprint: {},
      findings: [],
      usedPlaybooks: [],
      distilled: [],
      transcript: [],
    };
    const emit = (e: OrchestratorEvent) => {
      log.transcript.push(e.text);
      this.opts.onEvent?.(e);
    };

    // 시작 전 대상 인가 확인(fail-closed) — 재귀 하위 에이전트도 동일하게.
    const gate = this.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      emit({ type: "blocked", text: `[거부] ${gate.reason}` });
      this.opts.onEvent?.({ type: "done", text: "[완료] 인가 거부로 종료.", log });
      return log;
    }
    if (depth === 0) {
      emit({ type: "authorized", text: `[인가] ${gate.reason} — 목표: ${goal}`, target, goal });
      emit({ type: "phase", text: "[phase] rlm-agent (영구 REPL + 재귀 서브콜) 시작", phase: "exploit" });
    }

    const memories = this.opts.memories ?? [];
    const ctx: Record<string, unknown> = {
      goal,
      target: `${target.host}${target.port ? `:${target.port}` : ""}`,
      memories,
    };
    if (depth > 0) ctx.parent = "이 에이전트는 상위 작업의 일부를 위임받았다 — 요청된 부분만 처리하고 FINAL 로 답하라.";

    const repl = await ReplSession.create({
      guard: this.guard,
      target,
      auth: this.opts.session?.auth,
      jar: this.opts.session?.jar,
      proxy: this.opts.session?.proxy,
      timeoutMs: this.opts.stepTimeoutMs ?? 20000,
      budget: this.opts.budget,
      isolation: this.opts.isolation,
      trusted: this.opts.trusted ?? this.model.trusted === true,
      python: this.opts.python,
      ctx,
      onRlm: async (req) => {
        // RLM 재귀 서브콜: 같은 게이트·같은 예산으로 하위 에이전트를 돌리고 결과를 값으로 돌려준다.
        if (depth >= (this.opts.maxDepth ?? 3)) {
          emit({ type: "note", text: `[${label}] rlm() 최대 재귀 깊이(${this.opts.maxDepth ?? 3}) — 상위에서 직접 처리하도록 지시했습니다.` });
          return `[rlm] 최대 재귀 깊이(${this.opts.maxDepth ?? 3}) 초과 — 이 부분은 상위 에이전트가 직접 처리하세요.`;
        }
        const kid = new RlmAgent(this.guard, this.model, {
          ...this.opts,
          depth: depth + 1,
          maxIterations: Math.min(req.max_steps || 8, 8),
          onEvent: (e) => {
            if (e.type === "note" || e.type === "finding") {
              emit({ ...e, text: `[${label}↘] ${e.text}` });
            }
          },
        });
        const klog = await kid.run(target, req.prompt);
        // 하위 에이전트의 발견은 상위 로그로 승격(중복 제목 제외).
        for (const f of klog.findings) {
          if (!log.findings.some((x) => x.title === f.title)) {
            log.findings.push(f);
            emit({ type: "finding", finding: f, text: `[${label}↘ 발견] (${f.severity}) ${f.title}` });
          }
        }
        const text = kid.finalText || `[${label}↘ 완료] (${
          klog.findings.length ? `발견 ${klog.findings.length}건` : "발견 없음"
        }, 하위 에이전트 종료)`;
        return text;
      },
      onMemo: (m: ReplMem) => {
        this.memos.push(m);
        emit({ type: "note", text: `[${label}·기억] ${m.key}: ${m.text.slice(0, 200)}` });
      },
      onRequest: (info) =>
        info.blocked
          ? emit({ type: "blocked", phase: "exploit", tool: "python", text: `[차단] ${info.method} ${info.url}: ${info.blocked}` })
          : undefined,
    });

    const attempts: StepRecord[] = [];
    try {
      for (let i = 0; i < maxIter; i++) {
        const plan = await this.planStep(target, goal, attempts, memories, emit);
        if (!plan) {
          emit({ type: "note", text: `[${label}] 모델이 종료를 선언(또는 더 낼 코드 없음).` });
          break;
        }

        if (plan.text) {
          // FINAL: 접두사는 이 에이전트(재귀 값 포함)의 최종 답변이다.
          const FINAL = plan.text.indexOf("FINAL:");
          if (FINAL >= 0) {
            this.finalText = plan.text.slice(FINAL + "FINAL:".length).trim();
            emit({ type: "note", text: `[${label}] 최종 답변: ${clip(this.finalText, 400)}` });
            break;
          }
          emit({ type: "note", text: `[${label}] 관찰: ${clip(plan.text, 300)}` });
        }

        if (plan.code) {
          emit({
            type: "action",
            phase: "exploit",
            tool: "repl",
            rationale: plan.rationale,
            args: { code: plan.code },
            text: `[${label} #${i + 1}] REPL 코드 — ${plan.rationale}\n${indent(plan.code)}`,
          });
          const result = await repl.step(plan.code);
          attempts.push({ code: plan.code, rationale: plan.rationale, result });
          if (result.reset) {
            emit({ type: "note", text: `[${label}] REPL 이 타임아웃으로 재시작됐습니다 — 변수가 초기화되었습니다.` });
          }
          const summary = resultSummary(result);
          emit({ type: "tool_result", phase: "exploit", tool: "repl", ok: result.ok, summary, text: `[${label} #${i + 1}] 실행 결과 — ${summary}` });
          if (result.stdout.trim()) {
            // CodeAct 스타일 가시성: 스텝 출력을 패널/로그에 노출한다.
            emit({ type: "note", text: `[출력] ${clip(result.stdout.trim(), 400)}` });
          }
          if (result.syntax) {
            emit({ type: "note", text: `[구문 오류] ${clip(result.syntax, 300)} — 모델이 다음 시도에서 수정합니다.` });
          }
          if (result.danger) {
            emit({ type: "note", text: `[안전차단] ${result.danger} — 이 코드는 실행하지 않았습니다.` });
          }
          if (result.exc) {
            emit({ type: "note", text: `[${label}] 코드 예외: ${clip(result.exc, 300)}` });
          }
          for (const lg of result.logs) emit({ type: "note", text: `[관찰] ${lg}` });

          for (const f of result.findings) {
            if (log.findings.some((x) => x.title === f.title)) continue;
            const finding: EngagementFinding = { phase: "exploit", severity: f.severity, title: f.title, detail: plan.rationale, evidence: f.evidence, impact: f.impact };
            log.findings.push(finding);
            emit({ type: "finding", finding, text: `[발견] (${finding.severity}) ${finding.title}` });
          }

          // FINAL: 프린트는 이 에이전트(재귀 값 포함)의 최종 답변이다 — 코드로 답을 내는 RLM 계약.
          // (로그/발견 처리를 먼저 끝낸 뒤 종료한다 — break 가 관찰·발견을 삼키지 않도록.)
          const fi = result.stdout.indexOf("FINAL:");
          if (fi >= 0) {
            this.finalText = result.stdout.slice(fi + "FINAL:".length).trim();
            emit({ type: "note", text: `[${label}] 최종 답변: ${clip(this.finalText, 400)}` });
            break;
          }
        }

        if (plan.done) break;
      }
    } finally {
      await repl.close();
    }

    // 자기발전 기억: rc.memo() 수집분을 메모리 파일에 누적 기록.
    if (this.memos.length && this.opts.memoryFile) {
      try {
        const { appendFileSync } = await import("node:fs");
        appendFileSync(
          this.opts.memoryFile,
          this.memos.map((m) => `## ${m.key}\n${m.text}\n`).join("\n"),
          "utf8",
        );
        emit({ type: "note", text: `[기억] ${this.memos.length}건을 ${this.opts.memoryFile} 에 기록했습니다.` });
      } catch (e) {
        emit({ type: "note", text: `[기억] 메모리 파일 기록 실패: ${(e as Error).message}` });
      }
    }

    this.opts.onEvent?.({
      type: "done",
      text: `[완료] ${label} 종료 (스텝 ${attempts.length}회, 발견 ${log.findings.length}건${this.finalText ? `, 최종답변 있음` : ""}).`,
      log,
    });
    return log;
  }

  private memos: ReplMem[] = [];

  /** 모델에게 다음 REPL 코드/텍스트 한 조각을 받는다. null 이면 종료. */
  private async planStep(
    target: Target,
    goal: string,
    attempts: StepRecord[],
    memories: string[],
    emit: (e: OrchestratorEvent) => void,
  ): Promise<{ code?: string; text?: string; rationale: string; done: boolean } | null> {
    const history = attempts.slice(-4).map((a, i) => ({
      step: attempts.length - Math.min(4, attempts.length) + i + 1,
      code: a.code,
      ok: a.result.ok,
      danger: a.result.danger,
      syntax: a.result.syntax,
      exc: a.result.exc,
      stdout: clip(a.result.stdout, 1200),
      stderr: clip(a.result.stderr, 600),
      requests: a.result.requests,
      blocked: a.result.blockedRequests,
      findings: a.result.findings.map((f) => f.title),
    }));
    const prompt = JSON.stringify({
      instruction:
        `대상=${target.host}${target.port ? ":" + target.port : ""}. 목표=${goal}. ` +
        `직전 스텝들의 코드·출력을 보고 다음에 실행할 파이썬 코드 1개를 작성하라. ` +
        `REPL 은 영구이므로 이전 변수/ctx 를 이어 쓸 수 있다. ` +
        `부문제는 rlm('지시', 8) 재귀로 위임하고 결과를 값으로 받아라. ` +
        `통한 전략은 rc.memo('키','내용') 으로 남겨라. ` +
        `아직 확인 안 된 벡터를 노려라(쿠키 우회·SSRF 경유·SQLi·SSTI·인증우회·API 남용 등). ` +
        `문법을 보내기 전에 검사하라 — 문법 오류는 실행되지 않고 그대로 반환된다. ` +
        `모두 끝났으면 print('FINAL: ...') 하는 코드 또는 text 에 FINAL: 를 내라.`,
      target,
      helper_api:
        "rc.get(path)/rc.post(...)/rc.http(method, path_or_url, ...) → r.status/r.headers/r.text/r.json(); " +
        "rc.tcp(host, port, payload=b'...'|None); rc.b64e/b64d; rc.finding(title, severity, evidence=, impact=); " +
        "rc.log(...); rc.ctx_get(key, default)/rc.ctx_set(key, value) — 영구 맥락 변수(prompt-as-variable); " +
        "rlm(prompt, max_steps=8) → 하위 에이전트 최종 답변 문자열(값처럼 사용); rc.memo(key, text) — 자기발전 기억",
      ...(memories.length ? { memories: `이전 세션에서 학습한 기억(재사용해라):\n` + memories.map((m) => `  - ${m}`).join("\n") } : {}),
      previous_attempts: history,
      response_schema: { code: "string(python)|null", text: "string|null(FINAL: 접두사로 최종답변)", rationale: "string", done: "boolean" },
    });

    let raw: string;
    try {
      raw = await this.model.complete({ system: RLM_SYSTEM, prompt, json: true });
    } catch (e) {
      emit({ type: "error", text: `[모델오류] ${(e as Error).message}` });
      return null;
    }
    const parsed = safeJson(raw);
    if (!parsed) return null;
    if (parsed.done === true && !parsed.code && !parsed.text) return null;
    const out: { code?: string; text?: string; rationale: string; done: boolean } = {
      rationale: String(parsed.rationale ?? "코드 스텝"),
      done: parsed.done === true,
    };
    if (typeof parsed.code === "string" && parsed.code.trim()) out.code = parsed.code;
    if (typeof parsed.text === "string" && parsed.text.trim()) out.text = parsed.text;
    return out.code || out.text || out.done ? out : null;
  }
}

function resultSummary(r: ReplStepResult): string {
  if (r.syntax) return `구문 오류(미실행, 모델이 수정) — ${firstLine(r.syntax) || ""}`;
  if (r.danger) return `안전차단(미실행): ${r.danger}`;
  if (r.timedOut) return `타임아웃 — 요청 ${r.requests}건, REPL 재시작`;
  if (r.exc) return `코드 예외 — ${firstLine(r.exc) || ""}`;
  const parts = [`요청 ${r.requests}건`];
  if (r.blockedRequests) parts.push(`scope차단 ${r.blockedRequests}건`);
  if (r.findings.length) parts.push(`발견 ${r.findings.length}건`);
  if (r.memos?.length) parts.push(`기억 ${r.memos.length}건`);
  if (r.stdout.trim()) parts.push(`출력 ${r.stdout.trim().length}자`);
  return parts.join(" · ");
}

function firstLine(s: string): string {
  return s.split("\n").find((l) => l.trim())?.trim() ?? "";
}
function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function indent(code: string): string {
  return code.split("\n").map((l) => "    │ " + l).join("\n");
}
function safeJson(raw: string): Record<string, any> | null {
  try {
    const s = raw.indexOf("{");
    const e = raw.lastIndexOf("}");
    if (s < 0 || e < 0) return null;
    return JSON.parse(raw.slice(s, e + 1));
  } catch {
    return null;
  }
}