/**
 * PythonAgent — RedCell 의 "absolute-agent" 코어(prime-agent RLM 이식).
 *
 * 고정 툴박스에서 고르는 대신, 모델이 **파이썬 코드를 스스로 작성 → 실행 → 결과 관찰 →
 * 다른 방법 모색**을 반복하며 대상을 공략한다. 한 번의 시도가 통하지 않으면 관점을 바꿔
 * 새 코드를 쓴다(발산·백트래킹). 모든 대상 통신은 broker(ScopeGuard) 를 통과한다.
 *
 *   관측(직전 시도의 출력) → 코드 작성(모델) → 안전 실행(broker) → 발견 수집 → 반복
 *
 * 산출물은 기존 EngagementLog 형태라 리포트·시각 상황판·데스크톱 패널에 그대로 흐른다.
 */

import type { ScopeGuard, Target } from "../scope/scope-guard.js";
import type { ModelAdapter, EngagementLog, EngagementFinding } from "../core/types.js";
import type { OrchestratorEvent, SessionContext } from "../core/orchestrator.js";
import { runPython, type PyResult } from "./broker.js";

export interface PythonAgentOpts {
  /** 코드 작성→실행 반복 최대 횟수(기본 8). */
  maxIterations?: number;
  /** 각 코드 실행 타임아웃 ms(기본 15000). */
  stepTimeoutMs?: number;
  /** 실시간 이벤트 훅(Orchestrator 와 동일 형식 → 데스크톱 패널이 그대로 소비). */
  onEvent?: (e: OrchestratorEvent) => void;
  /** 로그인/프록시 세션(브로커 요청에 병합). */
  session?: SessionContext;
  python?: string;
  /**
   * OS 격리 정책(기본 "required"). "required"=격리 백엔드 없으면 신뢰불가 코드 실행 거부(fail-closed),
   * "best-effort"=경고 후 in-process 샌드박스만으로 실행, "off"=격리 강제 안 함(신뢰 어댑터/테스트용).
   */
  isolation?: "required" | "best-effort" | "off";
  /**
   * 코드 생성원 신뢰 여부(선택). 미지정 시 model.trusted 로부터 유도된다.
   * 신뢰되면 OS 격리 없이도 실행한다(MockCoder 등). 라이브 LLM 은 신뢰불가.
   */
  trusted?: boolean;
}

/** 한 번의 코드 시도 기록(다음 프롬프트에 관측으로 되먹임). */
interface Attempt {
  code: string;
  rationale: string;
  result: PyResult;
}

const SYSTEM =
  "너는 인가된 침투테스트를 돕는 창의적 화이트해커다. 파이썬 코드를 직접 작성해 대상을 " +
  "탐색·공략하되, 다음 규칙을 반드시 지킨다:\n" +
  "1) 대상과의 모든 HTTP 는 미리 정의된 헬퍼 `rc` 로만 한다: rc.get(path), rc.post(path, data=/json=), " +
  "rc.http(method, path_or_url, headers=, body=). 응답은 r.status, r.headers, r.text, r.json() 로 읽는다. " +
  "원시 TCP 조사는 rc.tcp(host, port, payload=None) 이 필요하다(인가 대상 한정 — banner/맞춤 프로토콜). " +
  "쿠키는 호출 간 자동 유지되므로 로그인→보호자원 접근 같은 멀티스텝을 한 코드에서 이어갈 수 있다. " +
  "base64 는 rc.b64e/rc.b64d 를 쓴다. requests/urllib/socket 등 직접 네트워크는 금지(정적 스캔 + AST 화이트리스트가 실행 자체를 막는다).\n" +
  "2) 취약 신호를 확인하면 rc.finding(title, severity, evidence=, impact=) 로 보고한다 " +
  "(severity: info|low|medium|high|critical). 확신이 없으면 rc.log(...) 로 관찰만 남긴다.\n" +
  "3) 인가된 대상이면 공격적으로 파고들어라: 쿠키 탈취/위조, SID·토큰 우회, SSRF(인가 호스트 경유), " +
  "낮은 난이도 순 SQLi·XSS·경로조작·SSTI·인증우회·API 남용을 실제 페이로드로 시도하고 결과까지 확인하라. " +
  "단, scope 밖 호스트 접근·데이터 파괴/변조·DoS(폭주/무한루프)는 금지 — 신호(signal) 확인만.\n" +
  "4) 한 번에 한 가지 방법을 짧게 시도한다. 직전 출력을 보고, 통했으면 심화하고 아니면 다른 벡터로 바꾼다.\n" +
  "5) 코드를 보내기 전에 문법(괄호/들여쓰기)을 스스로 검사하라. 문법 오류는 실행되지 않고 그대로 반환되므로 시도가 낭비된다." +
  "응답은 반드시 JSON 하나로만: {\"code\": \"<python>\", \"rationale\": \"<한 줄 근거>\", \"done\": <bool>}.";

export class PythonAgent {
  constructor(
    private readonly guard: ScopeGuard,
    private readonly model: ModelAdapter,
    private readonly opts: PythonAgentOpts = {},
  ) {}

  async run(target: Target, goal: string): Promise<EngagementLog> {
    const maxIter = this.opts.maxIterations ?? 8;
    const log: EngagementLog = {
      target,
      fingerprint: {},
      findings: [],
      usedPlaybooks: [],
      distilled: [],
      transcript: [],
    };
    const emit = (ev: OrchestratorEvent) => {
      log.transcript.push(ev.text);
      this.opts.onEvent?.(ev);
    };

    // 시작 전 대상 인가 확인(fail-closed).
    const gate = this.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      emit({ type: "blocked", text: `[거부] ${gate.reason}` });
      this.opts.onEvent?.({ type: "done", text: "[완료] 인가 거부로 종료.", log });
      return log;
    }
    emit({ type: "authorized", text: `[인가] ${gate.reason} — 목표: ${goal}`, target, goal });
    emit({ type: "phase", text: "[phase] python-agent (코드 작성→실행 반복) 시작", phase: "exploit" });

    const attempts: Attempt[] = [];
    for (let i = 0; i < maxIter; i++) {
      const plan = await this.planCode(target, goal, attempts, emit);
      if (!plan) {
        emit({ type: "note", text: `[python] 모델이 종료를 선언(또는 더 낼 코드 없음).` });
        break;
      }

      emit({
        type: "action",
        phase: "exploit",
        tool: "python",
        rationale: plan.rationale,
        args: { code: plan.code },
        text: `[python #${i + 1}] 코드 작성 — ${plan.rationale}\n${indent(plan.code)}`,
      });

      const result = await runPython(plan.code, {
        guard: this.guard,
        target,
        auth: this.opts.session?.auth,
        jar: this.opts.session?.jar,
        proxy: this.opts.session?.proxy,
        timeoutMs: this.opts.stepTimeoutMs ?? 15000,
        isolation: this.opts.isolation,
        trusted: this.opts.trusted ?? this.model.trusted === true,
        onRequest: (info) =>
          info.blocked
            ? emit({ type: "blocked", phase: "exploit", tool: "python", text: `[차단] ${info.method} ${info.url}: ${info.blocked}` })
            : undefined,
      });
      attempts.push({ code: plan.code, rationale: plan.rationale, result });

      // 실행 결과를 사람이 읽는 한 줄 + 이벤트로.
      const summary = resultSummary(result);
      emit({ type: "tool_result", phase: "exploit", tool: "python", ok: result.ok, summary, text: `[python #${i + 1}] 실행 결과 — ${summary}` });
      if (result.syntax) {
        // 정책 위반이 아니라 실행 불가능한 문법 오류 — 다음 시도에서 자동 수정된다.
        emit({ type: "note", text: `[구문 오류] 파이썬 문법 오류로 실행되지 않았습니다: ${clip(result.syntax, 300)} — 모델이 다음 시도에서 수정합니다.` });
      }
      if (result.danger) {
        emit({ type: "note", text: `[안전차단] ${result.danger} — 이 코드는 실행하지 않았습니다(인가 범위·파괴성·탈출 보호는 항상 유지).` });
      }
      for (const lg of result.logs) emit({ type: "note", text: `[관찰] ${lg}` });

      // 발견 수집(중복 제목 제외).
      for (const f of result.findings) {
        if (log.findings.some((x) => x.title === f.title)) continue;
        const finding: EngagementFinding = { phase: "exploit", severity: f.severity, title: f.title, detail: plan.rationale, evidence: f.evidence, impact: f.impact };
        log.findings.push(finding);
        emit({ type: "finding", finding, text: `[발견] (${finding.severity}) ${finding.title}` });
      }

      if (plan.done) {
        emit({ type: "note", text: `[python] 모델이 목표 달성/종료를 선언.` });
        break;
      }
    }

    this.opts.onEvent?.({ type: "done", text: `[완료] python-agent 종료 (시도 ${attempts.length}회, 발견 ${log.findings.length}건).`, log });
    return log;
  }

  /** 모델에게 다음 파이썬 코드 한 조각을 받는다. null 이면 종료. */
  private async planCode(
    target: Target,
    goal: string,
    attempts: Attempt[],
    emit: (e: OrchestratorEvent) => void,
  ): Promise<{ code: string; rationale: string; done: boolean } | null> {
    const history = attempts.slice(-4).map((a, i) => ({
      step: attempts.length - Math.min(4, attempts.length) + i + 1,
      code: a.code,
      ok: a.result.ok,
      danger: a.result.danger,
      syntax: a.result.syntax,
      stdout: clip(a.result.stdout, 1200),
      stderr: clip(a.result.stderr, 600),
      requests: a.result.requests,
      blocked: a.result.blockedRequests,
      findings: a.result.findings.map((f) => f.title),
    }));
    const prompt = JSON.stringify({
      instruction:
        `대상=${target.host}${target.port ? ":" + target.port : ""}. 목표=${goal}. ` +
        `직전 시도들의 코드와 출력을 보고, 다음에 실행할 파이썬 코드 1개를 작성하라. ` +
        `아직 확인 안 된 벡터를 노려라(SQLi·XSS·경로조작·인증우회·API 남용·SSTI 등 창의적으로). ` +
        `코드를 보내기 전에 문법(괄호 짝, 들여쓰기)을 스스로 검사하라 — 문법 오류는 실행되지 않고 그대로 반환된다. ` +
        `더 시도할 가치가 없으면 {"done": true} 를 반환하라.`,
      target,
      helper_api:
        "rc.get(path) / rc.post(path, data={}|json={}) / rc.http(method, path_or_url, headers={}, body='') → r.status, r.headers, r.text, r.json(); " +
        "rc.tcp(host, port, payload=b'...'|None, timeout=5) → bytes — 인가 대상에 대한 원시 TCP 조사(banner/맞춤 프로토콜), scope 밖은 rc.ScopeError; " +
        "쿠키는 호출 간 자동 유지(멀티스텝 로그인 플로우 가능); rc.b64e(data)/rc.b64d(s) 로 base64; " +
        "rc.finding(title, severity, evidence=, impact=); rc.log(...)",
      previous_attempts: history,
      response_schema: { code: "string(python)", rationale: "string", done: "boolean?" },
    });

    let raw: string;
    try {
      raw = await this.model.complete({ system: SYSTEM, prompt, json: true });
    } catch (e) {
      emit({ type: "error", text: `[모델오류] ${(e as Error).message}` });
      return null;
    }
    const parsed = safeJson(raw);
    if (!parsed) return null;
    if (parsed.done === true && !parsed.code) return null;
    if (!parsed.code || typeof parsed.code !== "string") return null;
    return { code: parsed.code, rationale: String(parsed.rationale ?? "코드 시도"), done: parsed.done === true };
  }
}

function resultSummary(r: PyResult): string {
  if (r.syntax) return `구문 오류(미실행, 모델이 수정) — ${firstLine(r.syntax) || ""}`;
  if (r.danger) return `안전차단(미실행): ${r.danger}`;
  if (r.timedOut) return `타임아웃 — 요청 ${r.requests}건`;
  if (r.exitCode !== 0) return `오류 종료(code=${r.exitCode}) — ${firstLine(r.stderr) || "stderr 없음"}`;
  const parts = [`요청 ${r.requests}건`];
  if (r.blockedRequests) parts.push(`scope차단 ${r.blockedRequests}건`);
  if (r.findings.length) parts.push(`발견 ${r.findings.length}건`);
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
