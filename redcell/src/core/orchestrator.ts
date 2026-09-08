/**
 * Orchestrator — RedCell 의 실행 루프.
 *
 * 자기발전 루프(self-improving loop):
 *   recall(과거 학습) → plan(모델) → gate(ScopeGuard) → act(툴)
 *     → observe(fingerprint 갱신) → record(플레이북 통계) → distill(새 학습)
 *
 * 모든 행동은 ScopeGuard 를 통과해야만 실행된다. 통과 못하면 그 액션은 건너뛴다.
 */

import { ScopeGuard, type Target } from "../scope/scope-guard.js";
import { SkillMemory, type Fingerprint, type Phase } from "../memory/skill-memory.js";
import type {
  EngagementLog,
  EngagementFinding,
  ModelAdapter,
  ProposedAction,
  Tool,
  ToolBox,
} from "./types.js";
import { harvestFromResult } from "./credential-harvest.js";
import { OPT_IN_TOOLS } from "../tools/toolbox.js";

const PHASES: Phase[] = ["recon", "enumerate", "exploit", "post"];

/** 인가 파일 자격증명 + 실행 중 수집한 자격증명을 합친다(인가 파일 우선). */
function mergeAuth(
  base: Record<string, string> | undefined,
  harvested: Record<string, string>,
  session?: Record<string, string>,
): Record<string, string> | undefined {
  // 우선순위: 로그인 세션(가장 신선) > 정적 credentials > 실행 중 수확.
  const merged = { ...harvested, ...(base ?? {}), ...(session ?? {}) };
  return Object.keys(merged).length ? merged : undefined;
}

/**
 * 실행 중 실시간으로 방출되는 구조화 이벤트.
 * 데스크톱 앱(redcell-desktop)이 이걸 NDJSON 으로 받아 좌측 로그/발견 패널을 갱신한다.
 * 모든 이벤트는 사람이 읽을 `text` 를 포함하며, 이 text 는 transcript 와 1:1 로 일치한다.
 */
export type OrchestratorEvent =
  | { type: "authorized"; text: string; target: Target; goal: string }
  | { type: "blocked"; text: string; tool?: string; phase?: Phase }
  | { type: "phase"; text: string; phase: Phase }
  | { type: "recall"; text: string; phase: Phase; count: number }
  | { type: "action"; text: string; phase: Phase; tool: string; rationale: string; args: Record<string, unknown> }
  | { type: "tool_result"; text: string; phase: Phase; tool: string; ok: boolean; summary: string; severity?: EngagementFinding["severity"] }
  | { type: "finding"; text: string; finding: EngagementFinding }
  | { type: "distilled"; text: string; id: string; title: string }
  | { type: "reflect"; text: string; round: number }
  | { type: "reward"; text: string; step: number; value: number }
  | { type: "verify"; text: string; verdict: "achieved" | "partial" | "unclear"; ratio: number }
  | { type: "note"; text: string }
  | { type: "error"; text: string }
  | { type: "done"; text: string; log: EngagementLog };

export interface OrchestratorOpts {
  /** phase 당 최대 액션 수(폭주 방지) */
  maxActionsPerPhase?: number;
  /** exploit/post 단계 진입 허용 여부. 기본 true 지만 dry-run 시 false. */
  allowActivePhases?: boolean;
  /** 실시간 이벤트 훅. 각 단계·발견·차단마다 호출된다(스트리밍 UI 연결점). */
  onEvent?: (e: OrchestratorEvent) => void;
  /** 로그인/프록시 세션 컨텍스트. 모든 툴 요청에 병합된다. */
  session?: SessionContext;
  /**
   * 명시적으로 켠 opt-in 프로브 이름들(logic_probe·cache_poison_probe 등). 모델이 여기에 없는
   * OPT_IN_TOOLS 를 제안하면 실행을 차단한다(대상별 동의 없이는 부작용성 프로브 금지).
   */
  enabledOptIns?: string[];
  /**
   * 커버리지 전수 모드(--max). 모델 계획이 끝난 뒤 해당 phase 의 아직 안 쓴 툴을 전부 1회씩
   * 추가 실행한다(모델이 몰라서 놓친 표면까지 뒤짐). argsFor 로 기본 인자를 생성한다.
   */
  coverage?: boolean;
  /** 툴별 기본 인자 생성기(보통 cli 의 autoArgsFor). coverage 모드에서 사용. */
  argsFor?: (tool: string, fp: Fingerprint) => Record<string, unknown>;
}

/** 로그인·프록시로 확립된 세션(모든 툴 요청 공유). */
export interface SessionContext {
  /** 로그인으로 얻은 인증 헤더(토큰 등). */
  auth?: Record<string, string>;
  /** 세션 쿠키 jar. */
  jar?: import("../net/http-client.js").CookieJar;
  /** 프록시 URL(Burp/ZAP 경유). */
  proxy?: string;
}

export class Orchestrator {
  constructor(
    private readonly guard: ScopeGuard,
    private readonly memory: SkillMemory,
    private readonly model: ModelAdapter,
    private readonly tools: ToolBox,
    private readonly opts: OrchestratorOpts = {},
  ) {}

  async run(target: Target, goal: string): Promise<EngagementLog> {
    const maxActions = this.opts.maxActionsPerPhase ?? 6;
    const log: EngagementLog = {
      target,
      fingerprint: {},
      findings: [],
      usedPlaybooks: [],
      distilled: [],
      transcript: [],
    };

    // transcript 기록과 실시간 이벤트를 항상 함께 방출한다(둘이 어긋나지 않도록).
    const emit = (ev: OrchestratorEvent) => {
      log.transcript.push(ev.text);
      this.opts.onEvent?.(ev);
    };

    // 시작 전 대상 자체가 인가되어 있는지 먼저 확인(fail-closed).
    const gate = this.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      emit({ type: "blocked", text: `[거부] ${gate.reason}` });
      this.opts.onEvent?.({ type: "done", text: "[완료] 인가 거부로 종료.", log });
      return log;
    }
    emit({ type: "authorized", text: `[인가] ${gate.reason} — 목표: ${goal}`, target, goal });

    // 발견 체이닝: 실행 중 대상이 흘린 자격증명을 모아 이후 요청에 실어 보낸다.
    const harvested: Record<string, string> = {};

    /** 하나의 툴 액션을 실행한다(모델 제안·커버리지 전수 공용). 안전 게이트는 동일하게 적용. */
    const runOne = async (
      phase: Phase,
      tool: Tool,
      toolName: string,
      args: Record<string, unknown>,
      rationale: string,
      fromPlaybook: string | undefined,
    ): Promise<void> => {
      // opt-in 게이트: 대상별로 켜지지 않은 부작용성 프로브는 제안돼도 실행하지 않는다.
      if (OPT_IN_TOOLS.has(tool.name) && !(this.opts.enabledOptIns ?? []).includes(tool.name)) {
        emit({
          type: "blocked",
          phase,
          tool: tool.name,
          text: `[차단] ${tool.name}: opt-in 프로브 미승인 — authorization.yaml optional_probes 또는 --enable 로 대상별 승인이 필요합니다.`,
        });
        return;
      }

      emit({
        type: "action",
        phase,
        tool: tool.name,
        rationale,
        args,
        text: `[${phase}] → ${toolName}(${JSON.stringify(args)})${rationale ? " · " + rationale : ""}`,
      });

      // 핵심: 실행 직전 ScopeGuard 재확인(툴의 intent 기준).
      const decision = this.guard.check({ ...target, intent: tool.intent });
      if (!decision.allowed) {
        emit({ type: "blocked", phase, tool: tool.name, text: `[차단] ${toolName}: ${decision.reason}` });
        return;
      }

      const auth = mergeAuth(this.guard.authHeaders, harvested, this.opts.session?.auth);
      const res = await tool.run(args, {
        target,
        rps: this.guard.requestsPerSecond,
        auth,
        jar: this.opts.session?.jar,
        proxy: this.opts.session?.proxy,
        validateIp: (h, ip) => this.guard.checkResolvedIp(h, ip).allowed,
      });

      // 발견 체이닝: 결과에서 노출된 자격증명을 이후 요청용으로 수집.
      const hv = harvestFromResult(res);
      for (const [k, v] of Object.entries(hv.headers)) {
        if (!(k in harvested)) {
          harvested[k] = v;
          emit({ type: "note", text: `[체이닝] ${toolName} 노출 자격증명 재사용: ${hv.notes.join(", ")}` });
        }
      }

      if (res.fingerprint) log.fingerprint = mergeFingerprint(log.fingerprint, res.fingerprint);

      // 이 액션이 playbook 기반이었다면 성공/실패를 학습에 반영.
      if (fromPlaybook) {
        await this.memory.record(fromPlaybook, res.ok ? "success" : "failure");
        if (!log.usedPlaybooks.includes(fromPlaybook)) log.usedPlaybooks.push(fromPlaybook);
      }

      // 단일 발견(기존 툴 규약: data.title) + 다중 발견(python_exec: data.findings) 통합 수집.
      const finding = this.toFinding(phase, { tool: toolName, args, rationale }, res);
      emit({
        type: "tool_result",
        phase,
        tool: tool.name,
        ok: res.ok,
        summary: res.summary,
        severity: finding?.severity,
        text: `[${phase}] ${toolName}: ${res.summary}`,
      });
      if (finding) {
        log.findings.push(finding);
        emit({ type: "finding", finding, text: `[발견] (${finding.severity}) ${finding.title}` });
      }
      const multi = (res.data as { findings?: EngagementFinding[] } | undefined)?.findings;
      if (Array.isArray(multi)) {
        for (const f of multi) {
          if (!f?.title || log.findings.some((x) => x.title === f.title)) continue;
          const ff: EngagementFinding = {
            phase,
            severity: f.severity ?? "info",
            title: f.title,
            detail: rationale,
            evidence: f.evidence,
            impact: f.impact,
          };
          log.findings.push(ff);
          emit({ type: "finding", finding: ff, text: `[발견] (${ff.severity}) ${ff.title}` });
        }
      }
    };


    for (const phase of PHASES) {
      if ((phase === "exploit" || phase === "post") && this.opts.allowActivePhases === false) {
        emit({ type: "note", text: `[건너뜀] active phase(${phase}) 비활성화됨(dry-run).` });
        continue;
      }

      emit({ type: "phase", text: `[phase] ${phase} 시작`, phase });

      const recalled = this.memory.recall(log.fingerprint, phase, 5);
      if (recalled.length > 0) {
        emit({
          type: "recall",
          phase,
          count: recalled.length,
          text:
            `[${phase}] 과거 학습 ${recalled.length}건 recall: ` +
            recalled.map((r) => `${r.playbook.title}(${r.score.toFixed(2)})`).join(", "),
        });
      }

      for (let i = 0; i < maxActions; i++) {
        const action = await this.plan(phase, target, goal, log.fingerprint, recalled.map((r) => r.playbook), log, emit);
        if (!action) {
          emit({ type: "note", text: `[${phase}] 모델이 이 단계 종료를 선언.` });
          break;
        }

        const tool = this.tools.get(action.tool);
        if (!tool) {
          emit({ type: "note", text: `[${phase}] 알 수 없는 툴: ${action.tool} — 건너뜀.` });
          continue;
        }
        await runOne(phase, tool, action.tool, action.args, action.rationale, action.fromPlaybook);
      }

      // 커버리지 전수(--max 공격 모드): 모델 계획이 소진된 뒤, 이번 phase 의 아직 안 쓴 툴을
      // 전부 1회씩 돌려 '모델이 몰라서 놓친 표면'까지 뒤진다. opt-in 게이트는 동일 적용.
      if (this.opts.coverage) {
        const tried = new Set(triedTools(log.transcript, phase));
        for (const t of this.tools.list()) {
          // python_exec 는 목표 지향(모델 제안)일 때만 — 기본 인자로는 실행 의미가 없다.
          if (t.name === "python_exec" || t.intent !== phase || tried.has(t.name)) continue;
          const args = (this.opts.argsFor ? this.opts.argsFor(t.name, log.fingerprint) : {}) ?? {};
          await runOne(phase, t, t.name, args, "커버리지(전수 시도)", undefined);
        }
      }
    }

    // 자기발전: 이번 engagement 에서 성공한 흐름을 새 playbook 으로 distill.
    await this.selfImprove(log, emit);
    this.opts.onEvent?.({ type: "done", text: "[완료] engagement 종료.", log });
    return log;
  }

  /** 모델에게 다음 액션 하나를 제안받는다. null 이면 단계 종료. */
  private async plan(
    phase: Phase,
    target: Target,
    goal: string,
    fp: Fingerprint,
    playbooks: { id: string; title: string; steps: unknown[] }[],
    log: EngagementLog,
    emit: (e: OrchestratorEvent) => void,
  ): Promise<(ProposedAction & { fromPlaybook?: string }) | null> {
    const system =
      "너는 인가된 침투테스트를 돕는 창의적 화이트해커 조수다. 오직 scope 안의 대상만 다룬다. " +
      "파괴적/DoS 행위는 제안하지 않는다. " +
      "핵심 원칙: 한 가지 방법에 갇히지 말고 서로 다른 공격 표면을 발산적으로 탐색하라. " +
      "같은 툴/같은 파라미터를 반복하지 말고, 이번 단계에서 아직 시도하지 않은 새로운 벡터를 골라라 " +
      "(예: 웹이면 XSS·경로조작·오픈리다이렉트·SSRF·IDOR·CORS·노출파일·GraphQL 등 다양한 각도). " +
      "이미 발견한 fingerprint/엔드포인트가 있으면 그것을 재료로 다음 액션의 인자를 구체화하라. " +
      "응답은 반드시 JSON 하나로만 한다.";
    const tried = triedTools(log.transcript, phase);
    const prompt = JSON.stringify({
      instruction:
        `현재 phase=${phase}. 목표=${goal}. 다음에 실행할 액션 1개를 제안하라. ` +
        `아래 already_tried 에 있는 접근은 피하고 새로운 벡터를 시도하라. ` +
        `이 단계에서 시도할 만한 서로 다른 벡터를 모두 소진했으면 {\"done\":true} 를 반환하라.`,
      target,
      known_fingerprint: fp,
      recalled_playbooks: playbooks.map((p) => ({ id: p.id, title: p.title })),
      available_tools: this.tools.list().map((t) => ({ name: t.name, intent: t.intent, description: t.description })),
      already_tried: tried,
      hint: tried.length > 0 ? "지금까지 성과가 없다면 관점을 바꿔 다른 부류의 취약점을 노려라(발산/백트래킹)." : undefined,
      recent_transcript: log.transcript.slice(-8),
      response_schema: { tool: "string", args: "object", rationale: "string", fromPlaybook: "string?", done: "boolean?" },
    });

    let raw: string;
    try {
      raw = await this.model.complete({ system, prompt, json: true });
    } catch (e) {
      emit({ type: "error", text: `[모델오류] ${(e as Error).message}` });
      return null;
    }
    const parsed = safeJson(raw);
    if (!parsed || parsed.done === true || !parsed.tool) return null;
    return {
      tool: String(parsed.tool),
      args: (parsed.args as Record<string, unknown>) ?? {},
      rationale: String(parsed.rationale ?? ""),
      fromPlaybook: parsed.fromPlaybook ? String(parsed.fromPlaybook) : undefined,
    };
  }

  private toFinding(phase: Phase, action: ProposedAction, res: { ok: boolean; summary: string; data?: unknown }): EngagementFinding | null {
    if (!res.ok) return null;
    const d = res.data as { severity?: EngagementFinding["severity"]; title?: string; evidence?: string; impact?: string } | undefined;
    if (!d?.title) return null;
    return {
      phase,
      severity: d.severity ?? "info",
      title: d.title,
      detail: action.rationale || res.summary,
      evidence: d.evidence,
      impact: d.impact,
    };
  }

  /** engagement 종료 후 성공 흐름을 재사용 가능한 playbook 으로 저장. */
  private async selfImprove(log: EngagementLog, emit: (e: OrchestratorEvent) => void): Promise<void> {
    const wins = log.findings.filter((f) => f.severity !== "info");
    if (wins.length === 0 || !log.fingerprint.service) return;

    for (const phase of ["exploit", "enumerate", "recon"] as Phase[]) {
      const phaseWins = wins.filter((w) => w.phase === phase);
      if (phaseWins.length === 0) continue;
      const pb = await this.memory.distill({
        title: `[학습] ${log.fingerprint.service} — ${phaseWins[0].title}`,
        phase,
        match: log.fingerprint,
        steps: phaseWins.map((w) => ({ action: w.title, expect: w.evidence })),
        tags: ["distilled", log.fingerprint.service],
      });
      log.distilled.push(pb);
      emit({ type: "distilled", id: pb.id, title: pb.title, text: `[자기발전] 새 playbook 저장: ${pb.title} (id=${pb.id})` });
    }
  }
}

/**
 * transcript 에서 "현재 phase 에 이미 시도한 툴" 이름을 뽑는다.
 * 액션 로그 형식 `[phase] → tool(...)` 를 파싱한다(발산/중복회피 힌트용).
 */
function triedTools(transcript: string[], phase: Phase): string[] {
  const out = new Set<string>();
  const re = new RegExp(`^\\[${phase}\\] → (\\w+)\\(`);
  for (const line of transcript) {
    const m = re.exec(line);
    if (m) out.add(m[1]);
  }
  return [...out];
}

function mergeFingerprint(a: Fingerprint, b: Fingerprint): Fingerprint {
  return {
    service: b.service ?? a.service,
    version: b.version ?? a.version,
    os: b.os ?? a.os,
    tech: dedupe([...(a.tech ?? []), ...(b.tech ?? [])]),
    indicators: dedupe([...(a.indicators ?? []), ...(b.indicators ?? [])]),
  };
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs.map((x) => x.trim()).filter(Boolean))];
}

function safeJson(raw: string): (Record<string, any>) | null {
  try {
    const s = raw.indexOf("{");
    const e = raw.lastIndexOf("}");
    if (s < 0 || e < 0) return null;
    return JSON.parse(raw.slice(s, e + 1));
  } catch {
    return null;
  }
}
