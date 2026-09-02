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
  ToolBox,
} from "./types.js";

const PHASES: Phase[] = ["recon", "enumerate", "exploit", "post"];

export interface OrchestratorOpts {
  /** phase 당 최대 액션 수(폭주 방지) */
  maxActionsPerPhase?: number;
  /** exploit/post 단계 진입 허용 여부. 기본 true 지만 dry-run 시 false. */
  allowActivePhases?: boolean;
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

    // 시작 전 대상 자체가 인가되어 있는지 먼저 확인(fail-closed).
    const gate = this.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      log.transcript.push(`[거부] ${gate.reason}`);
      return log;
    }
    log.transcript.push(`[인가] ${gate.reason} — 목표: ${goal}`);

    for (const phase of PHASES) {
      if ((phase === "exploit" || phase === "post") && this.opts.allowActivePhases === false) {
        log.transcript.push(`[건너뜀] active phase(${phase}) 비활성화됨(dry-run).`);
        continue;
      }

      const recalled = this.memory.recall(log.fingerprint, phase, 5);
      if (recalled.length > 0) {
        log.transcript.push(
          `[${phase}] 과거 학습 ${recalled.length}건 recall: ` +
            recalled.map((r) => `${r.playbook.title}(${r.score.toFixed(2)})`).join(", "),
        );
      }

      for (let i = 0; i < maxActions; i++) {
        const action = await this.plan(phase, target, goal, log.fingerprint, recalled.map((r) => r.playbook), log);
        if (!action) {
          log.transcript.push(`[${phase}] 모델이 이 단계 종료를 선언.`);
          break;
        }

        const tool = this.tools.get(action.tool);
        if (!tool) {
          log.transcript.push(`[${phase}] 알 수 없는 툴: ${action.tool} — 건너뜀.`);
          continue;
        }

        // 핵심: 실행 직전 ScopeGuard 재확인(툴의 intent 기준).
        const decision = this.guard.check({ ...target, intent: tool.intent });
        if (!decision.allowed) {
          log.transcript.push(`[차단] ${tool.name}: ${decision.reason}`);
          continue;
        }

        const res = await tool.run(action.args, { target, rps: this.guard.requestsPerSecond });
        log.transcript.push(`[${phase}] ${tool.name}: ${res.summary}`);

        if (res.fingerprint) log.fingerprint = mergeFingerprint(log.fingerprint, res.fingerprint);

        // 이 액션이 playbook 기반이었다면 성공/실패를 학습에 반영.
        if (action.fromPlaybook) {
          await this.memory.record(action.fromPlaybook, res.ok ? "success" : "failure");
          if (!log.usedPlaybooks.includes(action.fromPlaybook)) log.usedPlaybooks.push(action.fromPlaybook);
        }

        const finding = this.toFinding(phase, action, res);
        if (finding) log.findings.push(finding);
      }
    }

    // 자기발전: 이번 engagement 에서 성공한 흐름을 새 playbook 으로 distill.
    await this.selfImprove(log);
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
  ): Promise<(ProposedAction & { fromPlaybook?: string }) | null> {
    const system =
      "너는 인가된 침투테스트를 돕는 화이트해커 조수다. 오직 scope 안의 대상만 다룬다. " +
      "파괴적/DoS 행위는 제안하지 않는다. 응답은 반드시 JSON 하나로만 한다.";
    const prompt = JSON.stringify({
      instruction:
        `현재 phase=${phase}. 목표=${goal}. 다음에 실행할 액션 1개를 제안하라. ` +
        `더 할 것이 없으면 {\"done\":true} 를 반환하라.`,
      target,
      known_fingerprint: fp,
      recalled_playbooks: playbooks.map((p) => ({ id: p.id, title: p.title })),
      available_tools: this.tools.list().map((t) => ({ name: t.name, intent: t.intent, description: t.description })),
      recent_transcript: log.transcript.slice(-6),
      response_schema: { tool: "string", args: "object", rationale: "string", fromPlaybook: "string?", done: "boolean?" },
    });

    let raw: string;
    try {
      raw = await this.model.complete({ system, prompt, json: true });
    } catch (e) {
      log.transcript.push(`[모델오류] ${(e as Error).message}`);
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
    const d = res.data as { severity?: EngagementFinding["severity"]; title?: string; evidence?: string } | undefined;
    if (!d?.title) return null;
    return {
      phase,
      severity: d.severity ?? "info",
      title: d.title,
      detail: action.rationale || res.summary,
      evidence: d.evidence,
    };
  }

  /** engagement 종료 후 성공 흐름을 재사용 가능한 playbook 으로 저장. */
  private async selfImprove(log: EngagementLog): Promise<void> {
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
      log.transcript.push(`[자기발전] 새 playbook 저장: ${pb.title} (id=${pb.id})`);
    }
  }
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
