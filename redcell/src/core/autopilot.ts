/**
 * AutoPilot — "알아서 시도하고 학습하며 진행하는" 자율 인게이지먼트 드라이버.
 *
 * 구조:
 *   phase(recon→enumerate→exploit→post) 루프
 *     └ 각 단계에서 bandit 이 그 단계 툴들 중 하나를 선택(탐색/활용)
 *       → scope 게이트 → 실행 → 결과로 보상 계산 → bandit·memory 학습
 *       → fingerprint·findings 누적 → 진전 없으면 다음 단계로
 *   종료 후: 성공 흐름 distill(playbook) + bandit 영속화 + 리포트
 *
 * 모델 없이도 완전 자율 동작(경험 기반 학습). 선택적으로 proposer 로 후보를 확장.
 * 세션 간 학습은 BanditStore + SkillMemory 로 누적된다(실행할수록 똑똑해짐).
 */

import { ScopeGuard, type Target } from "../scope/scope-guard.js";
import { SkillMemory, type Fingerprint, type Phase } from "../memory/skill-memory.js";
import { ContextualBandit } from "../explore/bandit.js";
import type { BanditStore } from "../explore/bandit-store.js";
import type { EngagementFinding, ToolBox, ProposedAction } from "./types.js";

const PHASES: Phase[] = ["recon", "enumerate", "exploit", "post"];
const PHASE_INTENTS: Record<Phase, Array<Target["intent"]>> = {
  recon: ["recon"],
  enumerate: ["enumerate"],
  exploit: ["exploit"],
  post: ["post"],
  report: [],
};

const SEV_REWARD: Record<string, number> = { critical: 1, high: 1, medium: 0.6, low: 0.4, info: 0 };

export interface AutoPilotProposer {
  /** 단계별 추가 후보 액션(툴+args). 모델 연결 지점(선택). */
  propose(phase: Phase, fp: Fingerprint, history: string[]): Promise<ProposedAction[]> | ProposedAction[];
}

export interface AutoPilotOpts {
  maxStepsPerPhase?: number;
  globalBudget?: number; // 전체 스텝 상한
  proposer?: AutoPilotProposer;
  banditStore?: BanditStore; // 주면 종료 시 저장
  /** 실행할 액션 args 를 툴별로 보정하는 훅(발견 경로 활용 등) */
  argsFor?: (toolName: string, fp: Fingerprint) => Record<string, unknown>;
}

export interface AutoReport {
  target: Target;
  goal: string;
  fingerprint: Fingerprint;
  findings: EngagementFinding[];
  usedPlaybooks: string[];
  steps: number;
  solved: boolean;
  transcript: string[];
}

export class AutoPilot {
  constructor(
    private readonly guard: ScopeGuard,
    private readonly memory: SkillMemory,
    private readonly bandit: ContextualBandit,
    private readonly tools: ToolBox,
    private readonly opts: AutoPilotOpts = {},
  ) {}

  async run(target: Target, goal: string): Promise<AutoReport> {
    const maxPerPhase = this.opts.maxStepsPerPhase ?? 6;
    const globalBudget = this.opts.globalBudget ?? 40;
    const report: AutoReport = {
      target,
      goal,
      fingerprint: {},
      findings: [],
      usedPlaybooks: [],
      steps: 0,
      solved: false,
      transcript: [],
    };

    // 대상 자체 인가 확인(fail-closed).
    const gate = this.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      report.transcript.push(`[거부] ${gate.reason}`);
      return report;
    }
    report.transcript.push(`[시작] ${target.host} — 목표: ${goal}`);

    const seenFacts = new Set<string>();

    for (const phase of PHASES) {
      if (report.solved || report.steps >= globalBudget) break;

      // 이 단계 후보 툴(intent 매칭) + proposer 확장.
      const intents = PHASE_INTENTS[phase];
      let candidates = this.tools.list().filter((t) => intents.includes(t.intent)).map((t) => t.name);
      const proposed = this.opts.proposer ? await this.opts.proposer.propose(phase, report.fingerprint, report.transcript.slice(-6)) : [];
      const proposedByName = new Map(proposed.map((p) => [p.tool, p] as const));
      candidates = [...new Set([...candidates, ...proposed.map((p) => p.tool)])].filter((n) => this.tools.get(n));
      if (candidates.length === 0) continue;

      // 과거 학습 recall(참고 로그).
      const recalled = this.memory.recall(report.fingerprint, phase, 3);
      if (recalled.length) report.transcript.push(`[${phase}] recall ${recalled.length}건: ${recalled.map((r) => r.playbook.title).join(", ")}`);

      const context = () => `${phase}|${fpSignature(report.fingerprint)}`;
      let noProgress = 0;

      for (let i = 0; i < maxPerPhase && report.steps < globalBudget; i++) {
        const ctxKey = context();
        const action = this.bandit.select(ctxKey, candidates);
        const tool = this.tools.get(action)!;

        // 실행 직전 scope 재확인.
        const decision = this.guard.check({ ...target, intent: tool.intent });
        if (!decision.allowed) {
          report.transcript.push(`[차단] ${tool.name}: ${decision.reason}`);
          this.bandit.update(ctxKey, action, 0);
          continue;
        }

        const args = proposedByName.get(action)?.args ?? this.opts.argsFor?.(action, report.fingerprint) ?? {};
        report.steps += 1;
        const res = await tool.run(args, { target, rps: this.guard.requestsPerSecond });

        // 관측 → fingerprint 병합 + novelty.
        let novelty = 0;
        if (res.fingerprint) {
          const before = seenFacts.size;
          report.fingerprint = mergeFp(report.fingerprint, res.fingerprint, seenFacts);
          novelty = seenFacts.size - before;
        }

        // 보상 계산.
        const d = res.data as { severity?: string; title?: string; evidence?: string } | undefined;
        const sev = d?.severity ?? "info";
        let reward = SEV_REWARD[sev] ?? 0;
        if (reward === 0) reward = novelty > 0 ? 0.3 : 0.05;
        this.bandit.update(ctxKey, action, reward);

        report.transcript.push(`[${phase}] ${tool.name}: ${res.summary} (r=${reward.toFixed(2)})`);

        // 유의미 발견 수집(중복 제목 제외).
        if (d?.title && sev !== "info" && !report.findings.some((f) => f.title === d.title)) {
          report.findings.push({ phase, severity: sev as EngagementFinding["severity"], title: d.title, detail: res.summary, evidence: d.evidence });
        }
        // playbook 기반이면 결과 반영.
        const pbId = proposedByName.get(action)?.fromPlaybook;
        if (pbId) {
          await this.memory.record(pbId, reward > 0.3 ? "success" : "failure");
          if (!report.usedPlaybooks.includes(pbId)) report.usedPlaybooks.push(pbId);
        }

        // 진전 판정.
        if (reward >= 0.3) noProgress = 0;
        else noProgress += 1;

        // high/critical 발견 = 목표 달성으로 간주.
        if (sev === "high" || sev === "critical") {
          report.solved = true;
          report.transcript.push(`[성공] ${phase} 단계에서 ${sev} 발견 → 목표 달성으로 종료`);
          break;
        }
        // 모든 후보를 한 번씩 써봤고 진전이 멈추면 다음 단계로.
        if (noProgress >= 2 && candidates.every((c) => this.bandit.value(ctxKey, c) !== undefined)) {
          report.transcript.push(`[${phase}] 진전 없음 → 다음 단계`);
          break;
        }
      }
    }

    await this.selfImprove(report);
    if (this.opts.banditStore) await this.opts.banditStore.save(this.bandit);
    return report;
  }

  /** 성공 흐름을 재사용 playbook 으로 distill. */
  private async selfImprove(report: AutoReport): Promise<void> {
    const wins = report.findings.filter((f) => f.severity !== "info" && f.severity !== "low");
    if (wins.length === 0 || !report.fingerprint.service) return;
    for (const phase of ["exploit", "enumerate"] as Phase[]) {
      const pw = wins.filter((w) => w.phase === phase);
      if (!pw.length) continue;
      const pb = await this.memory.distill({
        title: `[auto] ${report.fingerprint.service} — ${pw[0].title}`,
        phase,
        match: report.fingerprint,
        steps: pw.map((w) => ({ action: w.title, expect: w.evidence })),
        tags: ["autopilot", report.fingerprint.service],
      });
      report.transcript.push(`[학습] playbook 저장: ${pb.title}`);
    }
  }
}

function fpSignature(fp: Fingerprint): string {
  return [fp.service ?? "?", fp.version ?? "?", ...(fp.tech ?? []).slice().sort()].join("/");
}

function mergeFp(a: Fingerprint, b: Fingerprint, seen: Set<string>): Fingerprint {
  for (const f of b.indicators ?? []) seen.add(f);
  for (const t of b.tech ?? []) seen.add(`tech:${t}`);
  return {
    service: a.service ?? b.service,
    version: a.version ?? b.version,
    os: a.os ?? b.os,
    tech: [...new Set([...(a.tech ?? []), ...(b.tech ?? [])])],
    indicators: [...new Set([...(a.indicators ?? []), ...(b.indicators ?? [])])],
  };
}
