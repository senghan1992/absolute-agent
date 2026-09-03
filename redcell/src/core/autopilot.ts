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
import type { EngagementFinding, EngagementLog, ToolBox, ProposedAction, Coverage, GateVerdict } from "./types.js";
import type { OrchestratorEvent, SessionContext } from "./orchestrator.js";
import { harvestFromResult } from "./credential-harvest.js";
import { deriveArgs } from "./target-map.js";
import { httpRequest } from "../net/http-client.js";
import { OPT_IN_TOOLS } from "../tools/toolbox.js";

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
  /** 실시간 이벤트 훅(Orchestrator 와 동일 형식 → 데스크톱 앱이 그대로 소비). */
  onEvent?: (e: OrchestratorEvent) => void;
  /** 로그인/프록시 세션 컨텍스트. 모든 툴 요청에 병합된다. */
  session?: SessionContext;
  /**
   * 게이트용 결정적 전수 모드. 밴딧 선택/조기이탈을 쓰지 않고 각 단계의 모든 후보 툴을
   * 등록 순서대로 정확히 1회씩 실행한다 → 같은 대상이면 항상 같은 커버리지(재현성).
   * 게이트(릴리스 관문)로 쓰려면 반드시 이 모드로 실행해야 한다.
   */
  full?: boolean;
  /**
   * 인증 표면 미점검을 허용(명시적 공개 서비스). 기본 false 면, 자격증명 없이 스캔한
   * 경우 "로그인 뒤" 표면을 못 봤으므로 clean 판정을 inconclusive 로 강등한다(거짓 안전 방지).
   */
  allowUnauth?: boolean;
  /**
   * 명시적으로 켠 opt-in 프로브 이름들(예: logic_probe·cache_poison_probe). 여기에 없는
   * OPT_IN_TOOLS 는 후보에서 제외한다(대상별 동의 없이는 부작용성 프로브를 돌리지 않음).
   */
  enabledOptIns?: string[];
}

/** run() 동안 공유되는 가변 상태(step 헬퍼가 갱신). */
interface RunState {
  report: AutoReport;
  seenFacts: Set<string>;
  harvested: Record<string, string>;
  toolsRun: Set<string>;
  vulnClasses: Set<string>;
  requestErrors: number;
  gotResponse: boolean;
  emit?: (e: OrchestratorEvent) => void;
  /** 중복실행 억제: 동일 (툴+인자) 조합의 결과를 기억해 같은 요청을 다시 쏘지 않는다. */
  ranActions: Map<string, { reward: number; sev: string }>;
}

/** 연결 계층 실패(도달 불가)로 볼 요약 패턴 — '취약점 없음'(정상 응답)과 구분한다. */
const CONN_ERR = /요청 실패|타임아웃|ECONN|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|ECONNRESET|ECONNREFUSED|socket hang up|연결/i;

export interface AutoReport {
  target: Target;
  goal: string;
  fingerprint: Fingerprint;
  findings: EngagementFinding[];
  usedPlaybooks: string[];
  steps: number;
  solved: boolean;
  transcript: string[];
  /** 게이트 커버리지(얼마나 봤는가). */
  coverage: Coverage;
  /** 게이트 판정(clean/findings/inconclusive). */
  verdict: GateVerdict;
  /** 판정 사유(사람이 읽는 한 줄). */
  verdictReason: string;
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
      coverage: emptyCoverage(!!this.opts.full),
      verdict: "inconclusive",
      verdictReason: "미실행",
    };

    const emit = this.opts.onEvent;

    // 대상 자체 인가 확인(fail-closed).
    const gate = this.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      report.transcript.push(`[거부] ${gate.reason}`);
      report.verdict = "inconclusive";
      report.verdictReason = `인가 거부로 스캔 미수행: ${gate.reason}`;
      emit?.({ type: "blocked", text: `[거부] ${gate.reason}` });
      emit?.({ type: "done", text: "[완료] 인가 거부로 종료.", log: asLog(report) });
      return report;
    }
    report.transcript.push(`[시작] ${target.host} — 목표: ${goal}${this.opts.full ? " (결정적 전수 모드)" : ""}`);
    emit?.({ type: "authorized", text: `[인가] ${gate.reason} — 목표: ${goal}`, target, goal });

    // 발견 체이닝: 실행 중 대상이 흘린 자격증명을 모아 이후 요청에 실어 보낸다.
    const st: RunState = {
      report,
      seenFacts: new Set<string>(),
      harvested: {},
      toolsRun: new Set<string>(),
      vulnClasses: new Set<string>(),
      requestErrors: 0,
      gotResponse: false,
      emit,
      ranActions: new Map(),
    };
    // 시도 대상이 된 총 툴 수(intent 가 스캔 단계에 속하는 것). 커버리지 분모.
    // opt-in 미승인 프로브는 애초에 후보에서 제외되므로 분모에서도 뺀다(그래야 "실행 가능한
    // 툴을 전부 돌렸다" = toolsRun==toolsTotal 불변식이 유지된다).
    const scanIntents = new Set<Target["intent"]>(["recon", "enumerate", "exploit", "post"]);
    const enabledOptIns = new Set(this.opts.enabledOptIns ?? []);
    const toolsTotal = this.tools
      .list()
      .filter((t) => scanIntents.has(t.intent))
      .filter((t) => !(OPT_IN_TOOLS.has(t.name) && !enabledOptIns.has(t.name))).length;

    // 게이트(전수) 모드: 도달성부터 빠르게 확인한다(짧은 타임아웃·재시도 없음). 대상이 죽어
    // 있으면 수십 개 툴이 각자 재시도·타임아웃으로 오래 grind 하다 '발견 0'으로 끝나 '통과'로
    // 오인되므로, 스캔을 시작하지 않고 즉시 inconclusive 로 끊는다(거짓 안전 + 90초 hang 방지).
    if (this.opts.full) {
      const reach = await this.reachable(target);
      if (!reach) {
        report.coverage = { ...emptyCoverage(true), toolsTotal };
        report.verdict = "inconclusive";
        report.verdictReason = "대상에 접속하지 못했습니다(연결 실패/타임아웃) — 스캔 미수행, '취약점 없음'이 아닙니다.";
        report.transcript.push(`[판정] INCONCLUSIVE — ${report.verdictReason}`);
        emit?.({ type: "done", text: `[완료] 도달 실패로 종료 (판정=inconclusive).`, log: asLog(report) });
        return report;
      }
      st.gotResponse = true;
    }

    for (const phase of PHASES) {
      // solved 는 "성과 있음" 표시일 뿐 종료 조건이 아니다(발산 유지).
      // 전체 예산 소진 시에만 중단한다.
      if (report.steps >= globalBudget) break;

      // 이 단계 후보 툴(intent 매칭) + proposer 확장.
      const intents = PHASE_INTENTS[phase];
      let candidates = this.tools.list().filter((t) => intents.includes(t.intent)).map((t) => t.name);
      const proposed = this.opts.proposer ? await this.opts.proposer.propose(phase, report.fingerprint, report.transcript.slice(-6)) : [];
      const proposedByName = new Map(proposed.map((p) => [p.tool, p] as const));
      candidates = [...new Set([...candidates, ...proposed.map((p) => p.tool)])].filter((n) => this.tools.get(n));
      // opt-in 게이트: 대상별로 켜지지 않은 부작용성 프로브(logic_probe·cache_poison_probe)는 제외한다.
      const gatedOut = candidates.filter((n) => OPT_IN_TOOLS.has(n) && !enabledOptIns.has(n));
      if (gatedOut.length) {
        candidates = candidates.filter((n) => !gatedOut.includes(n));
        const text = `[opt-in] 미승인 프로브 건너뜀: ${gatedOut.join(", ")} (authorization.yaml optional_probes 또는 --enable 로 대상별 승인 필요)`;
        report.transcript.push(text);
        emit?.({ type: "note", text });
      }
      if (candidates.length === 0) continue;
      emit?.({ type: "phase", text: `[phase] ${phase} 시작 (후보 ${candidates.length}종)`, phase });

      // 과거 학습 recall(참고 로그).
      const recalled = this.memory.recall(report.fingerprint, phase, 3);
      if (recalled.length) {
        const text = `[${phase}] recall ${recalled.length}건: ${recalled.map((r) => r.playbook.title).join(", ")}`;
        report.transcript.push(text);
        emit?.({ type: "recall", phase, count: recalled.length, text });
      }

      const context = () => `${phase}|${fpSignature(report.fingerprint)}`;

      // 결정적 전수(--full) 모드: 밴딧/조기이탈 없이 각 후보를 등록 순서대로 1회씩.
      // 같은 대상이면 항상 같은 커버리지가 나오므로 게이트로 재현 가능하다.
      if (this.opts.full) {
        for (const action of candidates) {
          if (report.steps >= globalBudget) break;
          const r = await this.step(phase, action, proposedByName, st, target, context());
          if (r.sev === "high" || r.sev === "critical") {
            report.solved = true;
            report.transcript.push(`[성과] ${phase} 단계에서 ${r.sev} 발견 — 전수 스윕 계속`);
          }
        }
        continue;
      }

      // 기본(밴딧) 모드: 탐색/활용으로 선택하며 진전이 멈추면 다음 단계로.
      let noProgress = 0;
      for (let i = 0; i < maxPerPhase && report.steps < globalBudget; i++) {
        const ctxKey = context();
        const action = this.bandit.select(ctxKey, candidates);
        const r = await this.step(phase, action, proposedByName, st, target, ctxKey);
        if (r.blocked) continue;

        // 진전 판정.
        if (r.reward >= 0.3) noProgress = 0;
        else noProgress += 1;

        // high/critical 발견은 "성과"로 표시하되 종료하지 않는다(발산형 원칙).
        // recon/enumerate 의 노출 파일 하나로 전체를 끝내면 창의적 exploit 벡터를
        // 전혀 못 본다. 전체 스텝은 globalBudget/maxPerPhase 로 유계라 폭주하지 않는다.
        if (r.sev === "high" || r.sev === "critical") {
          report.solved = true;
          report.transcript.push(`[성과] ${phase} 단계에서 ${r.sev} 발견 — 다른 벡터도 계속 탐색`);
          noProgress = 0;
        }
        // 모든 후보를 한 번씩 써봤고 진전이 멈추면 다음 단계로.
        if (noProgress >= 2 && candidates.every((c) => this.bandit.value(ctxKey, c) !== undefined)) {
          report.transcript.push(`[${phase}] 진전 없음 → 다음 단계`);
          break;
        }
      }
    }

    // 커버리지 확정 + 게이트 판정.
    const authScanned = !!(this.guard.authHeaders || this.opts.session?.auth) || Object.keys(st.harvested).length > 0;
    report.coverage = {
      reachable: st.gotResponse,
      toolsRun: st.toolsRun.size,
      toolsTotal,
      endpointsDiscovered: (report.fingerprint.indicators ?? []).filter((i) => /^endpoint /.test(i)).length,
      authScanned,
      vulnClassesTested: [...st.vulnClasses],
      requestErrors: st.requestErrors,
      deterministic: !!this.opts.full,
    };
    const v = decideVerdict(report.coverage, report.findings, !!this.opts.allowUnauth);
    report.verdict = v.verdict;
    report.verdictReason = v.reason;
    report.transcript.push(`[판정] ${v.verdict.toUpperCase()} — ${v.reason}`);

    await this.selfImprove(report, emit);
    if (this.opts.banditStore) await this.opts.banditStore.save(this.bandit);
    emit?.({
      type: "done",
      text: `[완료] engagement 종료 (steps=${report.steps}, 판정=${report.verdict}, solved=${report.solved}).`,
      log: asLog(report),
    });
    return report;
  }

  /**
   * 액션 하나를 실행하고 상태를 갱신한다(scope 재확인 → 인자 배선 → 실행 → 체이닝/핑거프린트/
   * 보상/발견/커버리지). 밴딧 모드와 전수 모드가 공유한다. 반환값으로 진전/이탈을 판단한다.
   */
  private async step(
    phase: Phase,
    action: string,
    proposedByName: Map<string, ProposedAction>,
    st: RunState,
    target: Target,
    ctxKey: string,
  ): Promise<{ reward: number; sev: string; blocked?: boolean }> {
    const { report, emit } = st;
    const tool = this.tools.get(action)!;

    // 실행 직전 scope 재확인.
    const decision = this.guard.check({ ...target, intent: tool.intent });
    if (!decision.allowed) {
      report.transcript.push(`[차단] ${tool.name}: ${decision.reason}`);
      emit?.({ type: "blocked", phase, tool: tool.name, text: `[차단] ${tool.name}: ${decision.reason}` });
      this.bandit.update(ctxKey, action, 0);
      return { reward: 0, sev: "info", blocked: true };
    }

    // 인자 우선순위: proposer > 운영자 argsFor > 정찰 표면 자동 배선(deriveArgs) > 빈값.
    // deriveArgs 는 crawl 이 fingerprint.indicators 에 남긴 실제 endpoint 를 읽어 인젝션 툴의
    // paths/params 로 자동 변환한다 → 운영자 개입 없이 발견된 표면 전체를 공략(자율성 핵심).
    const args =
      proposedByName.get(action)?.args ??
      this.opts.argsFor?.(action, report.fingerprint) ??
      deriveArgs(action, report.fingerprint.indicators ?? []);
    const rationale = proposedByName.get(action)?.rationale ?? (this.opts.full ? "전수 스윕(결정적)" : "밴딧 탐색/활용");

    // 중복실행 억제: 같은 (툴+인자) 를 이미 실행했으면 네트워크를 다시 쓰지 않고 캐시된
    // 결과를 재사용한다(같은 요청은 같은 응답 → 낭비·중복 트래픽 제거). 발견은 첫 실행에서
    // 이미 수집됐으므로 여기선 진전 판단용 reward/sev 만 되돌려준다.
    const dedupKey = `${action}::${stableArgs(args)}`;
    const cached = st.ranActions.get(dedupKey);
    if (cached) {
      report.transcript.push(`[중복스킵] ${tool.name}(${JSON.stringify(args)}) — 동일 요청 재사용`);
      emit?.({ type: "note", text: `[중복스킵] ${tool.name} 동일 인자 재실행 억제(요청 절약)` });
      this.bandit.update(ctxKey, action, cached.reward);
      return cached;
    }

    emit?.({ type: "action", phase, tool: tool.name, rationale, args, text: `[${phase}] → ${tool.name}(${JSON.stringify(args)})` });
    report.steps += 1;
    st.toolsRun.add(tool.name);

    const auth = mergeAuth(this.guard.authHeaders, st.harvested, this.opts.session?.auth);
    const res = await tool.run(args, {
      target,
      rps: this.guard.requestsPerSecond,
      auth,
      jar: this.opts.session?.jar,
      proxy: this.opts.session?.proxy,
      validateIp: (h, ip) => this.guard.checkResolvedIp(h, ip).allowed,
    });

    // 연결성 추적: 연결 실패/타임아웃이면 requestErrors, 그 외(정상 응답·취약점 없음 포함)는 도달.
    const reached = !(!res.ok && CONN_ERR.test(res.summary));
    if (!reached) st.requestErrors += 1;
    else st.gotResponse = true;
    // 측정된 취약점 계열(vulnClassesTested)은 "툴을 실행했다"가 아니라 "대상 표면에 도달해
    // 응답을 관측했다"를 기준으로 센다. 연결 실패/타임아웃으로 대상에 닿지 못한 익스플로잇 툴은
    // 그 취약점 계열을 실제로 검사한 것이 아니므로 커버리지에 넣지 않는다(거짓 커버리지 방지).
    if (tool.intent === "exploit" && reached) st.vulnClasses.add(tool.name);

    // 발견 체이닝: 이 결과에서 자격증명이 노출됐으면 이후 요청에 재사용.
    const hv = harvestFromResult(res);
    for (const [k, v] of Object.entries(hv.headers)) {
      if (!(k in st.harvested)) {
        st.harvested[k] = v;
        const note = `[체이닝] ${tool.name} 노출 자격증명 재사용: ${hv.notes.join(", ")}`;
        report.transcript.push(note);
        emit?.({ type: "tool_result", phase, tool: tool.name, ok: true, summary: note, text: note });
      }
    }

    // 관측 → fingerprint 병합 + novelty.
    let novelty = 0;
    if (res.fingerprint) {
      const before = st.seenFacts.size;
      report.fingerprint = mergeFp(report.fingerprint, res.fingerprint, st.seenFacts);
      novelty = st.seenFacts.size - before;
    }

    // 보상 계산.
    const d = res.data as { severity?: string; title?: string; evidence?: string; impact?: string } | undefined;
    const sev = d?.severity ?? "info";
    let reward = SEV_REWARD[sev] ?? 0;
    if (reward === 0) reward = novelty > 0 ? 0.3 : 0.05;
    this.bandit.update(ctxKey, action, reward);

    report.transcript.push(`[${phase}] ${tool.name}: ${res.summary} (r=${reward.toFixed(2)})`);
    emit?.({ type: "tool_result", phase, tool: tool.name, ok: res.ok, summary: res.summary, severity: sev as EngagementFinding["severity"], text: `[${phase}] ${tool.name}: ${res.summary}` });

    // 유의미 발견 수집(중복 제목 제외).
    if (d?.title && sev !== "info" && !report.findings.some((f) => f.title === d.title)) {
      const finding: EngagementFinding = { phase, severity: sev as EngagementFinding["severity"], title: d.title, detail: res.summary, evidence: d.evidence, impact: d.impact };
      report.findings.push(finding);
      emit?.({ type: "finding", finding, text: `[발견] (${finding.severity}) ${finding.title}` });
    }
    // playbook 기반이면 결과 반영.
    const pbId = proposedByName.get(action)?.fromPlaybook;
    if (pbId) {
      await this.memory.record(pbId, reward > 0.3 ? "success" : "failure");
      if (!report.usedPlaybooks.includes(pbId)) report.usedPlaybooks.push(pbId);
    }

    const outcome = { reward, sev };
    st.ranActions.set(dedupKey, outcome);
    return outcome;
  }

  /** 단일 요청(짧은 타임아웃·재시도 없음)으로 대상 도달성만 빠르게 확인. */
  private async reachable(target: Target): Promise<boolean> {
    const scheme = target.port === 443 || target.port === 8443 ? "https" : "http";
    const url = `${scheme}://${target.host}${target.port ? `:${target.port}` : ""}/`;
    try {
      await httpRequest(url, {
        method: "GET",
        timeoutMs: 4000,
        retries: 0,
        proxy: this.opts.session?.proxy,
      });
      return true;
    } catch {
      return false;
    }
  }

  /** 성공 흐름을 재사용 playbook 으로 distill. */
  private async selfImprove(report: AutoReport, emit?: (e: OrchestratorEvent) => void): Promise<void> {
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
      emit?.({ type: "distilled", id: pb.id, title: pb.title, text: `[자기발전] 새 playbook 저장: ${pb.title} (id=${pb.id})` });
    }
  }
}

/** AutoReport 를 done 이벤트가 기대하는 EngagementLog 형태로 변환. */
function asLog(report: AutoReport): EngagementLog {
  return {
    target: report.target,
    fingerprint: report.fingerprint,
    findings: report.findings,
    usedPlaybooks: report.usedPlaybooks,
    distilled: [],
    transcript: report.transcript,
    coverage: report.coverage,
    verdict: report.verdict,
    verdictReason: report.verdictReason,
  };
}

function emptyCoverage(deterministic: boolean): Coverage {
  return {
    reachable: false,
    toolsRun: 0,
    toolsTotal: 0,
    endpointsDiscovered: 0,
    authScanned: false,
    vulnClassesTested: [],
    requestErrors: 0,
    deterministic,
  };
}

/**
 * 게이트 판정 규칙 — "발견 0"을 곧바로 "안전"으로 부르지 않는다(거짓 안전 방지).
 * 우선순위: 미도달 → 취약점 발견 → 익스플로잇 미실행 → 인증 미점검 → clean.
 */
export function decideVerdict(
  cov: Coverage,
  findings: EngagementFinding[],
  allowUnauth: boolean,
): { verdict: GateVerdict; reason: string } {
  const actionable = findings.filter((f) => f.severity !== "info");
  if (!cov.reachable) {
    return { verdict: "inconclusive", reason: "대상에 접속하지 못했습니다(연결 실패/타임아웃) — 스캔 미수행, '취약점 없음'이 아닙니다." };
  }
  if (actionable.length > 0) {
    const crit = actionable.filter((f) => f.severity === "high" || f.severity === "critical").length;
    return { verdict: "findings", reason: `취약점 ${actionable.length}건 발견(high+ ${crit}건) — 게이트 실패.` };
  }
  if (cov.vulnClassesTested.length === 0) {
    return { verdict: "inconclusive", reason: "익스플로잇 계열 툴을 하나도 실행하지 못함 — 커버리지 불충분." };
  }
  if (!cov.authScanned && !allowUnauth) {
    return {
      verdict: "inconclusive",
      reason: "인증 표면 미점검(자격증명 없음) — '통과' 판정 불가. authorization.yaml 에 인가된 테스트 계정을 넣거나, 공개 서비스면 --allow-unauth 를 명시하세요.",
    };
  }
  return { verdict: "clean", reason: `검사한 ${cov.vulnClassesTested.length}개 익스플로잇 계열·${cov.toolsRun}개 툴에서 유의미 취약점 미발견(전체 안전 보장은 아님).` };
}

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

/** 인자를 키 순서에 무관하게 안정적으로 직렬화(중복실행 억제 키). */
function stableArgs(args: Record<string, unknown>): string {
  const norm = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(norm);
    if (v && typeof v === "object") {
      return Object.keys(v as Record<string, unknown>)
        .sort()
        .reduce<Record<string, unknown>>((o, k) => ((o[k] = norm((v as Record<string, unknown>)[k])), o), {});
    }
    return v;
  };
  try {
    return JSON.stringify(norm(args));
  } catch {
    return JSON.stringify(args);
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
