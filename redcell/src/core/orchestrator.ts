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
  /**
   * [안전 가드·비상 브레이크] 전체 액션 상한(폭주/비용 방지). 루프의 1차 종료 조건은
   * '목표 달성'(모델 종료 선언 + 추궁 통과)과 '정체'(새 소득 없음)이며, 이 상한은 그것들이
   * 실패했을 때 무한 루프를 막는 최후의 장치다(기본 150).
   */
  maxTotalActions?: number;
  /** [안전 가드] 벽시계 상한(분, 기본 20). */
  maxMinutes?: number;
  /** 정체 판정: 연속으로 새 소득(발견·지표·자격증명) 없는 액션이 이 횟수면 단계를 접는다(기본 4). */
  stagnationLimit?: number;
  /** (호환/게이트용) 단계당 액션 수 고정 예산 — 지정하면 목표 지향 대신 고정 루프. 미지정이 기본. */
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
   * 커버리지 전수 모드(--max/--coverage). 모델 계획이 끝난 뒤 해당 phase 의 아직 안 쓴 툴을
   * 전부 1회씩 추가 실행한다(모델이 몰라서 놓친 표면까지 뒤짐). argsFor 로 기본 인자를 생성한다.
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
  /** [안전 가드] 총 액션 상한/기한 — run() 시작 때 세팅. */
  private maxTotal: number | null = null;
  private deadline: number | null = null;
  private totalActions = 0;

  constructor(
    private readonly guard: ScopeGuard,
    private readonly memory: SkillMemory,
    private readonly model: ModelAdapter,
    private readonly tools: ToolBox,
    private readonly opts: OrchestratorOpts = {},
  ) {}

  async run(target: Target, goal: string): Promise<EngagementLog> {
    // 목표 지향 실행 — 단계 길이는 (모델 종료 선언+추궁)·소득 정체·안전 가드가 결정한다.
    this.maxTotal = this.opts.maxTotalActions ?? 150;
    this.deadline = Date.now() + (this.opts.maxMinutes ?? 20) * 60_000;
    this.totalActions = 0;
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


    // 목표 지향 루프의 공유 상태 — '횟수'가 아니라 '소득'이 진행을 결정한다.
    const executed = new Set<string>(); // 동일 툴+동일 인자 재제안 스킵(중복 예산 낭비 방지)
    const stagLimit = this.opts.stagnationLimit ?? 4;
    let staleScore = this.infoScore(log);

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

      // 목표 지향 루프 — 횟수가 아니라 '목표'와 '소득'이 단계의 길이를 결정한다:
      //   1) 모델이 종료를 선언하면 한 번 추궁한다("발견을 재료로 아직 할 수 있는 수 없나?").
      //      그래도 종료이면 다음 단계로 — 모델의 판단이 1차 종료 조건.
      //   2) 연속으로 새 소득(발견·지표·자격증명)이 없으면 정체로 보고 단계를 접는다(2차).
      //   3) 총 액션/시간 안전 가드는 비상 브레이크일 뿐, 일상 종료 조건이 아니다(3차).
      let stag = 0;
      let phaseActions = 0;
      while (true) {
        if (this.budgetStop(emit)) break;
        if (this.opts.maxActionsPerPhase != null && phaseActions >= this.opts.maxActionsPerPhase) break;

        const action = await this.plan(phase, target, goal, log, recalled.map((r) => r.playbook), emit);
        if (!action) {
          // 모델 종료 선언 → 추궁(challenge): 게으른 종료를 걸러낸다.
          emit({ type: "note", text: `[${phase}] 모델이 이 단계 종료를 선언 — 목표 관점에서 재검토한다.` });
          const ch = await this.plan(phase, target, goal, log, recalled.map((r) => r.playbook), emit, "challenge");
          if (!ch) break; // 추궁에서도 종료 → 다음 단계
          const ranC = await this.execAction(phase, ch, log, runOne, executed, emit);
          phaseActions++;
          // 실행+새 소득이면 정체 리셋, 그 외(중복 제안 포함)는 정체로 센다 — 무한 중복 루프 방지.
          const nowC = this.infoScore(log);
          stag = ranC && nowC > staleScore ? 0 : stag + 1;
          staleScore = nowC;
          if (stag >= stagLimit) { emit({ type: "note", text: `[${phase}] 새 소득 없음 ${stag}회 연속 — 단계를 접는다.` }); break; }
          continue;
        }

        const ran = await this.execAction(phase, action, log, runOne, executed, emit);
        phaseActions++;
        // 실행+새 소득(발견·지표·자격증명)이면 정체 리셋. 그 외(중복 제안 포함)는 정체로 센다.
        const now = this.infoScore(log);
        stag = ran && now > staleScore ? 0 : stag + 1;
        staleScore = now;
        if (stag >= stagLimit) {
          emit({ type: "note", text: `[${phase}] 새 소득 없는 시도 ${stag}회 연속 — 이 단계에서 얻을 것은 뽑았다고 판단, 다음으로 넘어간다.` });
          break;
        }
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

    // 자율 추격(free chase) — 단계 구조가 끝나도, 모델이 목표 관점에서 '아직 시도할 수'를
    // 제안하는 한 계속 실행한다(prime-agent 식 자기 주도). 단계 구분 없이 발견을 재료로
    // 사슬을 잇는다(예: 노출 파일 → 자격증명 → 로그인 → 권한 상승). 종료는 추궁·정체·가드가 결정.
    if (this.opts.maxActionsPerPhase == null) {
      let chaseStag = 0;
      while (true) {
        if (this.budgetStop(emit)) break;
        const a = await this.plan("post", target, goal, log, [], emit, "free");
        if (!a) {
          emit({ type: "note", text: "[추격] 목표 달성 여부를 최종 검토한다." });
          const ch = await this.plan("post", target, goal, log, [], emit, "challenge");
          if (!ch) { emit({ type: "note", text: "[추격] 모델이 목표 달성·가용 수 exhausted 를 확정 — 종료한다." }); break; }
          const ranCh = await this.execAction("post", ch, log, runOne, executed, emit);
          const nowCh = this.infoScore(log);
          chaseStag = ranCh && nowCh > staleScore ? 0 : chaseStag + 1;
          staleScore = nowCh;
          if (chaseStag >= stagLimit) { emit({ type: "note", text: "[추격] 새 소득 없음 — 종료한다." }); break; }
          continue;
        }
        const ranF = await this.execAction("post", a, log, runOne, executed, emit);
        const nowF = this.infoScore(log);
        chaseStag = ranF && nowF > staleScore ? 0 : chaseStag + 1;
        staleScore = nowF;
        if (chaseStag >= stagLimit) { emit({ type: "note", text: "[추격] 새 소득 없는 시도 연속 — 목표 달성으로 보고 종료한다." }); break; }
      }
    }

    // 자기발전: 이번 engagement 에서 성공한 흐름을 새 playbook 으로 distill.
    await this.selfImprove(log, emit);
    this.opts.onEvent?.({ type: "done", text: "[완료] engagement 종료.", log });
    return log;
  }

  /** 새 소득 지표 — 발견·수집 지표(엔드포인트/경로 리스트)·스택 지문의 총량. 증가 = 진행 중. */
  private infoScore(log: EngagementLog): number {
    return (
      log.findings.length * 10 +
      (log.fingerprint.indicators?.length ?? 0) +
      (log.fingerprint.tech?.length ?? 0)
    );
  }

  /** [안전 가드·비상 브레이크] 총 액션/시간 상한. 일상 종료 조건(목표 달성·정체)이 실패했을 때만 발동된다. */
  private budgetStop(emit: (e: OrchestratorEvent) => void): boolean {
    if (this.maxTotal != null && this.totalActions >= this.maxTotal) {
      emit({ type: "note", text: `[안전 가드] 총 액션 상한(${this.maxTotal}) 도달 — 종료한다. 목표 지향 루프의 비상 브레이크다.` });
      return true;
    }
    if (this.deadline != null && Date.now() > this.deadline) {
      emit({ type: "note", text: "[안전 가드] 시간 상한 도달 — 종료한다." });
      return true;
    }
    return false;
  }

  /**
   * 제안된 액션 1건을 실행한다(중복 제안 스킵·미지 툴 건너뛰기 포함).
   * 반환: 실제로 실행됐는지(중복/미지 툴은 false — 정체 카운터에 반영된다).
   */
  private async execAction(
    phase: Phase,
    action: ProposedAction & { fromPlaybook?: string },
    log: EngagementLog,
    runOne: (phase: Phase, tool: Tool, toolName: string, args: Record<string, unknown>, rationale: string, fromPlaybook?: string) => Promise<void>,
    executed: Set<string>,
    emit: (e: OrchestratorEvent) => void,
  ): Promise<boolean> {
    const tool = this.tools.get(action.tool);
    if (!tool) {
      emit({ type: "note", text: `[${phase}] 알 수 없는 툴: ${action.tool} — 건너뜀.` });
      return false;
    }
    const key = `${action.tool}|${stableArgs(action.args)}`;
    if (executed.has(key)) {
      emit({ type: "note", text: `[${phase}] ${action.tool} 동일 인자 재제안 — 스킵(이미 실행함).` });
      return false;
    }
    executed.add(key);
    this.totalActions++;
    await runOne(phase, tool, action.tool, action.args, action.rationale, action.fromPlaybook);
    return true;
  }

  /** 모델에게 다음 액션 하나를 제안받는다. null 이면 단계 종료. */
  private async plan(
    phase: Phase,
    target: Target,
    goal: string,
    log: EngagementLog,
    playbooks: { id: string; title: string; steps: unknown[] }[],
    emit: (e: OrchestratorEvent) => void,
    mode?: "challenge" | "free",
  ): Promise<(ProposedAction & { fromPlaybook?: string }) | null> {
    const system =
      "너는 인가된 침투테스트를 돕는 창의적 화이트해커 조수다. 오직 scope 안의 대상만 다룬다. " +
      "파괴적/DoS 행위는 제안하지 않는다. " +
      "핵심 원칙: 목표 지향으로 행동하라 — 목표가 달성될 때까지, 또는 시도할 수 있는 것이 사라질 때까지 계속 탐색하라. " +
      "한 가지 방법에 갇히지 말고 서로 다른 공격 표면을 발산적으로 탐색하되, " +
      "발견한 것을 재료로 다음 수를 사슬처럼 연결하라(예: 노출 설정 파일 → 자격증명 → 로그인 → 권한 상승, " +
      "엔드포인트 발견 → 파라미터 주입, 관리자 경로 발견 → 접근통제 점검). " +
      "종료(done)는 목표가 달성됐거나 정말 시도할 것이 없을 때만 선언하라. 게으른 종료는 추궁된다. " +
      "이미 발견한 fingerprint/엔드포인트가 있으면 그것을 재료로 다음 액션의 인자를 구체화하라. " +
      "응답은 반드시 JSON 하나로만 한다.";

    // 이미 시도한 것: free 모드(단계 구조 밖 추격)에선 전체, 아니면 이 단계만.
    const tried = mode === "free" ? triedTools(log.transcript) : triedTools(log.transcript, phase);
    const findings = log.findings.slice(-12).map((f) => ({ severity: f.severity, title: f.title }));

    let instruction: string;
    if (mode === "challenge") {
      instruction =
        `직전에 너는 이 단계의 종료를 선언했다. 목표=${goal}. ` +
        `아래 findings_so_far 와 discovered_surface 를 보라 — 목표 관점에서 아직 시도해보지 않은 수가 하나라도 있으면 그 액션을 제안하라. ` +
        `정말로 없을 때만 {"done":true,"reason":"..."} 로 확정하라.`;
    } else if (mode === "free") {
      instruction =
        `단계 구조는 끝났다. 목표=${goal}. 이제 단계 구분 없이 자유롭게 행동하라. ` +
        `지금까지의 발견·수집 목록을 재료로, 목표 달성에 가장 필요한 다음 액션 1개를 제안하라. ` +
        `더 이상 시도할 것이 없으면 {"done":true,"reason":"..."} 를 반환하라.`;
    } else {
      instruction =
        `현재 phase=${phase}. 목표=${goal}. 다음에 실행할 액션 1개를 제안하라. ` +
        `아래 already_tried 에 있는 접근은 피하고 새로운 벡터를 시도하라. ` +
        `목표가 달성됐거나 이 단계에서 시도할 만한 서로 다른 벡터를 모두 소진했을 때만 {"done":true,"reason":"..."} 를 반환하라. ` +
        `종료 판단은 신중하게 — 게으른 종료는 재검토된다.`;
    }

    const prompt = JSON.stringify({
      instruction,
      target,
      goal,
      phase,
      known_fingerprint: log.fingerprint,
      findings_so_far: findings,
      discovered_surface: (log.fingerprint.indicators ?? []).slice(0, 32),
      recalled_playbooks: playbooks.map((p) => ({ id: p.id, title: p.title })),
      available_tools: this.tools.list().map((t) => ({ name: t.name, intent: t.intent, description: t.description })),
      already_tried: tried,
      recent_results: log.transcript.filter((l) => l.startsWith("[") && l.includes(": ")).slice(-10),
      hint: tried.length > 0 ? "지금까지 성과가 없다면 관점을 바꿔 다른 부류의 취약점을 노려라(발산/백트래킹)." : undefined,
      response_schema: { tool: "string", args: "object", rationale: "string", fromPlaybook: "string?", done: "boolean?", reason: "string?" },
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
function triedTools(transcript: string[], phase?: Phase): string[] {
  const out = new Set<string>();
  const re = phase ? new RegExp(`\\[${phase}\\] → (\\w+)\\(`) : /^\[[a-z]+\] → (\w+)\(/;
  for (const line of transcript) {
    const m = re.exec(line);
    if (m) out.add(m[1]);
  }
  return [...out];
}

/** 액션 중복 판정용 안정 키(인자 키 정렬). */
function stableArgs(args: Record<string, unknown> | undefined): string {
  const keys = Object.keys(args ?? {}).sort();
  return keys.map((k) => `${k}=${JSON.stringify((args ?? {})[k])}`).join("&");
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
