/**
 * GoalAgent — 작업형 목표(정보 수집·파일 추출·정리)를 수행하는 목표 지향 에이전트.
 *
 * "하반기 1차 합격자 목록을 파일로 뽑아줘" 처럼 취약점 스캔이 아닌 **작업**을
 * prime-agent(pi) 처럼 자기 주도로 수행한다:
 *
 *   페이지 읽기(fetch_page) → 링크/파일 링크 추적 → 첨부 다운로드(download_file)
 *     → 추출·정리 결과를 파일로 저장(write_output) → 목표 달성 검증(challenge)
 *     → 최종 종합 보고
 *
 * 종료 조건은 횟수가 아니다 — ① 모델 종료 선언 + 추궁 통과, ② 소득 정체(새 정보·
 * 산출물 없음), ③ 안전 가드(총 액션/시간 — 비상 브레이크). 이 세 가지로 결정된다.
 *
 * 이벤트는 OrchestratorEvent 와 같은 형태로 방출해 데스크톱/CLI 스트리밍이 그대로 동작한다.
 * 모든 네트워크 액션은 ScopeGuard(recon intent)를 통과하고, 파일 쓰기는 resultsDir 아래로만.
 */

import path from "node:path";
import { ScopeGuard, type Target } from "../scope/scope-guard.js";
import type { EngagementLog, EngagementFinding, ModelAdapter, ProposedAction, Tool, ToolBox } from "./types.js";
import { DefaultToolBox } from "../tools/toolbox.js";
import { GOAL_TOOLS } from "../tools/goal-tools.js";
import { crawl } from "../tools/crawl.js";
import { httpProbe } from "../tools/http-probe.js";
import type { OrchestratorEvent, SessionContext } from "./orchestrator.js";
import { redcellHome } from "../config.js";
import { writeOutput } from "../tools/goal-tools.js";

export interface GoalAgentOpts {
  guard: ScopeGuard;
  model: ModelAdapter;
  /** 산출물 저장 디렉터리(필수 — 없으면 생성). */
  resultsDir?: string;
  session?: SessionContext;
  onEvent?: (e: OrchestratorEvent) => void;
  /** [안전 가드] 총 액션 상한(기본 60). */
  maxTotalActions?: number;
  /** [안전 가드] 시간 상한(분, 기본 15). */
  maxMinutes?: number;
  /** 정체 판정(연속 무소득 액션, 기본 4). */
  stagnationLimit?: number;
}

export interface GoalResult {
  log: EngagementLog;
  /** 저장된 산출물 파일 경로 목록. */
  artifacts: string[];
  /** 최종 종합 텍스트(사용자 보고용). */
  summary: string;
  /** 목표 달성으로 모델이 확정했는지. */
  achieved: boolean;
}

export class GoalAgent {
  private readonly toolbox: ToolBox;
  private readonly resultsDir: string;
  private totalActions = 0;
  private deadline = 0;

  constructor(private readonly opts: GoalAgentOpts) {
    // 작업 툴 3종 + 표면 수집(crawl/http_probe). 취약점 주입 툴은 의도적으로 제외 —
    // 작업형 목표에서 그런 제안이 나오면 "알 수 없는 툴"로 걸러진다(목표 이탈 방지).
    this.toolbox = new DefaultToolBox([...GOAL_TOOLS, crawl, httpProbe]);
    this.resultsDir =
      opts.resultsDir ?? path.join(redcellHome(), "results", `goal-${Date.now()}`);
  }

  async run(target: Target, goal: string): Promise<GoalResult> {
    const maxTotal = this.opts.maxTotalActions ?? 60;
    this.deadline = Date.now() + (this.opts.maxMinutes ?? 15) * 60_000;
    const stagLimit = this.opts.stagnationLimit ?? 4;

    const log: EngagementLog = { target, fingerprint: {}, findings: [], usedPlaybooks: [], distilled: [], transcript: [] };
    const artifacts: string[] = [];
    const emit = (e: OrchestratorEvent) => { log.transcript.push(e.text); this.opts.onEvent?.(e); };

    // 사전 scope 게이트(재확인 — 모든 요청은 툴 레벨에서도 다시 게이트된다).
    const gate = this.opts.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      emit({ type: "blocked", text: `[거부] ${gate.reason}` });
      emit({ type: "done", text: "[완료] 인가 거부로 종료.", log });
      return { log, artifacts, summary: gate.reason, achieved: false };
    }
    emit({ type: "authorized", text: `[인가] ${gate.reason} — 작업 목표: ${goal}`, target, goal });
    emit({ type: "note", text: `[모드] 목표 에이전트 — 페이지를 읽고 파일을 추출·저장합니다. 산출물: ${this.resultsDir}` });

    const executed = new Set<string>();
    let stag = 0;
    let achieved = false;
    let staleScore = this.infoScore(log, artifacts);

    while (true) {
      if (this.budgetStop(maxTotal, emit)) break;

      const action = await this.plan(target, goal, log, artifacts, emit);
      if (!action) {
        emit({ type: "note", text: "[종료 검토] 목표 달성 여부를 재검토한다." });
        const ch = await this.plan(target, goal, log, artifacts, emit, true);
        if (!ch) { achieved = true; break; }
        const ranC = await this.exec(ch, target, log, artifacts, executed, emit);
        const now = this.infoScore(log, artifacts);
        stag = ranC && now > staleScore ? 0 : stag + 1;
        staleScore = now;
        if (stag >= stagLimit) { emit({ type: "note", text: "[정체] 새 소득 없음 — 목표 수행을 마무리한다." }); break; }
        continue;
      }

      const ran = await this.exec(action, target, log, artifacts, executed, emit);
      const now = this.infoScore(log, artifacts);
      stag = ran && now > staleScore ? 0 : stag + 1;
      staleScore = now;
      if (stag >= stagLimit) {
        emit({ type: "note", text: `[정체] 새 소득 없는 시도 ${stag}회 연속 — 얻을 것은 얻었다고 판단, 마무리한다.` });
        break;
      }
    }

    // ── 최종 종합: 산출물이 목표에 부합하는지 검증하고, 부족하면 지금이라도 만든다 ──
    const summary = await this.finalize(target, goal, log, artifacts, achieved, emit);
    // 데스크톱(ndjson)에서도 최종 요약이 보이도록 이벤트로도 방출한다.
    emit({ type: "note", text: summary });
    emit({ type: "done", text: `[완료] 목표 수행 종료 — 산출물 ${artifacts.length}건`, log });
    return { log, artifacts, summary, achieved };
  }

  /** 새 소득 지표 — 발견·수집 지표·산출물의 총량. */
  private infoScore(log: EngagementLog, artifacts: string[]): number {
    return log.findings.length * 10 + (log.fingerprint.indicators?.length ?? 0) + artifacts.length * 20;
  }

  private budgetStop(maxTotal: number, emit: (e: OrchestratorEvent) => void): boolean {
    if (this.totalActions >= maxTotal) {
      emit({ type: "note", text: `[안전 가드] 총 액션 상한(${maxTotal}) 도달 — 종료한다.` });
      return true;
    }
    if (Date.now() > this.deadline) {
      emit({ type: "note", text: "[안전 가드] 시간 상한 도달 — 종료한다." });
      return true;
    }
    return false;
  }

  /** 제안 액션 실행(중복 스킵·미지 툴 거부·산출물 수집). */
  private async exec(
    action: ProposedAction,
    target: Target,
    log: EngagementLog,
    artifacts: string[],
    executed: Set<string>,
    emit: (e: OrchestratorEvent) => void,
  ): Promise<boolean> {
    const tool = this.toolbox.get(action.tool);
    if (!tool) {
      emit({ type: "note", text: `[건너뜀] ${action.tool} — 목표 에이전트 툴박스에 없는 툴(작업 목표와 무관한 제안은 거부).` });
      return false;
    }
    const key = `${action.tool}|${stableArgs(action.args)}`;
    if (executed.has(key)) {
      emit({ type: "note", text: `[건너뜀] ${action.tool} 동일 인자 재제안 — 스킵.` });
      return false;
    }
    executed.add(key);

    // 실행 직전 ScopeGuard 재확인(툴 intent 기준).
    const decision = this.opts.guard.check({ ...target, intent: tool.intent });
    if (!decision.allowed) {
      emit({ type: "blocked", tool: tool.name, text: `[차단] ${tool.name}: ${decision.reason}` });
      return false;
    }

    emit({
      type: "action",
      phase: "recon",
      tool: tool.name,
      rationale: action.rationale,
      args: action.args,
      text: `[목표] → ${action.tool}(${JSON.stringify(action.args)})${action.rationale ? " · " + action.rationale : ""}`,
    });

    this.totalActions++;
    let res;
    try {
      res = await tool.run(action.args, {
        target,
        rps: this.opts.guard.requestsPerSecond,
        auth: this.opts.session?.auth,
        jar: this.opts.session?.jar,
        proxy: this.opts.session?.proxy,
        validateIp: (h, ip) => this.opts.guard.checkResolvedIp(h, ip).allowed,
        resultsDir: this.resultsDir,
      });
    } catch (e) {
      emit({ type: "tool_result", phase: "recon", tool: tool.name, ok: false, summary: (e as Error).message, text: `[목표] ${tool.name}: 오류 — ${(e as Error).message}` });
      return true;
    }

    if (res.fingerprint) {
      const inds = new Set([...(log.fingerprint.indicators ?? []), ...(res.fingerprint.indicators ?? [])]);
      log.fingerprint = { ...log.fingerprint, ...res.fingerprint, indicators: [...inds] };
    }

    emit({ type: "tool_result", phase: "recon", tool: tool.name, ok: res.ok, summary: res.summary, text: `[목표] ${tool.name}: ${res.summary}` });

    const d = res.data as { title?: string; severity?: EngagementFinding["severity"]; evidence?: string; savedPath?: string } | undefined;
    if (d?.savedPath && !artifacts.includes(d.savedPath)) {
      artifacts.push(d.savedPath);
      emit({ type: "note", text: `[산출물] ${d.savedPath}` });
    }
    if (d?.title && res.ok) {
      const f: EngagementFinding = { phase: "recon", severity: d.severity ?? "info", title: d.title, detail: action.rationale || res.summary, evidence: d.evidence };
      if (!log.findings.some((x) => x.title === f.title)) {
        log.findings.push(f);
        emit({ type: "finding", finding: f, text: `[발견] (${f.severity}) ${f.title}` });
      }
    }
    return true;
  }

  /** 모델에게 다음 액션 하나를 제안받는다. challenge=true 면 종료 선언 재검토. */
  private async plan(
    target: Target,
    goal: string,
    log: EngagementLog,
    artifacts: string[],
    emit: (e: OrchestratorEvent) => void,
    challenge = false,
  ): Promise<ProposedAction | null> {
    const system =
      "너는 인가된 대상에서 사용자의 **작업 목표**를 수행하는 정보 수집 에이전트다. 오직 scope 안의 대상만 다룬다. " +
      "행동 원칙: " +
      "1) fetch_page 로 페이지를 읽어 목표에 필요한 정보(목록/공지/다운로드 링크)가 있는지 확인한다. " +
      "2) 목표 정보가 담긴 링크·페이지를 따라가며 단서를 좇는다 — 한 페이지에서 끝내지 말고 탐색하라. " +
      "3) 파일(PDF/엑셀/CSV 등)이 목표면 download_file 로 산출물 디렉터리에 저장한다. " +
      "4) 추출·정리가 목표면 모은 텍스트를 목표 형식(목록/표)으로 정리해 write_output 으로 파일을 만든다. " +
      "5) 목표 달성(또는 산출물 생성) 없이 done 을 선언하지 마라 — 게으른 종료는 추궁된다. " +
      "응답은 반드시 JSON 하나로만 한다.";

    const tried = [...log.transcript.filter((l) => l.startsWith("[목표] → ")).map((l) => l.slice(0, 60))];
    const instruction = challenge
      ? `직전에 너는 종료를 선언했다. 목표=${goal}. artifacts=${JSON.stringify(artifacts)}. ` +
        `목표가 정말 달성됐는지(특히 **요청한 파일 산출물이 실제로 만들어졌는지**) 검토하라. ` +
        `아직 할 수 있는 수가 하나라도 있으면 그 액션을 제안하고, 정말 없을 때만 {"done":true,"reason":"..."} 로 확정하라.`
      : `목표=${goal}. 이 목표를 달성하기 위한 다음 액션 1개를 제안하라. ` +
        `페이지 읽기 → 링크 추적 → 다운로드 → 파일 저장의 사슬로 진행하라. ` +
        `목표가 달성됐거나 더 시도할 수단이 없을 때만 {"done":true,"reason":"..."} 를 반환하라.`;

    const prompt = JSON.stringify({
      instruction,
      target,
      goal,
      collected_findings: log.findings.slice(-10).map((f) => f.title),
      artifacts_so_far: artifacts,
      discovered: (log.fingerprint.indicators ?? []).slice(0, 24),
      available_tools: this.toolbox.list().map((t) => ({ name: t.name, description: t.description })),
      already_tried: tried.slice(-12),
      recent_results: log.transcript.slice(-8),
      response_schema: { tool: "string", args: "object", rationale: "string", done: "boolean?", reason: "string?" },
    });

    let raw: string;
    try {
      raw = await this.opts.model.complete({ system, prompt, json: true });
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
    };
  }

  /**
   * 최종 종합 — 산출물이 목표에 부합하는지 검증하고, 부족하면 모델에게 지금 정리본을 만들게 한다.
   * 반환: 사용자에게 보여줄 최종 보고 텍스트.
   */
  private async finalize(
    target: Target,
    goal: string,
    log: EngagementLog,
    artifacts: string[],
    achieved: boolean,
    emit: (e: OrchestratorEvent) => void,
  ): Promise<string> {
    // 목표가 파일 산출인데 아무것도 저장되지 않았다면, 모은 텍스트로라도 지금 만든다.
    if (artifacts.length === 0 && log.findings.length > 0) {
      emit({ type: "note", text: "[종합] 파일 산출물이 없어 수집 내용으로 정리본을 작성한다." });
      try {
        const raw = await this.opts.model.complete({
          system: "수집된 정보를 사용자의 목표에 맞는 깔끔한 결과물(마크다운/표/목록)로 정리한다. 수집된 사실만 쓰고 지어내지 않는다.",
          prompt: JSON.stringify({
            goal,
            instruction: "아래 수집 결과를 목표에 맞게 정리한 최종 산출물 텍스트를 만들어라. {" + '"filename":"result.md","content":"..."' + "} 형식으로.",
            collected: log.findings.slice(-12).map((f) => ({ title: f.title, evidence: (f.evidence ?? "").slice(0, 800) })),
          }),
          json: true,
        });
        const parsed = safeJson(raw);
        if (parsed?.content) {
          const res = await writeOutput.run(
            { filename: String(parsed.filename ?? "result.md"), content: String(parsed.content), note: "최종 종합 정리본" },
            { target, rps: this.opts.guard.requestsPerSecond, resultsDir: this.resultsDir },
          );
          const sp = (res.data as { savedPath?: string } | undefined)?.savedPath;
          if (res.ok && sp) {
            artifacts.push(sp);
            emit({ type: "note", text: `[산출물] ${sp}` });
          }
        }
      } catch (e) {
        emit({ type: "note", text: `[종합] 정리본 작성 실패: ${(e as Error).message}` });
      }
    }

    const lines = [
      achieved ? "✅ 목표 달성을 확정했습니다." : "⚠️ 모델이 목표 달성을 확정하지 못한 채 종료했습니다(정체/안전 가드).",
      `산출물 ${artifacts.length}건:`,
      ...artifacts.map((a) => `  📄 ${a}`),
      artifacts.length ? `\n산출물 디렉터리: ${this.resultsDir}` : "",
    ].filter(Boolean);
    return lines.join("\n");
  }
}

function stableArgs(args: Record<string, unknown> | undefined): string {
  const keys = Object.keys(args ?? {}).sort();
  return keys.map((k) => `${k}=${JSON.stringify((args ?? {})[k])}`).join("&");
}

function safeJson(raw: string): (Record<string, any> | null) {
  try {
    const s = raw.indexOf("{");
    const e = raw.lastIndexOf("}");
    if (s < 0 || e < 0) return null;
    return JSON.parse(raw.slice(s, e + 1));
  } catch {
    return null;
  }
}
