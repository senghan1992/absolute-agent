/**
 * osint/agent — 목표 지향 '웹 샅샅이 뒤지기' 인텔리전스 에이전트.
 *
 * prime-agent 를 쓰면 사이트를 막 뒤져 원하는 정보를 가져다 주듯이, 이 에이전트는
 * 시드 사이트를 깊이 크롤링(deterministic walker)하고, 모델(또는 규칙)이 남은
 * frontier 를 보고 "어디를 더 파볼지"를 정하며, 목표와 맞는 인텔만 추려 보고한다.
 *
 * 안전 계약(다른 에이전트와 동일): 대상 자체가 인가 목록에 있어야 하고, 모든 요청은
 * ScopeGuard(호스트+해석 IP)를 통과한다. 같은 오리진만 따라간다(외부로 안 나감).
 * 순수 GET 관측 — 상태변경/제출 없음. 요청 수는 페이지 예산으로 제한(폭주 방지).
 */
import { ScopeGuard, type Target } from "../scope/scope-guard.js";
import { baseUrl } from "../tools/util.js";
import { deepDig, type DigResult, type IntelItem } from "./walker.js";
import type { ModelAdapter, EngagementLog, EngagementFinding } from "../core/types.js";
import type { OrchestratorEvent } from "../core/orchestrator.js";

export interface OsintAgentOpts {
  /** 모델 없이 결정적 속도전(auto). digest 는 규칙으로 생성된다. */
  auto?: boolean;
  /** 모델 계획 반복 횟수(프론티어 재선택). 기본 4. */
  maxIterations?: number;
  onEvent?: (e: OrchestratorEvent) => void;
  session?: { auth?: Record<string, string>; jar?: unknown; proxy?: string };
}

const KIND_LABEL: Record<string, string> = {
  email: "이메일",
  phone: "전화번호",
  secret: "시크릿/자격증명",
  api: "API/민감 경로",
  tech: "기술 스택",
  meta: "메타",
  endpoint: "엔드포인트",
  data: "데이터 조각",
};

/** 목표 키워드가 값에 포함되면 medium(정보 목표 적중), 아니면 info. */
function severityFor(value: string, goal: string): EngagementFinding["severity"] {
  const terms = goal
    .split(/[\s,.,()\[\]]+/)
    .map((t) => t.trim())
    .filter((t) => t.length >= 2);
  return terms.some((t) => value.toLowerCase().includes(t.toLowerCase())) ? "medium" : "info";
}

/** 인텔 목록을 사람이 읽는 요약으로(모델 컨텍스트/최종 보고 공용). */
export function digestIntel(intel: IntelItem[], goal: string, limit = 40): string {
  const lines: string[] = [];
  const counts = new Map<string, number>();
  for (const i of intel) counts.set(i.kind, (counts.get(i.kind) ?? 0) + 1);
  lines.push(`수집: ${intel.length}건 — ` + [...counts.entries()].map(([k, n]) => `${KIND_LABEL[k] ?? k} ${n}`).join(", "));
  for (const i of intel.slice(0, limit)) {
    const hit = severityFor(i.value, goal) === "medium" ? " 🎯" : "";
    lines.push(`- [${KIND_LABEL[i.kind] ?? i.kind}]${hit} ${i.value}  (${i.source})`);
  }
  return lines.join("\n");
}

export class OsintAgent {
  private readonly digest = new Map<string, IntelItem>();

  constructor(
    private readonly guard: ScopeGuard,
    private readonly model: ModelAdapter | null,
    private readonly opts: OsintAgentOpts = {},
  ) {}

  async run(target: Target, goal: string): Promise<EngagementLog> {
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

    const gate = this.guard.check({ ...target, intent: "recon" });
    if (!gate.allowed) {
      emit({ type: "blocked", text: `[거부] ${gate.reason}` });
      this.opts.onEvent?.({ type: "done", text: "[완료] 인가 거부로 종료.", log });
      return log;
    }
    emit({ type: "authorized", text: `[인가] ${gate.reason} — 목표: ${goal}`, target, goal });
    emit({ type: "phase", text: "[phase] osint-agent (샅샅이 뒤지기) 시작", phase: "recon" });

    const canFetch = (url: string): boolean => {
      try {
        const u = new URL(url);
        const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
        // 호스트 + 해석 IP 모두 ScopeGuard 통과(SSRF/rebinding 방지) — fail-closed.
        return this.guard.check({ host: u.hostname, port, intent: "recon" }).allowed;
      } catch {
        return false;
      }
    };
    const mergedAuth = this.opts.session?.auth;
    const jar = this.opts.session?.jar as never; // CookieJar
    const proxy = this.opts.session?.proxy;

    const attach = (d: DigResult) => {
      for (const it of d.intel) {
        const key = `${it.kind}:${it.value}`;
        if (this.digest.has(key)) continue;
        this.digest.set(key, it);
        emit({ type: "note", text: `[인텔] ${KIND_LABEL[it.kind] ?? it.kind}: ${it.value}  (${it.source})` });
      }
    };

    const seed = baseUrl(target) + "/";
    emit({ type: "action", phase: "recon", tool: "osint_walker", rationale: "시드부터 깊이 다이그", args: { url: seed }, text: `[osint] 시드: ${seed}` });

    // 1차 전수 다이그: 깊이 2, 최대 20페이지(같은 오리진 + robots/sitemap 얻어걸림).
    const first = await deepDig(seed, {
      rps: this.guard.requestsPerSecond,
      auth: mergedAuth,
      jar,
      proxy,
      validateIp: (h, ip) => this.guard.checkResolvedIp(h, ip).allowed,
      canFetch,
      maxPages: 20,
      maxDepth: 2,
      onPage: (p) => emit({ type: "note", text: `[방문] ${p.url} ${p.title ? "— " + p.title : ""} (인텔 ${p.intel.length})` }),
    });
    attach(first);
    emit({ type: "tool_result", phase: "recon", tool: "osint_walker", ok: first.crawled > 0, summary: `다이그: ${first.crawled}페이지, 인텔 ${first.intel.length}건, frontier ${first.frontier.length}`, text: `[osint] 1차 다이그: ${first.crawled}페이지 / 인텔 ${first.intel.length}건` });

    const maxIter = this.opts.maxIterations ?? 4;
    if (!this.opts.auto && this.model) {
      for (let i = 0; i < maxIter; i++) {
        const plan = await this.planNext(goal, first.frontier, emit);
        if (!plan || plan.done || !plan.pick) {
          if (plan?.digest) emit({ type: "note", text: `[요약] ${plan.digest}` });
          break;
        }
        emit({ type: "action", phase: "recon", tool: "osint_walker", rationale: plan.focus, args: { url: plan.pick }, text: `[osint #${i + 1}] 심화 다이그: ${plan.pick} — ${plan.focus}` });
        const d = await deepDig(plan.pick, {
          rps: this.guard.requestsPerSecond,
          auth: mergedAuth,
          jar,
          proxy,
          validateIp: (h, ip) => this.guard.checkResolvedIp(h, ip).allowed,
          canFetch,
          maxPages: 8,
          maxDepth: 1,
        });
        attach(d);
        emit({ type: "tool_result", phase: "recon", tool: "osint_walker", ok: d.crawled > 0, summary: `심화 다이그: ${d.crawled}페이지, 인텔 ${d.intel.length}건`, text: `[osint] 심화: ${d.crawled}페이지 / 인텔 ${d.intel.length}건` });
        if (i === maxIter - 1) {
          const finalDigest = digestIntel([...this.digest.values()], goal);
          emit({ type: "note", text: `[요약] ${finalDigest}` });
        }
      }
    } else {
      emit({ type: "note", text: `[요약] ${digestIntel([...this.digest.values()], goal)}` });
    }

    // 인텔 → 발견(finding) 수집(중복 제목 제거, cap 16).
    for (const it of [...this.digest.values()].slice(0, 16)) {
      const title = `${KIND_LABEL[it.kind] ?? it.kind} 인텔: ${it.value.slice(0, 60)}`;
      if (log.findings.some((f) => f.title === title)) continue;
      const finding: EngagementFinding = {
        phase: "recon",
        severity: severityFor(it.value, goal),
        title,
        detail: it.note ?? goal,
        evidence: it.value,
        impact: `출처: ${it.source}`,
      };
      log.findings.push(finding);
      emit({ type: "finding", finding, text: `[인텔-발견] (${finding.severity}) ${title}` });
    }
    if (log.fingerprint && log.fingerprint.tech === undefined) {
      const tech = [...this.digest.values()].filter((i) => i.kind === "tech").map((i) => i.value);
      if (tech.length) log.fingerprint.tech = dedupe(tech);
    }

    this.opts.onEvent?.({ type: "done", text: `[완료] osint 종료 (방문 ${first.crawled}페이지, 인텔 ${this.digest.size}건, 발견 ${log.findings.length}건).`, log });
    return log;
  }

  /** 모델에게 다음 다이그 지점을 받는다. null/실패면 종료. */
  private async planNext(
    goal: string,
    frontier: string[],
    emit: (e: OrchestratorEvent) => void,
  ): Promise<{ pick: string | null; focus: string; done: boolean; digest?: string } | null> {
    const prompt = JSON.stringify({
      instruction:
        `목표: ${goal}. 아래에 지금까지 수집한 인텔 요약과 미방문 URL(frontier)이 있다. ` +
        `목표에 도달하려면 어떤 URL 을 더 깊이 파볼지 1개 고르거나, 충분하면 마무리하라.`,
      collected: digestIntel([...this.digest.values()], goal, 25),
      frontier: frontier.slice(0, 15),
      response_schema: { pick: "string|null(파볼 같은 오리진 URL)", focus: "string(한 줄 이유)", done: "boolean", digest: "string(지금까지 얻은 정보 요약)" },
    });
    let raw: string;
    try {
      raw = await this.model!.complete({ system: OSINT_SYSTEM, prompt, json: true });
    } catch (e) {
      emit({ type: "error", text: `[모델오류] ${(e as Error).message}` });
      return null;
    }
    const parsed = safeJson(raw);
    if (!parsed) return null;
    return {
      pick: typeof parsed.pick === "string" && parsed.pick ? parsed.pick : null,
      focus: String(parsed.focus ?? ""),
      done: parsed.done === true,
      digest: typeof parsed.digest === "string" ? parsed.digest : undefined,
    };
  }
}

const OSINT_SYSTEM =
  "너는 인가된 OSINT(공개정보 수집) 분석관이다. 목표 정보를 얻기 위해 사이트를 샅샅이 " +
  "뒤지되 다음을 지킨다:\n" +
  "1) 같은 오리진 URL 만 제안한다(외부/다른 호스트는 요청조차 불가 — 시스템이 차단).\n" +
  "2) 순수 관측만: 페이지 읽기·링크 따라가기. 로그인 폼 제출·상태변경은 하지 않는다.\n" +
  "3) 이메일·API 경로·시크릿·기술 스택·메타 등 목표와 관련된 정보를 우선 수집한다.\n" +
  "4) 충분히 모였으면 done=true 와 digest 로 요약하라.";

function dedupe(xs: string[]): string[] {
  return [...new Set(xs)];
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