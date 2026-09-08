/**
 * 어썰트 파이프라인 — URL 하나를 넣으면 자동으로:
 *
 *   정찰(recon) → 열거(enumerate) → 익스플로잇 스윕(exploit) → 증거 수집(evidence)
 *   → AI/결정적 분석(analysis) → 전투 보고(report)
 *
 * 실행 원칙:
 *   - 인가(scope)는 운영자가 입력한 URL 자체다. --authorize 로 호스트를 개인 인가
 *     목록에 기록한 뒤에만 요청이 나가며, 그 외엔 fail-closed(종료코드 3).
 *   - 대상이 죽어 있으면 스캔을 시작하지 않는다(종료코드 4, '취약점 없음' 오인 방지).
 *   - 모든 요청은 ScopeGuard(도달성·DNS 재바인딩·횡적이동)를 통과해야 한다.
 *   - 증거 수집은 "탈취 가능한 정보가 무엇인지 증명"이지 전량 덤프가 아니다:
 *     항목당 cap(기본 1500자)·최대 항목 수(기본 40)·redaction(기본 켜짐).
 *   - AI 는 분석(전투 해석)에만 쓴다. 실행은 결정적이며 모델이 죽어도 완주한다.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { classifyTarget, DEFAULT_LIST_FILE } from "../scope/ip-list.js";
import { loadAuthorization } from "../scope/load-auth.js";
import { performLogin } from "../net/login.js";
import { DefaultToolBox, OPT_IN_TOOLS } from "../tools/toolbox.js";
import { decideVerdict } from "../core/autopilot.js";
import type { Coverage, EngagementFinding, ModelAdapter, ToolContext } from "../core/types.js";
import type { Target } from "../scope/scope-guard.js";
import type { Fingerprint, Phase } from "../memory/skill-memory.js";
import { redcellHome } from "../config.js";
import { authorizeTarget, parseAssaultUrl } from "./url.js";
import { makeArgsFor } from "./args.js";
import type { TargetMap } from "../core/target-map.js";
import { collectEvidence } from "./evidence.js";
import { analyze } from "./analysis.js";
import { logLine, toHtml, toJson, toMarkdown } from "./report.js";
import type { AssaultReport, AssaultStage, AssaultTarget, StageStatus, ToolOutcome } from "./types.js";

export interface AssaultOptions {
  /** 공격 대상 URL (http/https). */
  url: string;
  /** 인가 파일 경로. 기본 ~/.redcell/authorization.list. */
  authFile?: string;
  /** 운영자가 입력한 URL 자체를 인가로 삼는다 — 호스트를 인가 목록에 기록 후 진행. */
  authorize?: boolean;
  /** AI 분석 모델. 없으면 결정적 합성(오프라인 안전). */
  model?: ModelAdapter;
  /** 보고서에 표시할 모델 라벨(예: "anthropic:claude-3-5-sonnet"). */
  modelLabel?: string;
  /** 프록시(Burp/ZAP): "http://127.0.0.1:8080" 또는 env REDCELL_PROXY. */
  proxy?: string;
  /** AI 전투 해석 사용(기본 true — --no-ai 로 끔). */
  ai?: boolean;
  /** 샘플 redaction 끄기(--full-exposure). 기본 false(마스킹). */
  fullExposure?: boolean;
  /** 항목당 증거 샘플 cap 문자 수(--evidence-cap). 기본 1500. */
  evidenceCap?: number;
  /** 매니페스트 최대 항목 수(--evidence-max). 기본 40. */
  evidenceMax?: number;
  /** 대상별 opt-in 프로브(--enable, 콤마 구분; "all" = 전부). */
  enabledOptIns?: string[];
  /** --target-map: 툴별 인자를 수동 지정(데이터 흐름 자동화 오버라이드). */
  targetMap?: TargetMap;
  /** 보고서 출력 디렉터리. 기본 ~/.redcell/assault/<host>-<ts>. */
  outDir?: string;
  /** 실시간 이벤트(ndjson/패널 연동). */
  onEvent?: (e: Record<string, unknown>) => void;
}

export interface AssaultResult {
  report: AssaultReport;
  reportDir: string;
  /** 0=완료(발견 여부와 무관) 3=scope 차단 4=대상 미도달. */
  exitCode: 0 | 3 | 4;
}

// ── 단계별 툴 구성 ───────────────────────────────────────────────────────────

const RECON_TOOLS = [
  "http_probe", "header_audit", "waf_detect", "cookie_audit", "jwt_audit", "crawl", "api_discover",
];
const ENUMERATE_TOOLS = [
  "dir_enum", "secret_scan", "api_probe", "port_scan", "cors_audit", "graphql_probe",
  "method_audit", "host_header_audit", "deserialize_probe", "auth_session_probe", "csrf_audit", "upload_probe",
];
const EXPLOIT_TOOLS = [
  "sqli_probe", "xss_probe", "path_traversal", "open_redirect", "ssrf_probe", "idor_probe",
  "ssti_probe", "cmdi_probe", "xxe_probe", "access_control_probe", "param_pollution",
];
/** opt-in(대상별 승인)이 필요한 프록브 — DEFAULT 에 있어도 승인 없이 실행하지 않는다. */
const OPT_IN_REQUIRED = new Set<string>(OPT_IN_TOOLS);

const STAGE_TOOLS: Record<Exclude<AssaultStage, "evidence" | "analysis">, string[]> = {
  recon: RECON_TOOLS,
  enumerate: ENUMERATE_TOOLS,
  exploit: EXPLOIT_TOOLS,
};

const STAGE_INTENT: Record<Exclude<AssaultStage, "evidence" | "analysis">, Target["intent"]> = {
  recon: "recon",
  enumerate: "enumerate",
  exploit: "exploit",
};

/** 연결 계층 실패(도달 불가)로 볼 요약/오류 패턴. */
const CONN_ERR = /요청 실패|타임아웃|ECONN|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|ECONNRESET|ECONNREFUSED|socket hang up|연결/i;

function mergeFp(a: Fingerprint, b: Fingerprint | undefined): Fingerprint {
  if (!b) return a;
  return {
    service: a.service ?? b.service,
    version: a.version ?? b.version,
    os: a.os ?? b.os,
    tech: [...new Set([...(a.tech ?? []), ...(b.tech ?? [])])],
    indicators: [...new Set([...(a.indicators ?? []), ...(b.indicators ?? [])])],
  };
}

const PHASE: Record<Exclude<AssaultStage, "evidence" | "analysis">, Phase> = {
  recon: "recon", enumerate: "enumerate", exploit: "exploit",
};

function findingFrom(outcome: ToolOutcome): EngagementFinding | undefined {
  const f = outcome.finding;
  if (!f?.title || f.severity === "info") return undefined;
  return {
    phase: PHASE[outcome.stage as Exclude<AssaultStage, "evidence" | "analysis">] ?? "exploit",
    severity: f.severity,
    title: f.title,
    detail: f.detail ?? outcome.summary,
    evidence: f.evidence,
  };
}

// ── 파이프라인 ───────────────────────────────────────────────────────────────

export async function runAssault(opts: AssaultOptions): Promise<AssaultResult> {
  const startedAt = new Date().toISOString();
  const t0 = parseAssaultUrl(opts.url);
  const proxy = opts.proxy ?? process.env.REDCELL_PROXY;
  const emit = opts.onEvent ?? (() => {});
  const transcript: string[] = [];

  // 1. 인가 파일 확정 (+ --authorize: 입력 URL 자체를 인가 기록).
  const authFile = opts.authFile ?? path.join(redcellHome(), DEFAULT_LIST_FILE);
  if (opts.authorize) {
    classifyTarget(t0.host); // 형식 검증(fail-closed).
    const { added } = await authorizeTarget(authFile, t0);
    transcript.push(logLine("assault", added ? `--authorize: ${t0.host} 를 인가 목록에 기록 → ${authFile}` : `--authorize: ${t0.host} 는 이미 인가됨`));
  }
  const loaded = await loadAuthorization(authFile);
  const guard = loaded.guard;

  // 2. scope 사전 점검 — URL 의 호스트가 인가 밖이면 여기서 끝(종료코드 3).
  const pre = guard.check({ host: t0.host, port: t0.port, intent: "recon" });
  if (!pre.allowed) {
    emit({ type: "blocked", reason: pre.reason, target: { host: t0.host, port: t0.port } });
    transcript.push(logLine("assault", `SCOPE 차단: ${pre.reason}`));
    return { exitCode: 3, reportDir: "", report: stubReport(opts, t0, startedAt, transcript, "blocked", pre.reason, loaded.kind, authFile) };
  }

  // 3. 로그인/세션 (인가 파일에 login 블록이 있을 때).
  let session: { auth?: Record<string, string>; jar?: unknown; proxy?: string } | undefined;
  const loginCfg = guard.loginConfig;
  if (loginCfg) {
    const scheme = t0.port === 443 || t0.port === 8443 ? "https" : "http";
    const base = `${scheme}://${t0.host}${t0.port ? `:${t0.port}` : ""}`;
    const lr = await performLogin(base, loginCfg, guard.requestsPerSecond, proxy, (h, p) => guard.check({ host: h, port: p, intent: "recon" }).allowed);
    transcript.push(logLine("login", lr.detail));
    emit({ type: "note", text: `[login] ${lr.detail}` });
    session = { auth: lr.headers, jar: lr.jar, proxy };
  } else if (proxy) {
    session = { proxy };
  }

  const toolbox = new DefaultToolBox();
  const enabled = new Set<string>(opts.enabledOptIns ?? []);
  const argsFor = makeArgsFor(opts.targetMap);
  let fp: Fingerprint = {};
  const outcomes: ToolOutcome[] = [];
  const findings: EngagementFinding[] = [];
  const stages: AssaultReport["stages"] = {};
  const requestErrors: string[] = [];

  const ctxFor = (stage: Exclude<AssaultStage, "evidence" | "analysis">): ToolContext => ({
    target: { host: t0.host, port: t0.port, intent: STAGE_INTENT[stage] },
    rps: guard.requestsPerSecond,
    auth: session?.auth,
    jar: session?.jar as ToolContext["jar"],
    proxy: session?.proxy,
    validateIp: (h, ip) => guard.checkResolvedIp(h, ip).allowed,
  });

  // 4. 도달성 사전 점검 — 죽은 대상은 즉시 종료(종료코드 4).
  const probe = toolbox.get("http_probe");
  if (probe) {
    const tP = Date.now();
    const pr = await probe.run({ path: t0.path }, ctxFor("recon"));
    const probeMs = Date.now() - tP;
    emit({ type: "tool_result", tool: "http_probe", stage: "recon", ok: pr.ok, summary: pr.summary, text: `[recon] http_probe: ${pr.summary}` });
    transcript.push(logLine("http_probe", pr.summary));
    if (!pr.ok && CONN_ERR.test(pr.summary)) {
      transcript.push(logLine("assault", `대상 미도달: ${pr.summary}`));
      return { exitCode: 4, reportDir: "", report: stubReport(opts, t0, startedAt, transcript, "unreachable", pr.summary, loaded.kind, authFile) };
    }
    outcomes.push({ tool: "http_probe", stage: "recon", ok: pr.ok, summary: pr.summary, durationMs: probeMs, data: pr.data as Record<string, unknown> | undefined, fp: pr.fingerprint });
    fp = mergeFp(fp, pr.fingerprint);
  }

  // 5. 단계 실행 (recon → enumerate → exploit).
  const runStage = async (stage: "recon" | "enumerate" | "exploit"): Promise<void> => {
    const s0 = Date.now();
    const tNames = STAGE_TOOLS[stage];
    const ctx = ctxFor(stage);
    let ran = 0;
    const stageFindings: EngagementFinding[] = [];
    emit({ type: "action", phase: stage, tool: "stage", rationale: "fixed swarm", args: {}, text: `[${stage}] 시작 (툴 ${tNames.length})` });
    transcript.push(logLine(`-- ${stage} --`, `${tNames.length}개 툴`));

    for (const name of tNames) {
      // http_probe 는 도달성 사전 점검에서 이미 실행했다(중복 방지).
      if (outcomes.some((o) => o.tool === name)) {
        transcript.push(logLine(name, "skipped (사전 점검에서 이미 실행)"));
        continue;
      }
      if (OPT_IN_REQUIRED.has(name) && !enabled.has(name)) {
        transcript.push(logLine(name, "skipped (opt-in — --enable 으로 승인 필요)"));
        continue;
      }
      const tool = toolbox.get(name);
      if (!tool) {
        transcript.push(logLine(name, "skipped (미등록 툴)"));
        continue;
      }
      const t0t = Date.now();
      let ok = false;
      let summary = "";
      let error: string | undefined;
      let data: Record<string, unknown> | undefined;
      let tfp: Fingerprint | undefined;
      try {
        const args = argsFor(name, fp);
        const res = await tool.run(args, ctx);
        ok = res.ok;
        summary = res.summary;
        data = res.data as Record<string, unknown> | undefined;
        tfp = res.fingerprint;
      } catch (e) {
        error = (e as Error).message;
        summary = `실행 오류: ${error}`;
      }
      const durationMs = Date.now() - t0t;
      ran++;
      const d = (data ?? {}) as { severity?: string; title?: string; evidence?: string; detail?: string; impact?: string };
      const outcome: ToolOutcome = {
        tool: name,
        stage,
        ok,
        summary,
        durationMs,
        data,
        fp: tfp,
        error,
        finding: d.title ? { severity: (d.severity ?? "info") as EngagementFinding["severity"], title: d.title, detail: d.detail ?? summary, evidence: d.evidence } : undefined,
      };
      outcomes.push(outcome);
      fp = mergeFp(fp, tfp);
      const f = findingFrom(outcome);
      if (f) {
        if (!findings.some((x) => x.title === f.title)) findings.push(f);
        stageFindings.push(f);
        emit({ type: "finding", finding: f, text: `[발견] (${f.severity}) ${f.title}` });
      }
      if (ok === false && CONN_ERR.test(summary + (error ?? ""))) requestErrors.push(name);
      emit({ type: "tool_result", tool: name, stage, ok, summary, durationMs, severity: (d.severity ?? "info"), text: `[${stage}] ${name}: ${summary}` });
      transcript.push(logLine(name, summary));
    }
    const status: StageStatus = ran === 0 ? "skipped" : "done";
    stages[stage] = { status, durationMs: Date.now() - s0, toolsRun: ran, findings: stageFindings.length };
    emit({ type: "action", phase: stage, tool: "stage", rationale: "complete", args: {}, text: `[${stage}] 끝 (${status}, 툴 ${ran})` });
  };

  await runStage("recon");
  // http_probe 를 사전 점검에서 이미 돌렸으므로 recon 에서는 제외하고 돌린다.
  // (위 preflight 에서 outcome 을 남겼으므로 여기서 중복 실행 방지.)
  await runStage("enumerate");
  await runStage("exploit");

  // 6. 커버리지 + 판정.
  const endpoints = (fp.indicators ?? []).filter((i) => i.startsWith("endpoint ")).length;
  const coverage: Coverage = {
    reachable: outcomes.every((o) => o.ok || !CONN_ERR.test(o.summary + (o.error ?? ""))),
    toolsRun: outcomes.length,
    toolsTotal: RECON_TOOLS.length + ENUMERATE_TOOLS.length + EXPLOIT_TOOLS.length,
    endpointsDiscovered: endpoints,
    authScanned: !!session?.auth,
    vulnClassesTested: outcomes.filter((o) => o.stage === "exploit" && !requestErrors.includes(o.tool)).map((o) => o.tool),
    requestErrors: requestErrors.length,
    deterministic: true,
  };
  const v = decideVerdict(coverage, findings, false);

  // 7. 증거 수집(탈취 가능 정보 매니페스트).
  const cap = opts.evidenceCap ?? 1500;
  const maxItems = opts.evidenceMax ?? 40;
  const redact = !opts.fullExposure;
  const lastCtx = ctxFor("exploit");
  const { items: exposed, grabbed } = await collectEvidence(outcomes, lastCtx, { cap, maxItems, redact });
  for (const item of exposed) emit({ type: "note", text: `[증거] ${item.id} ${item.label} (${item.category})` });
  transcript.push(logLine("evidence", `탈취 가능 정보 ${exposed.length}건 (샘플 ${grabbed}건 재확인, redaction ${redact ? "ON" : "OFF"})`));

  // 8. 분석 (AI → 결정적 폴백).
  const ai = opts.ai !== false;
  const analysis = await analyze(opts.model, { target: t0, findings, exposed, outcomes }, ai);
  const finishedAt = new Date().toISOString();
  const durationMs = Date.parse(finishedAt) - Date.parse(startedAt);

  const report: AssaultReport = {
    target: t0,
    startedAt,
    finishedAt,
    durationMs,
    stages,
    outcomes,
    findings,
    coverage,
    verdict: v.verdict,
    verdictReason: v.reason,
    exposed,
    attackPaths: analysis.attackPaths,
    defense: analysis.defense,
    narrative: analysis.narrative,
    transcript,
    meta: {
      command: "redcell assault",
      model: opts.modelLabel ?? (opts.model ? "custom" : "deterministic"),
      authPath: authFile,
      authKind: loaded.kind,
      aiAnalyzed: analysis.aiAnalyzed,
      fullExposure: !redact,
      redact,
    },
  };

  // 9. 보고서 저장 + 반환.
  const ts = Date.now();
  const hostTag = t0.host.replace(/[^A-Za-z0-9.-]/g, "_");
  const reportDir = opts.outDir ?? path.join(redcellHome(), "assault", `${hostTag}-${ts}`);
  await fs.mkdir(reportDir, { recursive: true });
  const mdPath = path.join(reportDir, "report.md");
  const htmlPath = path.join(reportDir, "report.html");
  const jsonPath = path.join(reportDir, "report.json");
  await Promise.all([
    fs.writeFile(mdPath, toMarkdown(report), "utf8"),
    fs.writeFile(htmlPath, toHtml(report), "utf8"),
    fs.writeFile(jsonPath, toJson(report), "utf8"),
  ]);
  emit({ type: "report", dir: reportDir, md: mdPath, html: htmlPath, json: jsonPath, verdict: report.verdict });
  transcript.push(logLine("assault", `완료 → ${reportDir} (판정 ${report.verdict})`));
  return { report, reportDir, exitCode: 0 };
}

function stubReport(
  opts: AssaultOptions,
  target: AssaultTarget,
  startedAt: string,
  transcript: string[],
  why: "blocked" | "unreachable",
  reason: string,
  authKind: string,
  authFile: string,
): AssaultReport {
  const finishedAt = new Date().toISOString();
  const blocked = why === "blocked";
  const cov: Coverage = {
    reachable: !blocked,
    toolsRun: 0,
    toolsTotal: 0,
    endpointsDiscovered: 0,
    authScanned: false,
    vulnClassesTested: [],
    requestErrors: blocked ? 0 : 1,
    deterministic: true,
  };
  return {
    target,
    startedAt,
    finishedAt,
    durationMs: Date.parse(finishedAt) - Date.parse(startedAt),
    stages: {},
    outcomes: [],
    findings: [],
    coverage: cov,
    verdict: blocked ? "inconclusive" : "inconclusive",
    verdictReason: blocked ? `SCOPE 차단: ${reason}` : `대상 미도달: ${reason}`,
    exposed: [],
    attackPaths: [],
    defense: [],
    narrative: blocked
      ? `대상 ${target.host} 는 인가 목록에 없어 어떤 요청도 보내지 않았다. 인가 파일: ${authFile}`
      : `대상 ${target.host} 에 도달하지 못해 스캔을 시작하지 않았다: ${reason}`,
    transcript,
    meta: {
      command: "redcell assault",
      model: opts.modelLabel ?? (opts.model ? "custom" : "deterministic"),
      authPath: authFile,
      authKind,
      aiAnalyzed: false,
      fullExposure: false,
      redact: true,
    },
  };
}
