#!/usr/bin/env node
/**
 * RedCell CLI — prime-agent 처럼 서브커맨드로 동작한다.
 *
 *   redcell run --host 127.0.0.1 --port 8080 [--provider anthropic] [--model ...]
 *   redcell providers                 연결 가능한 프로바이더 + 자격증명 상태
 *   redcell models                    프로바이더별 기본 모델
 *   redcell scope [--auth <path>]     인가(scope) 상태
 *   redcell auth add|rm|list <대상>   간단 인가 목록 관리 — 내가 입력한 IP = 인가
 *   redcell explore [episodes] [ucb1|thompson]
 *   redcell mcts [depth] [branching]
 *   redcell config get|set [key] [value]
 *   redcell help | --version
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadAuthorization } from "./scope/load-auth.js";
import { parseIpList, classifyTarget, DEFAULT_LIST_FILE, DEFAULT_VALIDITY_DAYS } from "./scope/ip-list.js";
import { SkillMemory } from "./memory/skill-memory.js";
import { Orchestrator, type OrchestratorEvent, type SessionContext } from "./core/orchestrator.js";
import { LivePanel } from "./panel/panel.js";
import { performLogin } from "./net/login.js";
import { AutoPilot } from "./core/autopilot.js";
import { PythonAgent } from "./py/python-agent.js";
import { MockCoder } from "./py/mock-coder.js";
import { ContextualBandit } from "./explore/bandit.js";
import { BanditStore } from "./explore/bandit-store.js";
import { DefaultToolBox, DEFAULT_TOOLS, OPT_IN_TOOLS } from "./tools/toolbox.js";
import { pythonTool } from "./tools/python-tool.js";
import { OsintAgent } from "./osint/agent.js";
import { RlmAgent } from "./rlm/rlm-agent.js";
import { MockModel } from "./core/mock-model.js";
import { parseTargetMap, argsFromMap, type TargetMap } from "./core/target-map.js";
import type { Fingerprint } from "./memory/skill-memory.js";
import { forge, type VulnClass } from "./core/payload-forge.js";
import { httpRequest } from "./net/http-client.js";
import type { CookieJar } from "./net/http-client.js";
import { toMarkdown, type ReportOptions } from "./report/report.js";
import { toVisualBoard } from "./report/visual.js";
import { buildProvenance, applyWaivers, checkSeparationOfDuties } from "./report/provenance.js";
import { decideVerdict } from "./core/autopilot.js";
import { ProviderRegistry, type ProviderSpec } from "./providers/registry.js";
import { loadCustomProviders, upsertCustomProvider, removeCustomProvider, applyCustomProviders, validateSpec, customProvidersPath } from "./providers/custom-store.js";
import { loadConfig, saveConfig, resolveModel, redcellHome, type RedcellConfig } from "./config.js";
import type { ModelAdapter, EngagementFinding, Coverage, GateVerdict } from "./core/types.js";
import { execFileSync } from "node:child_process";
import type { ScopeGuard } from "./scope/scope-guard.js";
import { AuditLog, verifyAuditFile } from "./audit/audit-log.js";

// ── 인자 파서 ────────────────────────────────────────────────────────────────
interface Args {
  _: string[]; // positional
  flags: Record<string, string | boolean>;
}
function parse(argv: string[]): Args {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else flags[key] = true;
    } else _.push(a);
  }
  return { _, flags };
}
const str = (v: string | boolean | undefined): string | undefined => (typeof v === "string" ? v : undefined);

/**
 * 대상별로 켠 opt-in 프로브 목록을 계산한다.
 *   - authorization.yaml 의 optional_probes + CLI --enable(콤마 구분) 을 합친다.
 *   - "all" 은 등록된 OPT_IN_TOOLS 전체를 켠다(명시적 전체 승인).
 *   - OPT_IN_TOOLS 에 없는 이름은 무시한다(오타·비-opt-in 툴 방지).
 */
function resolveEnabledOptIns(fromAuth: string[], flag: string | undefined): string[] {
  const raw = [...fromAuth, ...(flag ? flag.split(",") : [])].map((s) => s.trim()).filter(Boolean);
  const out = new Set<string>();
  for (const name of raw) {
    if (name.toLowerCase() === "all") {
      for (const t of OPT_IN_TOOLS) out.add(t);
    } else if (OPT_IN_TOOLS.has(name)) {
      out.add(name);
    } else {
      console.error(`[opt-in] ⚠️ 무시: '${name}' 는 opt-in 프로브가 아닙니다(대상: ${[...OPT_IN_TOOLS].join(", ")}).`);
    }
  }
  return [...out];
}

// ── 서브커맨드 ───────────────────────────────────────────────────────────────
const registry = new ProviderRegistry();

async function cmdProviders(args: Args): Promise<void> {
  const sub = args._.shift();
  if (sub === "add") return void (await cmdProviderAdd(args));
  if (sub === "rm" || sub === "remove") return void (await cmdProviderRm(args));
  if (sub !== undefined) {
    console.error(`알 수 없는 providers 서브커맨드: '${sub}' (add | rm <name>)`);
    process.exitCode = 1;
    return;
  }

  const cfg = await loadConfig();
  console.log("프로바이더 (✅=자격증명 감지, —=미설정):\n");
  console.log(`${"".padEnd(2)}${"NAME".padEnd(16)}${"KIND".padEnd(15)}${"CREDENTIAL".padEnd(22)}DEFAULT MODEL`);
  for (const s of registry.list()) {
    const cred = registry.credential(s, process.env);
    const mark = cred ? "✅" : "—";
    const src = cred ? (cred.source || "(불필요)") : s.envKeys.join("|") || "-";
    const isDefault = cfg.defaultProvider === s.name ? " *" : "";
    const user = s.apiKey !== undefined && !s.envKeys.length ? " (사용자 정의)" : "";
    console.log(`${mark} ${s.name.padEnd(16)}${s.kind.padEnd(15)}${src.padEnd(22)}${s.defaultModel ?? "(--model 필요)"}${isDefault}${user}`);
  }
  console.log(
    `\n* = config 기본 프로바이더. 변경: redcell config set defaultProvider <name>\n` +
      `사용자 정의: redcell providers add <name> --base-url <url> [--api-key-env <ENV>] [--default-model <id>]  (${customProvidersPath()})`,
  );
}

/** redcell providers add <name> --base-url <url> [--kind openai-compat|anthropic] [--api-key-env ENV[,ENV]] [--api-key <키>] [--default-model <id>] [--header "K: V"[,K: V]] [--note "..."] */
async function cmdProviderAdd(args: Args): Promise<void> {
  const name = args._.shift();
  if (!name) {
    console.error("사용법: redcell providers add <name> --base-url <url> [--api-key-env <ENV>] [--default-model <id>] [--header \"K: V\"]");
    process.exitCode = 1;
    return;
  }
  const kind = str(args.flags.kind) ?? "openai-compat";
  const baseUrl = str(args.flags["base-url"]);
  const envKeys = (str(args.flags["api-key-env"]) ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const apiKey = str(args.flags["api-key"]);
  const defaultModel = str(args.flags["default-model"]);
  const note = str(args.flags.note);
  const headers: Record<string, string> = {};
  for (const pair of (str(args.flags.header) ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const m = /^([^:]+):\s*(.+)$/.exec(pair);
    if (!m) {
      console.error(`헤더 형식 오류: '${pair}' — "이름: 값" 형식이어야 합니다.`);
      process.exitCode = 1;
      return;
    }
    headers[m[1].trim()] = m[2].trim();
  }

  const spec: ProviderSpec = {
    name,
    kind: kind as ProviderSpec["kind"],
    baseUrl,
    envKeys,
    ...(apiKey ? { apiKey } : {}),
    ...(defaultModel ? { defaultModel } : {}),
    ...(Object.keys(headers).length ? { headers: () => headers } : {}),
    ...(note ? { note } : {}),
  };
  try {
    validateSpec(spec);
  } catch (e) {
    console.error(`[providers] ${(e as Error).message}`);
    process.exitCode = 1;
    return;
  }

  const builtin = registry.get(name);
  await upsertCustomProvider(validateSpec(spec), process.env);
  console.error(
    `[providers] 사용자 정의 프로바이더 '${name}' 저장: ${customProvidersPath()}` +
      (builtin ? ` (기존 '${name}' 정의 교체됨)` : ""),
  );
  console.log(`redcell providers add '${name}' 완료. 연결: redcell run --provider ${name} [--model <id>]`);
}

/** redcell providers rm <name> */
async function cmdProviderRm(args: Args): Promise<void> {
  const name = args._.shift();
  if (!name) {
    console.error("사용법: redcell providers rm <name>");
    process.exitCode = 1;
    return;
  }
  const builtin = registry.get(name) && !(await loadCustomProviders()).some((s) => s.name === name);
  const removed = await removeCustomProvider(name, process.env);
  if (!removed) {
    if (builtin) {
      console.error(`[providers] '${name}' 는 빌트인 프로바이더라 삭제할 수 없습니다(사용자 정의로 교체하려면 add 를 쓰세요).`);
    } else {
      console.error(`[providers] 사용자 정의 프로바이더 '${name}' 가 없습니다.`);
    }
    process.exitCode = 1;
    return;
  }
  console.error(`[providers] 사용자 정의 프로바이더 '${name}' 삭제됨.`);
}

async function cmdModels(): Promise<void> {
  console.log("프로바이더별 기본 모델 (--model 로 개별 지정 가능):\n");
  for (const s of registry.list()) {
    console.log(`  ${s.name.padEnd(16)} ${s.defaultModel ?? "(지정 필요)"}${s.baseUrl ? "   [" + s.baseUrl + "]" : ""}`);
  }
}

async function findAuthPath(explicit: string | undefined, cfg: RedcellConfig): Promise<string> {
  const candidates = [
    explicit,
    cfg.authPath,
    path.join(redcellHome(), DEFAULT_LIST_FILE),   // 간단 IP 목록 (redcell auth 로 관리 — 우선)
    path.join(redcellHome(), "authorization.yaml"),
    ".prime/agent/redcell/authorization.yaml",
    "config/authorization.yaml",
  ].filter(Boolean) as string[];
  for (const c of candidates) {
    try {
      await fs.access(c);
      return c;
    } catch {
      /* 다음 후보 */
    }
  }
  throw new Error(
    `인가 파일을 찾을 수 없습니다. --auth <path> 로 지정하거나 다음 중 하나에 두세요:\n  ${candidates.join("\n  ")}`,
  );
}

/**
 * 감사 추적을 열어 ScopeGuard 에 붙인다(항상 켜짐 — --no-audit 로만 끈다).
 * 모든 scope 판정이 변조탐지(해시체인) 로그에 남아 "봉쇄 증거"가 된다.
 * 감사 파일 자체를 열지 못하면(디스크/권한) 예외를 던져 스캔을 시작하지 않는다(fail-closed):
 * 봉쇄 증거를 남길 수 없는 상태로 공격성 액션을 하지 않기 위함.
 */
function attachAudit(guard: ScopeGuard, args: Args, meta: Record<string, unknown>): AuditLog | undefined {
  if (args.flags["no-audit"]) {
    console.error("[audit] 비활성화됨(--no-audit) — 봉쇄 증거가 기록되지 않습니다.");
    return undefined;
  }
  const engagement = guard.engagementMeta.name;
  let log: AuditLog;
  try {
    log = AuditLog.open(engagement, { dir: str(args.flags["audit-dir"]) });
  } catch (e) {
    throw new Error(
      `감사 추적을 열 수 없습니다: ${(e as Error).message}\n` +
        `봉쇄 증거 없이 실행하지 않습니다(fail-closed). --audit-dir 로 쓰기 가능한 경로를 지정하거나 --no-audit 로 명시적으로 끄세요.`,
    );
  }
  log.record("event", { kind: "meta", ...meta });
  guard.setAuditSink(log);
  console.error(`[audit] 감사 추적: ${log.filePath}`);
  return log;
}

/** 발견을 감사 추적에 기록하고 로그를 닫는다(판정 요약 포함). */
function auditFinishRun(audit: AuditLog | undefined, findings: EngagementFinding[], summary: Record<string, unknown>): void {
  if (!audit) return;
  for (const f of findings) {
    audit.record("finding", { severity: f.severity, title: f.title, phase: f.phase });
  }
  audit.end({ findings: findings.length, ...summary });
}

async function cmdAudit(args: Args): Promise<void> {
  const file = str(args._[1]) ?? str(args.flags.file);
  if (!file) throw new Error("사용법: redcell audit verify <감사파일.jsonl>");
  const sub = str(args._[0]);
  if (sub && sub !== "verify") throw new Error(`알 수 없는 audit 하위명령: ${sub}. 지원: verify`);
  const r = verifyAuditFile(file);
  if (r.ok) {
    console.log(`✅ 감사 무결성 확인: ${r.entries}개 항목, 해시 체인/순번 정상(변조 없음).`);
  } else {
    console.error(`❌ 감사 무결성 실패: ${r.reason}${r.brokenAtSeq ? ` (seq ${r.brokenAtSeq})` : ""}`);
    process.exit(2);
  }
}

async function cmdScope(args: Args): Promise<void> {
  const cfg = await loadConfig();
  const authPath = await findAuthPath(str(args.flags.auth), cfg);
  const { guard, kind, summary } = await loadAuthorization(authPath);
  console.log(`✅ 인가 로드됨: ${authPath}  (${kind === "ip-list" ? "간단 IP 목록" : "authorization.yaml"})`);
  if (kind === "ip-list") {
    try {
      const parsed = parseIpList(await fs.readFile(authPath, "utf8"));
      const allows = parsed.entries.filter((e) => e.kind === "allow");
      const denies = parsed.entries.filter((e) => e.kind === "deny");
      console.log(`허용 (${allows.length}):`);
      for (const e of allows) console.log(`   ${e.raw}`);
      if (denies.length) {
        console.log(`제외 (${denies.length}):`);
        for (const e of denies) console.log(`   !${e.raw}`);
      }
      console.log(`유효기간: ${parsed.until ?? `기본(실행 시점 +${DEFAULT_VALIDITY_DAYS}일)`}   허용 포트: ${parsed.ports?.join(",") ?? "전체"}`);
    } catch {
      /* 요약만으로 충분 */
    }
  }
  console.log(`   허용 ${summary.allows}개 · 제외 ${summary.denies}개 · 인가 만료 ${summary.until} · RPS ${guard.requestsPerSecond}/s`);
}

// ── 간단 인가 목록(auth) — 내가 입력한 IP = 인가 ───────────────────────────────
const IP_LIST_HEADER = `# RedCell 인가 목록 — 아래에 적힌 대상만 인가됩니다.
# 한 줄에 하나: IP / CIDR / 도메인  ·  ! 접두사 = 제외(allow 를 이김)  ·  # 주석
# 선택 지시자:  until: YYYY-MM-DD  ·  ports: 80,443,8080
`;

async function cmdAuth(args: Args): Promise<void> {
  const sub = str(args._[0]) ?? "list";
  const file = str(args.flags.auth) ?? path.join(redcellHome(), DEFAULT_LIST_FILE);
  const read = async (): Promise<string> => {
    try {
      return await fs.readFile(file, "utf8");
    } catch {
      return "";
    }
  };

  const show = (parsed: { entries: { kind: string; raw: string }[]; until?: string; ports?: number[] }): void => {
    const allows = parsed.entries.filter((e) => e.kind === "allow");
    const denies = parsed.entries.filter((e) => e.kind === "deny");
    console.log(`허용 (${allows.length}):`);
    for (const e of allows) console.log(`   ${e.raw}`);
    if (denies.length) {
      console.log(`제외 (${denies.length}):`);
      for (const e of denies) console.log(`   !${e.raw}`);
    }
    console.log(`유효기간: ${parsed.until ?? `기본(실행 시점 +${DEFAULT_VALIDITY_DAYS}일)`}   허용 포트: ${parsed.ports?.join(",") ?? "전체"}`);
  };

  if (sub === "add") {
    const target = str(args._[1]);
    if (!target) throw new Error("사용법: redcell auth add <ip|cidr|도메인> [--deny]");
    if (target.startsWith("!")) throw new Error("add 에는 ! 접두사를 쓰지 마세요. --deny 플래그를 사용하세요.");
    // 형식 검증: 잘못된 대상이면 여기서 즉시 실패(목록에 기록되지 않음).
    classifyTarget(target);

    let raw = await read();
    const line = (args.flags.deny ? "!" : "") + target;
    if (raw.split(/\r?\n/).map((l) => l.trim()).includes(line)) {
      console.log(`ℹ️  이미 목록에 있음: ${target}`);
    } else {
      await fs.mkdir(path.dirname(file), { recursive: true });
      if (raw.trim() === "") raw = IP_LIST_HEADER;
      await fs.appendFile(file, (raw.endsWith("\n") ? "" : "\n") + line + "\n", "utf8");
      console.log(`✅ 추가됨 (${args.flags.deny ? "제외" : "허용"}): ${target}`);
    }
    console.log(`   파일: ${file}\n`);
    show(parseIpList(await read()));
    return;
  }

  if (sub === "rm") {
    const target = str(args._[1]);
    if (!target) throw new Error("사용법: redcell auth rm <ip|cidr|도메인>");
    const raw = await read();
    const before = raw.split(/\r?\n/).length;
    const kept = raw.split(/\r?\n/).filter((l) => {
      const t = l.trim();
      return t !== target && t !== "!" + target;
    });
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, kept.join("\n"), "utf8");
    const removed = before - kept.length;
    console.log(removed > 0 ? `✅ 제거됨 (${removed}줄): ${target}` : `ℹ️  목록에 없음: ${target}`);
    console.log(`   파일: ${file}\n`);
    const after = (await read()).trim();
    if (after) show(parseIpList(after));
    else console.log("ℹ️  목록이 비어 있습니다. redcell auth add <ip> 로 추가하세요.");
    return;
  }

  if (sub === "list") {
    const raw = (await read()).trim();
    if (!raw) {
      console.log(`ℹ️  인가 목록이 비어 있습니다: ${file}`);
      console.log(`   redcell auth add 10.13.37.5   (CIDR·도메인 가능, --deny 로 제외)`);
      return;
    }
    console.log(`✅ 인가 목록: ${file}\n`);
    show(parseIpList(raw));
    return;
  }

  throw new Error("사용법: redcell auth add <대상> [--deny] | rm <대상> | list   (파일: --auth <path>, 기본 ~/.redcell/authorization.list)");
}

async function cmdRun(args: Args): Promise<void> {
  const cfg = await loadConfig();
  const host = str(args.flags.host);
  if (!host) throw new Error("redcell run 에는 --host 가 필요합니다. 예: redcell run --host 127.0.0.1 --port 8080");
  const port = args.flags.port ? Number(str(args.flags.port)) : undefined;
  const goal = str(args.flags.goal) ?? "인가된 대상의 취약점 식별 및 방어 권고 보고";

  const authPath = await findAuthPath(str(args.flags.auth), cfg);
  const loaded = await loadAuthorization(authPath);
  const guard = loaded.guard;
  const audit = attachAudit(guard, args, { command: "run", target: { host, port }, goal, authPath });

  // --full/--gate: 결정적 전수(게이트) 모드. 밴딧을 쓰지 않고 각 단계 모든 툴을 1회씩
  //   실행하며(재현성), 종료코드로 게이트 판정을 낸다(clean=0 / findings=2 / inconclusive=4).
  // --fresh: 영속 밴딧 상태(bandit.json)를 로드/저장하지 않는다(표적 간 오염 제거). full 이면 자동.
  const gate = !!args.flags.full || !!args.flags.gate;
  const fresh = !!args.flags.fresh || gate;
  const allowUnauth = !!args.flags["allow-unauth"];
  // --max: 공격 최대 모드 — 모델 계획 뒤 남은 툴을 phase 별 전수 시도(커버리지) + opt-in
  //   프로브 전체 + python_exec(파이썬 심화/정보추출) 활성. 칼리 대체식 '다 시도' 캠페인.
  const maxAttack = !!args.flags.max;
  const enabledOptIns = resolveEnabledOptIns(guard.enabledOptIns, str(args.flags.enable));
  const allOptIns = new Set([...enabledOptIns, ...(maxAttack ? [...OPT_IN_TOOLS] : [])]);
  const enabledOptInsFinal = [...allOptIns];
  if (enabledOptInsFinal.length) console.error(`[opt-in] 활성 프로브: ${enabledOptInsFinal.join(", ")}`);
  if (maxAttack) {
    console.error(
      "[모드] 공격 최대(--max): phase 별 전수 커버리지 + opt-in 전체 + python_exec(파이썬 심화·정보추출) 활성. " +
      "인가된 대상 외 요청은 ScopeGuard 가 전부 차단합니다.",
    );
  }
  const toolbox = new DefaultToolBox(maxAttack ? [...DEFAULT_TOOLS, pythonTool(guard)] : DEFAULT_TOOLS);
  // --no-visual: 초보자용 시각 상황판(ASCII)을 끄고 상세 리포트만 낸다(기본은 켜짐).
  const visual = !args.flags["no-visual"];
  // --auto: 밴딧 자율 드라이버(모델 불필요). 게이트 모드는 자동으로 auto 경로를 탄다.
  const auto = !!args.flags.auto || gate;

  // --target-map <file.json>: 운영자가 아는 경로/파라미터를 직접 주입(정찰 크롤 보강).
  const targetMap = await loadTargetMapFlag(str(args.flags["target-map"]));
  const argsForFn = targetMap
    ? (tool: string, fp: Fingerprint) => argsFromMap(tool, targetMap) ?? autoArgsFor(tool, fp)
    : autoArgsFor;
  if (targetMap) console.error(`[target-map] 로드됨: ${str(args.flags["target-map"])}`);

  // P0-4: 사전 scope 게이트. 대상/포트/인가기간이 막히면 로그인·엔게이지먼트 이전에
  // 즉시 중단한다(로그인 요청조차 미인가 대상에 보내지 않기 위해 login 앞에 둔다).
  // 조용히 빈 리포트로 끝나면 "정상 통과"로 오인되므로, stderr 경고 + 리포트 배너 +
  // 전용 종료코드(3)로 차단을 분명히 드러낸다.
  const preflight = guard.check({ host, port, intent: "recon" });
  if (!preflight.allowed) {
    const banner = scopeBlockedBanner(host, port, preflight.reason);
    console.error(banner);
    if (args.flags.ndjson) {
      process.stdout.write(JSON.stringify({ type: "blocked", text: preflight.reason, target: { host, port } }) + "\n");
    } else {
      console.log("\n" + banner + "\n");
    }
    audit?.end({ verdict: "scope-blocked", reason: preflight.reason });
    process.exit(3);
  }

  // 프록시(Burp/ZAP): --proxy 또는 env REDCELL_PROXY.
  const proxy = str(args.flags.proxy) ?? process.env.REDCELL_PROXY;

  // 로그인 플로우: 인가 파일에 login 블록이 있으면 실제 로그인으로 세션을 확립한다.
  let session: SessionContext | undefined;
  const loginCfg = guard.loginConfig;
  if (loginCfg) {
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    const base = `${scheme}://${host}${port ? `:${port}` : ""}`;
    const lr = await performLogin(base, loginCfg, guard.requestsPerSecond, proxy, (h, p) => guard.check({ host: h, port: p, intent: "recon" }).allowed);
    console.error(`[login] ${lr.detail}`);
    session = { auth: lr.headers, jar: lr.jar, proxy };
  } else if (proxy) {
    session = { proxy };
  }

  // 모델 선택: --provider mock 이면 오프라인, 아니면 레지스트리 해석.
  let model: ModelAdapter = new MockModel();
  let label = "mock";
  const provider = str(args.flags.provider);
  if (!auto) {
    if (provider === "mock") {
      model = new MockModel();
      label = "mock";
    } else {
      try {
        const r = resolveModel(registry, cfg, { provider, model: str(args.flags.model) });
        model = r.model;
        label = `${r.provider}:${r.modelId}${r.credentialSource ? ` (${r.credentialSource})` : ""}`;
      } catch (e) {
        if (args.flags.mock) {
          model = new MockModel();
          label = "mock(fallback)";
        } else {
          throw new Error(`${(e as Error).message}\n오프라인 검증은 --provider mock 또는 --mock 를 쓰세요.`);
        }
      }
    }
  }

  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const memory = new SkillMemory(path.join(root, "knowledge", "playbooks"));
  await memory.load();

  console.error(`[model] ${auto ? "autopilot(bandit, 모델 없음)" : label}`);
  console.error(`[scope] ${authPath}${loaded.kind === "ip-list" ? " (간단 IP 목록)" : ""}`);

  // --ndjson: 각 이벤트를 한 줄 JSON 으로 stdout 에 흘린다(데스크톱 앱 연동).
  //           이때 사람이 읽는 Markdown 리포트는 출력하지 않는다.
  const ndjson = !!args.flags.ndjson;
  if (ndjson) {
    process.stdout.write(JSON.stringify({ type: "meta", model: auto ? "autopilot" : label, authPath, target: { host, port }, goal }) + "\n");
  }
  let panel: LivePanel | undefined;
  if (args.flags.panel) {
    const pport = args.flags["panel-port"] ? Number(str(args.flags["panel-port"])) : 5173;
    panel = await LivePanel.start({ title: `run — ${host}:${port ?? ""} · ${auto ? "autopilot" : label}` }, pport);
    console.error(`[panel] 데스크톱 패널: http://127.0.0.1:${panel.port}`);
  }
  const emit = (e: OrchestratorEvent) => {
    if (ndjson) process.stdout.write(JSON.stringify(e) + "\n");
    panel?.push(e);
  };
  if (!auto && label.startsWith("mock")) {
    const warn =
      "mock 프로바이더는 LLM 없이 고정 시나리오로 동작합니다(오프라인 테스트용) — 지시/목표가 계획에 반영되지 않습니다. " +
      "지시 기반 공격 루트 생성·추론은 API 키를 설정하고 실제 프로바이더를 선택하세요 " +
      "(ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY / PRIME_API_KEY / GROQ_API_KEY, 또는 로컬 ollama).";
    console.error(`[주의] ${warn}`);
    emit?.({ type: "note", text: `[model] ${warn}` });
  }

  if (auto) {
    // 게이트 모드: 엔게이지먼트 전에 도달성부터 확인한다. 대상이 죽어 있으면 스캔이
    // 무의미하게 오래 돌다 '발견 0'으로 끝나 '통과'로 오인되므로, 즉시 종료코드 4 로 끊는다.
    if (gate) {
      const reach = await probeReachable(host, port, proxy);
      if (!reach.ok) {
        const banner = unreachableBanner(host, port, reach.detail);
        console.error(banner);
        if (ndjson) process.stdout.write(JSON.stringify({ type: "error", text: reach.detail }) + "\n");
        else console.log("\n" + banner + "\n");
        audit?.end({ verdict: "inconclusive", reason: reach.detail });
        process.exit(4);
      }
    }

    // 게이트/--fresh 는 영속 밴딧을 로드·저장하지 않는다(표적 간 오염 제거 → 재현성).
    const storePath = path.join(redcellHome(), "bandit.json");
    const store = new BanditStore(storePath);
    const bandit = fresh ? new ContextualBandit("ucb1") : await store.load("ucb1");
    const autopilot = new AutoPilot(guard, memory, bandit, toolbox, {
      maxStepsPerPhase: args.flags["max-actions"] ? Number(str(args.flags["max-actions"])) : 8,
      globalBudget: gate ? 200 : 60,
      banditStore: fresh ? undefined : store,
      argsFor: argsForFn,
      onEvent: emit,
      session,
      full: gate,
      allowUnauth,
      enabledOptIns,
    });
    const rep = await autopilot.run({ host, port }, goal);
    // 프로세스 성숙도: 직무분리 + waiver(수용된 위험 제외 판정) + 서명 리포트 출처.
    const gov = await governReport(guard, args, root, allowUnauth, {
      findings: rep.findings,
      coverage: rep.coverage,
      verdict: rep.verdict,
      verdictReason: rep.verdictReason,
    });
    if (!ndjson) {
      const log = {
        target: rep.target,
        fingerprint: rep.fingerprint,
        findings: gov.activeFindings, // 수용된 위험은 별도 섹션에 표기(중복 방지)
        usedPlaybooks: rep.usedPlaybooks,
        distilled: [],
        transcript: rep.transcript,
        coverage: rep.coverage,
        verdict: gov.verdict,
        verdictReason: gov.verdictReason,
      };
      if (visual) console.log("\n" + toVisualBoard(log, { waived: gov.reportOpts.waived }));
      console.log("\n" + toMarkdown(log, gov.reportOpts) + "\n");
    }
    auditFinishRun(audit, gov.activeFindings, { command: "run", mode: gate ? "gate" : "auto", verdict: gov.verdict ?? rep.verdict });
    // 게이트 모드: 판정을 종료코드로 낸다(CI 연동). findings=2, inconclusive=4, clean=0.
    // waiver 로 수용된 위험을 제외한 재계산 판정(gov.verdict)을 사용한다.
    if (gate) {
      console.error(gateExitBanner(gov.verdict ?? rep.verdict, gov.verdictReason ?? rep.verdictReason));
      if (gov.verdict === "findings") process.exit(2);
      if (gov.verdict === "inconclusive") process.exit(4);
    }
    return;
  }

  const orch = new Orchestrator(guard, memory, model, toolbox, {
    maxActionsPerPhase: args.flags["max-actions"] ? Number(str(args.flags["max-actions"])) : maxAttack ? 10 : 4,
    allowActivePhases: !args.flags["dry-run"],
    onEvent: emit,
    session,
    enabledOptIns: enabledOptInsFinal,
    // --max: 모델 계획 소진 후 남은 툴을 전수 1회씩(놓친 표면 보강).
    coverage: maxAttack,
    argsFor: argsForFn,
  });
  const log = await orch.run({ host, port }, goal);
  await panel?.close();
  let activeFindings = log.findings;
  if (!ndjson) {
    const gov = await governReport(guard, args, root, allowUnauth, { findings: log.findings });
    activeFindings = gov.activeFindings;
    log.findings = gov.activeFindings; // 수용된 위험은 별도 섹션으로 분리
    if (visual) console.log("\n" + toVisualBoard(log, { waived: gov.reportOpts.waived }));
    console.log("\n" + toMarkdown(log, gov.reportOpts) + "\n");
  }
  auditFinishRun(audit, activeFindings, { command: "run", mode: "orchestrator" });
}

/** scope 차단 시 사람이 놓칠 수 없는 배너(빈 리포트를 "정상 통과"로 오인하는 것을 막는다). */
function scopeBlockedBanner(host: string, port: number | undefined, reason: string): string {
  const t = `${host}${port != null ? ":" + port : ""}`;
  return [
    "╔══════════════════════════════════════════════════════════════╗",
    "║  ⛔ SCOPE 차단 — engagement 를 실행하지 않았습니다               ║",
    "╚══════════════════════════════════════════════════════════════╝",
    `대상   : ${t}`,
    `사유   : ${reason}`,
    "조치   : authorization.yaml 의 scope.allow / ports.allow_tcp / 인가기간을 확인하세요.",
    "         (인가된 대상만 추가할 것. 임시(ephemeral) 포트는 ports.allow_tcp 에 포함해야 함)",
    "종료코드: 3 (scope 차단) — 스캔이 수행되지 않았으므로 '취약점 없음'이 아닙니다.",
  ].join("\n");
}

/**
 * 게이트 도달성 사전 점검 — 단일 요청(짧은 타임아웃, 재시도 없음)으로 대상이 살아있는지 본다.
 * 죽은 대상에 대해 스캔이 오래 돌다 '발견 0'으로 끝나 '통과'로 오인되는 것을 막는다.
 */
async function probeReachable(host: string, port: number | undefined, proxy: string | undefined): Promise<{ ok: boolean; detail: string }> {
  const scheme = port === 443 || port === 8443 ? "https" : "http";
  const url = `${scheme}://${host}${port ? `:${port}` : ""}/`;
  try {
    const res = await httpRequest(url, { method: "GET", timeoutMs: 4000, retries: 0, proxy });
    return { ok: true, detail: `도달 확인: ${url} → HTTP ${res.status}` };
  } catch (e) {
    return { ok: false, detail: `대상 미도달: ${url} — ${(e as Error).message}` };
  }
}

/** 게이트 도달 실패 배너(종료코드 4 = 스캔 미수행, '취약점 없음' 아님). */
function unreachableBanner(host: string, port: number | undefined, detail: string): string {
  const t = `${host}${port != null ? ":" + port : ""}`;
  return [
    "╔══════════════════════════════════════════════════════════════╗",
    "║  🟡 INCONCLUSIVE — 대상에 도달하지 못해 스캔을 수행하지 못함     ║",
    "╚══════════════════════════════════════════════════════════════╝",
    `대상   : ${t}`,
    `사유   : ${detail}`,
    "조치   : 대상이 실행 중인지·포트가 맞는지·프록시 설정을 확인하세요.",
    "종료코드: 4 (도달 실패) — 스캔이 수행되지 않았으므로 '취약점 없음'이 아닙니다.",
  ].join("\n");
}

/** 게이트 판정 → 종료코드 요약 배너(CI 로그에서 결과를 놓치지 않도록). */
function gateExitBanner(verdict: string, reason: string): string {
  const map: Record<string, string> = {
    clean: "🟢 PASS(clean) — 종료코드 0",
    findings: "🔴 FAIL(findings) — 종료코드 2",
    inconclusive: "🟡 INCONCLUSIVE — 종료코드 4",
  };
  return [
    "──────────────────────────────────────────────────────────────",
    `게이트 판정: ${map[verdict] ?? verdict}`,
    `사유: ${reason}`,
    verdict === "clean"
      ? "주의: 이 PASS 는 검사한 표면 한정입니다. 수동 펜테스트·SCA·인증/로직 리뷰를 병행하세요."
      : "오픈 불가 — 위 사유를 해소한 뒤 재실행하세요.",
    "──────────────────────────────────────────────────────────────",
  ].join("\n");
}

/** RedCell 소스 커밋(있으면). 이 리포트를 낸 툴 빌드 식별용(best-effort). */
function toolCommit(root: string): string | undefined {
  try {
    return execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: root, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim() || undefined;
  } catch {
    return undefined;
  }
}

async function readVersion(root: string): Promise<string> {
  try {
    const pkg = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));
    return String(pkg.version ?? "0.0.0");
  } catch {
    return "0.0.0";
  }
}

interface ReportShape {
  findings: EngagementFinding[];
  coverage?: Coverage;
  verdict?: GateVerdict;
  verdictReason?: string;
}
interface Governed {
  reportOpts: ReportOptions;
  activeFindings: EngagementFinding[];
  verdict?: GateVerdict;
  verdictReason?: string;
}

/**
 * 프로세스 성숙도 게이트: 직무분리 확인 → waiver 적용(정식 위험수용) → 판정 재계산 →
 * 서명 리포트 출처 구성. 라이브러리(autopilot/orchestrator)는 건드리지 않고 CLI 경계에서만 적용한다.
 */
async function governReport(
  guard: ScopeGuard,
  args: Args,
  root: string,
  allowUnauth: boolean,
  log: ReportShape,
): Promise<Governed> {
  const meta = guard.engagementMeta;

  // 직무분리(SoD): 인가자≠운영자여야 한다. 위반 시 경고(차단은 아님 — 운영 정책에 위임).
  const sod = checkSeparationOfDuties(meta.authorizedBy, meta.operator);
  console.error(sod.ok ? `[직무분리] ${sod.message}` : `[직무분리] ⚠️ ${sod.message}`);

  // waiver(정식 위험수용): 만료된 waiver 는 적용하지 않는다.
  const w = applyWaivers(log.findings, guard.waivers);
  for (const iv of w.invalid) {
    console.error(`[waiver] ⚠️ 무효 waiver 무시: match="${iv.match}" (빈 패턴 또는 잘못된 정규식) → 어떤 발견도 수용하지 않음`);
  }
  for (const ex of w.expired) {
    console.error(`[waiver] ⚠️ 만료된 waiver 무시: "${ex.match}" (만료 ${ex.expires}) → 해당 발견 유효 유지`);
  }
  for (const wf of w.waived) {
    console.error(`[waiver] 수용된 위험: "${wf.finding.title}" (승인 ${wf.waiver.approved_by}, 만료 ${wf.waiver.expires})`);
  }

  // 판정 재계산: 수용된 위험을 제외하고 다시 판정한다(감사 가능한 게이트 통과).
  let verdict = log.verdict;
  let reason = log.verdictReason;
  if (log.coverage && w.waived.length > 0) {
    const v = decideVerdict(log.coverage, w.active, allowUnauth);
    verdict = v.verdict;
    reason = `${v.reason} (수용된 위험 ${w.waived.length}건 제외 — 승인된 waiver)`;
  }

  const version = await readVersion(root);
  const prov = buildProvenance({
    version,
    tools: new DefaultToolBox().list(),
    engagement: meta.name,
    authorizedBy: meta.authorizedBy,
    operator: meta.operator,
    targetRef: str(args.flags["target-ref"]) ?? meta.targetRef,
    toolCommit: toolCommit(root),
  });

  return {
    reportOpts: { provenance: prov, waived: w.waived, signingKey: guard.signingKey() },
    activeFindings: w.active,
    verdict,
    verdictReason: reason,
  };
}

/** AutoPilot 이 발견한 엔드포인트로 공격 툴 인자를 구성(툴 간 데이터 흐름). */
/** --target-map <file.json> 로드(없으면 undefined, 형식 오류면 던진다). */
async function loadTargetMapFlag(pathArg: string | undefined): Promise<TargetMap | undefined> {
  if (!pathArg) return undefined;
  let raw: string;
  try {
    raw = await fs.readFile(pathArg, "utf8");
  } catch {
    throw new Error(`--target-map 파일을 읽을 수 없습니다: ${pathArg}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new Error(`--target-map 파일이 올바른 JSON 이 아닙니다: ${pathArg}`);
  }
  return parseTargetMap(json);
}

function autoArgsFor(toolName: string, fp: Fingerprint): Record<string, unknown> {
  const endpoints: string[] = [];
  for (const i of fp.indicators ?? []) {
    const m = /^endpoint (\/\S+)/.exec(i);
    if (m) endpoints.push(m[1]);
  }
  const forgeMap: Record<string, VulnClass> = {
    xss_probe: "xss",
    path_traversal: "lfi",
    open_redirect: "redirect",
    ssrf_probe: "ssrf",
  };
  // 발견된 엔드포인트에서 서로 다른 경로/파라미터 집합을 추출한다.
  // 취약점은 엔드포인트마다 다르므로(예: /tpl→SSTI, /ping→CMDI), 주입 계열
  // 툴에는 발견한 경로·파라미터 전체를 넘겨 발산적으로 스윕하게 한다.
  const paths = [...new Set(endpoints.map((e) => e.split("?")[0]))].slice(0, 8);
  const params = [
    ...new Set(
      endpoints.flatMap((e) => {
        const q = e.split("?")[1];
        return q ? [...new URLSearchParams(q).keys()] : [];
      }),
    ),
  ].filter(Boolean).slice(0, 8);

  if (endpoints.length === 0) {
    // 엔드포인트가 없어도 페이로드 툴은 fp 기반 변형을 실어 발산을 유지한다.
    return forgeMap[toolName] ? { payloads: forge(forgeMap[toolName], fp) } : {};
  }
  const first = endpoints[0];
  const path0 = first.split("?")[0];
  // 주입 계열 툴: 발견한 경로 전체를 스윕(+ 파라미터 힌트). 페이로드는 fp 기반 변형.
  if (forgeMap[toolName]) {
    const a: Record<string, unknown> = { paths, payloads: forge(forgeMap[toolName], fp) };
    if (params.length) a.params = params;
    return a;
  }
  switch (toolName) {
    case "api_probe":
      return { paths };
    case "ssti_probe":
    case "cmdi_probe":
    case "logic_probe": {
      const a: Record<string, unknown> = { paths };
      if (params.length) a.params = params;
      return a;
    }
    case "xxe_probe":
    case "deserialize_probe":
    case "auth_session_probe":
    case "cache_poison_probe":
      return { paths };
    case "sqli_probe":
    case "cors_audit":
      return { path: path0, ...(params.length ? { params } : {}) };
    case "idor_probe": {
      const idPath = endpoints.find((e) => /\/\d+(\/?$)/.test(e.split("?")[0])) ?? first;
      return { path: idPath.split("?")[0] };
    }
    default:
      return {};
  }
}

async function cmdConfig(args: Args): Promise<void> {
  const [op, key, value] = args._;
  const cfg = await loadConfig();
  if (op === "get" || !op) {
    console.log(JSON.stringify(cfg, null, 2));
    return;
  }
  if (op === "set") {
    if (!key || value === undefined) throw new Error("사용법: redcell config set <key> <value>  (key: defaultProvider|defaultModel|authPath)");
    (cfg as Record<string, string>)[key] = value;
    await saveConfig(cfg);
    console.log(`저장됨: ${key} = ${value}  (${path.join(redcellHome(), "config.json")})`);
    return;
  }
  throw new Error("config 하위명령: get | set");
}

async function cmdExplore(args: Args): Promise<void> {
  // 데모는 별도 모듈에 있으므로 동적 import.
  process.argv = [process.argv[0], "explore-demo", ...args._];
  await import("./explore-demo.js");
}
async function cmdMcts(args: Args): Promise<void> {
  process.argv = [process.argv[0], "mcts-demo", ...args._];
  await import("./mcts-demo.js");
}

/**
 * cmdPyRun — "absolute-agent" 모드: 모델이 파이썬 코드를 스스로 작성·실행하며 대상을
 * 공략한다(고정 툴박스 대신). 모든 대상 통신은 broker(ScopeGuard) 를 경유한다.
 */
async function cmdPyRun(args: Args): Promise<void> {
  const cfg = await loadConfig();
  const host = str(args.flags.host);
  if (!host) throw new Error("redcell pyrun 에는 --host 가 필요합니다. 예: redcell pyrun --host 127.0.0.1 --port 8080");
  const port = args.flags.port ? Number(str(args.flags.port)) : undefined;
  const goal = str(args.flags.goal) ?? "인가된 대상의 취약점을 파이썬으로 직접 탐색하고 방어 권고 보고";

  const authPath = await findAuthPath(str(args.flags.auth), cfg);
  const loaded = await loadAuthorization(authPath);
  const guard = loaded.guard;
  const audit = attachAudit(guard, args, { command: "pyrun", target: { host, port }, goal, authPath });
  const allowUnauth = !!args.flags["allow-unauth"];
  const visual = !args.flags["no-visual"];

  // 사전 scope 게이트(로그인·실행 이전) — 미인가면 종료코드 3.
  const preflight = guard.check({ host, port, intent: "recon" });
  if (!preflight.allowed) {
    const banner = scopeBlockedBanner(host, port, preflight.reason);
    console.error(banner);
    if (args.flags.ndjson) process.stdout.write(JSON.stringify({ type: "blocked", text: preflight.reason, target: { host, port } }) + "\n");
    else console.log("\n" + banner + "\n");
    audit?.end({ verdict: "scope-blocked", reason: preflight.reason });
    process.exit(3);
  }

  const proxy = str(args.flags.proxy) ?? process.env.REDCELL_PROXY;
  let session: SessionContext | undefined;
  const loginCfg = guard.loginConfig;
  if (loginCfg) {
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    const base = `${scheme}://${host}${port ? `:${port}` : ""}`;
    const lr = await performLogin(base, loginCfg, guard.requestsPerSecond, proxy, (h, p) => guard.check({ host: h, port: p, intent: "recon" }).allowed);
    console.error(`[login] ${lr.detail}`);
    session = { auth: lr.headers, jar: lr.jar, proxy };
  } else if (proxy) {
    session = { proxy };
  }

  // 코드 작성 모델: --provider mock 이면 오프라인 MockCoder, 아니면 레지스트리 해석.
  let model: ModelAdapter = new MockCoder();
  let label = "mock-coder";
  const provider = str(args.flags.provider);
  if (provider !== "mock") {
    try {
      const r = resolveModel(registry, cfg, { provider, model: str(args.flags.model) });
      model = r.model;
      label = `${r.provider}:${r.modelId}${r.credentialSource ? ` (${r.credentialSource})` : ""}`;
    } catch (e) {
      if (args.flags.mock) {
        model = new MockCoder();
        label = "mock-coder(fallback)";
      } else {
        throw new Error(`${(e as Error).message}\n오프라인 검증은 --provider mock 또는 --mock 를 쓰세요.`);
      }
    }
  }

  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  console.error(`[model] python-agent · ${label}`);
  console.error(`[scope] ${authPath}${loaded.kind === "ip-list" ? " (간단 IP 목록)" : ""}`);

  const ndjson = !!args.flags.ndjson;
  if (ndjson) process.stdout.write(JSON.stringify({ type: "meta", model: label, mode: "python-agent", authPath, target: { host, port }, goal }) + "\n");
  const emit = ndjson ? (e: OrchestratorEvent) => process.stdout.write(JSON.stringify(e) + "\n") : undefined;

  // OS 격리 정책: 기본 required(신뢰불가 코드는 격리 백엔드 없으면 거부). --isolation 로 조정.
  const isoFlag = str(args.flags.isolation);
  const isolation: "required" | "best-effort" | "off" =
    isoFlag === "off" || isoFlag === "best-effort" || isoFlag === "required" ? isoFlag : "required";
  if (isoFlag && isoFlag !== isolation) throw new Error(`--isolation 값은 required|best-effort|off 중 하나여야 합니다(받은 값: ${isoFlag}).`);
  // required 정책에 격리 백엔드가 없으면 broker 가 fail-closed 로 거부한다(기본 안전 정책).
  // 데스크톱 앱은 인가 게이트가 이미 적용되므로 --isolation best-effort 를 명시해 실행한다.

  const agent = new PythonAgent(guard, model, {
    maxIterations: args.flags["max-actions"] ? Number(str(args.flags["max-actions"])) : 8,
    stepTimeoutMs: args.flags["step-timeout"] ? Number(str(args.flags["step-timeout"])) : 15000,
    onEvent: emit,
    session,
    isolation,
  });
  const log = await agent.run({ host, port }, goal);

  let activeFindings = log.findings;
  if (!ndjson) {
    const gov = await governReport(guard, args, root, allowUnauth, { findings: log.findings });
    activeFindings = gov.activeFindings;
    log.findings = gov.activeFindings;
    if (visual) console.log("\n" + toVisualBoard(log, { waived: gov.reportOpts.waived }));
    console.log("\n" + toMarkdown(log, gov.reportOpts) + "\n");
  }
  auditFinishRun(audit, activeFindings, { command: "pyrun", isolation });
}

/**
 * cmdOsint — OSINT 딥 다이그: 시드 사이트를 샅샅이 뒤져 목표 정보를 가져온다.
 * 결정적 walker(깊이 크롤 + robots/sitemap + 인텔 추출) + 모델의 frontier 선택.
 * 모든 요청은 ScopeGuard(인가 호스트 + 해석 IP)를 통과한다. 동일 오리진만, GET 관측 전용.
 */
async function cmdOsint(args: Args): Promise<void> {
  const cfg = await loadConfig();
  const host = str(args.flags.host);
  if (!host) throw new Error("redcell osint 에는 --host 가 필요합니다. 예: redcell osint --host example.com --goal '연락처 이메일 모으기'");
  const port = args.flags.port ? Number(str(args.flags.port)) : undefined;
  const goal = str(args.flags.goal) ?? "사이트를 샅샅이 뒤져 사용자에게 유용한 정보(연락처·API·기술스택·구성) 수집";

  const authPath = await findAuthPath(str(args.flags.auth), cfg);
  const loaded = await loadAuthorization(authPath);
  const guard = loaded.guard;
  const audit = attachAudit(guard, args, { command: "osint", target: { host, port }, goal, authPath });
  const allowUnauth = !!args.flags["allow-unauth"];
  const visual = !args.flags["no-visual"];

  const preflight = guard.check({ host, port, intent: "recon" });
  if (!preflight.allowed) {
    const banner = scopeBlockedBanner(host, port, preflight.reason);
    console.error(banner);
    if (args.flags.ndjson) process.stdout.write(JSON.stringify({ type: "blocked", text: preflight.reason, target: { host, port } }) + "\n");
    else console.log("\n" + banner + "\n");
    audit?.end({ verdict: "scope-blocked", reason: preflight.reason });
    process.exit(3);
  }

  const proxy = str(args.flags.proxy) ?? process.env.REDCELL_PROXY;

  // 로그인 플로우(인가 파일 login 블록) — 로그인 뒤 표면까지 샅샅이.
  let session: { auth?: Record<string, string>; jar?: CookieJar; proxy?: string } | undefined;
  const loginCfg = guard.loginConfig;
  if (loginCfg) {
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    const base = `${scheme}://${host}${port ? `:${port}` : ""}`;
    const lr = await performLogin(base, loginCfg, guard.requestsPerSecond, proxy, (h, p) => guard.check({ host: h, port: p, intent: "recon" }).allowed);
    console.error(`[login] ${lr.detail}`);
    session = { auth: lr.headers, jar: lr.jar, proxy };
  } else if (proxy) {
    session = { proxy };
  }

  // 모델: --auto 또는 --provider mock 이면 결정적 속도전(모델 없이 전체 다이그).
  let model: ModelAdapter = new MockModel();
  let label = "mock";
  let auto = !!args.flags.auto || str(args.flags.provider) === "mock";
  if (!auto) {
    try {
      const r = resolveModel(registry, cfg, { provider: str(args.flags.provider), model: str(args.flags.model) });
      model = r.model;
      label = `${r.provider}:${r.modelId}${r.credentialSource ? ` (${r.credentialSource})` : ""}`;
    } catch (e) {
      if (args.flags.mock) {
        model = new MockModel();
        label = "mock(fallback)";
        auto = true;
      } else {
        throw new Error(`${(e as Error).message}\n오프라인 검증은 --provider mock 또는 --auto 를 쓰세요.`);
      }
    }
  }

  if (auto) console.error("[모델] auto(결정적 전체 다이그, 모델 불필요)");
  else console.error(`[모델] osint-agent · ${label}`);
  console.error(`[scope] ${authPath}${loaded.kind === "ip-list" ? " (간단 IP 목록)" : ""}`);

  const ndjson = !!args.flags.ndjson;
  if (ndjson) process.stdout.write(JSON.stringify({ type: "meta", model: auto ? "auto" : label, mode: "osint", authPath, target: { host, port }, goal }) + "\n");
  const emit = ndjson ? (e: OrchestratorEvent) => process.stdout.write(JSON.stringify(e) + "\n") : undefined;

  const agent = new OsintAgent(guard, auto ? null : model, {
    auto,
    maxIterations: args.flags["max-actions"] ? Number(str(args.flags["max-actions"])) : 4,
    onEvent: emit,
    session,
  });
  const log = await agent.run({ host, port }, goal);

  let activeFindings = log.findings;
  if (!ndjson) {
    const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const gov = await governReport(guard, args, root, allowUnauth, { findings: log.findings });
    activeFindings = gov.activeFindings;
    log.findings = gov.activeFindings;
    if (visual) console.log("\n" + toVisualBoard(log, { waived: gov.reportOpts.waived }));
    console.log("\n" + toMarkdown(log, gov.reportOpts) + "\n");
  }
  auditFinishRun(audit, activeFindings, { command: "osint" });
}

/** 직전 세션의 RLM 기억 파일(rc.memo) 로드 — 없으면 빈 배열. */
async function loadMemories(memPath: string | undefined): Promise<string[]> {
  if (!memPath) return [];
  try {
    const md = await fs.readFile(memPath, "utf8");
    const out: string[] = [];
    for (const block of md.split(/\n## /)) {
      const lines = block.split("\n");
      const key = lines[0].trim();
      const text = lines.slice(1).join(" ").trim();
      if (key && text) out.push(`${key}: ${text}`);
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * cmdRlm — RLM 모드: 영구 파이썬 REPL + 재귀 서브콜(rlm()) + 자기발전 기억(rc.memo).
 * 모든 대상 통신은 runPython 과 동일한 브로커 게이트(ScopeGuard·공유 예산·RPS)를 통과한다.
 */
async function cmdRlm(args: Args): Promise<void> {
  const cfg = await loadConfig();
  const host = str(args.flags.host);
  if (!host) throw new Error("redcell rlm 에는 --host 가 필요합니다. 예: redcell rlm --host 127.0.0.1 --port 8080");
  const port = args.flags.port ? Number(str(args.flags.port)) : undefined;
  const goal = str(args.flags.goal) ?? "인가된 대상을 영구 REPL 로 재귀 탐색하고 취약점을 발견해 정리해줘";

  const authPath = await findAuthPath(str(args.flags.auth), cfg);
  const loaded = await loadAuthorization(authPath);
  const guard = loaded.guard;
  const audit = attachAudit(guard, args, { command: "rlm", target: { host, port }, goal, authPath });
  const allowUnauth = !!args.flags["allow-unauth"];
  const visual = !args.flags["no-visual"];

  // 사전 scope 게이트(로그인·실행 이전) — 미인가면 종료코드 3.
  const preflight = guard.check({ host, port, intent: "recon" });
  if (!preflight.allowed) {
    const banner = scopeBlockedBanner(host, port, preflight.reason);
    console.error(banner);
    if (args.flags.ndjson) process.stdout.write(JSON.stringify({ type: "blocked", text: preflight.reason, target: { host, port } }) + "\n");
    else console.log("\n" + banner + "\n");
    audit?.end({ verdict: "scope-blocked", reason: preflight.reason });
    process.exit(3);
  }

  const proxy = str(args.flags.proxy) ?? process.env.REDCELL_PROXY;
  let session: SessionContext | undefined;
  const loginCfg = guard.loginConfig;
  if (loginCfg) {
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    const base = `${scheme}://${host}${port ? `:${port}` : ""}`;
    const lr = await performLogin(base, loginCfg, guard.requestsPerSecond, proxy, (h, p) => guard.check({ host: h, port: p, intent: "recon" }).allowed);
    console.error(`[login] ${lr.detail}`);
    session = { auth: lr.headers, jar: lr.jar, proxy };
  } else if (proxy) {
    session = { proxy };
  }

  let model: ModelAdapter = new MockCoder();
  let label = "mock-coder";
  const provider = str(args.flags.provider);
  if (provider !== "mock") {
    try {
      const r = resolveModel(registry, cfg, { provider, model: str(args.flags.model) });
      model = r.model;
      label = `${r.provider}:${r.modelId}${r.credentialSource ? ` (${r.credentialSource})` : ""}`;
    } catch (e) {
      if (args.flags.mock) {
        model = new MockCoder();
        label = "mock-coder(fallback)";
      } else {
        throw new Error(`${(e as Error).message}\n오프라인 검증은 --provider mock 또는 --mock 를 쓰세요.`);
      }
    }
  }

  // 자기발전 기억 파일(rc.memo) — 기본 ~/.redcell/memories/<호스트>.md
  const memPath = str(args.flags.mem) ?? path.join(redcellHome(), "memories", `${host.replace(/[^\w.-]/g, "_")}.md`);
  const memories = await loadMemories(memPath);

  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  console.error(`[model] rlm-agent · ${label}`);
  console.error(`[scope] ${authPath}${loaded.kind === "ip-list" ? " (간단 IP 목록)" : ""}`);
  if (memories.length) console.error(`[기억] 이전 세션 기억 ${memories.length}건 재주입 (${memPath})`);

  const ndjson = !!args.flags.ndjson;
  if (ndjson) process.stdout.write(JSON.stringify({ type: "meta", model: label, mode: "rlm", authPath, target: { host, port }, goal, memories: memories.length }) + "\n");
  let panel: LivePanel | undefined;
  if (args.flags.panel) {
    const pport = args.flags["panel-port"] ? Number(str(args.flags["panel-port"])) : 5173;
    panel = await LivePanel.start({ title: `rlm — ${host}:${port ?? ""} · ${label}` }, pport);
    console.error(`[panel] 데스크톱 패널: http://127.0.0.1:${panel.port}`);
  }
  const emit = (e: OrchestratorEvent) => {
    if (ndjson) process.stdout.write(JSON.stringify(e) + "\n");
    panel?.push(e);
  };

  const isoFlag = str(args.flags.isolation);
  const isolation: "required" | "best-effort" | "off" =
    isoFlag === "off" || isoFlag === "best-effort" || isoFlag === "required" ? isoFlag : "required";
  if (isoFlag && isoFlag !== isolation) throw new Error(`--isolation 값은 required|best-effort|off 중 하나여야 합니다(받은 값: ${isoFlag}).`);

  try {
    await fs.mkdir(path.dirname(memPath), { recursive: true });
  } catch {
    /* 메모리 디렉터리 생성 실패는 무시(기록만 안 됨) */
  }

  const agent = new RlmAgent(guard, model, {
    maxIterations: args.flags["max-actions"] ? Number(str(args.flags["max-actions"])) : 10,
    maxDepth: args.flags.depth ? Number(str(args.flags.depth)) : 3,
    stepTimeoutMs: args.flags["step-timeout"] ? Number(str(args.flags["step-timeout"])) : 20000,
    budget: { used: 0, max: args.flags.budget ? Number(str(args.flags.budget)) : 240 },
    memories,
    memoryFile: memPath,
    onEvent: emit,
    session,
    isolation,
  });
  const log = await agent.run({ host, port }, goal);
  await panel?.close();

  let activeFindings = log.findings;
  if (!ndjson) {
    const gov = await governReport(guard, args, root, allowUnauth, { findings: log.findings });
    activeFindings = gov.activeFindings;
    log.findings = gov.activeFindings;
    if (visual) console.log("\n" + toVisualBoard(log, { waived: gov.reportOpts.waived }));
    console.log("\n" + toMarkdown(log, gov.reportOpts) + "\n");
  }
  auditFinishRun(audit, activeFindings, { command: "rlm", isolation });
}

function help(): void {
  console.log(`RedCell — 자기발전형 화이트해커 에이전트 (prime-agent 기반)

사용법: redcell <command> [options]

Commands:
  run          인가된 대상에 engagement 실행
                 --host <h> [--port <p>] [--goal <g>]
                 [--provider <name>] [--model <id>] [--auth <path>]
                 [--proxy <url>]  Burp/ZAP 등 프록시 경유(env REDCELL_PROXY 도 가능)
                 [--dry-run] [--mock] [--max-actions <n>] [--ndjson]
                 [--auto]  모델 없이 밴딧 자율 드라이버로 다각 벡터 발산 탐색
                 [--full|--gate]  결정적 전수(게이트) 모드: 밴딧 없이 모든 툴 1회씩 실행,
                                  종료코드로 판정(clean=0/findings=2/inconclusive=4)
                 [--fresh]  영속 밴딧 상태를 로드·저장하지 않음(표적 간 오염 제거·재현성)
                 [--allow-unauth]  공개 서비스로 간주해 인증 표면 미점검을 허용(게이트 판정)
                 [--enable <t[,t]>]  부작용성 opt-in 프로브를 대상별로 켠다(logic_probe,cache_poison_probe|all)
                 [--max]  공격 최대 모드: 모델 계획 후 phase 별 남은 툴 전수 1회씩 + opt-in 전체 +
                          python_exec(파이썬 심화 공격·정보추출) 활성 — 칼리 대체식 캠페인
                 [--target-ref <ref>]  검사 대상의 커밋/빌드 참조(서명 리포트 출처에 기록)
                 [--target-map <file.json>]  아는 경로/파라미터를 직접 주입(정찰 크롤 보강)
                 [--no-visual]  초보자용 시각 상황판(ASCII 그림)을 끄고 상세 리포트만 출력
                 [--panel]  로컬 라이브 패널(http://127.0.0.1:5173)에 이벤트를 흘린다
                 [--panel-port <n>]  패널 포트(기본 5173, 0=임의)
  pyrun        absolute-agent 모드: 모델이 파이썬 코드를 스스로 작성·실행하며 공략
                 --host <h> [--port <p>] [--goal <g>] [--provider <name>] [--model <id>]
                 [--auth <path>] [--proxy <url>] [--max-actions <n>] 코드 반복 횟수
                 [--step-timeout <ms>] 코드 1회 실행 타임아웃 [--ndjson] [--no-visual]
                 [--isolation required|best-effort|off] OS 격리 정책(기본 required):
                   신뢰불가(라이브 모델) 코드는 격리 백엔드(bwrap) 없으면 실행 거부(fail-closed)
                 대상과의 모든 HTTP 는 ScopeGuard 브로커를 경유(비파괴·RPS·scope 강제)
  osint        웹 샅샅이 뒤지기(OSINT): 사이트를 깊이 크롤링해 목표 정보를 가져온다
                 --host <h> [--port <p>] [--goal <g>]  원하는 정보를 구체적으로
                 [--provider <name>] [--model <id>] [--auth <path>] [--proxy <url>]
                 [--auto]  모델 없이 결정적 전체 다이그(오프라인/빠른 스윔)
                 [--max-actions <n>] 모델의 심화 다이그 선택 횟수 [--ndjson] [--no-visual]
                 같은 오리진만 GET 관측(robots/sitemap 얻어걸림), 전 요청 ScopeGuard 경유
  rlm          RLM(재귀 언어 모델) 모드: 영구 파이썬 REPL + 재귀 서브콜 + 자기발전 기억
                 --host <h> [--port <p>] [--goal <g>]  작업/목표를 자연어로
                 [--provider <name>] [--model <id>] [--auth <path>] [--proxy <url>]
                 [--mem <path>]  rc.memo() 기억 파일(기본 ~/.redcell/memories/<호스트>.md,
                                 이전 세션 기억이 자동 재주입 — continual harness)
                 [--depth <n>]  rlm() 재귀 깊이 상한(기본 3) [--budget <n>] 전체 요청 예산(기본 240)
                 [--max-actions <n>] REPL 스텝 수(기본 10) [--step-timeout <ms>]
                 [--isolation required|best-effort|off] OS 격리 정책(기본 required)
                 [--ndjson] [--no-visual]
                 [--panel]  로컬 라이브 패널(http://127.0.0.1:5173)에 학습 이벤트를 흘린다
                 [--panel-port <n>]  패널 포트(기본 5173, 0=임의)
                 REPL 변수 ctx(prompt-as-variable) 지속 · rlm('지시') 함수처럼 재귀 위임
  providers    연결 가능한 프로바이더와 자격증명 상태 표시
  models       프로바이더별 기본 모델 표시
  scope        인가(scope) 상태 확인   [--auth <path>]
  auth         간단 인가 목록 관리 — 내가 입력한 IP 가 곧 인가
                 add <ip|cidr|도메인> [--deny]  허용 추가(제외는 --deny)
                 rm <대상>                     목록에서 제거
                 list                          현재 목록 확인
                 (기본 파일 ~/.redcell/authorization.list, --auth <파일> 로 변경)
  audit        감사 추적 무결성 검증     verify <감사파일.jsonl>
                 (run/pyrun 은 기본으로 변조탐지 감사 추적을 남긴다: --no-audit 로 끄고,
                  --audit-dir <경로> 로 위치 지정. 기본 ~/.redcell/audit)
  explore      밴딧 자기발전 데모       [episodes] [ucb1|thompson]
  mcts         MCTS 트리검색 데모        [depth] [branching]
  config       설정 조회/변경           get | set <key> <value>
  help         이 도움말
  --version    버전

예:
  export ANTHROPIC_API_KEY=sk-ant-...
  export MY_LLM_KEY=...
  redcell providers add my-llm --base-url http://127.0.0.1:8000/v1 --api-key-env MY_LLM_KEY --default-model llama-3.3
  redcell providers
  redcell run --host 127.0.0.1 --port 8080 --goal "웹 취약점 정찰"
  redcell run --host 10.13.37.5 --provider openrouter --model moonshotai/kimi-k2.6`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const args = parse(argv);
  const cmd = args._.shift();

  if (args.flags.version) {
    const pkg = JSON.parse(await fs.readFile(path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), "package.json"), "utf8"));
    console.log(`redcell ${pkg.version}`);
    return;
  }

  // 사용자 정의 프로바이더(~/.redcell/providers.json)를 레지스트리에 주입
  try {
    applyCustomProviders(registry, await loadCustomProviders());
  } catch (e) {
    console.error(`[providers] ⚠️ ${(e as Error).message}`);
  }

  switch (cmd) {
    case "run": return void (await cmdRun(args));
    case "pyrun": return void (await cmdPyRun(args));
    case "osint": return void (await cmdOsint(args));
    case "rlm": return void (await cmdRlm(args));
    case "providers": return void (await cmdProviders(args));
    case "models": return void (await cmdModels());
    case "scope": return void (await cmdScope(args));
    case "auth": return void (await cmdAuth(args));
    case "audit": return void (await cmdAudit(args));
    case "explore": return void (await cmdExplore(args));
    case "mcts": return void (await cmdMcts(args));
    case "config": return void (await cmdConfig(args));
    case undefined:
    case "help": return help();
    default:
      console.error(`알 수 없는 명령: ${cmd}\n`);
      help();
      process.exit(1);
  }
}

main().catch((e) => {
  console.error("RedCell 오류:", (e as Error).message);
  process.exit(1);
});
