#!/usr/bin/env node
/**
 * RedCell CLI — prime-agent 처럼 서브커맨드로 동작한다.
 *
 *   redcell run --host 127.0.0.1 --port 8080 [--provider anthropic] [--model ...]
 *   redcell providers                 연결 가능한 프로바이더 + 자격증명 상태
 *   redcell models                    프로바이더별 기본 모델
 *   redcell scope [--auth <path>]     인가(scope) 상태
 *   redcell explore [episodes] [ucb1|thompson]
 *   redcell mcts [depth] [branching]
 *   redcell config get|set [key] [value]
 *   redcell help | --version
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadAuthorization } from "./scope/load-auth.js";
import { SkillMemory } from "./memory/skill-memory.js";
import { Orchestrator } from "./core/orchestrator.js";
import { DefaultToolBox } from "./tools/toolbox.js";
import { MockModel } from "./core/mock-model.js";
import { toMarkdown } from "./report/report.js";
import { ProviderRegistry } from "./providers/registry.js";
import { loadConfig, saveConfig, resolveModel, redcellHome, type RedcellConfig } from "./config.js";
import type { ModelAdapter } from "./core/types.js";

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

// ── 서브커맨드 ───────────────────────────────────────────────────────────────
const registry = new ProviderRegistry();

async function cmdProviders(): Promise<void> {
  const cfg = await loadConfig();
  console.log("프로바이더 (✅=자격증명 감지, —=미설정):\n");
  console.log(`${"".padEnd(2)}${"NAME".padEnd(16)}${"KIND".padEnd(15)}${"CREDENTIAL".padEnd(22)}DEFAULT MODEL`);
  for (const s of registry.list()) {
    const cred = registry.credential(s, process.env);
    const mark = cred ? "✅" : "—";
    const src = cred ? (cred.source || "(불필요)") : s.envKeys.join("|") || "-";
    const isDefault = cfg.defaultProvider === s.name ? " *" : "";
    console.log(`${mark} ${s.name.padEnd(16)}${s.kind.padEnd(15)}${src.padEnd(22)}${s.defaultModel ?? "(--model 필요)"}${isDefault}`);
  }
  console.log(`\n* = config 기본 프로바이더. 변경: redcell config set defaultProvider <name>`);
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

async function cmdScope(args: Args): Promise<void> {
  const cfg = await loadConfig();
  const authPath = await findAuthPath(str(args.flags.auth), cfg);
  const guard = await loadAuthorization(authPath);
  console.log(`✅ 인가 로드됨: ${authPath}`);
  console.log(`   RPS 제한: ${guard.requestsPerSecond}/s`);
}

async function cmdRun(args: Args): Promise<void> {
  const cfg = await loadConfig();
  const host = str(args.flags.host);
  if (!host) throw new Error("redcell run 에는 --host 가 필요합니다. 예: redcell run --host 127.0.0.1 --port 8080");
  const port = args.flags.port ? Number(str(args.flags.port)) : undefined;
  const goal = str(args.flags.goal) ?? "인가된 대상의 취약점 식별 및 방어 권고 보고";

  const authPath = await findAuthPath(str(args.flags.auth), cfg);
  const guard = await loadAuthorization(authPath);

  // 모델 선택: --provider mock 이면 오프라인, 아니면 레지스트리 해석.
  let model: ModelAdapter;
  let label: string;
  const provider = str(args.flags.provider);
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

  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const memory = new SkillMemory(path.join(root, "knowledge", "playbooks"));
  await memory.load();

  console.error(`[model] ${label}`);
  console.error(`[scope] ${authPath}`);

  const orch = new Orchestrator(guard, memory, model, new DefaultToolBox(), {
    maxActionsPerPhase: args.flags["max-actions"] ? Number(str(args.flags["max-actions"])) : 4,
    allowActivePhases: !args.flags["dry-run"],
  });
  const log = await orch.run({ host, port }, goal);
  console.log("\n" + toMarkdown(log) + "\n");
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

function help(): void {
  console.log(`RedCell — 자기발전형 화이트해커 에이전트 (prime-agent 기반)

사용법: redcell <command> [options]

Commands:
  run          인가된 대상에 engagement 실행
                 --host <h> [--port <p>] [--goal <g>]
                 [--provider <name>] [--model <id>] [--auth <path>]
                 [--dry-run] [--mock] [--max-actions <n>]
  providers    연결 가능한 프로바이더와 자격증명 상태 표시
  models       프로바이더별 기본 모델 표시
  scope        인가(scope) 상태 확인   [--auth <path>]
  explore      밴딧 자기발전 데모       [episodes] [ucb1|thompson]
  mcts         MCTS 트리검색 데모        [depth] [branching]
  config       설정 조회/변경           get | set <key> <value>
  help         이 도움말
  --version    버전

예:
  export ANTHROPIC_API_KEY=sk-ant-...
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

  switch (cmd) {
    case "run": return void (await cmdRun(args));
    case "providers": return void (await cmdProviders());
    case "models": return void (await cmdModels());
    case "scope": return void (await cmdScope(args));
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
