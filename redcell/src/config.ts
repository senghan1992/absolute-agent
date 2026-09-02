/**
 * RedCell 설정 파일 및 모델 해석(resolution).
 *
 * 설정 위치: $REDCELL_HOME/config.json (기본 ~/.redcell/config.json)
 * 모델 해석 우선순위(pi 참고):
 *   --provider/--model 플래그  →  config.json 기본값  →  자격증명 있는 첫 프로바이더
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ProviderRegistry, ResolvedModel } from "./providers/registry.js";

export interface RedcellConfig {
  defaultProvider?: string;
  defaultModel?: string;
  authPath?: string;
}

export function redcellHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.REDCELL_HOME ?? path.join(os.homedir(), ".redcell");
}

export function configPath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(redcellHome(env), "config.json");
}

export async function loadConfig(env: NodeJS.ProcessEnv = process.env): Promise<RedcellConfig> {
  try {
    return JSON.parse(await fs.readFile(configPath(env), "utf8")) as RedcellConfig;
  } catch {
    return {};
  }
}

export async function saveConfig(cfg: RedcellConfig, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  await fs.mkdir(redcellHome(env), { recursive: true });
  await fs.writeFile(configPath(env), JSON.stringify(cfg, null, 2) + "\n", "utf8");
}

export interface ResolveOpts {
  provider?: string;
  model?: string;
  env?: NodeJS.ProcessEnv;
}

/**
 * 우선순위대로 프로바이더/모델을 정한다. 아무 자격증명도 없으면 명확히 에러.
 */
export function resolveModel(registry: ProviderRegistry, cfg: RedcellConfig, opts: ResolveOpts = {}): ResolvedModel {
  const env = opts.env ?? process.env;

  // 1) 명시적 --provider
  if (opts.provider) {
    return registry.create(opts.provider, { model: opts.model ?? cfg.defaultModel, env });
  }
  // 2) config 기본 프로바이더
  if (cfg.defaultProvider) {
    return registry.create(cfg.defaultProvider, { model: opts.model ?? cfg.defaultModel, env });
  }
  // 3) 자격증명 + 사용가능한 모델(기본모델 또는 --model/REDCELL_MODEL)이 있는 첫 프로바이더.
  //    ollama 처럼 기본모델이 없는 프로바이더는 자동선택 대상에서 제외(명시 지정 필요).
  const model = opts.model ?? cfg.defaultModel;
  const available = registry.available(env).filter((s) => s.defaultModel || model || env.REDCELL_MODEL);
  if (available.length === 0) {
    throw new Error(
      "연결된 프로바이더가 없습니다. 예: export ANTHROPIC_API_KEY=... 또는 `redcell config set defaultProvider <name>`.\n" +
        "`redcell providers` 로 사용 가능한 프로바이더를 확인하세요.",
    );
  }
  return registry.create(available[0].name, { model, env });
}
