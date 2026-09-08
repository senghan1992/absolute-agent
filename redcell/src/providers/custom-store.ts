/**
 * 사용자 정의(custom) 프로바이더 저장소 — ~/.redcell/providers.json
 *
 * 코드 수정 없이 `redcell providers add <name> ...` 로 임의의
 * OpenAI 호환/Anthropic 호환 엔드포인트를 등록하고,
 * `--provider <name>` 으로 바로 연결한다.
 *
 * 파일 형식(headers 는 평객체 — 메모리에서는 ProviderSpec.headers 함수로 변환):
 *   {
 *     "providers": [
 *       {
 *         "name": "my-llm",
 *         "kind": "openai-compat",
 *         "baseUrl": "http://127.0.0.1:8000/v1",
 *         "envKeys": ["MY_LLM_API_KEY"],
 *         "apiKey": "…선택(리터럴 키… env 우선)",
 *         "defaultModel": "my-model",
 *         "headers": { "X-Tag": "redcell" },
 *         "note": "로컬 vLLM"
 *       }
 *     ]
 *   }
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { redcellHome } from "../config.js";
import type { ProviderSpec } from "./registry.js";

export const CUSTOM_PROVIDERS_FILE = "providers.json";

/** 파일에 저장되는 형태 — headers 는 함수가 아닌 평객체. */
export type CustomProviderSpec = Omit<ProviderSpec, "headers"> & { headers?: Record<string, string> };

export function customProvidersPath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(redcellHome(env), CUSTOM_PROVIDERS_FILE);
}

export type CustomProviderFile = { providers: CustomProviderSpec[] };

export async function loadCustomProviders(env: NodeJS.ProcessEnv = process.env): Promise<ProviderSpec[]> {
  try {
    const raw = await fs.readFile(customProvidersPath(env), "utf8");
    const parsed = JSON.parse(raw) as Partial<CustomProviderFile>;
    const list = Array.isArray(parsed?.providers) ? parsed.providers : [];
    return list.map((s) => validateSpec(s));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return []; // 파일 없음 = 정의 없음
    throw new Error(`사용자 정의 프로바이더 파일(${customProvidersPath(env)})을 읽지 못했습니다: ${(e as Error).message}`);
  }
}

/** 파일용 평객체 헤더 → 메모리용 함수 헤더. */
function toMemorySpec(spec: ProviderSpec | CustomProviderSpec): ProviderSpec {
  const { headers, ...rest } = spec;
  const out: ProviderSpec = { ...rest };
  if (headers !== undefined) {
    if (typeof headers === "function") {
      out.headers = headers;
    } else {
      const h = { ...headers };
      out.headers = () => h;
    }
  }
  return out;
}

/** 메모리용 함수 헤더 → 파일용 평객체 헤더. */
function toFileSpec(spec: ProviderSpec): CustomProviderSpec {
  const { headers, ...rest } = spec;
  const out: CustomProviderSpec = { ...rest };
  if (headers !== undefined) out.headers = headers();
  return out;
}

export async function saveCustomProviders(specs: ProviderSpec[], env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const p = customProvidersPath(env);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify({ providers: specs.map(toFileSpec) }, null, 2) + "\n", "utf8");
  await fs.chmod(p, 0o600).catch(() => undefined); // API 키가 들어갈 수 있으므로 소유자만
}

/** 이름 중복 시 교체(upsert). 빌트인 이름도 교체 가능(경고는 호출부에서). */
export async function upsertCustomProvider(spec: ProviderSpec, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const specs = await loadCustomProviders(env);
  const next = specs.filter((s) => s.name !== spec.name);
  next.push(validateSpec(spec));
  await saveCustomProviders(next, env);
}

export async function removeCustomProvider(name: string, env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  const specs = await loadCustomProviders(env);
  const next = specs.filter((s) => s.name !== name);
  if (next.length === specs.length) return false;
  await saveCustomProviders(next, env);
  return true;
}

/** Registry 에 사용자 정의 프로바이더를 주입한다. 빌트인 이름과 겹치면 교체(경고 로그). */
export function applyCustomProviders(registry: { register(spec: ProviderSpec): void; get(name: string): ProviderSpec | undefined }, specs: ProviderSpec[]): void {
  for (const s of specs) {
    const builtin = registry.get(s.name);
    if (builtin) console.error(`[providers] ⚠️ 빌트인 '${s.name}' 정의가 사용자 정의로 교체됨(providers.json).`);
    registry.register(s);
  }
}

const KINDS = new Set(["anthropic", "openai-compat"]);

/** 저장 전/후 검증 — 잘못된 정의는 명확한 에러로 거부한다. 메모리(함수 헤더) 또는 파일(평객체) 형태 모두 허용. */
export function validateSpec(raw: ProviderSpec | CustomProviderSpec): ProviderSpec {
  if (!raw.name || !/^[A-Za-z0-9._-]{1,40}$/.test(raw.name)) {
    throw new Error(`프로바이더 이름이 잘못됐습니다: '${raw.name ?? ""}' — 영문/숫자/._- 1~40자만 허용됩니다.`);
  }
  if (!KINDS.has(raw.kind)) {
    throw new Error(`kind 는 'anthropic' 또는 'openai-compat' 이어야 합니다: '${raw.kind as string}'`);
  }
  if (raw.kind === "openai-compat" && !raw.baseUrl) {
    throw new Error(`openai-compat 프로바이더 '${raw.name}' 는 baseUrl 이 필수입니다(--base-url).`);
  }
  if (raw.baseUrl && !/^https?:\/\//.test(raw.baseUrl)) {
    throw new Error(`baseUrl 은 http(s):// 로 시작해야 합니다: '${raw.baseUrl}'`);
  }
  if (raw.envKeys !== undefined && (!Array.isArray(raw.envKeys) || raw.envKeys.some((k) => typeof k !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)))) {
    throw new Error(`envKeys 는 env 변수명 문자열 배열이어야 합니다(예: ["MY_API_KEY"]).`);
  }
  if (raw.apiKey !== undefined && typeof raw.apiKey !== "string") {
    throw new Error(`apiKey 는 문자열이어야 합니다.`);
  }
  const { headers, ...rest } = raw;
  const spec = toMemorySpec({ ...rest });
  if (headers !== undefined) {
    if (typeof headers === "function") {
      spec.headers = headers;
    } else {
      if (typeof headers !== "object" || headers === null) {
        throw new Error(`headers 는 객체여야 합니다(예: {"X-Tag": "redcell"}).`);
      }
      for (const [k, v] of Object.entries({ ...headers })) {
        if (typeof v !== "string") throw new Error(`헤더 '${k}' 값은 문자열이어야 합니다.`);
      }
      const h = { ...headers };
      spec.headers = () => h;
    }
  }
  return spec;
}
