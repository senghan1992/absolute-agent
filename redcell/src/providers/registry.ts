/**
 * ProviderRegistry — pi(@earendil-works/pi-ai) 의 provider-agnostic 설계를 참고한
 * 다중 프로바이더 레지스트리.
 *
 * 하나의 ModelAdapter 인터페이스 뒤에 여러 프로바이더를 꽂는다:
 *  - kind "anthropic"      → 공식 Anthropic SDK (api.anthropic.com 또는 호환 baseURL)
 *  - kind "openai-compat"  → OpenAI 호환 /chat/completions (대부분의 서드파티)
 *
 * base URL / env 키 / 기본 모델은 prime-agent 의 값을 그대로 참고했다.
 * 새 프로바이더는 register() 로 런타임 추가 가능(pi.registerProvider 와 동일 취지).
 */

import type { ModelAdapter } from "../core/types.js";
import { AnthropicModel } from "../models/anthropic-model.js";
import { OpenAICompatModel } from "../models/openai-compat-model.js";

export interface ProviderSpec {
  name: string;
  kind: "anthropic" | "openai-compat";
  /** 자격증명 env 변수(앞에서부터 먼저 발견되는 값 사용). 비면 키 불필요(로컬). */
  envKeys: string[];
  /** openai-compat / anthropic 호환용 base URL */
  baseUrl?: string;
  /** 기본 모델(없으면 --model 필수) */
  defaultModel?: string;
  /** 프로바이더별 추가 헤더 생성기 */
  headers?: () => Record<string, string>;
  /** 설명(도움말 표시용) */
  note?: string;
}

// base URL / env / 기본모델은 prime-agent(packages/ai) 참고.
export const BUILTIN_PROVIDERS: ProviderSpec[] = [
  { name: "anthropic", kind: "anthropic", envKeys: ["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_API_KEY"], defaultModel: "claude-opus-5", note: "공식 Anthropic SDK" },
  { name: "openai", kind: "openai-compat", envKeys: ["OPENAI_API_KEY"], baseUrl: "https://api.openai.com/v1", defaultModel: "gpt-5.4" },
  { name: "openrouter", kind: "openai-compat", envKeys: ["OPENROUTER_API_KEY"], baseUrl: "https://openrouter.ai/api/v1", defaultModel: "moonshotai/kimi-k2.6", headers: () => ({ "HTTP-Referer": "https://github.com/redcell", "X-Title": "RedCell" }) },
  { name: "prime-inference", kind: "openai-compat", envKeys: ["PRIME_API_KEY"], baseUrl: "https://api.pinference.ai/api/v1", defaultModel: "z-ai/glm-5.2", note: "Prime Intellect inference" },
  { name: "groq", kind: "openai-compat", envKeys: ["GROQ_API_KEY"], baseUrl: "https://api.groq.com/openai/v1", defaultModel: "openai/gpt-oss-120b" },
  { name: "cerebras", kind: "openai-compat", envKeys: ["CEREBRAS_API_KEY"], baseUrl: "https://api.cerebras.ai/v1", defaultModel: "gpt-oss-120b" },
  { name: "xai", kind: "openai-compat", envKeys: ["XAI_API_KEY"], baseUrl: "https://api.x.ai/v1", defaultModel: "grok-4.20-0309-reasoning" },
  { name: "deepseek", kind: "openai-compat", envKeys: ["DEEPSEEK_API_KEY"], baseUrl: "https://api.deepseek.com", defaultModel: "deepseek-v4-pro" },
  { name: "mistral", kind: "openai-compat", envKeys: ["MISTRAL_API_KEY"], baseUrl: "https://api.mistral.ai/v1", defaultModel: "devstral-medium-latest" },
  { name: "moonshotai", kind: "openai-compat", envKeys: ["MOONSHOT_API_KEY"], baseUrl: "https://api.moonshot.ai/v1", defaultModel: "kimi-k2.6" },
  { name: "zai", kind: "openai-compat", envKeys: ["ZAI_API_KEY"], baseUrl: "https://api.z.ai/api/coding/paas/v4", defaultModel: "glm-5.1" },
  { name: "ollama", kind: "openai-compat", envKeys: [], baseUrl: "http://localhost:11434/v1", note: "로컬. --model 로 모델 지정" },
  { name: "custom", kind: "openai-compat", envKeys: ["REDCELL_OPENAI_API_KEY"], note: "REDCELL_OPENAI_BASE_URL / REDCELL_MODEL 로 임의 OpenAI 호환 엔드포인트" },
];

export interface ResolvedModel {
  model: ModelAdapter;
  provider: string;
  modelId: string;
  credentialSource?: string; // 어떤 env 로 인증했는지
}

export class ProviderRegistry {
  private specs = new Map<string, ProviderSpec>();

  constructor(specs: ProviderSpec[] = BUILTIN_PROVIDERS) {
    for (const s of specs) this.specs.set(s.name, s);
  }

  register(spec: ProviderSpec): void {
    this.specs.set(spec.name, spec);
  }

  get(name: string): ProviderSpec | undefined {
    return this.specs.get(name);
  }

  list(): ProviderSpec[] {
    return [...this.specs.values()];
  }

  /** 자격증명이 있는 env 를 찾는다(없으면 null). 키가 필요없는 프로바이더는 {source:""}. */
  credential(spec: ProviderSpec, env: NodeJS.ProcessEnv): { source: string; value?: string } | null {
    if (spec.envKeys.length === 0) return { source: "" }; // 로컬 등 키 불필요
    for (const k of spec.envKeys) {
      if (env[k]) return { source: k, value: env[k] };
    }
    return null;
  }

  /** 자격증명이 준비된 프로바이더 목록 */
  available(env: NodeJS.ProcessEnv = process.env): ProviderSpec[] {
    return this.list().filter((s) => this.credential(s, env) !== null && (s.kind !== "openai-compat" || this.effectiveBaseUrl(s, env)));
  }

  private effectiveBaseUrl(spec: ProviderSpec, env: NodeJS.ProcessEnv): string | undefined {
    if (spec.name === "custom") return env.REDCELL_OPENAI_BASE_URL;
    return spec.baseUrl;
  }

  /** name + 선택적 model 로 실제 ModelAdapter 생성 */
  create(name: string, opts: { model?: string; env?: NodeJS.ProcessEnv } = {}): ResolvedModel {
    const env = opts.env ?? process.env;
    const spec = this.specs.get(name);
    if (!spec) throw new Error(`알 수 없는 프로바이더: ${name} (사용가능: ${this.list().map((s) => s.name).join(", ")})`);

    const cred = this.credential(spec, env);
    if (cred === null) {
      throw new Error(`프로바이더 '${name}' 자격증명 없음. 필요한 env: ${spec.envKeys.join(" 또는 ")}`);
    }

    const modelId = opts.model ?? env.REDCELL_MODEL ?? spec.defaultModel;
    if (!modelId) throw new Error(`프로바이더 '${name}' 는 기본 모델이 없습니다. --model 로 모델을 지정하세요.`);

    if (spec.kind === "anthropic") {
      const isOauth = cred.source === "ANTHROPIC_OAUTH_TOKEN";
      return {
        model: new AnthropicModel({
          model: modelId,
          baseURL: spec.baseUrl,
          apiKey: isOauth ? undefined : cred.value,
          authToken: isOauth ? cred.value : undefined,
        }),
        provider: name,
        modelId,
        credentialSource: cred.source,
      };
    }

    const baseUrl = this.effectiveBaseUrl(spec, env);
    if (!baseUrl) throw new Error(`프로바이더 '${name}' base URL 미설정. (custom 은 REDCELL_OPENAI_BASE_URL 필요)`);
    return {
      model: new OpenAICompatModel({ baseUrl, apiKey: cred.value, model: modelId, headers: spec.headers?.() }),
      provider: name,
      modelId,
      credentialSource: cred.source,
    };
  }
}
