/**
 * 모델 팩토리 — 환경변수로 실제 모델을 선택. 키가 없으면 MockModel 로 폴백.
 *
 *   REDCELL_MODEL_PROVIDER = anthropic | openai-compat | mock
 *   ANTHROPIC_API_KEY (또는 `ant auth login`)     → anthropic
 *   REDCELL_OPENAI_BASE_URL, REDCELL_OPENAI_API_KEY, REDCELL_MODEL → openai-compat
 */

import type { ModelAdapter } from "../core/types.js";
import { MockModel } from "../core/mock-model.js";
import { AnthropicModel } from "./anthropic-model.js";
import { OpenAICompatModel } from "./openai-compat-model.js";

export { AnthropicModel } from "./anthropic-model.js";
export { OpenAICompatModel } from "./openai-compat-model.js";

export interface ModelChoice {
  model: ModelAdapter;
  label: string;
}

export function createModelFromEnv(env: NodeJS.ProcessEnv = process.env): ModelChoice {
  const provider = env.REDCELL_MODEL_PROVIDER;

  if (provider === "mock") return { model: new MockModel(), label: "mock" };

  if (provider === "openai-compat" || (!provider && env.REDCELL_OPENAI_BASE_URL)) {
    if (!env.REDCELL_OPENAI_BASE_URL || !env.REDCELL_MODEL) {
      throw new Error("openai-compat 사용 시 REDCELL_OPENAI_BASE_URL 과 REDCELL_MODEL 이 필요합니다.");
    }
    return {
      model: new OpenAICompatModel({
        baseUrl: env.REDCELL_OPENAI_BASE_URL,
        apiKey: env.REDCELL_OPENAI_API_KEY,
        model: env.REDCELL_MODEL,
      }),
      label: `openai-compat:${env.REDCELL_MODEL}`,
    };
  }

  if (provider === "anthropic" || env.ANTHROPIC_API_KEY || env.ANTHROPIC_AUTH_TOKEN) {
    const model = env.REDCELL_MODEL ?? "claude-opus-5";
    return { model: new AnthropicModel({ model }), label: `anthropic:${model}` };
  }

  // 키가 없으면 규칙기반 MockModel(오프라인 검증용).
  return { model: new MockModel(), label: "mock(no-credentials)" };
}
