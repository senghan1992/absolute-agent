/**
 * AnthropicModel — 공식 Anthropic SDK 로 ModelAdapter 구현.
 *
 * 기본 모델 claude-opus-5 + adaptive thinking. 계획/전략생성/반성에 사용.
 * 인증은 SDK 기본 해석(ANTHROPIC_API_KEY 또는 `ant auth login` 프로필).
 */

import Anthropic from "@anthropic-ai/sdk";
import type { ModelAdapter } from "../core/types.js";

export interface AnthropicModelOpts {
  model?: string;
  maxTokens?: number;
  /** low | medium | high | xhigh | max */
  effort?: "low" | "medium" | "high" | "xhigh" | "max";
  /** Anthropic 호환 엔드포인트를 쓸 때(기본은 공식 api.anthropic.com) */
  baseURL?: string;
  apiKey?: string;
  /** OAuth 토큰(ANTHROPIC_OAUTH_TOKEN). apiKey 대신 Bearer 로 전달된다. */
  authToken?: string;
}

export class AnthropicModel implements ModelAdapter {
  private client: Anthropic;
  private model: string;
  private maxTokens: number;
  private effort: NonNullable<AnthropicModelOpts["effort"]>;

  constructor(opts: AnthropicModelOpts = {}, client?: Anthropic) {
    this.client =
      client ??
      new Anthropic({
        ...(opts.baseURL ? { baseURL: opts.baseURL } : {}),
        ...(opts.apiKey ? { apiKey: opts.apiKey } : {}),
        ...(opts.authToken ? { authToken: opts.authToken } : {}),
      });
    this.model = opts.model ?? "claude-opus-5";
    this.maxTokens = opts.maxTokens ?? 4096;
    this.effort = opts.effort ?? "high";
  }

  async complete(input: { system: string; prompt: string; json?: boolean }): Promise<string> {
    const system = input.json ? `${input.system}\n반드시 JSON 하나만 출력하라. 다른 텍스트 금지.` : input.system;
    const res = await this.client.messages.create({
      model: this.model,
      max_tokens: this.maxTokens,
      thinking: { type: "adaptive" },
      output_config: { effort: this.effort },
      system,
      messages: [{ role: "user", content: input.prompt }],
    });

    if (res.stop_reason === "refusal") {
      throw new Error(`모델이 요청을 거부함(category=${res.stop_details?.category ?? "?"}).`);
    }
    return res.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("")
      .trim();
  }
}
