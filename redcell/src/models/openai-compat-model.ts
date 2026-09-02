/**
 * OpenAICompatModel — OpenAI 호환 /chat/completions 엔드포인트용 ModelAdapter.
 *
 * prime-inference(예: z-ai/glm-5.2), OpenRouter, 로컬 vLLM/Ollama 등
 * "OpenAI 호환" 제공자에 붙일 때 사용한다. (Anthropic 은 AnthropicModel 을 쓸 것)
 *
 * baseUrl/apiKey/model 은 명시적으로 주입한다 — 잘못된 URL 을 추측하지 않기 위함.
 */

import type { ModelAdapter } from "../core/types.js";

export interface OpenAICompatOpts {
  baseUrl: string; // 예: https://api.example.com/v1  (뒤에 /chat/completions 붙임)
  apiKey?: string;
  model: string; // 예: z-ai/glm-5.2
  temperature?: number;
  maxTokens?: number;
  /** 프로바이더별 추가 헤더(예: OpenRouter 의 HTTP-Referer/X-Title) */
  headers?: Record<string, string>;
}

export class OpenAICompatModel implements ModelAdapter {
  constructor(private readonly opts: OpenAICompatOpts) {}

  async complete(input: { system: string; prompt: string; json?: boolean }): Promise<string> {
    const url = `${this.opts.baseUrl.replace(/\/$/, "")}/chat/completions`;
    const body: Record<string, unknown> = {
      model: this.opts.model,
      temperature: this.opts.temperature ?? 0.4,
      max_tokens: this.opts.maxTokens ?? 2048,
      messages: [
        { role: "system", content: input.json ? `${input.system}\n반드시 JSON 하나만 출력.` : input.system },
        { role: "user", content: input.prompt },
      ],
    };
    if (input.json) body.response_format = { type: "json_object" };

    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(this.opts.apiKey ? { authorization: `Bearer ${this.opts.apiKey}` } : {}),
        ...(this.opts.headers ?? {}),
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`OpenAI-compat 오류 ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
    const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    return data.choices?.[0]?.message?.content?.trim() ?? "";
  }
}
