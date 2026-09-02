import { describe, it, expect } from "vitest";
import { ProviderRegistry } from "../src/providers/registry.js";
import { resolveModel } from "../src/config.js";
import { AnthropicModel } from "../src/models/anthropic-model.js";
import { OpenAICompatModel } from "../src/models/openai-compat-model.js";

const reg = new ProviderRegistry();

describe("ProviderRegistry", () => {
  it("주요 프로바이더가 등록되어 있다", () => {
    const names = reg.list().map((s) => s.name);
    expect(names).toContain("anthropic");
    expect(names).toContain("prime-inference");
    expect(names).toContain("openrouter");
    expect(names).toContain("groq");
  });

  it("자격증명 감지: env 에 키가 있으면 available", () => {
    const env = { ANTHROPIC_API_KEY: "sk-x", GROQ_API_KEY: "gk-x" } as NodeJS.ProcessEnv;
    const avail = reg.available(env).map((s) => s.name);
    expect(avail).toContain("anthropic");
    expect(avail).toContain("groq");
    expect(avail).not.toContain("openai");
  });

  it("anthropic 은 AnthropicModel, 기본 모델 claude-opus-5", () => {
    const r = reg.create("anthropic", { model: undefined, env: { ANTHROPIC_API_KEY: "sk-x" } as NodeJS.ProcessEnv });
    expect(r.model).toBeInstanceOf(AnthropicModel);
    expect(r.modelId).toBe("claude-opus-5");
    expect(r.credentialSource).toBe("ANTHROPIC_API_KEY");
  });

  it("openai-compat 프로바이더는 OpenAICompatModel", () => {
    const r = reg.create("groq", { env: { GROQ_API_KEY: "gk-x" } as NodeJS.ProcessEnv });
    expect(r.model).toBeInstanceOf(OpenAICompatModel);
    expect(r.modelId).toBe("openai/gpt-oss-120b");
  });

  it("--model 로 기본 모델을 덮어쓴다", () => {
    const r = reg.create("openrouter", { model: "x/y", env: { OPENROUTER_API_KEY: "or" } as NodeJS.ProcessEnv });
    expect(r.modelId).toBe("x/y");
  });

  it("자격증명 없으면 명확히 에러", () => {
    expect(() => reg.create("openai", { env: {} as NodeJS.ProcessEnv })).toThrow(/자격증명/);
  });

  it("알 수 없는 프로바이더는 에러", () => {
    expect(() => reg.create("nope", { env: {} as NodeJS.ProcessEnv })).toThrow(/알 수 없는/);
  });

  it("custom 은 REDCELL_OPENAI_BASE_URL 필요", () => {
    expect(() =>
      reg.create("custom", { model: "m", env: { REDCELL_OPENAI_API_KEY: "k" } as NodeJS.ProcessEnv }),
    ).toThrow(/base URL/);
  });
});

describe("resolveModel 우선순위", () => {
  it("명시적 provider 가 최우선", () => {
    const r = resolveModel(reg, { defaultProvider: "groq" }, { provider: "anthropic", env: { ANTHROPIC_API_KEY: "s", GROQ_API_KEY: "g" } as NodeJS.ProcessEnv });
    expect(r.provider).toBe("anthropic");
  });

  it("config 기본 프로바이더가 그다음", () => {
    const r = resolveModel(reg, { defaultProvider: "groq" }, { env: { GROQ_API_KEY: "g" } as NodeJS.ProcessEnv });
    expect(r.provider).toBe("groq");
  });

  it("아무것도 없으면 자격증명 있는 첫 프로바이더", () => {
    const r = resolveModel(reg, {}, { env: { OPENROUTER_API_KEY: "or" } as NodeJS.ProcessEnv });
    expect(r.provider).toBe("openrouter");
  });

  it("연결된 프로바이더가 없으면 에러", () => {
    expect(() => resolveModel(reg, {}, { env: {} as NodeJS.ProcessEnv })).toThrow(/프로바이더가 없습니다/);
  });
});
