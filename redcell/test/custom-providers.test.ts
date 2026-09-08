import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ProviderRegistry } from "../src/providers/registry.js";
import {
  customProvidersPath,
  loadCustomProviders,
  saveCustomProviders,
  upsertCustomProvider,
  removeCustomProvider,
  applyCustomProviders,
  validateSpec,
} from "../src/providers/custom-store.js";
import { OpenAICompatModel } from "../src/models/openai-compat-model.js";

let home: string;
let env: NodeJS.ProcessEnv;

beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-providers-"));
  env = { REDCELL_HOME: home } as NodeJS.ProcessEnv;
});

afterEach(async () => {
  await fs.rm(home, { recursive: true, force: true });
});

const base = {
  name: "my-llm",
  kind: "openai-compat" as const,
  baseUrl: "http://127.0.0.1:8000/v1",
  envKeys: ["MY_LLM_KEY"],
  defaultModel: "llama-3.3",
};

describe("custom provider 저장소 (providers.json)", () => {
  it("add → 파일에 저장되고 다시 읽힌다(헤더 평객체 왕복)", async () => {
    await upsertCustomProvider(
      { ...base, headers: () => ({ "X-Tag": "redcell" }), note: "로컬 vLLM" },
      env,
    );
    const file = await fs.readFile(customProvidersPath(env), "utf8");
    const parsed = JSON.parse(file) as { providers: Array<Record<string, unknown>> };
    expect(parsed.providers).toHaveLength(1);
    expect(parsed.providers[0].headers).toEqual({ "X-Tag": "redcell" }); // 함수가 아니라 평객체

    const loaded = await loadCustomProviders(env);
    expect(loaded[0].name).toBe("my-llm");
    expect(loaded[0].baseUrl).toBe("http://127.0.0.1:8000/v1");
    expect(loaded[0].headers?.()).toEqual({ "X-Tag": "redcell" }); // 메모리에서는 함수
    expect(loaded[0].note).toBe("로컬 vLLM");
  });

  it("같은 이름 재등록은 교체(upsert)", async () => {
    await upsertCustomProvider({ ...base }, env);
    await upsertCustomProvider({ ...base, baseUrl: "http://127.0.0.1:9000/v1" }, env);
    const loaded = await loadCustomProviders(env);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].baseUrl).toBe("http://127.0.0.1:9000/v1");
  });

  it("rm 은 삭제하고, 없는 이름은 false", async () => {
    await upsertCustomProvider({ ...base }, env);
    expect(await removeCustomProvider("my-llm", env)).toBe(true);
    expect(await loadCustomProviders(env)).toHaveLength(0);
    expect(await removeCustomProvider("my-llm", env)).toBe(false);
  });

  it("파일이 없으면 빈 목록(에러 아님)", async () => {
    expect(await loadCustomProviders(env)).toEqual([]);
  });

  it("잘못된 정의는 명확한 에러", async () => {
    expect(() => validateSpec({ ...base, name: "나쁜 이름!" })).toThrow(/이름/);
    expect(() => validateSpec({ ...base, name: "x", kind: "wat" as never })).toThrow(/kind/);
    expect(() => validateSpec({ ...base, name: "x", baseUrl: undefined })).toThrow(/baseUrl/);
    expect(() => validateSpec({ ...base, name: "x", baseUrl: "ftp://bad" })).toThrow(/http/);
    expect(() => validateSpec({ ...base as never, name: "x", baseUrl: "http://ok", envKeys: ["1BAD"] })).toThrow(/envKeys/);
    expect(() => validateSpec({ ...base, name: "x", headers: { "A": 1 as never } })).toThrow(/헤더/);
  });
});

describe("custom provider ↔ Registry 연결", () => {
  it("레지스트리에 주입되면 --provider 로 연결 가능(env 키)", () => {
    const reg = new ProviderRegistry();
    applyCustomProviders(reg, [validateSpec({ ...base })]);
    const r = reg.create("my-llm", { model: undefined, env: { MY_LLM_KEY: "k" } as NodeJS.ProcessEnv });
    expect(r.provider).toBe("my-llm");
    expect(r.model).toBeInstanceOf(OpenAICompatModel);
    expect(r.modelId).toBe("llama-3.3"); // defaultModel
    expect(r.credentialSource).toBe("MY_LLM_KEY");
    expect(reg.get("my-llm")?.baseUrl).toBe("http://127.0.0.1:8000/v1");
  });

  it("apiKey 리터럴 저장 — env 가 없으면 config 키를 쓴다", () => {
    const reg = new ProviderRegistry();
    applyCustomProviders(reg, [validateSpec({ ...base, apiKey: "sk-literal" })]);
    const noEnv = reg.create("my-llm", { model: "m", env: {} as NodeJS.ProcessEnv });
    expect(noEnv.credentialSource).toBe("config(apiKey)");
    // env 가 있으면 env 가 우선
    const withEnv = reg.create("my-llm", { model: "m", env: { MY_LLM_KEY: "sk-env" } as NodeJS.ProcessEnv });
    expect(withEnv.credentialSource).toBe("MY_LLM_KEY");
  });

  it("빌트인 이름도 사용자 정의로 교체 가능하고 available() 에 잡힌다", () => {
    const reg = new ProviderRegistry();
    applyCustomProviders(reg, [validateSpec({ name: "groq", kind: "openai-compat", baseUrl: "http://127.0.0.1:7000/v1", envKeys: ["GROQ_API_KEY"], defaultModel: "local-groq" })]);
    expect(reg.get("groq")?.baseUrl).toBe("http://127.0.0.1:7000/v1");
    const avail = reg.available({ GROQ_API_KEY: "x" } as NodeJS.ProcessEnv).map((s) => s.name);
    expect(avail).toContain("groq");
  });

  it("flex: 사용자 정의 프로바이더도 모델 없이 available 이면 자동선택 후보", () => {
    const reg = new ProviderRegistry();
    applyCustomProviders(reg, [validateSpec({ ...base })]);
    const names = reg.available({ MY_LLM_KEY: "k" } as NodeJS.ProcessEnv).map((s) => s.name);
    expect(names).toContain("my-llm");
  });

  it("깨진 파일은 안내 에러", async () => {
    await fs.writeFile(customProvidersPath(env), "{{{", "utf8");
    await expect(loadCustomProviders(env)).rejects.toThrow(/읽지 못했습니다/);
  });

  it("소유자 전용 권한(600)으로 저장된다", async () => {
    await saveCustomProviders([validateSpec({ ...base })], env);
    const st = await fs.stat(customProvidersPath(env));
    // eslint-disable-next-line no-bitwise
    expect(st.mode & 0o777).toBe(0o600);
  });
});
