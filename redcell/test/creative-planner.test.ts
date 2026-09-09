import { describe, it, expect } from "vitest";
import { MockModel } from "../src/core/mock-model.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";

const TOOLS = new DefaultToolBox().list().map((t) => ({ name: t.name, intent: t.intent, description: t.description }));

/** 오케스트레이터가 MockModel 에 넘기는 프롬프트 형태를 흉내낸다. */
function ask(model: MockModel, phase: string, goal: string, indicators: string[], service?: string) {
  const prompt = JSON.stringify({
    instruction: `현재 phase=${phase}. 목표=${goal}. 다음 액션 1개를 제안하라.`,
    target: { host: "127.0.0.1" },
    known_fingerprint: { service, indicators },
    available_tools: TOOLS,
    recent_transcript: [],
  });
  return model.complete({ system: "", prompt, json: true }).then((r) => JSON.parse(r));
}

/** 단계가 끝날 때까지(=done) 제안된 툴들을 순서대로 모은다. */
async function drain(model: MockModel, phase: string, goal: string, indicators: string[], service?: string, cap = 12) {
  const picked: string[] = [];
  for (let i = 0; i < cap; i++) {
    const a = await ask(model, phase, goal, indicators, service);
    if (a.done) break;
    picked.push(a.tool);
  }
  return picked;
}

describe("MockModel 발산형 플래너", () => {
  it("recon 첫 수는 http_probe + seed playbook 재사용(회귀 방지)", async () => {
    const a = await ask(new MockModel(), "recon", "웹 스택 식별", []);
    expect(a.tool).toBe("http_probe");
    expect(a.fromPlaybook).toBe("pb_seed_http_recon");
  });

  it("한 단계에서 같은 툴을 반복하지 않고 여러 벡터로 발산한다(exploit)", async () => {
    const model = new MockModel();
    const picked = await drain(model, "exploit", "웹 취약점 탐색", [
      "endpoint /item?id=1",
      "endpoint /api/orders/1000",
    ]);
    // 서로 다른 벡터가 다수 시도됨(중복 없음).
    expect(new Set(picked).size).toBe(picked.length);
    expect(picked.length).toBeGreaterThanOrEqual(4);
    // 대표적 웹 취약점 벡터가 포함됨.
    expect(picked).toContain("sqli_probe");
    expect(picked).toContain("xss_probe");
    // 모두 exploit intent 툴이어야 함.
    const exploitNames = new Set(TOOLS.filter((t) => t.intent === "exploit").map((t) => t.name));
    expect(picked.every((p) => exploitNames.has(p))).toBe(true);
  });

  it("발견한 엔드포인트를 다음 액션 인자로 구체화한다(발산 스윕)", async () => {
    const model = new MockModel();
    // exploit 첫 벡터(sqli)에 발견된 경로×파라미터가 스윕 인자로 반영되는지 확인.
    const a = await ask(model, "exploit", "탐색", ["endpoint /item?id=1"]);
    expect(a.tool).toBe("sqli_probe");
    expect(a.args.paths).toContain("/item");
    expect(a.args.params).toContain("id");
  });

  it("정보수집 목표면 enumerate 에서 api_probe 를 우선한다", async () => {
    const model = new MockModel();
    const a = await ask(model, "enumerate", "API 정보 수집", ["endpoint /api/users"], "nginx");
    expect(a.tool).toBe("api_probe");
    expect(a.args.paths).toContain("/api/users");
  });

  it("벡터를 모두 소진하면 done 을 반환한다", async () => {
    const model = new MockModel();
    const picked = await drain(model, "exploit", "탐색", [], undefined, 30);
    // 등록된 exploit 툴 수만큼만 시도하고 종료.
    const exploitCount = TOOLS.filter((t) => t.intent === "exploit").length;
    expect(picked.length).toBe(exploitCount);
  });
});
