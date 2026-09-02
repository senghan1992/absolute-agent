import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { AddressInfo } from "node:net";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { SkillMemory } from "../src/memory/skill-memory.js";
import { ContextualBandit } from "../src/explore/bandit.js";
import { AutoPilot } from "../src/core/autopilot.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (["/admin", "/login", "/robots.txt"].includes(url.pathname)) {
      res.statusCode = 200;
      res.end("ok");
      return;
    }
    if (url.pathname === "/item") {
      const id = url.searchParams.get("id") ?? "";
      res.statusCode = id.includes("'") ? 500 : 200;
      res.end(id.includes("'") ? "You have an error in your SQL syntax near MySQL" : "item");
      return;
    }
    res.setHeader("Server", "nginx/1.18.0");
    res.setHeader("X-Powered-By", "PHP/7.4.3");
    res.setHeader("Set-Cookie", "PHPSESSID=x");
    res.end("<html>DVWA</html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function auth(): AuthorizationFile {
  return {
    engagement: { name: "auto", authorized_from: "2026-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 200 },
  };
}

describe("AutoPilot 자율 인게이지먼트", () => {
  it("정찰→열거→익스플로잇을 스스로 진행하며 학습·발견·distill", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-auto-"));
    const memory = new SkillMemory(dir);
    await memory.load();
    const bandit = new ContextualBandit("ucb1");
    const auto = new AutoPilot(new ScopeGuard(auth()), memory, bandit, new DefaultToolBox(), {
      maxStepsPerPhase: 5,
      globalBudget: 30,
      // 익스플로잇 단계에서 발견된 경로로 sqli_probe 유도(툴 간 데이터 흐름 시뮬)
      argsFor: (name) => (name === "sqli_probe" ? { path: "/item", param: "id" } : {}),
    });

    const rep = await auto.run({ host: "127.0.0.1", port }, "웹 취약점 자동 탐색");

    // 스택을 스스로 핑거프린팅
    expect(rep.fingerprint.service).toBe("nginx");
    expect(rep.fingerprint.tech).toContain("php");
    // 익스플로잇 단계에서 SQLi(high) 발견 → 목표 달성
    expect(rep.findings.some((f) => f.severity === "high" && /SQL/i.test(f.title))).toBe(true);
    expect(rep.solved).toBe(true);
    // 학습: 성공 흐름을 playbook 으로 저장
    expect(memory.all().some((p) => p.tags?.includes("autopilot"))).toBe(true);
    // bandit 이 상황별로 학습(recon 컨텍스트에 값 존재)
    const reconCtx = bandit.ranking("recon|nginx/?").length + bandit.ranking("recon|?/?").length;
    expect(reconCtx).toBeGreaterThan(0);
  });

  it("scope 밖 대상은 아무 것도 실행하지 않음", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-auto2-"));
    const memory = new SkillMemory(dir);
    await memory.load();
    const auto = new AutoPilot(new ScopeGuard(auth()), memory, new ContextualBandit("ucb1"), new DefaultToolBox());
    const rep = await auto.run({ host: "8.8.8.8", port: 80 }, "거부되어야 함");
    expect(rep.transcript.some((l) => l.includes("[거부]"))).toBe(true);
    expect(rep.steps).toBe(0);
    expect(rep.solved).toBe(false);
  });
});
