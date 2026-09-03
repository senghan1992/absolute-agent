import { describe, it, expect, afterAll, beforeAll } from "vitest";
import http from "node:http";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { AddressInfo } from "node:net";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { SkillMemory } from "../src/memory/skill-memory.js";
import { Orchestrator } from "../src/core/orchestrator.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";
import { MockModel } from "../src/core/mock-model.js";
import { toMarkdown } from "../src/report/report.js";

// 인가된 로컬 대상을 흉내내는 미니 웹서버(취약 스택 배너 노출).
let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.setHeader("Server", "nginx/1.18.0");
    res.setHeader("X-Powered-By", "PHP/7.4.3");
    res.setHeader("Set-Cookie", "PHPSESSID=abc; path=/");
    res.end("<html><body>DVWA Login</body></html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});

afterAll(() => server.close());

function authFor(): AuthorizationFile {
  return {
    engagement: { name: "e2e", authorized_from: "2026-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    // 테스트 서버는 임의 포트를 쓰므로 포트 제한은 두지 않는다.
    limits: { max_requests_per_second: 50, disallow_destructive: true, disallow_dos: true },
  };
}

describe("Orchestrator end-to-end", () => {
  it("정찰→핑거프린팅→자기발전(playbook 저장) 전 과정 동작", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-e2e-"));
    const guard = new ScopeGuard(authFor());
    const memory = new SkillMemory(dir);
    await memory.load();

    const orch = new Orchestrator(guard, memory, new MockModel(), new DefaultToolBox());
    const log = await orch.run({ host: "127.0.0.1", port }, "웹 스택 식별");

    // 대상이 인가되어 정찰이 수행됨
    expect(log.transcript.some((l) => l.includes("[인가]"))).toBe(true);
    // 실제 HTTP 응답에서 nginx/php 를 핑거프린팅
    expect(log.fingerprint.service).toBe("nginx");
    expect(log.fingerprint.tech).toContain("php");
    // recon 단계에서 seed playbook 을 재사용해 통계가 기록됨
    expect(log.usedPlaybooks).toContain("pb_seed_http_recon");

    const md = toMarkdown(log);
    expect(md).toContain("RedCell Engagement Report");
    expect(md).toContain("nginx");
    // cmdi/sqli 가 출력 기반 미탐 시 시간 기반 블라인드까지 스윕하므로 요청 수가 늘어(RPS 제한 하)
    // 전체 오케스트레이션 런이 5s 를 살짝 넘는다. 여유 있는 타임아웃을 준다.
  }, 20000);

  it("scope 밖 대상은 거부하고 아무 것도 실행하지 않음", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-e2e2-"));
    const guard = new ScopeGuard(authFor());
    const memory = new SkillMemory(dir);
    await memory.load();
    const orch = new Orchestrator(guard, memory, new MockModel(), new DefaultToolBox());

    const log = await orch.run({ host: "8.8.8.8", port: 80 }, "이건 거부되어야 함");
    expect(log.transcript.some((l) => l.includes("[거부]"))).toBe(true);
    expect(log.findings.length).toBe(0);
    expect(log.fingerprint.service).toBeUndefined();
  });
});
