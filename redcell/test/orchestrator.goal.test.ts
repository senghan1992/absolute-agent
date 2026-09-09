/**
 * 목표 지향 자율 루프 테스트 — Orchestrator 가 '횟수'가 아니라 '목표/소득'으로 동작하는지.
 *
 *  1) 추궁(challenge): 모델이 성급하게 done 을 선언하면 한 번 더 물어 소득을 끌어낸다.
 *  2) 중복 방어: 같은 액션만 계속 제안하는 모델 → 정체 판정으로 반드시 종료(무한 루프 금지).
 *  3) 안전 가드: 항상 새로운 액션을 제안하는 모델도 총 액션 상한에서 멈춘다(비상 브레이크).
 *  4) 자유 추격(free chase): 단계 구조가 끝나도 남은 소득이 있으면 단계 구분 없이 계속 실행.
 */

import { describe, it, expect, afterAll, beforeAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { SkillMemory } from "../src/memory/skill-memory.js";
import { Orchestrator, type OrchestratorEvent } from "../src/core/orchestrator.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";
import type { EngagementLog, ModelAdapter, ToolBox } from "../src/core/types.js";

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    res.setHeader("Server", "nginx/1.18.0");
    if (u.pathname === "/search") return res.end("<html>Results for x</html>");
    if (u.pathname === "/item") return res.end("<html>item page</html>");
    res.end('<html><body>DVWA <a href="/search?q=1">s</a> <a href="/item?id=1">i</a></body></html>');
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => server.close());

function authFor(): AuthorizationFile {
  return {
    engagement: { name: "e2e", authorized_from: "2026-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 100, disallow_destructive: true, disallow_dos: true },
  };
}

/** 스크립트된 모델 — 큐에서 순서대로 응답. 소진되면 done. */
class ScriptedModel implements ModelAdapter {
  constructor(private readonly replies: unknown[]) {}
  async complete(): Promise<string> {
    const r = this.replies.shift() ?? { done: true, reason: "no more" };
    return JSON.stringify(r);
  }
}

/** 끝없이 새로운 액션을 제안하는 모델(안전 가드 검증용). */
class EndlessModel implements ModelAdapter {
  private n = 0;
  async complete(): Promise<string> {
    this.n++;
    return JSON.stringify({ tool: "http_probe", args: { path: `/${this.n}`, note: `probe-${this.n}` }, rationale: "계속 탐색" });
  }
}

/** 같은 액션만 반복 제안하는 모델(중복 방어 검증용). */
class StuckModel implements ModelAdapter {
  async complete(): Promise<string> {
    return JSON.stringify({ tool: "http_probe", args: { path: "/" }, rationale: "같은 것 반복" });
  }
}

async function makeOrch(model: ModelAdapter, opts: ConstructorParameters<typeof Orchestrator>[4] = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-"));
  const guard = new ScopeGuard(authFor());
  const memory = new SkillMemory(dir);
  await memory.load();
  return new Orchestrator(guard, memory, model, new DefaultToolBox(), opts);
}

describe("목표 지향 자율 루프", () => {
  it("추궁(challenge): 성급한 done 에도 소득을 끌어낸다", async () => {
    // exploit 단계에서 모델이 1 액션 뒤 done 선언 → 추궁에서 추가 액션 제출.
    const model = new ScriptedModel([
      { tool: "http_probe", args: { path: "/" }, rationale: "정찰" },
      { done: true, reason: "그만" }, // recon 종료 선언(성급)
      { tool: "header_audit", args: { path: "/" }, rationale: "추궁에서 꺼낸 추가 수" },
      { done: true, reason: "이제 진짜 없음" },
      // enumerate 이후는 전부 done
      { done: true }, { done: true }, { done: true }, { done: true },
    ]);
    const notes: string[] = [];
    const orch = await makeOrch(model, {
      onEvent: (e: OrchestratorEvent) => { if (e.type === "note") notes.push(e.text); },
    });
    const log = await orch.run({ host: "127.0.0.1", port }, "웹 정찰");

    const ran = log.transcript.filter((l) => l.startsWith("[recon] → "));
    expect(ran.some((l) => l.includes("http_probe"))).toBe(true);
    expect(ran.some((l) => l.includes("header_audit"))).toBe(true); // 추궁이 추가 액션을 끌어냄
    expect(notes.some((n) => n.includes("재검토"))).toBe(true);
  });

  it("중복 방어: 같은 액션만 제안하는 모델도 반드시 종료한다(무한 루프 금지)", async () => {
    const orch = await makeOrch(new StuckModel(), { maxMinutes: 1 });
    const started = Date.now();
    const log = await orch.run({ host: "127.0.0.1", port }, "정찰");
    expect(Date.now() - started).toBeLessThan(60_000); // 데드라인(60초) 전에 종료
    const ran = log.transcript.filter((l) => l.startsWith("[recon] → http_probe"));
    expect(ran.length).toBe(1); // 동일 액션은 1회만 실행
    expect(log.transcript.some((l) => l.includes("동일 인자 재제안"))).toBe(true);
  });

  it("안전 가드: 계속 새 액션을 제안해도 총 액션 상한에서 멈춘다", async () => {
    const orch = await makeOrch(new EndlessModel(), { maxTotalActions: 6, maxMinutes: 2 });
    const log = await orch.run({ host: "127.0.0.1", port }, "끝없는 탐색");
    const actions = log.transcript.filter((l) => /→ \w+\(/.test(l));
    expect(actions.length).toBeLessThanOrEqual(10); // 상한 근처에서 반드시 멈춤(단계별 여유 포함)
    expect(log.transcript.some((l) => l.includes("안전 가드"))).toBe(true);
  });

  it("자유 추격: 단계 구조 이후에도 남은 소득이 있으면 단계 구분 없이 실행한다", async () => {
    // post 단계까지 전부 done 으로 소진 → free chase 에서 마지막 액션 1개를 꺼낸다.
    const model = new ScriptedModel([
      { done: true }, { done: true }, // recon(+추궁)
      { done: true }, { done: true }, // enumerate
      { done: true }, { done: true }, // exploit
      { done: true }, { done: true }, // post
      { tool: "http_probe", args: { path: "/followup" }, rationale: "추격에서 꺼낸 마지막 수" },
      { done: true, reason: "진짜 끝" },
    ]);
    const orch = await makeOrch(model);
    const log: EngagementLog = await orch.run({ host: "127.0.0.1", port }, "추격 테스트");
    expect(log.transcript.some((l) => l.includes("/followup"))).toBe(true);
    expect(log.transcript.some((l) => l.includes("[추격]"))).toBe(true);
  });
});
