/**
 * rlm.test — RLM(Recursive Language Model) harness 검증.
 *
 * RLM 패러다임(prime-agent/OASYS)의 네 축을 오프라인으로 검증한다:
 *   1) 영구 REPL — 변수·ctx 가 스텝을 넘어 지속되는가(prompt-as-variable).
 *   2) 재귀 서브콜 — 파이썬 rlm() 호출이 하위 에이전트를 실행하고 결과를 값으로 돌려주는가.
 *   3) 자기발전 기억 — rc.memo() 가 수집·파일 기록되고 다음 세션에 재주입되는가.
 *   4) 안전 — REPL 경로에서도 ScopeGuard·공유 예산·정적 스캔이 그대로 강제되는가(재귀 포함).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { ReplSession } from "../src/py/broker.js";
import { RlmAgent } from "../src/rlm/rlm-agent.js";
import type { ModelAdapter } from "../src/core/types.js";

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/item") {
      const id = url.searchParams.get("id") ?? "";
      if (id.includes("'")) {
        res.statusCode = 500;
        res.end("You have an error in your SQL syntax near MySQL");
        return;
      }
      res.statusCode = 200;
      res.end("item ok");
      return;
    }
    res.setHeader("Server", "nginx/1.18.0");
    res.end("<html>root</html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function auth(): AuthorizationFile {
  return {
    engagement: { name: "rlm", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 200 },
  };
}
const guard = () => new ScopeGuard(auth());
const target = () => ({ host: "127.0.0.1", port });

/** 프롬프트 내용으로 분기하는 스크립트 모델(trusted → 격리 없이 실행, 결정적). */
class ScriptedModel implements ModelAdapter {
  readonly trusted = true;
  prompts: string[] = [];
  /** (prompt) → 응답객체 | null(done). 각 depth 의 에이전트가 프롬프트를 보고 분기한다. */
  constructor(private fn: (prompt: string) => Record<string, unknown> | null) {}
  async complete(input: { system: string; prompt: string; json?: boolean }): Promise<string> {
    this.prompts.push(input.prompt);
    const o = this.fn.call(this, input.prompt);
    return JSON.stringify(o ?? { done: true });
  }
}

describe("ReplSession: 영구 REPL", () => {
  it("변수·ctx 가 스텝을 넘어 지속된다(prompt-as-variable)", async () => {
    const s = await ReplSession.create({ guard: guard(), target: target(), isolation: "off", ctx: { goal: "테스트" } });
    try {
      const r1 = await s.step("ctx['x'] = 5\nctx['y'] = 'persist'\nrc.log('step1 done')");
      expect(r1.ok).toBe(true);
      expect(r1.logs).toContain("step1 done");

      const r2 = await s.step("print('has-x', ctx.get('x'), 'y=', ctx.get('y'))");
      expect(r2.stdout).toContain("has-x 5");
      expect(r2.stdout).toContain("y= persist");
    } finally {
      await s.close();
    }
  });

  it("rc.finding/rc.log 마커를 수집하고 실행 결과를 돌려준다", async () => {
    const s = await ReplSession.create({ guard: guard(), target: target(), isolation: "off" });
    try {
      const r = await s.step("rc.finding('테스트 발견', severity='low', evidence='x')\nrc.log('observed')");
      expect(r.ok).toBe(true);
      expect(r.findings).toHaveLength(1);
      expect(r.findings[0].title).toBe("테스트 발견");
      expect(r.logs).toContain("observed");
    } finally {
      await s.close();
    }
  });

  it("정적 위험 스캔은 REPL 경로에서도 실행 전에 차단한다", async () => {
    const s = await ReplSession.create({ guard: guard(), target: target(), isolation: "off" });
    try {
      const r = await s.step("import socket\nsocket.socket()");
      expect(r.ok).toBe(false);
      expect(r.danger).toMatch(/socket/);
    } finally {
      await s.close();
    }
  });

  it("rlm() 재귀 콜이 엔진 콜백을 호출하고 결과를 값으로 돌려준다", async () => {
    let called = 0;
    const s = await ReplSession.create({
      guard: guard(),
      target: target(),
      isolation: "off",
      onRlm: async (req) => {
        called++;
        expect(req.prompt).toContain("하위 작업");
        return "하위 결과: pong";
      },
    });
    try {
      const r = await s.step("r = rlm('하위 작업 좀 해줘', 3)\nprint('GOT:', r)");
      expect(called).toBe(1);
      expect(r.stdout).toContain("GOT: 하위 결과: pong");
    } finally {
      await s.close();
    }
  });

  it("rc.memo() 가 onMemo 로 수집된다", async () => {
    const memos: Array<{ key: string; text: string }> = [];
    const s = await ReplSession.create({ guard: guard(), target: target(), isolation: "off", onMemo: (m) => memos.push(m) });
    try {
      const r = await s.step("rc.memo('sqli-recipe', '작은따옴표 + DB 오류 시그니처로 확인한다')");
      expect(r.ok).toBe(true);
      expect(memos).toHaveLength(1);
      expect(memos[0].key).toBe("sqli-recipe");
    } finally {
      await s.close();
    }
  });

  it("공유 예산(budget)을 초과하면 브로커가 차단한다(재귀 폭주 방지)", async () => {
    const s = await ReplSession.create({
      guard: guard(),
      target: target(),
      isolation: "off",
      budget: { used: 0, max: 1 },
    });
    try {
      const r1 = await s.step("rc.get('/')");
      expect(r1.ok).toBe(true);
      expect(r1.requests).toBe(1);
      const r2 = await s.step("try:\n    rc.get('/')\n    print('UNEXPECTED')\nexcept Exception as e:\n    print('BLOCKED:', str(e)[:60])");
      expect(r2.stdout).toContain("BLOCKED");
      expect(r2.stdout).not.toContain("UNEXPECTED");
    } finally {
      await s.close();
    }
  });
});

describe("RlmAgent: 재귀 서브콜 + 자기발전 기억", () => {
  it("rlm() 재귀 위임: 하위 에이전트 최종답변을 값으로 받고 발견이 승격된다", async () => {
    const events: string[] = [];
    const steps = { n: 0 };
    const model = new ScriptedModel((prompt) => {
      if (prompt.includes("통합 재귀 테스트")) {
        steps.n++;
        return steps.n === 1
          ? {
              code: "sub = rlm('하위 작업: 루트를 확인하고 발견을 보고해라', 2)\nrc.log('parent got:', sub[:50])\nprint('PARENT-GOT:', sub)",
              rationale: "부문제를 하위 에이전트에 위임",
            }
          : { text: "FINAL: 전체 작업 완료", rationale: "완료", done: true };
      }
      // 하위 에이전트(재귀)는 항상: 루트 관찰 + 발견 후 FINAL.
      return {
        code: "r = rc.get('/')\nrc.log('child root', r.status)\nrc.finding('자식 발견 SQLi', severity='high', evidence='ev')\nprint('FINAL: child done ok')",
        rationale: "자식: 루트 관찰 + 발견",
      };
    });
    const agent = new RlmAgent(guard(), model, {
      maxIterations: 5,
      maxDepth: 2,
      isolation: "off",
      onEvent: (e) => events.push(e.text),
    });
    const log = await agent.run(target(), "통합 재귀 테스트");
    const joined = events.join("\n");
    expect(joined).toContain("child root");
    expect(joined).toContain("PARENT-GOT:");
    expect(joined).toContain("child done ok"); // 하위 FINAL 이 값으로 돌아와 출력됨
    expect(log.findings.some((f) => f.title === "자식 발견 SQLi")).toBe(true);
    expect(log.findings.some((f) => f.severity === "high")).toBe(true);
  });

  it("최대 재귀 깊이를 넘기면 위임을 거부하고 상위 힌트를 준다", async () => {
    const events: string[] = [];
    const steps = { n: 0 };
    const model = new ScriptedModel((prompt) => {
      if (prompt.includes("깊이 제한")) {
        steps.n++;
        return steps.n === 1
          ? { code: "sub = rlm('다시 위임해라', 2)\nprint('RESULT:', sub)", rationale: "위임" }
          : { done: true };
      }
      return {
        code: "sub2 = rlm('또 위임', 2)\nprint('CHILD-SEES:', sub2)",
        rationale: "재위임(깊이 초과)",
      };
    });
    const agent = new RlmAgent(guard(), model, {
      maxIterations: 4,
      maxDepth: 1,
      isolation: "off",
      onEvent: (e) => events.push(e.text),
    });
    const log = await agent.run(target(), "깊이 제한");
    const joined = events.join("\n");
    // 하위(깊이 1)가 다시 rlm() 을 부르면 깊이 한도에 걸려 힌트 문자열이 값으로 돌아온다.
    expect(joined).toContain("최대 재귀 깊이");
    expect(log.transcript.join("\n")).toContain("CHILD-SEES: [rlm]");
  });

  it("rc.memo() 기억이 파일에 기록되고 다음 세션에 재주입된다(continual harness)", async () => {
    const memDir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-mem-"));
    const memFile = path.join(memDir, "memories.md");
    const memoStep = { done: false };
    try {
      const model1 = new ScriptedModel((prompt) => {
        if (prompt.includes("기억 테스트") && !memoStep.done) {
          memoStep.done = true;
          return { code: "rc.memo('login-trick', '세션 쿠키를 먼저 탈취한다')\nrc.log('memo saved')", rationale: "기억 저장" };
        }
        return null;
      });
      const a1 = new RlmAgent(guard(), model1, { maxIterations: 3, isolation: "off", memoryFile: memFile });
      await a1.run(target(), "기억 테스트");
      const md = await fs.readFile(memFile, "utf8");
      expect(md).toContain("## login-trick");
      expect(md).toContain("세션 쿠키를 먼저 탈취한다");

      // 다음 세션: 파일에서 기억을 로드해 모델 프롬프트에 재주입.
      const loaded = md
        .split(/\n## /)
        .map((b) => {
          const lines = b.split("\n");
          const key = lines[0].trim();
          const text = lines.slice(1).join(" ").trim();
          return key && text ? `${key}: ${text}` : null;
        })
        .filter(Boolean) as string[];
      expect(loaded.length).toBeGreaterThanOrEqual(1);

      const model2 = new ScriptedModel(() => null);
      const a2 = new RlmAgent(guard(), model2, { maxIterations: 2, isolation: "off", memories: loaded });
      await a2.run(target(), "두 번째 세션");
      expect(model2.prompts.join("\n")).toContain("login-trick: 세션 쿠키를 먼저 탈취한다");
    } finally {
      await fs.rm(memDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  it("미인가 대상은 REPL 실행 이전에 거부한다(fail-closed)", async () => {
    const model = new ScriptedModel(() => null);
    const agent = new RlmAgent(guard(), model, { maxIterations: 3, isolation: "off" });
    const log = await agent.run({ host: "10.99.99.99", port: 80 }, "테스트");
    expect(log.transcript.join("\n")).toMatch(/거부/);
    expect(log.findings).toHaveLength(0);
  });
});