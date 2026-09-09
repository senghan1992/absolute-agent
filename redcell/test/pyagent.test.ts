/**
 * pyagent.test — 결정적 python_exec 에이전트 루프(src/assault/pyagent.ts) 검증.
 *
 * 핵심 검증:
 *   1) 후보 추출: 정찰 지표에서 쿼리 파라미터 엔드포인트만 정규화해 뽑는다(값 제거·중복 제거).
 *   2) 프로그램 생성: 생성 코드가 broker 정적 스캔(scanDanger)과 AST 샌드박스를 통과하고,
 *      금지 패턴(직접 네트워크/프로세스/파일 삭제)을 포함하지 않는다.
 *   3) 루프 동작: 블라인드 명령 주입 랩에서 코드 생성→실행→로그 회수→디코드→검증된 증거까지
 *      한 번에 완료한다(마커 포함 증거 + FLAG).
 *   4) FP 통제: 로그 싱크가 없는 서버·쿼리 파라미터가 없는 서버에서는 발견 0.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { exec } from "node:child_process";
import { AddressInfo } from "node:net";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { scanDanger } from "../src/py/broker.js";
import { runPyAgent, candidateParams, buildInjectionProgram } from "../src/assault/pyagent.js";
import type { ToolContext } from "../src/core/types.js";
import type { ToolOutcome } from "../src/assault/types.js";

// --- 블라인드 명령 주입 랩(테스트 전용): 응답은 고정 JSON, 출력은 로그 싱크로만. ---
let server: http.Server;
let port: number;
let workdir: string;
let logPath: string;

function startLab(opts: { sink: boolean }): Promise<void> {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://x");
      const send = (code: number, body: string) => {
        res.writeHead(code, { "content-type": "text/plain" });
        res.end(body);
      };
      if (url.pathname === "/ping") {
        const host = url.searchParams.get("host") ?? "";
        exec("( echo PING " + host + " ) >> " + JSON.stringify(logPath) + " 2>&1", { cwd: workdir }, () => {
          send(200, JSON.stringify({ ok: true, host }));
        });
        return;
      }
      if (url.pathname === "/logs" && opts.sink) {
        const marker = url.searchParams.get("marker") ?? "";
        fs.readFile(logPath, "utf8", (err, data) => {
          if (err) {
            send(200, "no logs");
            return;
          }
          const lines = data.split(/\r?\n/).filter((l) => l.length > 0);
          const idx = marker ? lines.findIndex((l) => l.includes(marker)) : -1;
          if (marker && idx < 0) {
            send(404, "no logs");
            return;
          }
          send(200, marker ? lines.slice(idx, idx + 100).join("\n") : lines.slice(-20).join("\n"));
        });
        return;
      }
      send(200, "root");
    });
    server.listen(0, "127.0.0.1", () => {
      port = (server.address() as AddressInfo).port;
      resolve();
    });
  });
}

beforeAll(async () => {
  workdir = fs.mkdtempSync(path.join(os.tmpdir(), "redcell-pyagent-"));
  fs.writeFileSync(path.join(workdir, "flag.txt"), "FLAG-PYAGENT-42\n");
  logPath = path.join(workdir, "logs.txt");
  await startLab({ sink: true });
});
afterAll(() => {
  server.close();
  fs.rmSync(workdir, { recursive: true, force: true });
});

function auth(): AuthorizationFile {
  return {
    engagement: { name: "pyagent", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 200 },
  };
}
const guard = () => new ScopeGuard(auth());
const target = () => ({ host: "127.0.0.1", port });
const ctx = (): ToolContext => ({ target: target(), rps: 50, validateIp: (h) => h === "127.0.0.1" });

function outcome(ind: string[]): ToolOutcome {
  return { tool: "crawl", stage: "recon", ok: true, summary: "ok", durationMs: 1, fp: { indicators: ind } };
}

describe("후보 추출(candidateParams)", () => {
  it("쿼리 파라미터가 있는 엔드포인트만 정규화해 뽑는다", () => {
    const out = [
      outcome(["endpoint /ping?host=127.0.0.1", "path / (200)"]),
      outcome(["endpoint /search?q=a&page=2"]),
      outcome(["endpoint /plain", "path /admin (200)"]),
    ];
    expect(candidateParams(out)).toEqual(["/ping?host=", "/search?q=&page="]);
  });
  it("상한 초과분은 버린다", () => {
    const out = Array.from({ length: 8 }, (_, i) => outcome([`endpoint /p${i}?x=1`]));
    expect(candidateParams(out, 3)).toHaveLength(3);
  });
});

describe("프로그램 생성(buildInjectionProgram)", () => {
  it("생성 코드는 broker 정적 위험 스캔과 샌드박스 규칙을 통과한다", () => {
    const code = buildInjectionProgram("/ping?host=", "RCXabc_0");
    expect(scanDanger(code)).toBeNull();
    expect(code).toContain("RCXabc_0");
    // 직접 네트워크/프로세스 실행 경로가 생성 코드에 없어야 한다.
    expect(code).not.toMatch(/import (socket|requests|urllib)|os\.system|subprocess|rmtree|__import__/);
    expect(code).toContain("rc.get");
    expect(code).toContain("rc.b64d");
    expect(code).toContain("rc.finding");
  });
  it("삽입 페이로드는 percent-encoding 되어 있다", () => {
    const code = buildInjectionProgram("/ping?host=", "RCXz_1");
    expect(code).toContain('base + enc');
    expect(code).not.toContain("; echo"); // 원문 세미콜론이 그대로 들어가면 안 된다
  });
});

describe("결정적 에이전트 루프(runPyAgent)", () => {
  it("블라인드 명령 주입 랩에서 서버 파일 탈취를 검증된 증거로 완료한다", async () => {
    const res = await runPyAgent(ctx(), [outcome(["endpoint /ping?host=127.0.0.1"])], { guard: guard(), target: target() });
    expect(res.attempts).toBeGreaterThan(0);
    expect(res.requests).toBeGreaterThanOrEqual(3);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].title).toContain("명령 실행");
    expect(res.findings[0].severity).toBe("high");
    expect(res.items).toHaveLength(1);
    const item = res.items[0];
    expect(item.category).toBe("endpoint");
    expect(item.verification?.status).toBe("verified");
    expect(item.verification?.proof).toContain("FLAG");
    expect(item.sample).toContain("FLAG-PYAGENT-42");
  });

  it("쿼리 파라미터가 없으면 시도조차 하지 않는다(FP 0)", async () => {
    const res = await runPyAgent(ctx(), [outcome(["endpoint /ping", "path / (200)"])], { guard: guard(), target: target() });
    expect(res.attempts).toBe(0);
    expect(res.findings).toHaveLength(0);
    expect(res.items).toHaveLength(0);
  });
});

describe("FP 통제: 로그 싱크가 없는 서버", () => {
  it("주입은 보내지만 회수 불가 → 발견 없음", async () => {
    const old = server;
    const srv2 = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://x");
      if (url.pathname === "/ping") {
        exec("( echo PING " + (url.searchParams.get("host") ?? "") + " ) >> " + JSON.stringify(logPath) + " 2>&1", { cwd: workdir }, () => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true }));
        });
        return;
      }
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
    });
    await new Promise<void>((r) => srv2.listen(0, "127.0.0.1", r));
    const p2 = (srv2.address() as AddressInfo).port;
    try {
      const res = await runPyAgent(
        { target: { host: "127.0.0.1", port: p2 }, rps: 50, validateIp: (h) => h === "127.0.0.1" },
        [outcome(["endpoint /ping?host=x"])],
        { guard: guard(), target: { host: "127.0.0.1", port: p2 } },
      );
      expect(res.attempts).toBe(1);
      expect(res.findings).toHaveLength(0);
      expect(res.items).toHaveLength(0);
    } finally {
      srv2.close();
      void old;
    }
  });
});
