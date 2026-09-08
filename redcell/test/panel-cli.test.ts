/**
 * 데스크톱 패널 CLI 연동 e2e — `redcell rlm --panel` 이 로컬 패널을 띄우고
 * 이벤트를 SSE 로 흘리는지 검증한다.
 *
 * 흐름: 취약 lab 서버 시작 → CLI(rlm --mock --panel) spawn → stderr 에서
 * `[panel] ... http://127.0.0.1:<PORT>` 라인 수집 → HTML/SSE fetch → CLI 종료 확인.
 *
 * (패널은 CLI 수명과 함께 닫히므로, fetch 는 포트 라인이 보이는 즉시 실행한다.)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn } from "node:child_process";
import http from "node:http";
import { AddressInfo } from "node:net";
import path from "node:path";
import os from "node:os";
import { writeFile, rm, mkdtemp } from "node:fs/promises";

const CLI = path.resolve(__dirname, "../src/cli.ts");
const AUTH = path.join(os.tmpdir(), `rc-panel-${process.pid}.yaml`);
const AUDIT_DIR = path.join(os.tmpdir(), `rc-panel-audit-${process.pid}`);
const AUTH_YAML = `engagement:
  name: "panel-cli-e2e"
  authorized_from: "2000-01-01"
  authorized_until: "2999-12-31"
  authorized_by: "test"
scope:
  allow:
    - host: "127.0.0.1"
limits:
  max_requests_per_second: 100
`;

let lab: http.Server;
let labPort: number;
let memDir: string;

beforeAll(async () => {
  await writeFile(AUTH, AUTH_YAML, "utf8");
  await mkdtemp(path.join(os.tmpdir(), "rc-panel-mem-")).then((d) => (memDir = d));
  lab = http.createServer((req, res) => {
    res.setHeader("content-type", "text/html");
    res.setHeader("content-length", "13");
    res.end("<html>lab</html>");
  });
  await new Promise<void>((r) => lab.listen(0, "127.0.0.1", r));
  labPort = (lab.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((r) => lab.close(() => r()));
  await rm(AUTH, { force: true });
  await rm(AUDIT_DIR, { recursive: true, force: true });
  await rm(memDir, { recursive: true, force: true });
});

/** CLI 를 spawn 하고 stderr 에서 `[panel]` 포트 라인을 기다린 뒤 즉시 fetch 한다. */
async function runWithPanel(maxActions: number): Promise<{
  panelPort: number;
  htmlStatus: number;
  htmlHasPanel: boolean;
  sse: string;
  exitCode: number | null;
}> {
  const child = spawn("npx", ["tsx", CLI, "rlm", "--host", "127.0.0.1", "--port", String(labPort),
    "--mock", "--auth", AUTH, "--panel", "--panel-port", "0", "--max-actions", String(maxActions),
    "--mem", path.join(memDir, "m.md")], {
    cwd: path.resolve(__dirname, ".."),
    env: { ...process.env, REDCELL_AUDIT_DIR: AUDIT_DIR },
  });

  let stderr = "";
  let panelPort: number | null = null;
  const portRe = /\[panel\] 데스크톱 패널: http:\/\/127\.0\.0\.1:(\d+)/;

  const gotPort = new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`panel port timeout. stderr: ${stderr.slice(-500)}`)), 60_000);
    child.stderr.on("data", (c: Buffer) => {
      stderr += c.toString();
      const m = stderr.match(portRe);
      if (m) { clearTimeout(timer); resolve(Number(m[1])); }
    });
    child.on("exit", (code) => {
      if (panelPort === null) {
        clearTimeout(timer);
        reject(new Error(`cli exited early (code ${code}) before panel port. stderr: ${stderr.slice(-500)}`));
      }
    });
  });

  panelPort = await gotPort;

  // 포트가 보이는 즉시 fetch(패널은 CLI 종료와 함께 닫힌다).
  const htmlRes = await fetch(`http://127.0.0.1:${panelPort}/`);
  const html = await htmlRes.text();
  let sseAcc = "";
  const sse = await new Promise<string>((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:${panelPort}/events`, (res) => {
      res.on("data", (c: Buffer) => {
        sseAcc += c.toString();
        if (sseAcc.includes("phase") || sseAcc.includes("note")) {
          req.destroy();
          resolve(sseAcc);
        }
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    setTimeout(() => reject(new Error("sse timeout")), 10_000);
  }).catch((e: unknown) => `SSE-ERR ${String(e)}`);

  const exitCode = await new Promise<number | null>((r2) => child.on("exit", (c) => r2(c)));

  return {
    panelPort,
    htmlStatus: htmlRes.status,
    htmlHasPanel: html.includes("REDCELL"),
    sse,
    exitCode,
  };
}

describe("rlm --panel CLI e2e", () => {
  it("패널 HTML/SSE 를 서빙하고 CLI 는 정상 종료한다", async () => {
    const res = await runWithPanel(30);
    expect(res.htmlStatus).toBe(200);
    expect(res.htmlHasPanel).toBe(true);
    expect(res.sse).toContain("data: ");
    expect(res.exitCode).toBe(0);
  }, 90_000);
});
