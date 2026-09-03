/**
 * P0-4 — scope 차단 가시성 회귀 테스트.
 *
 * 미인가 대상/포트로 `redcell run` 을 실행하면:
 *   - engagement 를 수행하지 않고
 *   - 전용 종료코드(3)로 끝나며
 *   - "SCOPE 차단" 배너를 출력한다(빈 리포트를 '정상 통과'로 오인 방지).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, rm } from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const run = promisify(execFile);
const CLI = path.resolve(__dirname, "../src/cli.ts");
const AUTH = path.join(os.tmpdir(), `rc-scope-${process.pid}.yaml`);

const AUTH_YAML = `engagement:
  name: "scope-block-test"
  authorized_from: "2000-01-01"
  authorized_until: "2999-12-31"
  authorized_by: "test"
scope:
  allow:
    - host: "127.0.0.1"
ports:
  allow_tcp: [8080]
limits:
  max_requests_per_second: 50
`;

beforeAll(async () => {
  await writeFile(AUTH, AUTH_YAML, "utf8");
});
afterAll(async () => {
  await rm(AUTH, { force: true });
});

/** tsx 로 CLI 를 실행하고 {code, stdout, stderr} 를 돌려준다(비-0 종료도 성공적으로 캡처). */
async function cli(argsList: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run("npx", ["tsx", CLI, ...argsList], { cwd: path.resolve(__dirname, "..") });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: err.code ?? -1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

describe("scope 차단 가시성 (P0-4)", () => {
  it("미인가 호스트는 종료코드 3 + 배너로 차단한다", async () => {
    const r = await cli(["run", "--host", "8.8.8.8", "--port", "8080", "--auth", AUTH, "--auto", "--goal", "t"]);
    expect(r.code).toBe(3);
    expect(r.stderr + r.stdout).toContain("SCOPE 차단");
  }, 30_000);

  it("인가 호스트라도 미허용(임시) 포트는 종료코드 3 으로 차단한다", async () => {
    const r = await cli(["run", "--host", "127.0.0.1", "--port", "54321", "--auth", AUTH, "--auto", "--goal", "t"]);
    expect(r.code).toBe(3);
    expect(r.stderr + r.stdout).toMatch(/포트 54321|허용 포트/);
  }, 30_000);
});
