/**
 * 게이트 모드 CLI 종료코드 회귀 테스트.
 *
 * `redcell run --full` 은 게이트 판정을 종료코드로 낸다:
 *   - clean        → 0
 *   - findings     → 2
 *   - inconclusive → 4 (도달 실패 포함)
 * CI 파이프라인이 이 코드로 "오픈 가능/불가"를 자동 판별할 수 있어야 한다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, rm, readdir } from "node:fs/promises";
import http from "node:http";
import { AddressInfo } from "node:net";
import path from "node:path";
import os from "node:os";

const run = promisify(execFile);
const CLI = path.resolve(__dirname, "../src/cli.ts");
const AUTH = path.join(os.tmpdir(), `rc-gate-${process.pid}.yaml`);
// 감사 추적을 임시 디렉터리로 격리(실제 ~/.redcell 오염 방지) + 무결성 검증 테스트에 사용.
const AUDIT_DIR = path.join(os.tmpdir(), `rc-gate-audit-${process.pid}`);

// 포트 제한 없음(임시 포트 도달 테스트용) + 127.0.0.1 허용.
const AUTH_YAML = `engagement:
  name: "gate-cli-test"
  authorized_from: "2000-01-01"
  authorized_until: "2999-12-31"
  authorized_by: "test"
scope:
  allow:
    - host: "127.0.0.1"
limits:
  max_requests_per_second: 100
`;

let vulnSrv: http.Server;
let vulnPort: number;
let deadPort: number;

beforeAll(async () => {
  await writeFile(AUTH, AUTH_YAML, "utf8");

  // 취약 서버: /item?id=' 에 SQL 오류 노출 → findings.
  vulnSrv = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/item") {
      const id = url.searchParams.get("id") ?? "";
      res.statusCode = id.includes("'") ? 500 : 200;
      res.end(id.includes("'") ? "You have an error in your SQL syntax near MySQL" : "item");
      return;
    }
    res.end(`<html><a href="/item?id=1">i</a></html>`);
  });
  await new Promise<void>((r) => vulnSrv.listen(0, "127.0.0.1", r));
  vulnPort = (vulnSrv.address() as AddressInfo).port;

  // 확실히 닫힌 포트 확보(열었다 닫음).
  const tmp = http.createServer();
  await new Promise<void>((r) => tmp.listen(0, "127.0.0.1", r));
  deadPort = (tmp.address() as AddressInfo).port;
  await new Promise<void>((r) => tmp.close(() => r()));
});
afterAll(async () => {
  vulnSrv.close();
  await rm(AUTH, { force: true });
  await rm(AUDIT_DIR, { recursive: true, force: true });
});

async function cli(argsList: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run("npx", ["tsx", CLI, ...argsList], {
      cwd: path.resolve(__dirname, ".."),
      env: { ...process.env, REDCELL_AUDIT_DIR: AUDIT_DIR },
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: err.code ?? -1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

describe("게이트 CLI 종료코드", () => {
  it("도달 실패 대상은 종료코드 4(inconclusive) + 배너로 끝난다", async () => {
    const r = await cli(["run", "--full", "--host", "127.0.0.1", "--port", String(deadPort), "--auth", AUTH]);
    expect(r.code).toBe(4);
    expect(r.stderr + r.stdout).toMatch(/INCONCLUSIVE|도달/);
  }, 30_000);

  it("취약점 발견 대상은 종료코드 2(findings)로 끝난다", async () => {
    const r = await cli(["run", "--full", "--host", "127.0.0.1", "--port", String(vulnPort), "--auth", AUTH]);
    expect(r.code).toBe(2);
    expect(r.stderr + r.stdout).toMatch(/FAIL|findings|게이트 판정/);
  }, 60_000);

  it("실행은 변조탐지 감사 추적을 남기고 audit verify 로 무결성이 확인된다", async () => {
    const r = await cli(["run", "--full", "--host", "127.0.0.1", "--port", String(vulnPort), "--auth", AUTH]);
    expect(r.stderr).toMatch(/\[audit\] 감사 추적:/);
    // 감사 디렉터리에 파일이 생겼는지 + 각 파일이 verify 를 통과하는지.
    const files = (await readdir(AUDIT_DIR)).filter((f) => f.endsWith(".jsonl"));
    expect(files.length).toBeGreaterThanOrEqual(1);
    const target = path.join(AUDIT_DIR, files[files.length - 1]);
    const v = await cli(["audit", "verify", target]);
    expect(v.code).toBe(0);
    expect(v.stdout).toMatch(/감사 무결성 확인/);
  }, 60_000);

  it("서명 리포트: 출처 섹션 + 무결성 다이제스트가 출력된다", async () => {
    const r = await cli(["run", "--full", "--allow-unauth", "--host", "127.0.0.1", "--port", String(vulnPort), "--auth", AUTH, "--target-ref", "demo@git:abc1234"]);
    expect(r.stdout).toContain("리포트 출처·무결성");
    expect(r.stdout).toMatch(/룰셋 해시: `[0-9a-f]{16}`/);
    expect(r.stdout).toContain("demo@git:abc1234");
    expect(r.stdout).toMatch(/무결성 다이제스트\(SHA-256\): `[0-9a-f]{64}`/);
  }, 60_000);
});

describe("프로세스 성숙도(waiver·직무분리) CLI", () => {
  const AUTH_WAIVER = path.join(os.tmpdir(), `rc-waiver-${process.pid}.yaml`);
  beforeAll(async () => {
    await writeFile(
      AUTH_WAIVER,
      `engagement:
  name: "waiver-cli-test"
  authorized_from: "2000-01-01"
  authorized_until: "2999-12-31"
  authorized_by: "alice (approver)"
  operator: "bob (operator)"
scope:
  allow:
    - host: "127.0.0.1"
limits:
  max_requests_per_second: 100
waivers:
  - match: "/^SQL Injection/"
    reason: "레거시 모듈, 다음 분기 수정 예정"
    approved_by: "alice (CISO)"
    expires: "2999-12-31"
    ticket: "SEC-42"
`,
      "utf8",
    );
  });
  afterAll(async () => rm(AUTH_WAIVER, { force: true }));

  it("승인된 waiver 는 발견을 '수용된 위험'으로 분리하고 판정 high+ 에서 제외한다", async () => {
    const r = await cli(["run", "--full", "--allow-unauth", "--host", "127.0.0.1", "--port", String(vulnPort), "--auth", AUTH_WAIVER]);
    // 수용된 위험 섹션에 SQL Injection 이 승인자와 함께 표기된다(숨김 아님).
    expect(r.stdout).toContain("수용된 위험(Accepted Risk / Waived)");
    expect(r.stdout).toMatch(/SQL Injection[\s\S]*alice \(CISO\)/);
    // waiver 로 유일한 high 를 수용 → 재계산 판정은 high+ 0 건.
    expect(r.stdout + r.stderr).toMatch(/high\+ 0건/);
    expect(r.stdout + r.stderr).toContain("수용된 위험 1건 제외");
    // 직무분리(SoD): 인가자≠운영자 확인 메시지.
    expect(r.stderr).toMatch(/\[직무분리\].*인가자.*운영자/);
  }, 60_000);
});
