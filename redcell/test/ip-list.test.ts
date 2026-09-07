/**
 * 간단 IP 목록 인가(ip-list) 테스트 — "내가 입력한 IP = 인가" 방식.
 *
 * 1) 파서: 형식(주석/deny/지시자), 잘못된 입력 fail-closed
 * 2) ScopeGuard 통합: allow/deny/포트/기간/파괴액션 기본 차단
 * 3) loadAuthorization 자동 감지: YAML(정식) vs IP 목록
 * 4) CLI e2e: auth add/rm/list + scope 로 전체 체인
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, rm, mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { parseIpList, buildAuthFromIpList, classifyTarget } from "../src/scope/ip-list.js";
import { loadAuthorization } from "../src/scope/load-auth.js";
import { ScopeGuard } from "../src/scope/scope-guard.js";
import { redcellHome } from "../src/config.js";

const run = promisify(execFile);
const CLI = path.resolve(__dirname, "../src/cli.ts");

// ── 파서 ─────────────────────────────────────────────────────────────────
describe("parseIpList", () => {
  it("주석·빈 줄을 무시하고 허용/제외/CIDR/도메인을 파싱한다", () => {
    const p = parseIpList(`
# 주석
127.0.0.1
10.13.37.0/24

*.vulnlab.local
!10.13.37.1
`);
    expect(p.entries).toEqual([
      { kind: "allow", raw: "127.0.0.1", type: "host" },
      { kind: "allow", raw: "10.13.37.0/24", type: "cidr" },
      { kind: "allow", raw: "*.vulnlab.local", type: "domain" },
      { kind: "deny", raw: "10.13.37.1", type: "host" },
    ]);
    expect(p.until).toBeUndefined();
    expect(p.ports).toBeUndefined();
  });

  it("until/ports 지시자를 파싱한다", () => {
    const p = parseIpList("127.0.0.1\nuntil: 2027-12-31\nports: 80, 443, 8080\n");
    expect(p.until).toBe("2027-12-31");
    expect(p.ports).toEqual([80, 443, 8080]);
  });

  it("IPv6·호스트명(localhost 등)도 허용한다", () => {
    expect(classifyTarget("::1").type).toBe("host");
    expect(classifyTarget("localhost").type).toBe("host");
    expect(classifyTarget("example.com").type).toBe("host"); // 정확 일치
    expect(classifyTarget("*.example.com").type).toBe("domain");
  });

  it("잘못된 대상은 예외(fail-closed)", () => {
    expect(() => parseIpList("127.0.0.1\nnot an ip!")).toThrow();
    expect(() => parseIpList("10.0.0.0/99")).toThrow(); // CIDR 비트 오버
    expect(() => parseIpList("256.1.1.1")).toThrow(); // 잘못된 IP
    expect(() => parseIpList("ports: notports\n1.2.3.4")).toThrow();
    expect(() => parseIpList("until: next-year\n1.2.3.4")).toThrow();
  });

  it("허용 대상이 하나도 없으면 예외(fail-closed)", () => {
    expect(() => parseIpList("!1.2.3.4")).toThrow(/허용 대상이 하나도 없/);
    expect(() => parseIpList("# 주석만\n")).toThrow();
  });
});

// ── AuthorizationFile 변환 + ScopeGuard 통합 ─────────────────────────────
describe("buildAuthFromIpList + ScopeGuard", () => {
  const NOW = new Date("2026-09-07T00:00:00Z");

  it("기본 인가 기간은 실행 시점 +365일, until 지시자가 없으면 기본값", () => {
    const a = buildAuthFromIpList("127.0.0.1", { now: NOW });
    expect(a.engagement.authorized_from).toBe("2026-09-07");
    expect(a.engagement.authorized_until).toBe("2027-09-07");
    expect(a.scope.allow).toEqual([{ host: "127.0.0.1" }]);
  });

  it("until 지시자가 있으면 그 날짜를 쓴다", () => {
    const a = buildAuthFromIpList("127.0.0.1\nuntil: 2027-01-01", { now: NOW });
    expect(a.engagement.authorized_until).toBe("2027-01-01");
  });

  it("ports 지시자는 ports.allow_tcp 로, 없으면 포트 제한 없음", () => {
    expect(buildAuthFromIpList("127.0.0.1\nports: 80,8080").ports).toEqual({ allow_tcp: [80, 8080] });
    expect(buildAuthFromIpList("127.0.0.1").ports).toBeUndefined();
  });

  it("ScopeGuard: 허용 IP 통과·비허용 차단·deny 가 allow 를 이김", () => {
    const g = new ScopeGuard(
      buildAuthFromIpList("127.0.0.1\n10.13.37.0/24\n*.vulnlab.local\n!10.13.37.99", { now: NOW }),
    );
    expect(g.check({ host: "127.0.0.1" }).allowed).toBe(true);
    expect(g.check({ host: "10.13.37.5" }).allowed).toBe(true);
    expect(g.check({ host: "app.vulnlab.local" }).allowed).toBe(true);
    expect(g.check({ host: "8.8.8.8" }).allowed).toBe(false); // scope 밖
    expect(g.check({ host: "10.13.37.99" }).allowed).toBe(false); // deny 최우선
  });

  it("포트 제한·파괴/DoS 기본 차단·기간 만료 차단·RPS 기본값 유지", () => {
    const g = new ScopeGuard(buildAuthFromIpList("127.0.0.1\nports: 8080", { now: NOW }));
    expect(g.check({ host: "127.0.0.1", port: 8080 }).allowed).toBe(true);
    expect(g.check({ host: "127.0.0.1", port: 22 }).allowed).toBe(false); // 포트 제한
    expect(g.check({ host: "127.0.0.1", intent: "destructive" }).allowed).toBe(false);
    expect(g.check({ host: "127.0.0.1", intent: "dos" }).allowed).toBe(false);
    expect(g.requestsPerSecond).toBe(10); // limits 없음 = 기본 RPS
    // 인가 기간 만료
    const expired = new ScopeGuard(buildAuthFromIpList("127.0.0.1\nuntil: 2000-01-01", { now: NOW }));
    expect(expired.check({ host: "127.0.0.1" }).allowed).toBe(false);
  });

  it("내부대역 측면이동 차단 유지 (명시 CIDR 허용 시 통과)", () => {
    const g = new ScopeGuard(buildAuthFromIpList("vuln.local", { now: NOW }));
    // 호스트명이 사설 IP 로 해석 → 차단
    expect(g.checkResolvedIp("vuln.local", "10.0.0.5").allowed).toBe(false);
    // CIDR 이 명시 허용된 경우 통과
    const g2 = new ScopeGuard(buildAuthFromIpList("vuln.local\n10.0.0.0/8", { now: NOW }));
    expect(g2.checkResolvedIp("vuln.local", "10.0.0.5").allowed).toBe(true);
  });
});

// ── loadAuthorization 자동 감지 ──────────────────────────────────────────
describe("loadAuthorization 자동 감지", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "rc-auth-"));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("정식 YAML은 yaml 으로, IP 목록은 ip-list 로 감지한다", async () => {
    const yamlPath = path.join(dir, "auth.yaml");
    await writeFile(
      yamlPath,
      `engagement:\n  name: t\n  authorized_from: "2000-01-01"\n  authorized_until: "2999-12-31"\n  authorized_by: test\nscope:\n  allow:\n    - host: "127.0.0.1"\n`,
      "utf8",
    );
    const y = await loadAuthorization(yamlPath);
    expect(y.kind).toBe("yaml");
    expect(y.summary.allows).toBe(1);
    expect(y.guard.check({ host: "127.0.0.1" }).allowed).toBe(true);

    const listPath = path.join(dir, "auth.list");
    await writeFile(listPath, "127.0.0.1\n!10.13.37.1\n", "utf8");
    const l = await loadAuthorization(listPath);
    expect(l.kind).toBe("ip-list");
    expect(l.summary.denies).toBe(1);
    expect(l.guard.check({ host: "127.0.0.1" }).allowed).toBe(true);
    expect(l.guard.check({ host: "10.13.37.1" }).allowed).toBe(false);
  });

  it("파일 없음·허용 없음은 예외(fail-closed)", async () => {
    await expect(loadAuthorization(path.join(dir, "none.list"))).rejects.toThrow(/찾을 수 없/);
    await writeFile(path.join(dir, "empty.list"), "!1.2.3.4\n", "utf8");
    await expect(loadAuthorization(path.join(dir, "empty.list"))).rejects.toThrow();
  });
});

// ── CLI e2e: auth add/rm/list + scope ────────────────────────────────────
describe("redcell auth CLI (e2e)", () => {
  let home: string;
  let authFile: string;
  let env: Record<string, string>;
  beforeAll(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "rc-home-"));
    authFile = path.join(home, "authorization.list");
    env = { ...process.env, REDCELL_HOME: home };
  });
  afterAll(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("auth add → 기본 파일(~/.redcell/authorization.list)에 기록되고 scope 로 인지된다", async () => {
    await run("npx", ["tsx", CLI, "auth", "add", "127.0.0.1"], { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 });
    await run("npx", ["tsx", CLI, "auth", "add", "10.13.37.0/24"], { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 });
    await run("npx", ["tsx", CLI, "auth", "add", "10.13.37.99", "--deny"], { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 });

    const content = await readFile(authFile, "utf8");
    expect(content).toContain("127.0.0.1");
    expect(content).toContain("10.13.37.0/24");
    expect(content).toContain("!10.13.37.99");

    // scope 명령이 기본 경로로 이 파일을 감지
    const sc = await run("npx", ["tsx", CLI, "scope"], { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 });
    expect(sc.stdout).toContain("간단 IP 목록");
    expect(sc.stdout).toContain("127.0.0.1");
    expect(sc.stdout).toContain("!10.13.37.99");
    expect(sc.stdout).toContain("허용 (2)");
  }, 120_000);

  it("auth rm → 목록에서 제거", async () => {
    await run("npx", ["tsx", CLI, "auth", "rm", "10.13.37.0/24"], { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 });
    const content = await readFile(authFile, "utf8");
    expect(content).not.toContain("10.13.37.0/24");
  }, 120_000);

  it("중복 add 는 무시된다", async () => {
    const before = await readFile(authFile, "utf8");
    await run("npx", ["tsx", CLI, "auth", "add", "127.0.0.1"], { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 });
    expect(await readFile(authFile, "utf8")).toBe(before);
  }, 120_000);

  it("잘못된 대상은 add 에서 즉시 실패한다", async () => {
    await expect(
      run("npx", ["tsx", CLI, "auth", "add", "999.1.1.1"], { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 }),
    ).rejects.toThrow(/인식할 수 없는 대상|잘못된 IP/);
  }, 120_000);

  it("ip-list 로 run --dry-run 이 동작하고, scope 밖 대상은 차단된다", async () => {
    // 허용된 로컬 대상: dry-run 으로 실행 가능(감사는 임시 홈에 남음)
    const ok = await run(
      "npx", ["tsx", CLI, "run", "--host", "127.0.0.1", "--port", "1", "--goal", "t", "--provider", "mock", "--dry-run"],
      { cwd: path.resolve(__dirname, ".."), env, timeout: 120_000 },
    );
    expect(ok.stdout + ok.stderr).toContain("간단 IP 목록");
  }, 120_000);
});