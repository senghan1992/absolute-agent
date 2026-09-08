/**
 * assault e2e — 로컬 취약 서버 대상 전체 파이프라인(진입→증거→보고서) 테스트.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runAssault } from "../../src/assault/pipeline.js";

let server: Server;
beforeAll(async () => {
  server = createServer((req, res) => {
    const u = new URL(req.url!, "http://x");
    const p = u.pathname;
    if (p === "/.env") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("DB_PASSWORD=sup3rSecret\nAPI_KEY=sk-live-abcdef1234567890\n");
    } else if (p === "/users/1" || p === "/users/2") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: Number(p.slice(-1)), email: "kim@corp.local", ssn: "900101-1234567" }));
    } else if (p === "/search" && u.searchParams.has("q")) {
      const q = u.searchParams.get("q")!;
      if (q.includes("'")) {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("SQLSTATE syntax error near '' OR 1=1--'' at line 1 (SELECT * FROM users WHERE name='" + q.replace(/['\\]/g, "") + "')");
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("[{\"name\":\"kim\"}]");
      }
    } else if (p === "/graphql" && req.method === "POST") {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ data: { __schema: { queryType: { name: "Query" }, types: [{ name: "User", kind: "OBJECT" }] } } }));
      });
    } else if (p === "/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body><a href='/users/1'>account</a></body></html>");
    } else {
      res.writeHead(404); res.end("nope");
    }
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
});
afterAll(() => new Promise<void>((ok) => server.close(() => ok())));

describe("runAssault e2e", () => {
  it("로컬 취약 서버: 자동 진입→발견→증거→보고서, exitCode 0", async () => {
    const port = (server.address() as { port: number }).port;
    const dir = mkdtempSync(join(tmpdir(), "rc-e2e-"));
    const authFile = join(dir, "authorization.list");

    const res = await runAssault({
      url: `http://127.0.0.1:${port}/`,
      authFile,
      authorize: true,
      ai: false,
      outDir: join(dir, "out"),
    });

    expect(res.exitCode).toBe(0);
    expect(res.reportDir).not.toBe("");
    expect(existsSync(join(res.reportDir, "report.md"))).toBe(true);
    expect(existsSync(join(res.reportDir, "report.html"))).toBe(true);
    expect(existsSync(join(res.reportDir, "report.json"))).toBe(true);

    const r = res.report;
    expect(r.findings.length).toBeGreaterThanOrEqual(3); // secret, sql, idor 등
    expect(r.exposed.length).toBeGreaterThanOrEqual(2);

    // 기본 redaction — 원본 시크릿이 보고서에 남지 않는다.
    const md = readFileSync(join(res.reportDir, "report.md"), "utf8");
    expect(md).not.toContain("sup3rSecret");
    // 매니페스트 존재
    expect(md).toContain("ev01");

    rmSync(dir, { recursive: true, force: true });
  }, 120_000);

  it("미인가 호스트는 exitCode 3 으로 차단한다", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rc-e2e-b-"));
    const authFile = join(dir, "authorization.list");
    writeFileSync(authFile, "# RedCell 인가 목록\n198.51.100.1\n"); // 다른 호스트만 인가
    const res = await runAssault({ url: "http://203.0.113.7/", authFile, authorize: false, ai: false });
    expect(res.exitCode).toBe(3);
    rmSync(dir, { recursive: true, force: true });
  }, 30_000);

  it("미도달 대상은 exitCode 4", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rc-e2e-c-"));
    const authFile = join(dir, "authorization.list");
    // authorize 후 닫힌 포트 → 도달 불가
    const port = (server.address() as { port: number }).port;
    const tmp = createServer(() => {});
    await new Promise<void>((ok) => tmp.listen(0, "127.0.0.1", ok));
    const openPort = (tmp.address() as { port: number }).port;
    await new Promise<void>((ok) => tmp.close(() => ok()));
    const res = await runAssault({ url: `http://127.0.0.1:${openPort}/`, authFile, authorize: true, ai: false });
    expect(res.exitCode).toBe(4);
    rmSync(dir, { recursive: true, force: true });
  }, 30_000);
});
