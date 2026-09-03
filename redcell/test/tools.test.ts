import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { dirEnum } from "../src/tools/dir-enum.js";
import { headerAudit } from "../src/tools/header-audit.js";
import { sqliProbe } from "../src/tools/sqli-probe.js";
import type { ToolContext } from "../src/core/types.js";

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    // 민감 경로 열거 대상
    if (["/admin", "/robots.txt", "/login"].includes(url.pathname)) {
      res.statusCode = 200;
      res.end("ok");
      return;
    }
    // SQLi 시뮬: id 파라미터에 작은따옴표가 있으면 DB 오류 노출
    if (url.pathname === "/item") {
      const id = url.searchParams.get("id") ?? "";
      if (id.includes("'")) {
        res.statusCode = 500;
        res.end("You have an error in your SQL syntax; check the manual for MySQL");
      } else {
        res.statusCode = 200;
        res.end("item 1");
      }
      return;
    }
    res.statusCode = 404;
    res.end("nf");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function ctx(): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 100 };
}

describe("dir_enum", () => {
  it("민감 경로(/admin)를 발견하고 medium 발견으로 보고", async () => {
    const res = await dirEnum.run({}, ctx());
    expect(res.ok).toBe(true);
    expect(res.fingerprint?.indicators?.some((i) => i.includes("/admin"))).toBe(true);
    expect((res.data as any)?.severity).toBe("medium");
  });
});

describe("dir_enum — 접근통제된 민감 경로는 노출로 오탐하지 않는다", () => {
  let s2: http.Server;
  let p2: number;
  beforeAll(async () => {
    s2 = http.createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      // /admin 은 존재하나 403 으로 차단(=노출 아님), /login 은 302 리다이렉트.
      if (u.pathname === "/admin") { res.statusCode = 403; res.end("forbidden"); return; }
      if (u.pathname === "/login") { res.statusCode = 302; res.setHeader("location", "/"); res.end(); return; }
      res.statusCode = 404; res.end("nf");
    });
    await new Promise<void>((r) => s2.listen(0, "127.0.0.1", r));
    p2 = (s2.address() as AddressInfo).port;
  });
  afterAll(() => s2.close());

  it("403/302 민감 경로는 info(접근통제됨)로 강등하고 medium 노출로 보고하지 않는다", async () => {
    const res = await dirEnum.run({}, { target: { host: "127.0.0.1", port: p2 }, rps: 100 });
    expect(res.ok).toBe(true);
    expect((res.data as any)?.severity).toBe("info");
    expect((res.data as any)?.title).toMatch(/접근통제됨/);
    expect((res.data as any)?.title).not.toMatch(/노출/);
  });
});

describe("header_audit", () => {
  it("보안 헤더 누락을 발견으로 보고", async () => {
    const res = await headerAudit.run({}, ctx());
    expect(res.ok).toBe(true);
    expect((res.data as any)?.title).toMatch(/보안 헤더 누락/);
  });
});

describe("sqli_probe", () => {
  it("오류 기반 SQLi 신호를 탐지(추출 없음)", async () => {
    const res = await sqliProbe.run({ path: "/item", param: "id" }, ctx());
    expect(res.ok).toBe(true);
    expect((res.data as any)?.severity).toBe("high");
    expect((res.data as any)?.title).toMatch(/SQL Injection/);
  });
  it("취약하지 않으면 탐지하지 않음", async () => {
    const res = await sqliProbe.run({ path: "/safe", param: "q" }, ctx());
    expect(res.ok).toBe(false);
  });
});
