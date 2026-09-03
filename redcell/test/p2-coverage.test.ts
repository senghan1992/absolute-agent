/**
 * P2 커버리지 확장 툴 테스트 — 안전 신호형 신규 + 비파괴 비즈니스로직.
 *
 * 모두 비파괴(읽기 전용 GET/OPTIONS/TRACE 관찰)이며, 취약 대상은 탐지하고
 * 안전 대상은 오탐하지 않는지 확인한다. 각 발견은 피해 반경(impact)도 서술한다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import type { ToolContext } from "../src/core/types.js";
import { methodAudit } from "../src/tools/method-audit.js";
import { hostHeaderAudit } from "../src/tools/host-header-audit.js";
import { accessControlProbe } from "../src/tools/access-control.js";
import { paramPollution } from "../src/tools/param-pollution.js";

// 취약 목 서버(로컬, 인가 가정).
let vuln: http.Server, safe: http.Server;
let vulnPort: number, safePort: number;

function handler(hardened: boolean): http.RequestListener {
  return (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const p = u.pathname;
    if (req.method === "OPTIONS") {
      res.setHeader("Allow", hardened ? "GET, POST, HEAD, OPTIONS" : "GET, POST, PUT, DELETE, TRACE, OPTIONS");
      res.statusCode = hardened ? 204 : 200;
      return res.end();
    }
    if (req.method === "TRACE") {
      if (hardened) {
        res.statusCode = 405;
        return res.end("no");
      }
      res.statusCode = 200;
      return res.end(`TRACE ${req.url}\n` + Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join("\n"));
    }
    if (p === "/reset") {
      const fwd = req.headers["x-forwarded-host"];
      const host = hardened ? "app.example.com" : String(fwd ?? req.headers["host"]);
      res.statusCode = 200;
      return res.end(`<a href="https://${host}/reset/confirm?token=abc">reset</a>`);
    }
    if (p === "/admin") {
      if (hardened) {
        res.statusCode = 403;
        return res.end("Forbidden");
      }
      res.statusCode = 200;
      return res.end(`<h1>Admin Dashboard</h1> User Management <script>{"users":[{"id":1}]}</script>`);
    }
    if (p === "/hpp") {
      const val = hardened ? (u.searchParams.get("q") ?? "") : u.searchParams.getAll("q").join(",");
      res.statusCode = 200;
      return res.end(`Query: ${val}`);
    }
    res.statusCode = 404;
    res.end("nope");
  };
}

beforeAll(async () => {
  vuln = http.createServer(handler(false));
  safe = http.createServer(handler(true));
  await new Promise<void>((r) => vuln.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => safe.listen(0, "127.0.0.1", r));
  vulnPort = (vuln.address() as AddressInfo).port;
  safePort = (safe.address() as AddressInfo).port;
});
afterAll(() => {
  vuln.close();
  safe.close();
});

function ctx(port: number): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 200 };
}
type Data = { severity?: string; impact?: string };

describe("P2 커버리지 확장 툴 (비파괴)", () => {
  it("http_method_audit: TRACE 에코(XST)를 high 로 탐지 + 피해 반경 서술", async () => {
    const r = await methodAudit.run({ path: "/" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
    expect((r.data as Data).impact).toBeTruthy();
  });
  it("http_method_audit: 안전 메서드만 열린 서버는 오탐하지 않는다", async () => {
    const r = await methodAudit.run({ path: "/" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });

  it("host_header_audit: 스푸핑 Host 반영을 high 로 탐지", async () => {
    const r = await hostHeaderAudit.run({ path: "/reset" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
  });
  it("host_header_audit: 고정 정규 호스트 서버는 오탐하지 않는다", async () => {
    const r = await hostHeaderAudit.run({ path: "/reset" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });

  it("access_control_probe: 무인증 관리 패널 노출을 high 로 탐지", async () => {
    const r = await accessControlProbe.run({ path: "/admin" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
  });
  it("access_control_probe: 403 으로 막힌 서버는 오탐하지 않는다", async () => {
    const r = await accessControlProbe.run({ path: "/admin" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });

  it("param_pollution: 중복 파라미터 이중 반영을 medium 으로 탐지", async () => {
    const r = await paramPollution.run({ path: "/hpp", param: "q" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("medium");
  });
  it("param_pollution: 첫 값만 채택하는 서버는 오탐하지 않는다", async () => {
    const r = await paramPollution.run({ path: "/hpp", param: "q" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});
