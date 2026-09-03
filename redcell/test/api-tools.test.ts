import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { apiDiscover } from "../src/tools/api-discover.js";
import { apiProbe } from "../src/tools/api-probe.js";
import type { ToolContext } from "../src/core/types.js";

let server: http.Server;
let port: number;

// 공모전 페이지를 흉내내는 미니 앱: 프런트가 backend API 를 호출하고,
// 일부 엔드포인트는 인증 없이 데이터/민감정보를 노출한다.
beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const json = (code: number, body: unknown) => {
      res.statusCode = code;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    };
    switch (url.pathname) {
      case "/":
        res.statusCode = 200;
        res.setHeader("content-type", "text/html");
        res.end(`<html><head><script src="/assets/app.js"></script></head>
          <body>제출 목록 <a href="/api/teams">teams</a></body></html>`);
        return;
      case "/assets/app.js":
        res.statusCode = 200;
        res.setHeader("content-type", "application/javascript");
        res.end(`const a = fetch("/api/submissions"); axios.get("/api/evaluations/summary");
          const admin = "/api/admin/users";`);
        return;
      case "/openapi.json":
        return json(200, { openapi: "3.0.0", paths: { "/api/submissions": {}, "/api/scores": {} } });
      case "/api/submissions":
        return json(200, [
          { id: 1, team: "alpha", title: "AI 헬스케어", score: 88 },
          { id: 2, team: "beta", title: "핀테크 봇", score: 91 },
        ]);
      case "/api/admin/users":
        return json(200, [{ id: 1, email: "u@x.com", password: "hunter2" }]);
      case "/api/private":
        res.statusCode = 401;
        res.end("unauthorized");
        return;
      default:
        res.statusCode = 404;
        res.end("nf");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function ctx(): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 100 };
}

describe("api_discover", () => {
  it("페이지·JS·openapi 에서 backend API 엔드포인트를 발견", async () => {
    const res = await apiDiscover.run({ path: "/" }, ctx());
    expect(res.ok).toBe(true);
    const data = res.data as any;
    const eps: string[] = data.endpoints;
    // JS 번들에서 참조된 경로
    expect(eps).toContain("/api/submissions");
    expect(eps.some((e) => e.startsWith("/api/evaluations"))).toBe(true);
    // openapi.json 노출 → medium + 문서 내 경로 흡수
    expect(data.severity).toBe("medium");
    expect(eps).toContain("/api/scores");
  });
});

describe("api_discover — GraphQL 노출 판정은 introspection 성공 여부로 구분한다", () => {
  it("introspection 이 꺼진 /graphql(400/errors)은 명세 노출(medium)로 보고하지 않는다", async () => {
    let s: http.Server;
    const off = http.createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      if (u.pathname === "/graphql") {
        res.statusCode = 400;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ errors: [{ message: "introspection is disabled" }] }));
        return;
      }
      res.statusCode = 404; res.end("nf");
    });
    s = off;
    await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
    const p = (s.address() as AddressInfo).port;
    const res = await apiDiscover.run({ path: "/" }, { target: { host: "127.0.0.1", port: p }, rps: 100 });
    const data = res.data as any;
    // 엔드포인트 존재는 잡되(descriptor), 명세 "노출"로 승격(medium)하지 않는다.
    expect(data?.severity).not.toBe("medium");
    expect(data?.title ?? "").not.toMatch(/API 명세 노출/);
    s.close();
  });

  it("introspection 이 실제로 응답하는 /graphql(200 + __schema)은 명세 노출(medium)로 보고한다", async () => {
    const on = http.createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      if (u.pathname === "/graphql") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ data: { __schema: { queryType: { name: "Query" }, types: [{ name: "User" }] } } }));
        return;
      }
      res.statusCode = 404; res.end("nf");
    });
    await new Promise<void>((r) => on.listen(0, "127.0.0.1", r));
    const p = (on.address() as AddressInfo).port;
    const res = await apiDiscover.run({ path: "/" }, { target: { host: "127.0.0.1", port: p }, rps: 100 });
    const data = res.data as any;
    expect(data?.severity).toBe("medium");
    expect(data?.title).toMatch(/API 명세 노출/);
    on.close();
  });
});

describe("api_probe", () => {
  it("인증 없는 데이터 노출을 medium 으로 보고하고 레코드 수/필드를 요약", async () => {
    const res = await apiProbe.run({ path: "/api/submissions" }, ctx());
    expect(res.ok).toBe(true);
    const data = res.data as any;
    expect(data.severity).toBe("medium");
    expect(data.probes[0].count).toBe(2);
    expect(data.probes[0].fields).toEqual(expect.arrayContaining(["team", "score"]));
  });

  it("인증 없는 민감정보(email/password) 노출을 high 로 승급", async () => {
    const res = await apiProbe.run({ paths: ["/api/admin/users"] }, ctx());
    const data = res.data as any;
    expect(data.severity).toBe("high");
    expect(data.probes[0].sensitive).toEqual(expect.arrayContaining(["email", "password"]));
  });

  it("보호된 엔드포인트(401)는 노출로 보고하지 않음", async () => {
    const res = await apiProbe.run({ path: "/api/private" }, ctx());
    const data = res.data as any;
    expect(data.severity).toBe("info");
    expect(data.probes[0].authRequired).toBe(true);
  });
});
