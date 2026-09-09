
import { describe, it, expect, afterAll } from "vitest";
import http from "node:http";
import { crawl } from "../src/tools/crawl.js";
import type { ToolContext } from "../src/core/types.js";

let server: http.Server | undefined;
const port = () => (server!.address() as any).port;

describe("crawl (파라미터 없는 링크 표면 발견)", () => {
  it("링크에 쿼리가 없어도 endpoint 로 수집한다 (truthiness 회귀)", async () => {
    server = http.createServer((req, res) => {
      const p = req.url ?? "/";
      if (p === "/") {
        res.end(`<html><body><a href="/search">검색</a><a href="/users/1">u1</a><a href="/admin?x=1">admin</a></body></html>`);
        return;
      }
      res.end("<html><body>ok</body></html>");
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const ctx: ToolContext = { target: { host: "127.0.0.1", port: port(), intent: "recon" }, rps: 200 } as any;
    const res = await crawl.run({}, ctx);
    expect(res.ok).toBe(true);
    const inds = (res.fingerprint?.indicators ?? []) as string[];
    expect(inds).toContain("endpoint /search");
    expect(inds).toContain("endpoint /users/1");
    expect(inds).toContain("endpoint /admin?x=");
  });
});

afterAll(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));
