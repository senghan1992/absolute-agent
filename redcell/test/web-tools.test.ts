import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import type { Target } from "../src/scope/scope-guard.js";
import type { ToolContext } from "../src/core/types.js";
import { xssProbe } from "../src/tools/xss-probe.js";
import { pathTraversal } from "../src/tools/path-traversal.js";
import { openRedirect } from "../src/tools/open-redirect.js";
import { ssrfProbe } from "../src/tools/ssrf-probe.js";
import { corsAudit } from "../src/tools/cors-audit.js";
import { secretScan } from "../src/tools/secret-scan.js";
import { graphqlProbe } from "../src/tools/graphql-probe.js";
import { idorProbe } from "../src/tools/idor-probe.js";
import { cookieAudit } from "../src/tools/cookie-audit.js";

// 여러 웹 취약점을 의도적으로 노출하는 목 서버(로컬, 인가 가정).
let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const p = url.pathname;

    // 노출된 비밀 파일.
    if (p === "/.env") {
      res.statusCode = 200;
      res.end("APP_KEY=base64:ZZZ\nDB_PASSWORD=hunter2\n");
      return;
    }
    // GraphQL introspection 노출.
    if (p === "/graphql") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ data: { __schema: { queryType: { name: "Query" }, types: [{ name: "User", kind: "OBJECT" }, { name: "Query", kind: "OBJECT" }] } } }));
      return;
    }
    // IDOR: id 별로 서로 다른 객체를 무인증 반환.
    const idm = /^\/api\/orders\/(\d+)$/.exec(p);
    if (idm) {
      res.statusCode = 200;
      res.end(JSON.stringify({ orderId: Number(idm[1]), owner: `user${idm[1]}`, total: Number(idm[1]) * 3 }));
      return;
    }
    // 오픈 리다이렉트: next 값으로 그대로 30x.
    if (p === "/go") {
      const next = url.searchParams.get("next") ?? "/";
      res.statusCode = 302;
      res.setHeader("location", next);
      res.end();
      return;
    }
    // SSRF: url 파라미터가 메타데이터를 가리키면 그 내용을 대신 반환.
    if (p === "/fetch") {
      const t = url.searchParams.get("url") ?? "";
      if (t.includes("169.254.169.254")) {
        res.end('{"AccessKeyId":"ASIA...","Token":"x","iam/security-credentials":true}');
      } else {
        res.end("nothing");
      }
      return;
    }
    // 경로 조작/LFI: file 파라미터에 traversal 이 있으면 passwd 내용 노출.
    if (p === "/download") {
      const f = decodeURIComponent(url.searchParams.get("file") ?? "");
      if (/passwd/.test(f) && /\.\.|%2e/i.test(url.search)) {
        res.end("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n");
      } else {
        res.end("file not found");
      }
      return;
    }
    // CORS: 요청 Origin 을 그대로 신뢰(+credentials).
    if (p === "/api/me") {
      const origin = req.headers["origin"];
      if (origin) {
        res.setHeader("access-control-allow-origin", String(origin));
        res.setHeader("access-control-allow-credentials", "true");
      }
      res.setHeader("content-type", "application/json");
      res.end('{"user":"me"}');
      return;
    }
    // 기본 "/": 반사형 XSS(q 등 반사) + 플래그 없는 세션 쿠키.
    res.setHeader("Set-Cookie", "SESSIONID=abc123; Path=/");
    const q = url.searchParams.get("q") ?? url.searchParams.get("s") ?? url.searchParams.get("search") ?? "";
    res.setHeader("content-type", "text/html");
    res.end(`<html><body><h1>hi</h1><div>${q}</div></body></html>`);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function ctx(): ToolContext {
  const target: Target = { host: "127.0.0.1", port };
  return { target, rps: 100 };
}

describe("웹/앱 다각 공격 벡터 툴", () => {
  it("xss_probe: 미이스케이프 반사를 high 로 탐지", async () => {
    const r = await xssProbe.run({ path: "/", param: "q" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
  });

  it("path_traversal: /etc/passwd 노출을 high 로 탐지", async () => {
    const r = await pathTraversal.run({ path: "/download", param: "file" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
    expect((r.data as any).evidence).toMatch(/passwd/);
  });

  it("open_redirect: 외부 canary 로 30x 를 medium 으로 탐지", async () => {
    const r = await openRedirect.run({ path: "/go", param: "next" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("medium");
  });

  it("ssrf_probe: 클라우드 메타데이터 반사를 high 로 탐지", async () => {
    const r = await ssrfProbe.run({ path: "/fetch", param: "url" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
  });

  it("ssrf_probe: 단순 입력 반사 엔드포인트는 SSRF 로 오탐하지 않는다", async () => {
    // "/" 는 q 파라미터를 그대로 반사한다. payload URL 에 computeMetadata 같은
    // 메타데이터 시그니처가 들어있어도, 그것이 그저 반사된 것이면 SSRF 가 아니다.
    const r = await ssrfProbe.run({ path: "/", param: "q" }, ctx());
    expect((r.data as any)?.severity).not.toBe("high");
  });

  it("cors_audit: Origin 반사+credentials 를 high 로 탐지", async () => {
    const r = await corsAudit.run({ path: "/api/me" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
  });

  it("secret_scan: 노출된 .env 를 high 로 탐지", async () => {
    const r = await secretScan.run({}, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
    expect((r.data as any).paths).toContain("/.env");
  });

  it("graphql_probe: introspection 노출을 medium 으로 탐지", async () => {
    const r = await graphqlProbe.run({ path: "/graphql" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("medium");
  });

  it("idor_probe: 무인증 인접 id 열람을 high 로 탐지", async () => {
    const r = await idorProbe.run({ path: "/api/orders/1000" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
  });

  it("cookie_audit: 세션 쿠키 플래그 누락을 탐지", async () => {
    const r = await cookieAudit.run({ path: "/" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as any).evidence).toMatch(/HttpOnly/);
  });

  it("안전한 대상에서는 오탐하지 않는다(반사 없음)", async () => {
    // param 반사가 없는 경로(/api/me 는 q 를 반사하지 않음)
    const r = await xssProbe.run({ path: "/api/me", param: "q" }, ctx());
    expect(r.ok).toBe(false);
  });
});
