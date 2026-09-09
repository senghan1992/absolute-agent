/**
 * 다단계 체이닝(credential reuse) 테스트 — P2.
 *   - 환경변수 파싱/자격증명 쌍 추출/로그인 폼 파서(순수 함수)
 *   - 로컬 서버 통합: /.env 노출 → /login 폼 → 자격증명 재사용 로그인 → /admin 보호자원 접근
 *   - 오탐 방지: 틀린 크리덴셜/로그인 없는 사이트에서는 체인을 만들지 않는다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import type { ToolContext } from "../src/core/types.js";
import type { ToolOutcome } from "../src/assault/types.js";
import { parseEnv, credPairsFromEnv, findLoginForms, candidateUrls, runChain } from "../src/assault/chain.js";

let srv: http.Server;
let port: number;

const ADMIN_USER = "admin";
const ADMIN_PASS = "s3cr3t-lab-77";

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => resolve(d));
  });
}

const handler: http.RequestListener = async (req, res) => {
  const u = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
  const p = u.pathname;
  if (p === "/.env") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`${ADMIN_USER.toUpperCase()}_USER=${ADMIN_USER}\n${ADMIN_USER.toUpperCase()}_PASSWORD=${ADMIN_PASS}\nDB_HOST=127.0.0.1\n`);
    return;
  }
  if (p === "/") {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<html><body><a href="/login">로그인</a></body></html>`);
    return;
  }
  if (p === "/login" && req.method === "GET") {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<form action="/login" method="post"><input name="username" type="text"><input name="password" type="password"><button>로그인</button></form>`);
    return;
  }
  if (p === "/login" && req.method === "POST") {
    const body = await readBody(req);
    const params = new URLSearchParams(body);
    if (params.get("username") === ADMIN_USER && params.get("password") === ADMIN_PASS) {
      res.writeHead(302, { location: "/admin", "set-cookie": "session=valid-abc; Path=/" });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<html><body>로그인 실패</body></html>`);
    return;
  }
  if (p === "/admin") {
    const cookie = req.headers.cookie ?? "";
    if (cookie.includes("session=valid-abc")) {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<html><body><h1>관리자 대시보드</h1><p>플래그: FLAG-CHAIN-OK-42</p></body></html>`);
      return;
    }
    res.writeHead(302, { location: "/login" });
    res.end();
    return;
  }
  res.writeHead(404);
  res.end("not found");
};

function ctx(): ToolContext {
  return {
    target: { host: "127.0.0.1", port, intent: "exploit" },
    rps: 60,
    validateIp: () => true,
  } as ToolContext;
}

function outcomeWith(indicators: string[]): ToolOutcome {
  return {
    tool: "test",
    stage: "enumerate",
    ok: true,
    summary: "test",
    durationMs: 1,
    fp: { indicators, tech: [] },
  };
}

describe("chain pure functions", () => {
  it("parseEnv 는 KEY=VALUE 만 추출한다", () => {
    const env = parseEnv("ADMIN_USER=admin\nADMIN_PASSWORD=s3cr3t\n# comment\nDB_HOST=127.0.0.1\nFOO: bar\n");
    expect(env.get("ADMIN_USER")).toBe("admin");
    expect(env.get("ADMIN_PASSWORD")).toBe("s3cr3t");
    expect(env.get("DB_HOST")).toBe("127.0.0.1");
    expect(env.get("FOO")).toBe("bar");
    expect(env.size).toBe(4);
  });

  it("credPairsFromEnv 는 admin user/pass 를 우선 조합한다", () => {
    const env = parseEnv("ADMIN_USER=admin\nADMIN_PASSWORD=secret1\nDB_PASSWORD=secret2\n");
    const pairs = credPairsFromEnv(env, "/.env");
    expect(pairs.length).toBeGreaterThanOrEqual(1);
    expect(pairs[0]).toEqual({ user: "admin", pass: "secret1", via: "/.env" });
  });

  it("findLoginForms 는 패스워드 폼만, user/pass 필드를 찾는다", () => {
    const html = `<form action="/login" method="post"><input name="username" type="text"><input name="password" type="password"></form>`;
    const forms = findLoginForms(html, "http://x/");
    expect(forms.length).toBe(1);
    expect(forms[0].userField).toBe("username");
    expect(forms[0].passField).toBe("password");
    expect(forms[0].url).toBe("http://x/login");
  });

  it("findLoginForms 는 패스워드 없는 폼을 무시한다", () => {
    const html = `<form action="/q"><input name="q" type="text"></form>`;
    expect(findLoginForms(html, "http://x/").length).toBe(0);
  });

  it("candidateUrls 는 시드 + endpoint/exposed 지표를 모은다", () => {
    const urls = candidateUrls([outcomeWith(["endpoint /login", "exposed /.env"])], "http://127.0.0.1:1");
    expect(urls).toContain("http://127.0.0.1:1/");
    expect(urls).toContain("http://127.0.0.1:1/login");
    expect(urls).not.toContain("http://127.0.0.1:1/.env");
  });
});

describe("chain integration (credential reuse)", () => {
  beforeAll(async () => {
    srv = http.createServer(handler);
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    port = (srv.address() as AddressInfo).port;
    srv.unref?.();
  });
  afterAll(() => new Promise<void>((r) => srv.close(() => r())));

  it("노출 .env 자격증명으로 로그인하고 보호자원 접근을 실증한다", async () => {
    const outcomes = [outcomeWith(["endpoint /login", "exposed /.env"])];
    const res = await runChain(ctx(), outcomes, { maxPages: 4, maxPairs: 4 });
    expect(res.attempts).toBeGreaterThan(0);
    expect(res.items.length).toBe(1);
    const item = res.items[0];
    expect(item.verification?.status).toBe("verified");
    expect(item.sample).toContain("관리자 대시보드");
    expect(item.sample).not.toContain(ADMIN_PASS); // redaction
    expect(item.severity).toBe("high");
    expect(res.findings[0].title).toContain("자격증명 재사용");
    expect(res.findings[0].severity).toBe("high");
  });

  it("틀린 비밀 파일(크리덴셜 불일치)은 체인을 만들지 않는다(오탐 방지)", async () => {
    const srv2 = http.createServer((req, res) => {
      const u2 = new URL(req.url ?? "/", `http://127.0.0.1`);
      if (u2.pathname === "/.env") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ADMIN_USER=admin\nADMIN_PASSWORD=wrong-pass-000\n");
        return;
      }
      if (u2.pathname === "/login" && req.method === "POST") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(`<form action="/login" method="post"><input name="username" type="text"><input name="password" type="password"></form>`);
        return;
      }
      if (u2.pathname === "/") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(`<form action="/login" method="post"><input name="username" type="text"><input name="password" type="password"><button>로그인</button></form>`);
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => srv2.listen(0, "127.0.0.1", r));
    const port2 = (srv2.address() as AddressInfo).port;
    const res = await runChain(
      { target: { host: "127.0.0.1", port: port2, intent: "exploit" }, rps: 60, validateIp: () => true } as ToolContext,
      [outcomeWith(["endpoint /login", "exposed /.env"])],
      { maxPages: 4, maxPairs: 4 },
    );
    expect(res.attempts).toBeGreaterThan(0); // POST 거부 경로까지 실제 시도
    expect(res.items.length).toBe(0);
    expect(res.findings.length).toBe(0);
    await new Promise<void>((r) => srv2.close(() => r()));
  });

  it("로그인 폼이 없는 사이트는 시도 자체를 하지 않는다", async () => {
    const outcomes = [outcomeWith(["exposed /.env"])];
    const res = await runChain(ctx(), outcomes, { maxPages: 4, maxPairs: 4 });
    expect(res.attempts).toBe(0);
    expect(res.items.length).toBe(0);
  });
});
