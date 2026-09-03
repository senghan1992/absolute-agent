/**
 * xss_probe 문맥 인식(context-aware) 회귀 테스트.
 *
 * 반사(reflection) 자체는 XSS 가 아니다 — 반사된 위치가 브라우저에서 실제로
 * "실행 가능한 문맥"일 때만 high 다. 이 구분이 깨지면(예: javascript: 문자열이
 * 본문 텍스트에 반사된 걸 high 로 오탐) 벤치마크 정밀도가 떨어진다.
 *
 *   - 본문 텍스트에 반사 + HTML 이스케이프됨      → high 아님 (실행 불가 / 오탐 방지)
 *   - href 속성값 안에 javascript: 반사           → high     (클릭 시 실행)
 *   - 이스케이프 없이 태그를 여는 반사             → high     (태그 주입)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import type { ToolContext } from "../src/core/types.js";
import { xssProbe } from "../src/tools/xss-probe.js";

function htmlEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const p = url.pathname;
    const q = url.searchParams.get("q") ?? "";
    res.setHeader("content-type", "text/html");

    // 본문 텍스트에 반사하되 HTML 특수문자를 이스케이프한다.
    // → 태그/이벤트 페이로드는 무력화되고, javascript: 문자열만 살아남지만
    //   그건 그냥 텍스트일 뿐이라 실행되지 않는다. high 로 잡으면 오탐.
    if (p === "/text") {
      return void res.end(`<html><body>Results for ${htmlEscape(q)}</body></html>`);
    }
    // href 속성값 안에 반사(이스케이프됨). javascript: 는 특수문자가 없어 살아남고,
    // href 안이므로 클릭 시 실행 가능 → high.
    if (p === "/href") {
      return void res.end(`<html><body><a href="${htmlEscape(q)}">click</a></body></html>`);
    }
    // 이스케이프 없이 그대로 반사 → 태그 주입 실행 가능 → high.
    if (p === "/raw") {
      return void res.end(`<html><body><div>${q}</div></body></html>`);
    }
    // 미이스케이프 반사이나 CSP(unsafe-inline 없이 default-src 'self')로 인라인 실행 차단
    // → 결함은 실재하나 악용 완화 → high 아님(medium).
    if (p === "/raw-csp") {
      res.setHeader("content-security-policy", "default-src 'self'");
      return void res.end(`<html><body><div>${q}</div></body></html>`);
    }
    // 미이스케이프 반사이나 비-HTML 응답 + nosniff → 브라우저가 HTML 로 파싱 안 함 → medium.
    if (p === "/raw-nonhtml") {
      res.setHeader("content-type", "text/plain");
      res.setHeader("x-content-type-options", "nosniff");
      return void res.end(`<div>${q}</div>`);
    }
    res.statusCode = 404;
    res.end("nope");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function ctx(): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 200 };
}

describe("xss_probe 문맥 인식", () => {
  it("이스케이프된 본문 텍스트 반사는 high 로 오탐하지 않는다", async () => {
    const r = await xssProbe.run({ path: "/text", param: "q" }, ctx());
    // 반사는 관측될 수 있으나(low), 실행 불가하므로 절대 high 가 아니다.
    expect((r.data as { severity?: string } | undefined)?.severity).not.toBe("high");
  });

  it("href 속성값 안의 javascript: 반사는 high 로 탐지한다", async () => {
    const r = await xssProbe.run({ path: "/href", param: "q" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as { severity?: string }).severity).toBe("high");
  });

  it("이스케이프 없는 태그 주입 반사는 high 로 탐지한다", async () => {
    const r = await xssProbe.run({ path: "/raw", param: "q" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as { severity?: string }).severity).toBe("high");
  });

  it("CSP(unsafe-inline 없음)로 인라인 실행이 막히면 high 가 아니라 medium 으로 낮춘다", async () => {
    const r = await xssProbe.run({ path: "/raw-csp", param: "q" }, ctx());
    expect(r.ok).toBe(true);
    const d = r.data as { severity?: string; evidence?: string };
    expect(d.severity).toBe("medium");
    expect(d.evidence).toMatch(/완화|CSP/);
  });

  it("비-HTML 응답 + nosniff 로 렌더되지 않으면 high 가 아니라 medium 으로 낮춘다", async () => {
    const r = await xssProbe.run({ path: "/raw-nonhtml", param: "q" }, ctx());
    expect(r.ok).toBe(true);
    const d = r.data as { severity?: string; evidence?: string };
    expect(d.severity).toBe("medium");
    expect(d.evidence).toMatch(/완화|비-HTML/);
  });
});
