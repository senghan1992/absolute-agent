/**
 * 적대적 오탐(FP) 방지 테스트 — "취약해 보이지만 정상"인 경로를 오탐하지 않는지 확인.
 *
 * P0-3: idor_probe / access_control_probe 재설계 회귀 가드.
 *   - 공개 카탈로그: 인접 id 가 서로 다른 공개 객체를 반환하나 개인정보 없음 → IDOR 아님.
 *   - 로그인 스플래시: 제목이 "Admin Dashboard"지만 로그인 폼이라 막혀 있음 → 접근통제 우회 아님.
 * 동시에 진짜 취약(사적 객체 IDOR / 무인증 특권 데이터)은 여전히 high 로 잡아야 한다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import type { ToolContext } from "../src/core/types.js";
import { idorProbe } from "../src/tools/idor-probe.js";
import { accessControlProbe } from "../src/tools/access-control.js";

let srv: http.Server;
let port: number;

const handler: http.RequestListener = (req, res) => {
  const p = new URL(req.url ?? "/", "http://x").pathname;

  // 공개 카탈로그(정상): 서로 다른 공개 객체, 개인정보 없음.
  const cat = /^\/catalog\/(\d+)$/.exec(p);
  if (cat) {
    res.statusCode = 200;
    return res.end(JSON.stringify({ id: Number(cat[1]), name: `Widget ${cat[1]}`, price: 9.99, category: "tools" }));
  }
  // 사적 주문(취약): 무인증 인접 id 로 타인 객체(owner 포함) 열람.
  const ord = /^\/api\/orders\/(\d+)$/.exec(p);
  if (ord) {
    res.statusCode = 200;
    return res.end(JSON.stringify({ orderId: Number(ord[1]), owner: `user${ord[1]}`, total: Number(ord[1]) * 3 }));
  }
  // 로그인 스플래시(정상): 제목만 관리자, 실제로는 로그인 폼.
  if (p === "/portal") {
    res.statusCode = 200;
    return res.end(
      `<h1>Admin Dashboard</h1><p>Please sign in.</p><form action="/login" method="post"><input name="password" type="password"/></form>`,
    );
  }
  // 진짜 무인증 관리 데이터(취약): 사용자 목록 JSON 노출.
  if (p === "/admin") {
    res.statusCode = 200;
    return res.end(`<h1>Admin</h1><script>{"users":[{"id":1,"role":"admin"}]}</script>`);
  }
  res.statusCode = 404;
  res.end("no");
};

beforeAll(async () => {
  srv = http.createServer(handler);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  port = (srv.address() as AddressInfo).port;
});
afterAll(() => srv.close());

function ctx(): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 200 };
}
type Data = { severity?: string };

describe("적대적 오탐 방지 (P0-3)", () => {
  it("idor_probe: 공개 카탈로그(개인정보 없음)는 오탐하지 않는다", async () => {
    const r = await idorProbe.run({ path: "/catalog/5" }, ctx());
    expect(r.ok).toBe(false);
    expect(r.summary).toMatch(/공개 카탈로그|개인정보 신호 없음/);
  });

  it("idor_probe: 사적 객체(owner 포함)의 무인증 인접 열람은 high 로 잡는다", async () => {
    const r = await idorProbe.run({ path: "/api/orders/1000" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
  });

  it("access_control_probe: 로그인 스플래시(제목만 Admin)는 오탐하지 않는다", async () => {
    const r = await accessControlProbe.run({ path: "/portal" }, ctx());
    expect(r.ok).toBe(false);
  });

  it("access_control_probe: 무인증 관리 데이터(사용자 목록) 노출은 high 로 잡는다", async () => {
    const r = await accessControlProbe.run({ path: "/admin" }, ctx());
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
  });
});
