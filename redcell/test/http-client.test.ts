/**
 * http-client — 연결 시점 IP 검증/핀(pinning) 회귀 테스트.
 *
 * 호스트명(비-IP)으로 요청할 때, 실제 해석된 IP 를 validateIp 로 검증한 뒤 그 IP 로
 * 직접 연결해야 한다(TOCTOU/DNS rebinding 제거). validateIp 가 거부하면 연결하지 않고
 * 오류를 던진다. 외부 네트워크 없이 loopback(localhost)로만 검증한다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { promises as dnsp } from "node:dns";
import { httpRequest } from "../src/net/http-client.js";

let server: http.Server;
let port: number;
let loop: string; // localhost 가 실제 해석되는 loopback 주소(127.0.0.1 또는 ::1)

beforeAll(async () => {
  loop = (await dnsp.lookup("localhost", { all: true }))[0].address;
  server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.end("ok-from-localhost");
  });
  await new Promise<void>((r) => server.listen(0, loop, r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

describe("연결 시점 IP 검증/핀", () => {
  it("validateIp 가 해석된 IP 를 허용하면 그 IP 로 pinned 연결해 정상 응답한다", async () => {
    const res = await httpRequest(`http://localhost:${port}/`, {
      validateIp: (_h, ip) => ip === loop,
      retries: 0,
    });
    expect(res.status).toBe(200);
    expect(res.body).toMatch(/ok-from-localhost/);
  });

  it("validateIp 가 해석된 IP 를 거부하면 연결하지 않고 오류를 던진다(내부IP/rebinding 차단)", async () => {
    await expect(
      httpRequest(`http://localhost:${port}/`, { validateIp: () => false, retries: 0 }),
    ).rejects.toThrow(/인가되지 않았|rebinding|내부 IP/);
  });

  it("IP 리터럴 대상은 해석 없이 그대로 연결한다(validateIp 있어도 DNS 안 함)", async () => {
    // 127.0.0.1 로 직접 요청 — net.isIP 가 true 라 lookup/validateIp 경유하지 않는다.
    if (loop !== "127.0.0.1") return; // IPv4 loopback 이 아닐 때만 스킵
    const res = await httpRequest(`http://127.0.0.1:${port}/`, { validateIp: () => false, retries: 0 });
    expect(res.status).toBe(200);
  });
});
