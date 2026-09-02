import { describe, it, expect, beforeAll, afterAll } from "vitest";
import net from "node:net";
import { AddressInfo } from "node:net";
import { portScan } from "../src/tools/port-scan.js";
import type { ToolContext } from "../src/core/types.js";

let server: net.Server;
let openPort: number;

beforeAll(async () => {
  server = net.createServer((s) => s.end());
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  openPort = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

describe("port_scan", () => {
  it("열린 포트를 찾고 닫힌 포트는 제외한다", async () => {
    // 닫힌 포트 후보(사용 안 할 높은 포트) + 열린 포트
    const closed = openPort + 1;
    const ctx: ToolContext = { target: { host: "127.0.0.1" }, rps: 200 };
    const res = await portScan.run({ ports: [openPort, closed], concurrency: 8, timeoutMs: 800 }, ctx);
    expect(res.ok).toBe(true);
    expect(res.fingerprint?.indicators?.some((i) => i.includes(String(openPort)))).toBe(true);
    expect(res.summary).toContain("1개");
  });

  it("모두 닫혀 있으면 ok=false", async () => {
    const ctx: ToolContext = { target: { host: "127.0.0.1" }, rps: 200 };
    const res = await portScan.run({ ports: [openPort + 2, openPort + 3], timeoutMs: 500 }, ctx);
    expect(res.ok).toBe(false);
  });
});
