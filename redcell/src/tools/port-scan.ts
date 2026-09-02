/**
 * port_scan — 동시 TCP connect 스캔. 성능형 정찰 툴.
 *
 * 흔한 포트 집합을 병렬로 connect 시도해 열린 포트를 찾는다.
 * ctx.rps 를 RateLimiter 로 준수하고, 동시성으로 처리량을 낸다(비파괴 connect only).
 */

import net from "node:net";
import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { RateLimiter, mapLimit } from "../net/rate-limiter.js";

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 11211, 27017,
];

const PORT_HINTS: Record<number, string> = {
  22: "ssh", 21: "ftp", 25: "smtp", 53: "dns", 80: "http", 443: "https", 3306: "mysql", 5432: "postgres", 6379: "redis", 3389: "rdp", 445: "smb", 27017: "mongodb", 9200: "elasticsearch", 8080: "http-alt", 8443: "https-alt", 11211: "memcached",
};

function checkPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(port, host);
  });
}

export const portScan: Tool = {
  name: "port_scan",
  description: "흔한 TCP 포트를 동시 스캔해 열린 서비스를 찾는다(connect only, RPS 준수).",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const ports = Array.isArray(args.ports) ? (args.ports as number[]) : COMMON_PORTS;
    const concurrency = typeof args.concurrency === "number" ? args.concurrency : 16;
    const timeoutMs = typeof args.timeoutMs === "number" ? args.timeoutMs : 1200;
    const limiter = new RateLimiter(ctx.rps, Math.max(ctx.rps, concurrency));

    const open: number[] = [];
    await mapLimit(ports, concurrency, async (port) => {
      await limiter.acquire();
      if (await checkPort(ctx.target.host, port, timeoutMs)) open.push(port);
    });
    open.sort((a, b) => a - b);

    const services = open.map((p) => `${p}${PORT_HINTS[p] ? "/" + PORT_HINTS[p] : ""}`);
    const tech = open.map((p) => PORT_HINTS[p]).filter(Boolean) as string[];

    return {
      ok: open.length > 0,
      summary: `포트 스캔 완료: 열린 포트 ${open.length}개 [${services.join(", ") || "none"}]`,
      fingerprint: open.length ? { tech, indicators: services.map((s) => `open ${s}`) } : undefined,
      data: open.length
        ? {
            severity: "info",
            title: `열린 포트 ${open.length}개`,
            evidence: services.join(", "),
          }
        : undefined,
    };
  },
};
