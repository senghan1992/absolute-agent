/**
 * detection-depth.test.ts — P1 탐지 심화(FN 회피) 변경의 정탐/오탐을 함께 고정한다.
 *
 * 각 개선마다 "잡아야 할 케이스(정탐)"와 "잡으면 안 되는 미끼(FN-트랩)"를 쌍으로 검증한다.
 *   - secret_scan  : .env.production 등 변형 경로를 "내용 시그니처"로만 확정(단순 200 아님)
 *   - cmdi_probe   : 출력이 안 돌아오는 대상에 시간 기반 블라인드로 탐지(균일 지연엔 오탐 금지)
 *   - sqli_probe   : 부울 블라인드에서 절대 최소 차이(≥24B)를 요구(작은 페이지 지터 오탐 금지)
 *
 * 시간 기반 케이스는 실제 지연(3s)을 쓰되 임계(2.5s)와 여유가 커서 비-플래키하다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { ToolContext } from "../src/core/types.js";
import { secretScan } from "../src/tools/secret-scan.js";
import { cmdiProbe } from "../src/tools/cmdi-probe.js";
import { sqliProbe } from "../src/tools/sqli-probe.js";

type Handler = (req: http.IncomingMessage, res: http.ServerResponse, url: URL) => void;

const servers: http.Server[] = [];
async function start(handler: Handler): Promise<number> {
  const server = http.createServer((req, res) => handler(req, res, new URL(req.url ?? "/", "http://x")));
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}
const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
function ctx(port: number): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 200 };
}

afterAll(() => servers.forEach((s) => s.close()));

describe("secret_scan — 내용 시그니처 게이트(변형 .env 경로)", () => {
  let vulnPort: number;
  let decoyPort: number;
  beforeAll(async () => {
    // 정탐: /.env 는 404 지만 /.env.production 이 실제 시크릿을 노출.
    vulnPort = await start((_req, res, url) => {
      if (url.pathname === "/.env.production") return res.end("APP_KEY=base64:zzz\nDB_PASSWORD=hunter2\n");
      res.statusCode = 404;
      res.end("Not Found");
    });
    // FN-트랩: 모든 경로에 200 을 주지만 시크릿 시그니처는 없음(포괄 200 서버).
    decoyPort = await start((_req, res) => res.end("<html><body>ok</body></html>"));
  });

  it("변형 경로(.env.production)의 실제 시크릿을 high 로 잡는다", async () => {
    const r = await secretScan.run({}, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
    expect((r.data as any).paths).toContain("/.env.production");
  });

  it("포괄 200 서버(시그니처 없음)에서는 오탐하지 않는다", async () => {
    const r = await secretScan.run({}, ctx(decoyPort));
    expect(r.ok).toBe(false);
  });
});

describe("cmdi_probe — 시간 기반 블라인드", () => {
  let blindPort: number;
  let slowPort: number;
  beforeAll(async () => {
    // 정탐: 출력은 절대 안 돌려주고(blind), sleep 페이로드에만 3s 지연.
    blindPort = await start(async (_req, res, url) => {
      const v = url.searchParams.get("ip") ?? "";
      if (/sleep\s*\d/i.test(v)) await delay(3000);
      res.end("pong"); // 명령 출력 시그니처 없음
    });
    // FN-트랩: 입력과 무관하게 항상 ~600ms 지연(균일 지연) → 기준 대비 초과분 없음.
    slowPort = await start(async (_req, res) => {
      await delay(600);
      res.end("pong");
    });
  });

  it("출력이 없어도 조건부 지연을 critical(블라인드 RCE)로 잡는다", async () => {
    const r = await cmdiProbe.run({ path: "/", param: "ip" }, ctx(blindPort));
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("critical");
    expect((r.data as any).title).toMatch(/time-based blind/);
  }, 20000);

  it("균일하게 느린 엔드포인트는 오탐하지 않는다(기준 대비 비교)", async () => {
    const r = await cmdiProbe.run({ path: "/", param: "ip" }, ctx(slowPort));
    expect(r.ok).toBe(false);
  }, 20000);
});

describe("sqli_probe — 부울 블라인드 절대 최소 차이(ABS_DIVERGENCE)", () => {
  let tinyPort: number;
  let bigPort: number;
  beforeAll(async () => {
    // FN-트랩: 참/거짓 응답이 상대 10% 는 넘지만 절대 5B 차이(<24B) → 지터로 봐야 함(오탐 금지).
    tinyPort = await start((_req, res, url) => {
      const id = url.searchParams.get("id") ?? "";
      res.end(/'1'='2/.test(id) ? "RESULT: NONE" : "RESULT: FOUND ROW"); // 12B vs 17B
    });
    // 정탐: 참/거짓 응답이 절대·상대 모두 크게 갈림 → 부울 블라인드로 탐지.
    bigPort = await start((_req, res, url) => {
      const id = url.searchParams.get("id") ?? "";
      res.end(/'1'='2/.test(id) ? "none" : `FOUND: ${"row,".repeat(60)}`); // 4B vs ~250B
    });
  });

  it("작은 페이지의 미세 차이(<24B)는 부울 신호로 오탐하지 않는다", async () => {
    const r = await sqliProbe.run({ path: "/", param: "id" }, ctx(tinyPort));
    expect(r.ok).toBe(false);
  });

  it("절대·상대 모두 큰 차이는 부울 블라인드로 high 탐지", async () => {
    const r = await sqliProbe.run({ path: "/", param: "id" }, ctx(bigPort));
    expect(r.ok).toBe(true);
    expect((r.data as any).severity).toBe("high");
    expect((r.data as any).title).toMatch(/boolean-based blind/);
  });
});
