/**
 * sqli-extract.test.ts — P0.5: SQLi UNION 기반 실증 추출.
 *
 * 오류기반 탐지 확정 후, UNION SELECT 페이로드(마커+@@version)가 응답에 반영되면
 * "실제 DB 값 추출(검증된 착취)"로 증명된다. 여기서는 MySQL 오류 서버를 흉내낸다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { ToolContext } from "../src/core/types.js";
import { sqliProbe } from "../src/tools/sqli-probe.js";

let server: http.Server | undefined;
let port = 0;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const q = url.searchParams.get("id") ?? "";
    if (q.includes("R3DX9")) {
      // UNION 추출 행이 렌더링되는 취약한 앱: 마커|버전이 그대로 노출된다.
      res.end("result: <td>R3DX9</td><td>8.0.32</td>");
      return;
    }
    if (q.includes("'")) {
      res.statusCode = 500;
      res.end("SQLSTATE[42000]: Syntax error near '1' in mysql query (MySQL server 8.0.32)");
      return;
    }
    res.end("no rows");
  });
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
  port = (server!.address() as AddressInfo).port;
});
afterAll(() => server?.close());

function ctx(): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 200 };
}

describe("sqli_probe — UNION 실증 추출", () => {
  it("오류기반 확정 후 UNION SELECT 로 실제 DB 버전 값을 추출해 실증한다", async () => {
    const r = await sqliProbe.run({ path: "/", param: "id", payloads: ["'"] }, ctx());
    expect(r.ok).toBe(true);
    const d = r.data as any;
    expect(d.title).toMatch(/error-based/);
    expect(d.extracted).toBe("MySQL/MariaDB 8.0.32");
    expect(d.evidence).toContain("UNION 데이터 추출 실증: MySQL/MariaDB 8.0.32 (컬럼 1개)");
  });
});
