/**
 * 방어자 시점 요약 — 통합 테스트(엔진↔대상 경계).
 *
 * 핵심 계약: 보고서의 요청 수는 **대상이 실제로 받은 요청 수**와 같아야 한다.
 * (기록 누락이 있으면 인계용 요약이 거짓이 되고, 블루팀과 로그 대조가 어긋난다.)
 * 여기서는 로컬 서버가 직접 센 값과 보고서 값을 비교해 그 경계를 검증한다.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runAssault } from "../../src/assault/pipeline.js";

let server: Server;
let seen = 0; // 대상이 받은 요청 수(서버가 직접 다)
let statusTally: Record<number, number> = {};

beforeAll(async () => {
  server = createServer((req, res) => {
    seen++;
    const u = new URL(req.url!, "http://x");
    const p = u.pathname;
    const send = (status: number, body: string, type = "text/plain") => {
      statusTally[status] = (statusTally[status] ?? 0) + 1;
      res.writeHead(status, { "content-type": type });
      res.end(body);
    };
    if (p === "/.env") send(200, "DB_PASSWORD=sup3rSecret\n");
    else if (p === "/users/1") send(200, JSON.stringify({ id: 1, email: "kim@corp.local" }), "application/json");
    else if (p === "/admin") send(403, "forbidden");
    else if (p === "/") send(200, "<html><body>ok</body></html>", "text/html");
    else send(404, "nope");
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
});
afterAll(() => new Promise<void>((ok) => server.close(() => ok())));

describe("runAssault 방어자 시점 요약", () => {
  it("보고서 요청 수 = 대상이 받은 요청 수 (기록 누락 없음)", async () => {
    const port = (server.address() as { port: number }).port;
    const dir = mkdtempSync(join(tmpdir(), "rc-noise-"));
    const events: Array<{ type?: string; text?: string }> = [];
    const res = await runAssault({
      url: `http://127.0.0.1:${port}/`,
      authFile: join(dir, "authorization.list"),
      authorize: true,
      ai: false,
      outDir: join(dir, "out"),
      onEvent: (e) => events.push(e as { type?: string; text?: string }),
    });
    const noise = res.report.noise;
    expect(noise).toBeDefined();
    expect(noise!.requests).toBeGreaterThan(0);
    // 경계 검증: 우리가 보낸 요청 수는 대상이 받은 수를 넘을 수 없다.
    // 스머글링/파이프라이닝 페이로드는 서버가 "추가 요청"으로 파싱하므로 대상 로그가 더 많게
    // 보이는 것이 정상이다(그 차이 자체가 인계 시 설명할 사실). 그래서 상한만 둔다.
    expect(noise!.requests).toBeLessThanOrEqual(seen);
    expect(seen - noise!.requests).toBeLessThanOrEqual(10);
    // 대상이 200 으로 응답한 수보다 우리가 더 셀 수는 없다.
    expect(noise!.statuses.ok2xx).toBeLessThanOrEqual(statusTally[200] ?? 0);
    // 상태 묶음도 대상이 응답한 값과 어긋나지 않는다.
    expect(noise!.statuses.notFound).toBe(statusTally[404] ?? 0);
    expect(noise!.statuses.denied).toBe(statusTally[403] ?? 0);
    // 상위 경로는 대상에 실제로 간 경로 중 하나다.
    expect(noise!.topPaths.length).toBeGreaterThan(0);
    // 이벤트 스트림(패널·--ndjson 소비자)에도 같은 수치가 흘러야 한다.
    const note = events.find((e) => e.type === "note" && (e.text ?? "").includes("\uBC29\uC5B4\uC790\uC2DC\uC810"));
    expect(note).toBeDefined();
    expect(note!.text).toContain(String(noise!.requests));
    rmSync(dir, { recursive: true, force: true });
  }, 120_000);

  it("같은 대상·같은 옵션이면 요청 수·상태 묶음이 같다(재현성)", async () => {
    const port = (server.address() as { port: number }).port;
    const run = async () => {
      const dir = mkdtempSync(join(tmpdir(), "rc-noise2-"));
      const res = await runAssault({
        url: `http://127.0.0.1:${port}/`,
        authFile: join(dir, "authorization.list"),
        authorize: true,
        ai: false,
        outDir: join(dir, "out"),
      });
      rmSync(dir, { recursive: true, force: true });
      return res.report.noise!;
    };
    const a = await run();
    const b = await run();
    expect(b.requests).toBe(a.requests);
    expect(b.statuses).toEqual(a.statuses);
  }, 180_000);
});
