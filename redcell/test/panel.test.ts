/**
 * LivePanel — 로컬 데스크톱 패널(HTTP + SSE) 회귀 테스트.
 *
 * OrchestratorEvent 스트림을 127.0.0.1 에 서빙하고 브로드캐스트한다:
 *   GET /        : 셀프컨테인드 HTML 패널(외부 CDN 없음 — 오프라인 동작)
 *   GET /events  : SSE — meta + 히스토리 재생 + 이후 push 브로드캐스트
 */

import { describe, it, expect } from "vitest";
import http from "node:http";
import { LivePanel } from "../src/panel/panel.js";

function sseChunk(port: number, until: (acc: string) => boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:${port}/events`, (res) => {
      let acc = "";
      res.on("data", (c) => {
        acc += c.toString();
        if (until(acc)) {
          req.destroy();
          resolve(acc);
        }
      });
      res.on("error", reject);
    });
    req.on("error", reject);
  });
}

describe("LivePanel", () => {
  it("HTML 패널을 서빙하고 SSE 로 meta+히스토리+push 를 브로드캐스트한다", async () => {
    const panel = await LivePanel.start({ title: "test-panel" }, 0);
    expect(panel.port).toBeGreaterThan(0);

    const page = await (await fetch(`http://127.0.0.1:${panel.port}/`)).text();
    expect(page).toContain("REDCELL");
    expect(page).toContain("/events"); // SSE 엔드포인트 연결 코드
    expect(page).not.toMatch(/https?:\/\/\S+cdn/); // 외부 CDN 금지(오프라인)

    const first = sseChunk(panel.port, (acc) => acc.includes("meta") && acc.includes("phase"));
    panel.push({ type: "phase", text: "recon 시작", phase: "recon" as const });
    const body = await first;
    expect(body).toContain('"type":"meta"');
    expect(body).toContain("test-panel");
    expect(body).toContain('"type":"phase"');

    // 히스토리 재생: 새 구독자는 이미 push 된 이벤트를 받는다.
    const second = sseChunk(panel.port, (acc) => acc.includes("reward"));
    panel.push({ type: "reward", text: "+0.05", step: 1, value: 0.05 });
    const body2 = await second;
    expect(body2).toContain('"type":"reward"');
    expect(body2).toContain("+0.05");

    await panel.close();
  });

  it("클라이언트 연결 없이도 push 는 누락 없이 히스토리에 쌓인다", async () => {
    const panel = await LivePanel.start({}, 0);
    for (let i = 0; i < 3; i++) panel.push({ type: "note", text: `n${i}` });
    const body = await sseChunk(panel.port, (acc) => acc.split("data: ").length >= 5); // meta + 3건
    expect(body).toContain("n0");
    expect(body).toContain("n2");
    await panel.close();
  });
});
