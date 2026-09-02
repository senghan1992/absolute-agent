import { describe, it, expect } from "vitest";
import { RateLimiter, mapLimit } from "../src/net/rate-limiter.js";

describe("RateLimiter", () => {
  it("대략적으로 RPS 를 제한한다", async () => {
    const rps = 20;
    const limiter = new RateLimiter(rps, rps);
    const start = Date.now();
    // burst(20) 소진 후 추가 20건은 최소 ~1초 소요
    for (let i = 0; i < 40; i++) await limiter.acquire();
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(700); // 여유 있게
  });
});

describe("mapLimit", () => {
  it("동시성 상한을 지키고 순서대로 결과를 반환한다", async () => {
    let active = 0;
    let maxActive = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    const out = await mapLimit(items, 4, async (x) => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      return x * 2;
    });
    expect(maxActive).toBeLessThanOrEqual(4);
    expect(out).toEqual(items.map((x) => x * 2));
  });

  it("빈 배열도 안전", async () => {
    expect(await mapLimit([], 4, async () => 1)).toEqual([]);
  });
});
