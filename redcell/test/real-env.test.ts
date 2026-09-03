import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";
import { RealTargetEnv } from "../src/explore/real-env.js";
import { ContextualBandit } from "../src/explore/bandit.js";
import { Explorer } from "../src/explore/explorer.js";

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((_q, r) => {
    r.setHeader("Server", "nginx/1.18.0");
    r.setHeader("X-Powered-By", "PHP/7.4.3");
    r.end("<html>DVWA</html>");
  });
  await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

// 결정적 테스트를 위한 시드 RNG(mulberry32). 프로덕션의 무작위 발산 탐색은
// 그대로 두고, 테스트에서만 밴딧의 미시도 arm 선택 순서를 고정한다.
function seededRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function auth(): AuthorizationFile {
  return {
    engagement: { name: "real", authorized_from: "2026-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 50 },
  };
}

describe("RealTargetEnv + Explorer (동일 엔진으로 실대상 구동)", () => {
  it("인가된 대상을 정찰하면 fingerprint 를 학습한다", async () => {
    const env = new RealTargetEnv(new ScopeGuard(auth()), new DefaultToolBox(), { host: "127.0.0.1", port }, 5);
    const explorer = new Explorer(new ContextualBandit("ucb1", Math.SQRT2, seededRng(1)), { maxSteps: 5 });
    const res = await explorer.runEpisode(env);

    expect(res.steps).toBeGreaterThan(0);
    // 첫 http_probe 에서 nginx/php 사실을 얻어 양의 보상(진전)이 있었어야 함
    expect(res.path.some((p) => p.reward > 0)).toBe(true);
  });

  it("scope 밖 대상은 툴 실행이 차단된다(음의 보상)", async () => {
    const env = new RealTargetEnv(new ScopeGuard(auth()), new DefaultToolBox(), { host: "8.8.8.8", port: 80 }, 3);
    const explorer = new Explorer(new ContextualBandit("ucb1"), { maxSteps: 3 });
    const res = await explorer.runEpisode(env);
    // 모든 스텝이 차단(blocked)되어 진전이 없어야 함
    expect(res.path.every((p) => p.reward <= 0)).toBe(true);
    expect(res.success).toBe(false);
  });
});
