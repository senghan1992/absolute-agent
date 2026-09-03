/**
 * 게이트 신뢰성(P0) 회귀 테스트.
 *
 * 게이트(릴리스 관문)로 쓰려면 세 가지가 성립해야 한다:
 *   1) 결정성 — 같은 대상이면 밴딧 상태와 무관하게 항상 같은 커버리지/발견(재현성).
 *   2) 도달 실패 = 통과 아님 — 죽은 대상은 '취약점 없음'이 아니라 inconclusive.
 *   3) 커버리지 정직성 — '발견 0'을 함부로 clean 으로 부르지 않는다(인증 미점검·미실행 시 inconclusive).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { AddressInfo } from "node:net";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { SkillMemory } from "../src/memory/skill-memory.js";
import { ContextualBandit } from "../src/explore/bandit.js";
import { AutoPilot, decideVerdict } from "../src/core/autopilot.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";
import type { Coverage, EngagementFinding } from "../src/core/types.js";

let server: http.Server;
let port: number;

// 취약 서버: /item?id=' 에 SQL 오류를 노출한다(결정적 발견용).
beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/item") {
      const id = url.searchParams.get("id") ?? "";
      res.statusCode = id.includes("'") ? 500 : 200;
      res.end(id.includes("'") ? "You have an error in your SQL syntax near MySQL" : "item");
      return;
    }
    res.setHeader("Server", "nginx/1.18.0");
    res.end("<html>home</html>");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => server.close());

function auth(): AuthorizationFile {
  return {
    engagement: { name: "gate", authorized_from: "2026-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 200 },
  };
}

async function mem(): Promise<SkillMemory> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-gate-"));
  const m = new SkillMemory(dir);
  await m.load();
  return m;
}

/** 무관한 과거 학습을 잔뜩 심어 밴딧 선택을 왜곡시킨다(비결정성 유발 조건 재현). */
function pollutedBandit(): ContextualBandit {
  const b = new ContextualBandit("ucb1", undefined, () => 0.42);
  for (const ctx of ["recon|?/?", "exploit|nginx/?", "enumerate|nginx/?"]) {
    for (const arm of ["http_probe", "sqli_probe", "xss_probe", "crawl", "dir_enum"]) {
      b.update(ctx, arm, 0.9);
    }
  }
  return b;
}

async function runFull(bandit: ContextualBandit): Promise<Awaited<ReturnType<AutoPilot["run"]>>> {
  const ap = new AutoPilot(new ScopeGuard(auth()), await mem(), bandit, new DefaultToolBox(), {
    full: true,
    globalBudget: 200,
    // sqli_probe 를 취약 경로로 유도(툴 간 데이터 흐름 시뮬 — 결정적 발견 보장).
    argsFor: (name) => (name === "sqli_probe" ? { path: "/item", param: "id" } : {}),
  });
  return ap.run({ host: "127.0.0.1", port }, "게이트 전수 스캔");
}

describe("게이트 신뢰성 (P0)", () => {
  it("결정성: 밴딧 상태가 달라도 --full 은 같은 커버리지/발견을 낸다", async () => {
    const a = await runFull(new ContextualBandit("ucb1")); // 백지 상태
    const b = await runFull(pollutedBandit()); // 오염 상태

    // 실행된 툴 수·발견 제목 집합이 동일해야 한다(재현성).
    expect(b.coverage.toolsRun).toBe(a.coverage.toolsRun);
    expect(b.coverage.deterministic).toBe(true);
    const titles = (r: typeof a) => r.findings.map((f) => f.title).sort();
    expect(titles(b)).toEqual(titles(a));
    // 취약 서버이므로 SQLi(high) 를 잡고 판정은 findings.
    expect(a.findings.some((f) => f.severity === "high" && /SQL/i.test(f.title))).toBe(true);
    expect(a.verdict).toBe("findings");
  });

  it("전수 모드는 모든 스캔 단계 툴을 최소 1회씩 실행한다(조기 이탈 없음)", async () => {
    const r = await runFull(new ContextualBandit("ucb1"));
    // recon+enumerate+exploit 툴 전부(post 없음) → toolsRun == toolsTotal.
    expect(r.coverage.toolsRun).toBe(r.coverage.toolsTotal);
    expect(r.coverage.vulnClassesTested.length).toBeGreaterThan(0);
    expect(r.coverage.reachable).toBe(true);
  });

  it("도달 실패(닫힌 포트)는 clean 이 아니라 inconclusive 로 판정한다", async () => {
    // 잠깐 열었다 닫아 '확실히 안 열린' 포트를 얻는다.
    const tmp = http.createServer();
    await new Promise<void>((r) => tmp.listen(0, "127.0.0.1", r));
    const deadPort = (tmp.address() as AddressInfo).port;
    await new Promise<void>((r) => tmp.close(() => r()));

    const ap = new AutoPilot(new ScopeGuard(auth()), await mem(), new ContextualBandit("ucb1"), new DefaultToolBox(), {
      full: true,
      globalBudget: 200,
    });
    const r = await ap.run({ host: "127.0.0.1", port: deadPort }, "죽은 대상");
    expect(r.coverage.reachable).toBe(false);
    expect(r.verdict).toBe("inconclusive");
  }, 30_000);
});

describe("게이트 판정 규칙 (decideVerdict)", () => {
  const base: Coverage = {
    reachable: true,
    toolsRun: 20,
    toolsTotal: 27,
    endpointsDiscovered: 3,
    authScanned: false,
    vulnClassesTested: ["sqli_probe", "xss_probe"],
    requestErrors: 0,
    deterministic: true,
  };
  const noFindings: EngagementFinding[] = [];
  const oneHigh: EngagementFinding[] = [{ phase: "exploit", severity: "high", title: "SQLi", detail: "x" }];

  it("미도달 → inconclusive", () => {
    expect(decideVerdict({ ...base, reachable: false }, noFindings, true).verdict).toBe("inconclusive");
  });
  it("취약점 발견 → findings (미도달보다도 발견이 우선하지 않음: 도달 먼저 확인)", () => {
    expect(decideVerdict(base, oneHigh, true).verdict).toBe("findings");
  });
  it("익스플로잇 미실행 → inconclusive", () => {
    expect(decideVerdict({ ...base, vulnClassesTested: [] }, noFindings, true).verdict).toBe("inconclusive");
  });
  it("인증 미점검 + allowUnauth=false → inconclusive", () => {
    expect(decideVerdict(base, noFindings, false).verdict).toBe("inconclusive");
  });
  it("인증 미점검 + allowUnauth=true → clean", () => {
    expect(decideVerdict(base, noFindings, true).verdict).toBe("clean");
  });
  it("인증 점검함 → clean", () => {
    expect(decideVerdict({ ...base, authScanned: true }, noFindings, false).verdict).toBe("clean");
  });
});
