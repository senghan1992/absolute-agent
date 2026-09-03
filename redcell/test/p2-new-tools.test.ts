/**
 * P2 신규 취약점 툴 + 배선/체인/중복억제 회귀 테스트.
 *
 * 대상:
 *   - deserialize_probe  : 클라이언트 제어 위치의 직렬화 blob → 잠재 RCE(high)
 *   - auth_session_probe : 예측 가능한 세션 토큰(high) / 정상 토큰 오탐 없음
 *   - cache_poison_probe : unkeyed 헤더 + 캐시 서빙(2단계) → high(안전 cache-buster)
 *   - logic_probe        : 민감 파라미터 비정상 값 반영 → medium(수동확인)
 *   - target-map 오버라이드(parseTargetMap/indicatorsFromMap/argsFromMap)
 *   - 신규 공격 체인 규칙(deriveChains)
 *   - AutoPilot 중복 실행 억제(동일 툴+인자 재요청 스킵)
 * 모두 비파괴(GET 관찰)이며, 취약 대상은 탐지·안전 대상은 오탐하지 않는지 확인한다.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { AddressInfo } from "node:net";
import type { Tool, ToolBox, ToolContext, ToolResult, EngagementFinding } from "../src/core/types.js";
import { deserializeProbe } from "../src/tools/deserialize-probe.js";
import { authSessionProbe } from "../src/tools/auth-session-probe.js";
import { cachePoisonProbe } from "../src/tools/cache-poison-probe.js";
import { logicProbe } from "../src/tools/logic-probe.js";
import { deriveChains } from "../src/report/chains.js";
import { parseTargetMap, indicatorsFromMap, argsFromMap } from "../src/core/target-map.js";
import { AutoPilot } from "../src/core/autopilot.js";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { SkillMemory } from "../src/memory/skill-memory.js";
import { ContextualBandit } from "../src/explore/bandit.js";

let vuln: http.Server, safe: http.Server;
let vulnPort: number, safePort: number;
let sessionCounter = 1000;
const cache = new Map<string, string>(); // 취약 서버의 공유 캐시 시뮬(키: rc_cb)

function vulnHandler(): http.RequestListener {
  return (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const p = u.pathname;

    // 1) 역직렬화: Set-Cookie 에 Java 직렬화 blob(클라이언트 제어 위치).
    if (p === "/serial") {
      res.setHeader("Set-Cookie", "state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA; path=/");
      res.statusCode = 200;
      return res.end("<html>ok</html>");
    }

    // 2) 세션: 요청마다 순차 증가하는 전부-숫자 짧은 토큰(예측 가능).
    if (p === "/session") {
      res.setHeader("Set-Cookie", `SID=${++sessionCounter}; path=/`);
      res.statusCode = 200;
      return res.end("<html>home</html>");
    }

    // 3) 캐시 포이즈닝: unkeyed x-forwarded-host 반영 + 캐시 가능 + 공유 캐시 서빙.
    if (p === "/cache") {
      const cb = u.searchParams.get("rc_cb") ?? "";
      const fwd = req.headers["x-forwarded-host"];
      res.setHeader("Cache-Control", "public, max-age=60");
      if (fwd) {
        const body = `<a href="https://${String(fwd)}/next">next</a>`;
        cache.set(cb, body); // 오염 응답을 캐시에 저장
        res.statusCode = 200;
        return res.end(body);
      }
      // 헤더 없는 2차 요청: 같은 cache-buster 키의 오염 응답을 캐시에서 서빙.
      const cached = cache.get(cb);
      res.statusCode = 200;
      return res.end(cached ?? `<a href="https://app.example.com/next">next</a>`);
    }

    // 4) 비즈니스 로직: price 파라미터를 검증 없이 그대로 반영.
    if (p === "/buy") {
      const price = u.searchParams.get("price") ?? "100";
      res.statusCode = 200;
      return res.end(`<div>주문: price=${price} total=${price}</div>`);
    }

    res.statusCode = 404;
    res.end("nope");
  };
}

function safeHandler(): http.RequestListener {
  return (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const p = u.pathname;
    if (p === "/serial") {
      res.setHeader("Set-Cookie", "sess=8f14a2b9c0d3e5; path=/; HttpOnly");
      res.statusCode = 200;
      return res.end("<html>ok</html>");
    }
    if (p === "/session") {
      // 정상적인(하지만 짧은) 고엔트로피 세션ID — 외부 벤치의 PHPSESSID 와 동형. 오탐 금지.
      res.setHeader("Set-Cookie", "PHPSESSID=3f8a9b2c1d; path=/; HttpOnly");
      res.statusCode = 200;
      return res.end("<html>home</html>");
    }
    if (p === "/cache") {
      // forwarded 헤더 무시, 고정 정규 호스트만 반영 → 반영/오염 없음.
      res.setHeader("Cache-Control", "public, max-age=60");
      res.statusCode = 200;
      return res.end(`<a href="https://app.example.com/next">next</a>`);
    }
    if (p === "/buy") {
      // 서버측 검증: 비정상 값이면 거부, 정상값은 고정 응답(반영/변화 없음).
      const price = Number(u.searchParams.get("price") ?? "100");
      if (!Number.isFinite(price) || price <= 0) {
        res.statusCode = 200;
        return res.end("<div>invalid price</div>");
      }
      res.statusCode = 200;
      return res.end("<div>주문 확인</div>");
    }
    res.statusCode = 404;
    res.end("nope");
  };
}

beforeAll(async () => {
  vuln = http.createServer(vulnHandler());
  safe = http.createServer(safeHandler());
  await new Promise<void>((r) => vuln.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => safe.listen(0, "127.0.0.1", r));
  vulnPort = (vuln.address() as AddressInfo).port;
  safePort = (safe.address() as AddressInfo).port;
});
afterAll(() => {
  vuln.close();
  safe.close();
});

function ctx(port: number): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 200 };
}
type Data = { severity?: string; impact?: string; title?: string };

describe("deserialize_probe (역직렬화 표면)", () => {
  it("쿠키의 Java 직렬화 blob 을 잠재 RCE(high) 로 탐지", async () => {
    const r = await deserializeProbe.run({ path: "/serial" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
    expect((r.data as Data).title).toMatch(/역직렬화/);
  });
  it("정상 쿠키 서버는 오탐하지 않는다", async () => {
    const r = await deserializeProbe.run({ path: "/serial" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("auth_session_probe (세션 강도)", () => {
  it("순차 증가·전부 숫자 토큰을 high 로 탐지", async () => {
    const r = await authSessionProbe.run({ path: "/session" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
  });
  it("짧은 고엔트로피 세션ID(정상)는 오탐하지 않는다 — 외부 벤치 회귀", async () => {
    const r = await authSessionProbe.run({ path: "/session" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("cache_poison_probe (안전 cache-buster 2단계)", () => {
  it("unkeyed 헤더가 캐시된 응답에 서빙되면 high 로 확정", async () => {
    const r = await cachePoisonProbe.run({ path: "/cache" }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("high");
  });
  it("헤더를 무시하는 서버는 오탐하지 않는다", async () => {
    const r = await cachePoisonProbe.run({ path: "/cache" }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
});

describe("logic_probe (비즈니스 로직 신호)", () => {
  it("민감 파라미터의 비정상 값 반영을 medium 으로 표시", async () => {
    const r = await logicProbe.run({ path: "/buy", params: ["price"] }, ctx(vulnPort));
    expect(r.ok).toBe(true);
    expect((r.data as Data).severity).toBe("medium");
  });
  it("서버가 검증/무시하면 오탐하지 않는다", async () => {
    const r = await logicProbe.run({ path: "/buy", params: ["price"] }, ctx(safePort));
    expect(r.ok).toBe(false);
  });
  it("민감 파라미터가 없으면 대상 없음으로 조용히 넘어간다", async () => {
    const r = await logicProbe.run({ path: "/buy", params: ["color"] }, ctx(vulnPort));
    expect(r.ok).toBe(false);
  });
});

describe("신규 공격 체인 규칙", () => {
  const f = (title: string, severity: EngagementFinding["severity"] = "high"): EngagementFinding =>
    ({ phase: "exploit", severity, title, detail: "", evidence: "" });

  it("RCE(역직렬화/SSTI) + SSRF → 내부망 장악(critical)", () => {
    const chains = deriveChains([f("안전하지 않은 역직렬화 표면 (Java 직렬화)"), f("SSRF 로 내부 서비스 접근")]);
    expect(chains.some((c) => c.severity === "critical" && /내부망/.test(c.title))).toBe(true);
  });
  it("SQLi + 인증/세션 → 인증 우회·자격증명 DB 탈취(critical)", () => {
    const chains = deriveChains([f("SQL 인젝션 (id)"), f("로그인 폼 인증 우회 가능")]);
    expect(chains.some((c) => c.severity === "critical" && /SQL 인젝션/.test(c.title))).toBe(true);
  });
  it("XXE + SSRF → 내부 파일 열람(high)", () => {
    const chains = deriveChains([f("XXE 내부 엔티티 확장"), f("내부 메타데이터 접근(SSRF)")]);
    expect(chains.some((c) => /XXE/.test(c.title))).toBe(true);
  });
  it("오픈 리다이렉트 + OAuth/토큰 → 토큰 탈취(high)", () => {
    const chains = deriveChains([f("오픈 리다이렉트 (return)"), f("OAuth 토큰 엔드포인트 노출")]);
    expect(chains.some((c) => /OAuth\/토큰 탈취/.test(c.title))).toBe(true);
  });
  it("Host 헤더 주입 + 캐시 포이즈닝 → 대규모 확산(high)", () => {
    const chains = deriveChains([f("Host 헤더 주입 반영"), f("웹 캐시 포이즈닝 (/, x-forwarded-host)")]);
    expect(chains.some((c) => /대규모 확산/.test(c.title))).toBe(true);
  });
  it("약한 세션 + IDOR → 계정 탈취(high)", () => {
    const chains = deriveChains([f("약한 세션 토큰 (SID)"), f("IDOR: 타 사용자 객체 접근")]);
    expect(chains.some((c) => /계정 탈취/.test(c.title))).toBe(true);
  });
});

describe("target-map 오버라이드", () => {
  it("paths/params/idPath 를 방어적으로 파싱한다", () => {
    const m = parseTargetMap({ paths: ["/a", "/b", 3], params: ["id"], idPath: "/u/1" });
    expect(m.paths).toEqual(["/a", "/b"]);
    expect(m.params).toEqual(["id"]);
    expect(m.idPath).toBe("/u/1");
  });
  it("빈/무효 맵은 예외를 던진다(fail-closed)", () => {
    expect(() => parseTargetMap({})).toThrow();
    expect(() => parseTargetMap("nope")).toThrow();
  });
  it("맵을 합성 endpoint indicators 로 변환한다", () => {
    const inds = indicatorsFromMap({ paths: ["/search"], params: ["q"] });
    expect(inds).toContain("endpoint /search");
    expect(inds.some((i) => /endpoint \/search\?q=1/.test(i))).toBe(true);
  });
  it("tools[tool] 직접지정이 최우선(합성 표면보다 우선)한다", () => {
    const m = parseTargetMap({ paths: ["/x"], tools: { sqli_probe: { path: "/login", param: "user" } } });
    expect(argsFromMap("sqli_probe", m)).toEqual({ path: "/login", param: "user" });
  });
  it("직접지정이 없으면 합성 표면에서 deriveArgs 로 인자를 만든다", () => {
    const m = parseTargetMap({ paths: ["/search"], params: ["q"] });
    const a = argsFromMap("sqli_probe", m);
    expect(a?.params).toEqual(["q"]);
    expect(Array.isArray(a?.paths)).toBe(true);
  });
});

describe("AutoPilot 중복 실행 억제", () => {
  it("동일 (툴+인자) 재선택 시 네트워크 재요청 없이 캐시 결과를 재사용한다", async () => {
    let runs = 0;
    const counting: Tool = {
      name: "count_probe",
      description: "테스트용 계수 툴",
      intent: "enumerate",
      async run(): Promise<ToolResult> {
        runs++;
        return { ok: false, summary: "obs" };
      },
    };
    const box: ToolBox = { get: (n) => (n === "count_probe" ? counting : undefined), list: () => [counting] };

    const auth: AuthorizationFile = {
      engagement: { name: "t", authorized_from: "2026-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
      scope: { allow: [{ host: "127.0.0.1" }] },
      limits: { max_requests_per_second: 200 },
    };
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-dedup-"));
    const memory = new SkillMemory(dir);
    await memory.load();
    const auto = new AutoPilot(new ScopeGuard(auth), memory, new ContextualBandit("ucb1"), box, {
      maxStepsPerPhase: 8,
      globalBudget: 20,
      argsFor: () => ({ path: "/fixed" }), // 항상 같은 인자 → 첫 실행 후 전부 중복
    });
    const rep = await auto.run({ host: "127.0.0.1", port: vulnPort }, "중복 억제 확인");

    // 밴딧이 같은 툴을 여러 번 골라도 실제 run 은 1회만 수행된다.
    expect(runs).toBe(1);
    expect(rep.transcript.some((l) => /중복스킵/.test(l))).toBe(true);
  });
});
