/**
 * 신규 3종 공격 표면 툴(HTTP Request Smuggling·웹 캐시 기만·JWT 위조 실증) 테스트.
 *
 * 듀얼 서버 패턴(test/new-hacker-tools.test.ts 컨벤션):
 *   - 취약 서버: 각 취약점을 실제로 시뮬레이션 — 툴이 실증(verified)을 내는지.
 *   - 안전/견고 서버: 동일 경로가 정상 동작 — 오탐이 없는지.
 * smuggle 의 취약 서버는 raw TCP 로 CL-우선 파서를 직접 구현한다(Node http 서버는
 * RFC 준수라 모호 프레이밍을 400 으로 거부 — 그 자체가 "견고" 대조군이 된다).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import net from "node:net";
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { ToolContext, ToolResult } from "../src/core/types.js";
import { smuggleProbe } from "../src/tools/smuggle-probe.js";
import { cacheDeceptionProbe } from "../src/tools/cache-deception-probe.js";
import { jwtAttack } from "../src/tools/jwt-attack.js";
import { verifyExposure } from "../src/assault/verify.js";
import { collectEvidence } from "../src/assault/evidence.js";
import type { ToolOutcome } from "../src/assault/types.js";

type Data = { severity?: string; evidence?: string; title?: string };
const ctx = (port: number, extra: Partial<ToolContext> = {}): ToolContext => ({
  target: { host: "127.0.0.1", port },
  rps: 500,
  ...extra,
});

const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
const hs256 = (hp: string, secret: string): string => createHmac("sha256", secret).update(hp).digest("base64url");

// ── 1) smuggle: CL-우선(raw) 취약 서버 ────────────────────────────────────────

interface ParsedReq {
  complete: boolean;
  consume: number;
  path?: string;
}

/** 취약 파서: CL 이 있으면 TE 를 무시하고 CL 을 따른다. 중복 CL 은 가장 큰 값을 고른다. */
function tryParse(buf: string): ParsedReq {
  const end = buf.indexOf("\r\n\r\n");
  if (end < 0) return { complete: false, consume: 0 };
  const head = buf.slice(0, end);
  const cls = [...head.matchAll(/content-length:\s*(\d+)/gi)].map((m) => Number(m[1]));
  const hasTe = /transfer-encoding:/i.test(head);
  if (cls.length === 0 && !hasTe) return { complete: true, consume: end + 4, path: head.split("\r\n")[0].split(" ")[1] };
  if (cls.length === 0) return { complete: false, consume: 0 }; // TE-전용(테스트 범위 밖) — 대기
  const cl = Math.max(...cls); // 불일치 파서 시뮬레이션: 가장 큰 값 선택
  const total = end + 4 + cl;
  if (buf.length < total) return { complete: false, consume: 0 };
  return { complete: true, consume: total, path: head.split("\r\n")[0].split(" ")[1] };
}

let smugVuln: net.Server, smugSafe: http.Server;
let smugVulnPort: number, smugSafePort: number;

beforeAll(async () => {
  smugVuln = net.createServer((sock) => {
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      for (;;) {
        const r = tryParse(buf);
        if (!r.complete) break;
        buf = buf.slice(r.consume);
        const body = `ok path=${r.path}`;
        sock.write(`HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
        sock.end(); // 테스트는 1연결 1요청
        return;
      }
    });
    sock.on("error", () => {});
  });
  await new Promise<void>((r) => smugVuln.listen(0, "127.0.0.1", r));
  smugVulnPort = (smugVuln.address() as AddressInfo).port;

  smugSafe = http.createServer((_req, res) => {
    res.setHeader("content-type", "text/plain");
    res.end("ok");
  });
  await new Promise<void>((r) => smugSafe.listen(0, "127.0.0.1", r));
  smugSafePort = (smugSafe.address() as AddressInfo).port;
});

afterAll(() => {
  smugVuln.close();
  smugSafe.close();
});

describe("smuggle_probe", () => {
  it("CL-우선 파서 서버: 프레이밍 모호성 스톨 → 실증(high)", async () => {
    const r: ToolResult = await smuggleProbe.run({ path: "/" }, ctx(smugVulnPort));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("high");
    expect(d.evidence).toContain("스머글링 실증");
  }, 30000);

  it("RFC 준수 서버(Node): 모호 프레이밍 일관 거부 → high/medium 오탐 없음", async () => {
    const r = await smuggleProbe.run({ path: "/" }, ctx(smugSafePort));
    const d = (r.data ?? {}) as Data;
    const sev = d.severity ?? "none";
    expect(["none", "low"]).toContain(sev); // low = 관찰(수용)까지, high/medium 이면 오탐
  }, 30000);
});

// ── 2) cache_deception: 접미사 경로 캐시 시뮬레이션 ───────────────────────────

const VICTIM_PAGE = `<html><body><h1>마이페이지</h1><p>안녕하세요 victim@example.com 님</p></body></html>`;
const SESSION = "sid=abc123victim";
const LOGIN_REDIRECT = `<html><body>redirecting to login</body></html>`;

function deceptionHandler(mode: "vuln" | "safe"): http.RequestListener {
  return (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const p = u.pathname;
    const authed = (req.headers.cookie ?? "").includes(SESSION);
    const send = (code: number, body: string, headers: Record<string, string> = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.statusCode = code;
      res.end(body);
    };
    if (p === "/profile") {
      if (!authed) return send(302, LOGIN_REDIRECT, { Location: "/login" });
      return send(200, VICTIM_PAGE, { "Cache-Control": "no-store" });
    }
    // 정적 확장자 접미사 경로(/profile/*.css|js)
    if (/^\/profile\/[^/]+\.(css|js)$/.test(p)) {
      if (mode === "vuln") {
        // 취약: 서버가 접미사를 무시하고 개인 페이지를 주고, 캐시는 이를 공개 캐시에 저장
        // (무인증 요청도 캐시된 개인 본문을 그대로 받는 것으로 시뮬레이션).
        return send(200, VICTIM_PAGE, { "Cache-Control": "public, max-age=60", "X-Cache": authed ? "MISS" : "HIT" });
      }
      // 견고: 캐시 규칙이 개인 페이지를 저장하지 않는다 — 무인증 요청은 캐시 없이 거부.
      if (!authed) return send(302, LOGIN_REDIRECT, { Location: "/login" });
      return send(200, VICTIM_PAGE, { "Cache-Control": "private, no-store" });
    }
    return send(404, "nf");
  };
}

let cdVuln: http.Server, cdSafe: http.Server;
let cdVulnPort: number, cdSafePort: number;

beforeAll(async () => {
  cdVuln = http.createServer(deceptionHandler("vuln"));
  await new Promise<void>((r) => cdVuln.listen(0, "127.0.0.1", r));
  cdVulnPort = (cdVuln.address() as AddressInfo).port;
  cdSafe = http.createServer(deceptionHandler("safe"));
  await new Promise<void>((r) => cdSafe.listen(0, "127.0.0.1", r));
  cdSafePort = (cdSafe.address() as AddressInfo).port;
});

afterAll(() => {
  cdVuln.close();
  cdSafe.close();
});

describe("cache_deception_probe", () => {
  it("접미사 경로 캐시 + 무인증 개인 본문 반환 → 실증(high)", async () => {
    const r: ToolResult = await cacheDeceptionProbe.run({ path: "/profile" }, ctx(cdVulnPort, { jar: { store: new Map([[`http://127.0.0.1:${cdVulnPort}`, new Map([["sid", "abc123victim"]])]]) } }));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("high");
    expect(d.evidence).toContain("캐시 기만 실증");
  });

  it("캐시 규칙이 개인 페이지를 저장하지 않으면 미탐", async () => {
    const r = await cacheDeceptionProbe.run({ path: "/profile" }, ctx(cdSafePort, { jar: { store: new Map([[`http://127.0.0.1:${cdSafePort}`, new Map([["sid", "abc123victim"]])]]) } }));
    expect(r.ok).toBe(false);
  });

  it("인증 세션 없으면 스킵(판별 불가)", async () => {
    const r = await cacheDeceptionProbe.run({ path: "/profile" }, ctx(cdVulnPort));
    expect(r.ok).toBe(false);
    expect(r.summary).toContain("인증 세션 없음");
  });
});

// ── 3) jwt_attack: 약한 시크릿 + alg=none 수용 ────────────────────────────────

const WEAK = "secret";
const STRONG = "9f2c7a1e5d3b8a064f7c2e9b1d4a8f3c6e5b7d2a9f4c1e8b3d6a2f5c8e1b4d7a";

function jwtFor(user: string, role: string, secret: string): string {
  const hp = `${b64u({ typ: "JWT", alg: "HS256" })}.${b64u({ user, role, iat: 1700000000, exp: 1900000000 })}`;
  return `${hp}.${hs256(hp, secret)}`;
}

function jwtHandler(mode: "vuln" | "hardened"): http.RequestListener {
  const secret = mode === "vuln" ? WEAK : STRONG;
  return (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const send = (code: number, body: string, headers: Record<string, string> = {}) => {
      for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
      res.statusCode = code;
      res.end(body);
    };
    const bearer = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
    if (u.pathname === "/api/me") {
      const payload = verifyJwt(bearer, mode);
      if (!payload) return send(401, `{"error":"unauthorized signature invalid"}`);
      return send(200, `{"user":"${payload.user}","role":"${payload.role}"}`);
    }
    if (u.pathname === "/login") {
      const tok = jwtFor("admin", "user", secret);
      return send(200, `{"token":"${tok}"}`, {});
    }
    return send(404, "nf");
  };
}

/** 취약 서버는 alg=none 을 수용(서명 검증 생략), 견고 서버는 라이브러리 검증 모사. */
function verifyJwt(tok: string, mode: "vuln" | "hardened"): { user: string; role: string } | null {
  const parts = tok.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as { alg?: string };
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as { user: string; role: string };
    if (header.alg === "none") {
      if (mode === "vuln") return payload; // 서명 검증 생략(취약)
      return null;
    }
    const expected = hs256(`${parts[0]}.${parts[1]}`, mode === "vuln" ? WEAK : STRONG);
    if (expected === parts[2]) return payload;
    return null;
  } catch {
    return null;
  }
}

let jwtVuln: http.Server, jwtSafe: http.Server;
let jwtVulnPort: number, jwtSafePort: number;

beforeAll(async () => {
  jwtVuln = http.createServer(jwtHandler("vuln"));
  await new Promise<void>((r) => jwtVuln.listen(0, "127.0.0.1", r));
  jwtVulnPort = (jwtVuln.address() as AddressInfo).port;
  jwtSafe = http.createServer(jwtHandler("hardened"));
  await new Promise<void>((r) => jwtSafe.listen(0, "127.0.0.1", r));
  jwtSafePort = (jwtSafe.address() as AddressInfo).port;
});

afterAll(() => {
  jwtVuln.close();
  jwtSafe.close();
});

describe("jwt_attack", () => {
  it("약한 시크릿 role=admin 재서명 토큰 수용 → 실증(critical, 특권 신호)", async () => {
    const tok = jwtFor("admin", "user", WEAK);
    const r: ToolResult = await jwtAttack.run({ path: "/api/me" }, ctx(jwtVulnPort, { auth: { authorization: `Bearer ${tok}` } }));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("critical");
    expect(d.evidence).toContain("JWT 실증");
    expect(d.evidence).toContain("특권 신호");
  }, 20000);

  it("원본이 alg=none 토큰인 서버(서명 검증 생략 파서)도 실증", async () => {
    // alg=none 원본 토큰을 관찰 상황으로 심는다 — 취약 서버는 none 을 수용하므로 B=200,
    // 위조(none 변형)도 수용 → critical. 서명 검증 생략 파서가 잡히는지 확인.
    const noneTok = `${b64u({ typ: "JWT", alg: "none" })}.${b64u({ user: "admin", role: "user", iat: 1700000000, exp: 1900000000 })}.`;
    const r: ToolResult = await jwtAttack.run({ path: "/api/me" }, ctx(jwtVulnPort, { auth: { authorization: `Bearer ${noneTok}` } }));
    expect(r.ok).toBe(true);
    const d = r.data as Data;
    expect(d.severity).toBe("critical");
  }, 20000);

  it("견고 서버(강한 시크릿·none 거부)는 미탐", async () => {
    const tok = jwtFor("admin", "user", STRONG);
    const r = await jwtAttack.run({ path: "/api/me" }, ctx(jwtSafePort, { auth: { authorization: `Bearer ${tok}` } }));
    expect(r.ok).toBe(false);
  }, 20000);

  it("토큰이 관찰되지 않으면 시도 없음", async () => {
    const r = await jwtAttack.run({ path: "/api/me" }, ctx(jwtVulnPort));
    expect(r.ok).toBe(false);
    expect(r.summary).toContain("찾지 못함");
  });
});

// ── 4) 검증 엔진·증거 수집 통합 ────────────────────────────────────────────────

describe("신규 3종 실증 마커 — 검증 엔진 통합", () => {
  it("smuggle 증거 → verified", () => {
    const v = verifyExposure("exploit", "스머글링 실증: 프레이밍 모호성으로 백엔드 대기 관측 — CL.TE 충돌 스톨. baseline 5ms 정상.");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("Request Smuggling 실증");
  });

  it("cache deception 증거 → verified", () => {
    const v = verifyExposure("exploit", "캐시 기만 실증: 무인증 요청에 개인 본문 반환 — 보호 경로 /profile(무세션=차단) vs 접미사 /profile/rc.css");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("캐시 기만 실증");
  });

  it("jwt 위조 증거 → verified", () => {
    const v = verifyExposure("exploit", "JWT 실증: 위조 토큰(alg=none(서명 제거))이 유효 세션으로 수용 — 무토큰 HTTP 401 / 원본 HTTP 200 / 위조 HTTP 200");
    expect(v.status).toBe("verified");
    expect(v.proof).toContain("JWT 위조 실증");
  });

  it("collectEvidence — 3종 툴 결과가 exploit 증거로 수집되고 검증 배지 부착", async () => {
    const outcomes: ToolOutcome[] = [
      {
        tool: "smuggle_probe", stage: "exploit", ok: true, summary: "s", durationMs: 1,
        finding: { severity: "high", title: "HTTP Request Smuggling (/)" },
        data: { severity: "high", title: "HTTP Request Smuggling (/)", evidence: "스머글링 실증: 프레이밍 모호성으로 백엔드 대기 관측 — CL.TE 충돌 스톨" },
      },
      {
        tool: "cache_deception_probe", stage: "exploit", ok: true, summary: "s", durationMs: 1,
        finding: { severity: "high", title: "웹 캐시 기만 (/profile/rc.css)" },
        data: { severity: "high", title: "웹 캐시 기만 (/profile/rc.css)", evidence: "캐시 기만 실증: 무인증 요청에 개인 본문 반환 — /profile vs /profile/rc.css" },
      },
      {
        tool: "jwt_attack", stage: "exploit", ok: true, summary: "s", durationMs: 1,
        finding: { severity: "critical", title: "JWT 위조 실증 (/api/me)" },
        data: { severity: "critical", title: "JWT 위조 실증 (/api/me)", evidence: "JWT 실증: 위조 토큰(약한 시크릿 재서명(role=admin))이 유효 세션으로 수용 — HTTP 200" },
      },
    ];
    const { items } = await collectEvidence(outcomes, ctx(1), { cap: 1500, maxItems: 10 });
    const cats = items.map((i) => i.category);
    expect(cats).toContain("exploit");
    const exploitItems = items.filter((i) => i.category === "exploit");
    expect(exploitItems.length).toBeGreaterThanOrEqual(3);
    for (const it of exploitItems) {
      expect(it.verification?.status).toBe("verified");
    }
  });
});
