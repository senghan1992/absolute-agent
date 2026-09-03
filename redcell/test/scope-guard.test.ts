import { describe, it, expect } from "vitest";
import { ScopeGuard, ipInCidr, matchDomain, isInternalIp, type AuthorizationFile } from "../src/scope/scope-guard.js";

const auth: AuthorizationFile = {
  engagement: {
    name: "test",
    authorized_from: "2026-01-01",
    authorized_until: "2999-12-31",
    authorized_by: "test",
  },
  scope: {
    allow: [{ host: "127.0.0.1" }, { host: "localhost" }, { cidr: "10.13.37.0/24" }, { domain: "*.vulnlab.local" }],
    deny: [{ host: "10.13.37.1" }],
  },
  ports: { allow_tcp: [80, 443, 8080] },
  limits: { disallow_destructive: true, disallow_dos: true },
};

describe("ScopeGuard", () => {
  const g = new ScopeGuard(auth);

  it("allows an in-scope host", () => {
    expect(g.check({ host: "127.0.0.1", port: 8080 }).allowed).toBe(true);
  });

  it("allows a host inside an allowed CIDR", () => {
    expect(g.check({ host: "10.13.37.50" }).allowed).toBe(true);
  });

  it("denies a host outside scope", () => {
    const d = g.check({ host: "8.8.8.8" });
    expect(d.allowed).toBe(false);
  });

  it("deny beats allow (gateway excluded)", () => {
    expect(g.check({ host: "10.13.37.1" }).allowed).toBe(false);
  });

  it("blocks destructive intent even in scope", () => {
    expect(g.check({ host: "127.0.0.1", intent: "destructive" }).allowed).toBe(false);
  });

  it("blocks dos intent even in scope", () => {
    expect(g.check({ host: "127.0.0.1", intent: "dos" }).allowed).toBe(false);
  });

  it("blocks a disallowed port", () => {
    expect(g.check({ host: "127.0.0.1", port: 9999 }).allowed).toBe(false);
  });

  it("matches wildcard domains", () => {
    expect(g.check({ host: "shop.vulnlab.local" }).allowed).toBe(true);
    expect(g.check({ host: "vulnlab.local.evil.com" }).allowed).toBe(false);
  });

  it("rejects outside the authorization window", () => {
    const expired = new ScopeGuard({ ...auth, engagement: { ...auth.engagement, authorized_until: "2020-01-01" } });
    expect(expired.check({ host: "127.0.0.1" }).allowed).toBe(false);
  });
});

describe("checkResolvedIp — 연결 시점 IP 검증(내부IP·rebinding·측면이동 차단)", () => {
  it("인가된 호스트명이 클라우드 메타데이터/링크로컬 IP 로 해석되면 차단한다", () => {
    const g = new ScopeGuard(auth);
    const d = g.checkResolvedIp("shop.vulnlab.local", "169.254.169.254");
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/측면이동|내부|rebinding|SSRF/);
  });

  it("인가된 호스트명이 RFC1918 사설 IP 로 해석되면 차단한다", () => {
    const g = new ScopeGuard(auth);
    expect(g.checkResolvedIp("shop.vulnlab.local", "10.0.0.5").allowed).toBe(false);
    expect(g.checkResolvedIp("shop.vulnlab.local", "192.168.1.9").allowed).toBe(false);
  });

  it("scope.allow 에 명시된 CIDR 안의 IP 로 해석되면 허용한다(명시 인가)", () => {
    const g = new ScopeGuard(auth);
    // 10.13.37.0/24 는 명시 인가된 CIDR → 사설대역이라도 명시적 허용이므로 통과.
    expect(g.checkResolvedIp("host.vulnlab.local", "10.13.37.50").allowed).toBe(true);
  });

  it("루프백(127.0.0.1)으로 해석되는 이름은 허용한다(로컬 테스트 흔함)", () => {
    const g = new ScopeGuard(auth);
    expect(g.checkResolvedIp("localhost", "127.0.0.1").allowed).toBe(true);
  });

  it("공인 IP 로 해석되면 허용한다(인가된 이름의 정상 외부 대상)", () => {
    const g = new ScopeGuard(auth);
    expect(g.checkResolvedIp("shop.vulnlab.local", "93.184.216.34").allowed).toBe(true);
  });

  it("같은 호스트명이 다른 IP 로 재해석되면(rebinding) 차단한다", () => {
    const g = new ScopeGuard(auth);
    expect(g.checkResolvedIp("shop.vulnlab.local", "93.184.216.34").allowed).toBe(true); // 최초 pin
    const d = g.checkResolvedIp("shop.vulnlab.local", "93.184.216.35"); // 이후 다른 IP
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/rebinding/);
  });

  it("deny 목록의 IP 로 해석되면 차단한다", () => {
    const g = new ScopeGuard(auth);
    expect(g.checkResolvedIp("host.vulnlab.local", "10.13.37.1").allowed).toBe(false);
  });

  it("disallow_lateral_beyond_scope=false 면 내부 IP 해석을 허용한다(opt-out)", () => {
    const g = new ScopeGuard({ ...auth, limits: { ...auth.limits, disallow_lateral_beyond_scope: false } });
    expect(g.checkResolvedIp("shop.vulnlab.local", "10.0.0.5").allowed).toBe(true);
  });
});

describe("isInternalIp", () => {
  it("내부/사설/링크로컬 대역을 식별한다", () => {
    for (const ip of ["169.254.169.254", "10.1.2.3", "172.16.0.1", "192.168.0.1", "100.64.0.1", "fe80::1", "fd00::1", "::"]) {
      expect(isInternalIp(ip)).toBe(true);
    }
  });
  it("루프백과 공인 IP 는 내부로 보지 않는다", () => {
    for (const ip of ["127.0.0.1", "::1", "8.8.8.8", "93.184.216.34"]) {
      expect(isInternalIp(ip)).toBe(false);
    }
  });
});

describe("cidr / domain helpers", () => {
  it("ipInCidr", () => {
    expect(ipInCidr("10.13.37.5", "10.13.37.0/24")).toBe(true);
    expect(ipInCidr("10.13.38.5", "10.13.37.0/24")).toBe(false);
    expect(ipInCidr("192.168.1.1", "0.0.0.0/0")).toBe(true);
  });
  it("matchDomain", () => {
    expect(matchDomain("*.a.local", "x.a.local")).toBe(true);
    expect(matchDomain("*.a.local", "a.local")).toBe(false);
    expect(matchDomain("a.local", "a.local")).toBe(true);
  });
});
