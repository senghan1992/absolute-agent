import { describe, it, expect } from "vitest";
import { ScopeGuard, ipInCidr, matchDomain, type AuthorizationFile } from "../src/scope/scope-guard.js";

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
