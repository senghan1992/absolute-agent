/**
 * audit-log — 변조탐지(해시 체인) 감사 추적 회귀 테스트.
 *
 * 검증 포인트: (1) 정상 기록은 verify 통과, (2) 내용 변조/삭제/재정렬은 verify 에서 반드시
 * 드러난다, (3) ScopeGuard 싱크로 모든 scope 판정이 추적에 남는다(봉쇄 증거).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import { readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { AuditLog, verifyAuditFile, GENESIS_HASH } from "../src/audit/audit-log.js";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";

let dir: string;
beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-audit-"));
});
afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

describe("AuditLog: 기록 + 무결성 검증", () => {
  it("engagement·scope·finding 을 남기고 체인이 정상 검증된다", () => {
    const log = AuditLog.open("acme-test", { dir });
    log.scope({ host: "127.0.0.1", port: 8080, intent: "recon", allowed: true, reason: "ok" });
    log.scope({ host: "8.8.8.8", allowed: false, reason: "scope 밖" });
    log.record("finding", { severity: "high", title: "SQLi" });
    log.end({ findings: 1 });

    const r = verifyAuditFile(log.filePath);
    expect(r.ok).toBe(true);
    expect(r.entries).toBe(5); // engagement + 2 scope + finding + end

    // 첫 항목의 prevHash 는 제네시스, seq 는 1부터 증가.
    const lines = readFileSync(log.filePath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines[0].prevHash).toBe(GENESIS_HASH);
    expect(lines[0].kind).toBe("engagement");
    expect(lines.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5]);
    // 각 항목의 prevHash 는 직전 항목의 hash.
    for (let i = 1; i < lines.length; i++) expect(lines[i].prevHash).toBe(lines[i - 1].hash);
  });

  it("닫힌 뒤 기록하면 예외", () => {
    const log = AuditLog.open("x", { dir });
    log.end();
    expect(() => log.record("event", {})).toThrow();
  });

  it("항목 내용 변조는 검증에서 드러난다", () => {
    const log = AuditLog.open("tamper", { dir });
    log.scope({ host: "127.0.0.1", allowed: true, reason: "ok" });
    log.record("finding", { severity: "low", title: "원본" });
    log.end();

    const lines = readFileSync(log.filePath, "utf8").trim().split("\n");
    const e = JSON.parse(lines[2]); // finding
    e.data.title = "조작됨"; // hash 는 그대로 두고 내용만 바꾼다
    lines[2] = JSON.stringify(e);
    writeFileSync(log.filePath, lines.join("\n") + "\n");

    const r = verifyAuditFile(log.filePath);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/해시 불일치|변조/);
    expect(r.brokenAtSeq).toBe(3);
  });

  it("중간 항목 삭제(재정렬)는 검증에서 드러난다", () => {
    const log = AuditLog.open("del", { dir });
    log.scope({ host: "a", allowed: true, reason: "1" });
    log.scope({ host: "b", allowed: true, reason: "2" });
    log.end();

    const lines = readFileSync(log.filePath, "utf8").trim().split("\n");
    lines.splice(2, 1); // 두 번째 scope 삭제
    writeFileSync(log.filePath, lines.join("\n") + "\n");

    const r = verifyAuditFile(log.filePath);
    expect(r.ok).toBe(false);
    // 순번 또는 prevHash 불일치로 탐지.
    expect(r.reason).toMatch(/순번|이전 해시|해시/);
  });

  it("빈/없는 파일 검증", () => {
    expect(verifyAuditFile(path.join(dir, "nope.jsonl")).ok).toBe(false);
  });
});

describe("ScopeGuard 감사 싱크(봉쇄 증거)", () => {
  const auth: AuthorizationFile = {
    engagement: { name: "sink", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "t" },
    scope: { allow: [{ host: "127.0.0.1" }, { domain: "*.ok.local" }] },
    ports: { allow_tcp: [80] },
  };

  it("check/checkResolvedIp 판정이 모두 감사 추적에 남는다", () => {
    const log = AuditLog.open("sink", { dir });
    const g = new ScopeGuard(auth);
    g.setAuditSink(log);

    expect(g.check({ host: "127.0.0.1", port: 80, intent: "recon" }).allowed).toBe(true);
    expect(g.check({ host: "8.8.8.8" }).allowed).toBe(false); // scope 밖
    expect(g.checkResolvedIp("shop.ok.local", "10.0.0.5").allowed).toBe(false); // 내부 IP
    log.end();

    const entries = readFileSync(log.filePath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const scopes = entries.filter((e) => e.kind === "scope");
    const ips = entries.filter((e) => e.kind === "resolved-ip");
    expect(scopes).toHaveLength(2);
    expect(scopes[0]).toMatchObject({ data: { host: "127.0.0.1", allowed: true } });
    expect(scopes[1]).toMatchObject({ data: { host: "8.8.8.8", allowed: false } });
    expect(ips).toHaveLength(1);
    expect(ips[0].data.allowed).toBe(false);
    expect(verifyAuditFile(log.filePath).ok).toBe(true);
  });

  it("싱크가 던져도 판정은 정상 반환된다(감사 실패가 스캔을 막지 않음)", () => {
    const g = new ScopeGuard(auth);
    g.setAuditSink({
      scope() { throw new Error("boom"); },
      resolvedIp() { throw new Error("boom"); },
    });
    expect(g.check({ host: "127.0.0.1", port: 80 }).allowed).toBe(true);
    expect(g.checkResolvedIp("localhost", "127.0.0.1").allowed).toBe(true);
  });
});
