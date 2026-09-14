/**
 * harden 모듈 테스트 — 출시 전 사전 진단 + 강화 게이트.
 *
 * 1) describeSystem: 텍스트 → 구성 요소/포트/플래그 결정적 파싱(오프라인)
 * 2) parseProfileFile: JSON 프로필 파일 파싱
 * 3) assessProfile: 38규칙 평가 (redis → H-01 critical 등)
 * 4) runHarden 오프라인: 게이트 판정 + 종료코드(PASS=0/FAIL=1/PASS_WITH_RISKS=0) + 파일 생성
 * 5) runHarden live: 인가 밖 차단(3) / 도달 불가(4) / 로컬 서버 정상(0)
 * 6) 리포트 렌더러: markdown/html/json 산출
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describeSystem, parseProfileFile, hasComponent, portHeld, hasFlag } from "../src/harden/profile.js";
import { assessProfile } from "../src/harden/knowledge.js";
import { runHarden } from "../src/harden/pipeline.js";
import { toMarkdown, toHtml, toJson } from "../src/harden/report.js";
import { HARDEN_RULES } from "../src/harden/knowledge.js";

// ── describeSystem ────────────────────────────────────────────────────────
describe("describeSystem — 텍스트 → 프로필 결정적 파싱", () => {
  it("redis + 6379 포트 → redis 구성요소·포트 추출", () => {
    const p = describeSystem("내부 redis 서버가 6379 포트로 동작", "cache");
    expect(p.name).toBe("cache");
    expect(hasComponent(p, "redis")).toBe(true);
    expect(portHeld(p, 6379)).toBe(true);
    expect(p.raw).toContain("redis");
  });

  it("구성요소 기본 포트를 추론하고 명시 포트가 우선", () => {
    const p = describeSystem("nginx 리버스 프록시 + postgres");
    expect(hasComponent(p, "nginx")).toBe(true);
    expect(hasComponent(p, "postgresql")).toBe(true);
    // nginx 기본 포트 80/443, postgres 5432 추론
    expect(portHeld(p, 80)).toBe(true);
    expect(portHeld(p, 443)).toBe(true);
    expect(portHeld(p, 5432)).toBe(true);
  });

  it("gitlab 버전을 캡처한다", () => {
    const p = describeSystem("gitlab 15.7.3 커뮤니티 에디션");
    expect(hasComponent(p, "gitlab")).toBe(true);
    const c = p.components.find((x) => x.key === "gitlab");
    expect(c?.version).toBe("15.7.3");
  });

  it("플래그: 노출·MFA 부재(no-mfa 기본 부여)를 감지", () => {
    const p = describeSystem("인터넷에 노출된 정적 웹 앱");
    expect(hasFlag(p, "exposed")).toBe(true);
    // MFA 언급이 없으면 no-mfa (보수적 기본)
    expect(hasFlag(p, "no-mfa")).toBe(true);
    expect(p.notes.length).toBeGreaterThan(0);
  });

  it("방어 통제 언급은 notes 로 남기고 게이트에 영향 주지 않는다", () => {
    const p = describeSystem("waf + hsts 적용된 nginx");
    expect(p.notes.some((n) => /방어 통제/.test(n))).toBe(true);
  });
});

// ── parseProfileFile ──────────────────────────────────────────────────────
describe("parseProfileFile — JSON 프로필 파일", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "redcell-harden-"));
    await writeFile(
      path.join(dir, "profile.json"),
      JSON.stringify({
        name: "demo",
        description: "인터넷에 노출된 redis 캐시 서버",
        components: [{ name: "Redis", version: "7.0" }],
        ports: [6379],
        flags: ["exposed"],
      }),
      "utf8",
    );
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("구조화 JSON → 구성요소/포트/플래그 병합", () => {
    const p = parseProfileFile(path.join(dir, "profile.json"));
    expect(p.name).toBe("demo");
    expect(hasComponent(p, "redis")).toBe(true);
    expect(portHeld(p, 6379)).toBe(true);
    expect(hasFlag(p, "exposed")).toBe(true);
  });
});

// ── assessProfile ─────────────────────────────────────────────────────────
describe("assessProfile — 규칙 평가", () => {
  it("38개 규칙이 존재하고 결정적 when() 을 가진다", () => {
    expect(HARDEN_RULES.length).toBeGreaterThanOrEqual(38);
    for (const r of HARDEN_RULES) {
      expect(typeof r.when).toBe("function");
      expect(r.id).toMatch(/^H-\d+$/);
    }
  });

  it("redis 노출 → H-01 critical 발견", () => {
    const p = describeSystem("redis 서버 6379 포트, 인증 없음");
    const findings = assessProfile(p);
    const h01 = findings.find((f) => f.id === "H-01");
    expect(h01).toBeDefined();
    expect(h01?.severity).toBe("critical");
    expect(h01?.fix).toContain("requirepass");
  });

  it("안전한 정적 앱 → 발견 없음(또는 정보만)", () => {
    const p = describeSystem("정적 웹 앱, HTTPS, MFA 적용");
    const findings = assessProfile(p);
    expect(findings.filter((f) => f.severity !== "info").length).toBe(0);
  });
});

// ── runHarden 오프라인(결정적 게이트) ─────────────────────────────────────
describe("runHarden — 오프라인 게이트 판정", () => {
  let outDir: string;
  beforeAll(async () => {
    outDir = await mkdtemp(path.join(os.tmpdir(), "redcell-harden-out-"));
  });
  afterAll(async () => {
    await rm(outDir, { recursive: true, force: true });
  });

  it("critical/high 발견 → FAIL(exit 1) + 파일 3종 생성", async () => {
    const transcript: string[] = [];
    const res = await runHarden({
      description: "redis 서버 6379 포트, 인터넷에 노출, docker 컨테이너",
      name: "cache-poc",
      outDir,
      transcript,
    });
    expect(res.exitCode).toBe(1);
    expect(res.report.gate.verdict).toBe("FAIL");
    expect(res.report.findings.length).toBeGreaterThan(0);
    expect(res.report.findings.some((f) => f.severity === "critical")).toBe(true);
    expect(res.files).toHaveLength(3);
    expect(transcript.length).toBeGreaterThan(0);

    const md = await readFile(res.files[0], "utf8");
    const html = await readFile(res.files[1], "utf8");
    const json = await readFile(res.files[2], "utf8");
    expect(md).toContain("Hardening Report");
    expect(md).toContain("H-01");
    expect(html).toContain("<!doctype html>");
    expect(JSON.parse(json).verdict).toBe("FAIL");
  });

  it("발견 없음 → PASS(exit 0)", async () => {
    const res = await runHarden({
      description: "정적 웹 앱, HTTPS, MFA 적용",
      name: "clean",
      outDir,
      reportName: "clean",
    });
    expect(res.exitCode).toBe(0);
    expect(res.report.gate.verdict).toBe("PASS");
  });

  it("medium 만 → PASS_WITH_RISKS(exit 0)", async () => {
    const res = await runHarden({
      description: "haproxy 로드밸런서 + 정적 웹 앱, MFA 적용",
      name: "risk",
      outDir,
      reportName: "risks",
    });
    expect(res.exitCode).toBe(0);
    expect(res.report.gate.verdict).toBe("PASS_WITH_RISKS");
    expect(res.report.findings.some((f) => f.id === "H-35")).toBe(true);
  });

  it("공격경로 합성: redis 노출 프로필에서 루트가 나올 수 있다", async () => {
    const res = await runHarden({
      description: "nginx + postgres 데모 사이트, 관리자 패널, 인증 없음, 기본 비밀번호",
      name: "routes",
      outDir,
      reportName: "routes",
    });
    expect(res.report.routes).toBeInstanceOf(Array);
    if (res.report.findings.length > 0) {
      // planRoutes 가 능력 기반으로 루트를 만들었거나 빈 배열(연결 규칙 없음) —
      // 둘 다 합법인 결정적 결과다.
      expect(res.report.routes.length).toBeLessThanOrEqual(12);
    }
  });
});

// ── runHarden live (ScopeGuard 경유) ──────────────────────────────────────
describe("runHarden — live cross-check(ScopeGuard)", () => {
  let dir: string;
  let authOk: string;
  let authOther: string;
  let server: http.Server;
  let base: string;

  beforeAll(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "redcell-harden-live-"));
    authOk = path.join(dir, "ok.list");
    authOther = path.join(dir, "other.list");
    await writeFile(authOk, "127.0.0.1\n", "utf8");
    await writeFile(authOther, "203.0.113.5\n", "utf8"); // 로컬 서버는 인가 밖

    server = http.createServer((req, res) => {
      res.writeHead(200, { "content-type": "text/html", server: "nano-test" });
      res.end("<html><body>demo</body></html>");
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    const port = (server.address() as { port: number }).port;
    base = `http://127.0.0.1:${port}/`;
  });

  afterAll(async () => {
    await new Promise<void>((ok) => server.close(() => ok()));
    await rm(dir, { recursive: true, force: true });
  });

  it("인가 밖 호스트 → fail-closed 차단(exit 3, verdict FAIL·reason 명시)", async () => {
    const res = await runHarden({
      description: "redis 서버",
      url: "http://10.99.99.99:8080/",
      authFile: authOther,
      outDir: path.join(dir, "blocked"),
    });
    expect(res.exitCode).toBe(3);
    expect(res.report.gate.verdict).toBe("FAIL");
    expect(res.report.gate.reason).toContain("인가");
    expect(res.report.findings.length).toBeGreaterThan(0); // 규칙 평가는 수행됨
  });

  it("도달 불가 호스트 → INCONCLUSIVE(exit 4)", async () => {
    const res = await runHarden({
      description: "redis 서버",
      url: "http://127.0.0.1:1/", // 로컬이지만 닫힌 포트
      authFile: authOk,
      outDir: path.join(dir, "unreachable"),
    });
    expect(res.exitCode).toBe(4);
    expect(res.report.gate.verdict).toBe("INCONCLUSIVE");
  }, 30000);

  it("로컬 서버 + 규칙 발견 → 정상 통합(exit 1, live 결과 리포트 포함)", async () => {
    const res = await runHarden({
      description: "redis 서버 6379 포트 노출",
      url: base,
      authFile: authOk,
      outDir: path.join(dir, "ok"),
    });
    expect(res.report.live).toBeDefined();
    expect(res.report.live?.reachable).toBe(true);
    expect(res.report.live?.url).toBe(base);
    expect(res.report.live?.toolSummaries.length).toBeGreaterThan(0);
    // live 발견 → hardening 변환 결과가 findings 에 병합된 경우도 허용(규칙 기반 critical 은 반드시 존재)
    expect(res.report.findings.some((f) => f.id === "H-01")).toBe(true);
    expect(res.exitCode).toBe(1); // H-01 critical → FAIL
  });
});

// ── 리포트 렌더러 ────────────────────────────────────────────────────────
describe("harden 리포트 렌더러", () => {
  it("toMarkdown/toHtml/toJson 이 일관된 내용을 낸다", async () => {
    const outDir = await mkdtemp(path.join(os.tmpdir(), "redcell-harden-render-"));
    try {
      const res = await runHarden({
        description: "redis 서버 6379 포트, 인터넷 노출",
        name: "render",
        outDir,
        reportName: "render",
      });
      const md = toMarkdown(res.report);
      const html = toHtml(res.report);
      const json = JSON.parse(toJson(res.report));

      expect(md).toContain("# 🔒 Hardening Report — render");
      expect(md).toContain("❌ 차단"); // FAIL 배너
      expect(md).toContain("공격 루트 합성");
      expect(html).toContain("<html");
      expect(json.schema).toBe("harden-report/1");
      expect(json.verdict).toBe("FAIL");
      expect(json.findings.length).toBe(res.report.findings.length);
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("transcript 를 리포트에 포함한다", async () => {
    const outDir = await mkdtemp(path.join(os.tmpdir(), "redcell-harden-trans-"));
    try {
    const t: string[] = ["hello harden"];
    const res = await runHarden({
      description: "정적 웹 앱, MFA",
      name: "trans",
      outDir,
      reportName: "trans",
      transcript: t,
    });
    expect(res.report.transcript).toContain("hello harden");
    expect(toMarkdown(res.report)).toContain("hello harden");
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });
});