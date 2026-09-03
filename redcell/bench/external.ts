/**
 * 외부 표준 취약앱 검증 러너 — 블라인드 재현율 측정.
 *
 * bench/vulnapp.ts(자기참조: 툴에 정답 경로를 직접 먹임)와 달리, 이 러너는 RedCell 을
 * **아무 힌트 없이** 돌린다: AutoPilot 을 결정적 전수(--full) 모드로 실행하면
 *   crawl(표면 발견) → deriveArgs(자동 배선) → 각 탐지 툴(스윕)
 * 만으로 취약점을 찾아야 한다. 정답 경로/파라미터를 주지 않는다.
 *
 * 그리고 **정직하게** 채점한다: 100% 를 조작하지 않는다. 심은 12개 중 아키텍처/배선상
 * 못 잡을 3개(저장형 XSS·CSRF·비즈니스 로직)를 명시적으로 "미탐 기대"로 두고, 실제로
 * 못 잡는지까지 확인한다 → 재현율은 탐지 기대(9개) 기준과 전체(12개) 기준 둘 다 보고한다.
 *
 * 실행: npm run bench:external  (또는 npx tsx bench/external.ts)
 *
 * 라이브 DVWA/Juice Shop 은 이 환경(도커 없음)에서 띄울 수 없어, 이 픽스처가 재현 가능한
 * 최강의 대체물이다. 실제 컨테이너가 있으면 같은 AutoPilot 을 그 host:port 에 겨누면 된다.
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { SkillMemory } from "../src/memory/skill-memory.js";
import { ContextualBandit } from "../src/explore/bandit.js";
import { AutoPilot } from "../src/core/autopilot.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";
import type { EngagementFinding } from "../src/core/types.js";
import { startExternalApp } from "./external-app.js";

export type MissKind = "architectural" | "wiring";

export interface Planted {
  /** 안정적인 취약점 클래스 키. */
  klass: string;
  /** 실제 심은 위치(사람이 읽는 근거). */
  where: string;
  /** RedCell 이 잡을 수 있다고 기대하는가. false 면 "정직한 미탐"(FN). */
  detectable: boolean;
  /** finding.title 을 이 클래스로 귀속시키는 매칭기. */
  match: RegExp;
  /** 미탐 기대일 때 그 사유 종류. */
  missKind?: MissKind;
  /** 근거/설명. */
  note: string;
}

/** 지상 진실(ground truth). external-app.ts 가 실제로 심은 것과 일치해야 한다. */
export const PLANTED: Planted[] = [
  // ── 탐지 기대(9) ──────────────────────────────────────────────────────────
  { klass: "SQL Injection", where: "/vulnerabilities/sqli/?id · /rest/products/search?q", detectable: true, match: /SQL Injection/i, note: "오류 기반. sqli_probe 가 crawl 이 찾은 param 경로를 스윕." },
  { klass: "Reflected XSS", where: "/vulnerabilities/xss_r/?name", detectable: true, match: /Reflected XSS/i, note: "미이스케이프 반사 → 실행 가능 컨텍스트." },
  { klass: "OS Command Injection", where: "/vulnerabilities/exec/?ip", detectable: true, match: /Command Injection/i, note: "구분자+무해 명령(id) 출력 시그니처." },
  { klass: "Path Traversal / LFI", where: "/vulnerabilities/fi/?page", detectable: true, match: /Path Traversal|LFI/i, note: "../etc/passwd 시그니처." },
  { klass: "Open Redirect", where: "/redirect?to", detectable: true, match: /Open Redirect/i, note: "외부 canary 로 30x Location." },
  // IDOR/데이터 노출: idor_probe 뿐 아니라 api_probe("민감정보 노출")도 같은 결함을 잡는다(보강).
  { klass: "IDOR", where: "/api/Users/:id", detectable: true, match: /IDOR|접근통제|민감정보 노출|인증 없는 민감/i, note: "무인증 인접 id + 개인정보(email) 신호. idor_probe·api_probe 가 함께 확증." },
  // 노출 VCS: secret_scan("민감 파일 노출") 뿐 아니라 dir_enum("민감 경로 노출")도 같은 파일을 잡는다(보강).
  { klass: "Exposed Secrets (VCS)", where: "/.git/config · /.git/HEAD", detectable: true, match: /파일 노출|민감 파일|정보성 파일|경로 노출/i, note: "secret_scan 자체 워드리스트로 도달(crawl 무관). dir_enum 도 함께 확증." },
  { klass: "Missing Security Headers", where: "모든 응답", detectable: true, match: /보안 헤더 누락/i, note: "CSP/HSTS/XFO/XCTO/RP 전부 누락." },
  { klass: "Insecure Session Cookie", where: "PHPSESSID (모든 응답)", detectable: true, match: /쿠키|HttpOnly/i, note: "세션 쿠키에 HttpOnly/Secure/SameSite 누락." },

  // ── 미탐 기대(3) — 정직한 False Negative ────────────────────────────────────
  { klass: "Stored XSS", where: "/vulnerabilities/xss_s/ (POST→GET)", detectable: false, missKind: "architectural", match: /Stored XSS|저장형/i, note: "단일 요청-응답 반사만 봄. 저장(POST)→렌더(GET) 상관 안 함." },
  { klass: "CSRF", where: "/vulnerabilities/csrf/ (토큰 없는 POST 폼)", detectable: false, missKind: "wiring", match: /CSRF/i, note: "csrf_audit 은 PATH_ONLY 배선으로 단일 param 경로만 봄 + 이 페이지는 crawl 방문 상한(5) 초과로 미파싱." },
  { klass: "Business Logic", where: "/rest/basket/checkout (음수 수량/쿠폰)", detectable: false, missKind: "architectural", match: /Business Logic|비즈니스/i, note: "로직 결함 — 콘텐츠 시그니처가 없어 규칙 기반 탐지 불가." },
];

export interface ClassResult {
  klass: string;
  where: string;
  detectable: boolean;
  missKind?: MissKind;
  found: boolean;
  severity?: string;
  title?: string;
  note: string;
}

export interface ExternalResult {
  classes: ClassResult[];
  /** PLANTED 어디에도 귀속되지 않은 예상 밖 finding(오탐 후보). */
  unexpected: EngagementFinding[];
  reachable: boolean;
  toolsRun: number;
  toolsTotal: number;
  endpointsDiscovered: number;
  verdict: string;
  /** 탐지 기대(9개) 기준 재현율. */
  recallDetectable: number;
  /** 전체(12개) 기준 정직 재현율. */
  recallOverall: number;
}

function auth(): AuthorizationFile {
  return {
    engagement: { name: "external-vulnapp-bench", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "local bench fixture" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 500 },
  };
}

/** 외부 픽스처를 블라인드(--full, argsFor 없음)로 스캔하고 결과를 채점한다. */
export async function runExternalBench(): Promise<ExternalResult> {
  const app = await startExternalApp();
  try {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redcell-external-"));
    const memory = new SkillMemory(dir);
    await memory.load();

    // 핵심: argsFor 를 주지 않는다 → deriveArgs(crawl 표면 자동 배선)만으로 공격.
    const ap = new AutoPilot(new ScopeGuard(auth()), memory, new ContextualBandit("ucb1"), new DefaultToolBox(), {
      full: true,
      globalBudget: 200,
      allowUnauth: true, // 공개 서비스로 간주(인증 표면 미점검이 판정을 흐리지 않게).
    });
    const report = await ap.run({ host: "127.0.0.1", port: app.port }, "외부 취약앱 블라인드 재현율 측정");

    const findings = report.findings;
    const usedTitles = new Set<string>();
    const classes: ClassResult[] = PLANTED.map((p) => {
      const hit = findings.find((f) => p.match.test(f.title));
      if (hit) usedTitles.add(hit.title);
      return {
        klass: p.klass,
        where: p.where,
        detectable: p.detectable,
        missKind: p.missKind,
        found: !!hit,
        severity: hit?.severity,
        title: hit?.title,
        note: p.note,
      };
    });

    // 어떤 PLANTED 클래스에도 귀속되지 않은 finding = 예상 밖(오탐 후보).
    const unexpected = findings.filter((f) => !PLANTED.some((p) => p.match.test(f.title)));

    const detectable = classes.filter((c) => c.detectable);
    const foundDetectable = detectable.filter((c) => c.found).length;
    const foundAll = classes.filter((c) => c.found).length;

    return {
      classes,
      unexpected,
      reachable: report.coverage.reachable,
      toolsRun: report.coverage.toolsRun,
      toolsTotal: report.coverage.toolsTotal,
      endpointsDiscovered: report.coverage.endpointsDiscovered,
      verdict: report.verdict,
      recallDetectable: foundDetectable / detectable.length,
      recallOverall: foundAll / classes.length,
    };
  } finally {
    await app.close();
  }
}

function pct(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}

async function main(): Promise<void> {
  const t0 = Date.now();
  const r = await runExternalBench();

  console.log("\n═══ RedCell 외부 표준 취약앱 블라인드 검증 (DVWA/Juice Shop 모델) ═══\n");
  console.log("모드: AutoPilot --full (결정적 전수) · 정답 경로 미제공 · crawl→deriveArgs→탐지만으로 공략\n");
  console.log(`도달=${r.reachable}  실행 툴=${r.toolsRun}/${r.toolsTotal}  발견 endpoint=${r.endpointsDiscovered}  판정=${r.verdict}\n`);

  console.log(`${"취약점 클래스".padEnd(26)}${"기대".padEnd(8)}${"결과".padEnd(12)}위치`);
  console.log("─".repeat(96));
  for (const c of r.classes) {
    const expect = c.detectable ? "탐지" : `미탐(${c.missKind === "architectural" ? "아키" : "배선"})`;
    let mark: string;
    if (c.detectable) mark = c.found ? `✅ ${c.severity}` : "❌ 놓침";
    else mark = c.found ? "⚠️ 예상외탐지" : "✓ 정직미탐";
    console.log(`${c.klass.padEnd(26)}${expect.padEnd(8)}${mark.padEnd(12)}${c.where}`);
  }
  console.log("─".repeat(96));

  const detectable = r.classes.filter((c) => c.detectable);
  const missed = detectable.filter((c) => !c.found);
  console.log(`\n탐지 기대 ${detectable.length}개 중 ${detectable.length - missed.length}개 탐지`);
  console.log(`재현율(탐지 기대 기준) : ${pct(r.recallDetectable)}`);
  console.log(`재현율(전체 12개 기준·정직): ${pct(r.recallOverall)}  ← 심은 아키텍처/배선 한계 미탐을 포함한 실제 수치`);

  if (missed.length) {
    console.log(`\n놓친(기대했으나 미탐) ${missed.length}건 — 회귀:`);
    for (const c of missed) console.log(`  ❌ ${c.klass} @ ${c.where}`);
  }
  const expectedMisses = r.classes.filter((c) => !c.detectable);
  console.log(`\n정직한 미탐(설계상 못 잡음) ${expectedMisses.filter((c) => !c.found).length}/${expectedMisses.length}건:`);
  for (const c of expectedMisses) {
    const state = c.found ? "⚠️ 그런데 탐지됨(재평가 필요)" : "✓ 예상대로 미탐";
    console.log(`  ${state} — ${c.klass} [${c.missKind}]: ${c.note}`);
  }
  if (r.unexpected.length) {
    console.log(`\n예상 밖 발견(오탐 후보) ${r.unexpected.length}건:`);
    for (const f of r.unexpected) console.log(`  ⚠️ (${f.severity}) ${f.title} — ${f.detail}`);
  }

  console.log(`\n소요 ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  // 회귀 게이트: 탐지 기대 클래스를 하나라도 놓치거나, sev>=medium 오탐이 나오면 실패.
  const fpSevere = r.unexpected.filter((f) => f.severity === "medium" || f.severity === "high" || f.severity === "critical");
  const ok = missed.length === 0 && fpSevere.length === 0;
  console.log(
    ok
      ? `\n✅ 외부 검증 통과 — 탐지 기대 ${detectable.length}개 전부 블라인드 탐지, 심각 오탐 0.\n`
      : `\n❌ 외부 검증 미달 — 놓침 ${missed.length}건, 심각 오탐 ${fpSevere.length}건.\n`,
  );
  process.exit(ok ? 0 : 1);
}

// 직접 실행일 때만 main.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error("external bench 오류:", e);
    process.exit(2);
  });
}
