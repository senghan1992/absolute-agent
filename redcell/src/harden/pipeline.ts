/**
 * harden 파이프라인: 설명서(또는 파일) → SystemProfile → 하드닝 규칙 평가 →
 * (선택) live 크로스체크 → 통합 발견 → 공격경로 합성 → 게이트 판정 → 리포트 3종(md/html/json) 파일 생성.
 *
 * live cross-check 가 인가 목록(ScopeGuard) 밖에 있으면 fail-closed 로 종료(exitCode 3)한다.
 * 판정: critical/high ≥1 → FAIL(1), medium only → PASS_WITH_RISKS(0), 없음 → PASS(0),
 *       live 미인가 → FAIL(3), live 도달불가 → INCONCLUSIVE(4).
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { assessProfile, liveFindingsToHardening } from "./knowledge.js";
import { runLiveRecon } from "./live.js";
import { describeSystem, parseProfileFile } from "./profile.js";
import { toHtml, toJson, toMarkdown } from "./report.js";
import type {
  GateResult,
  HardeningFinding,
  HardenOptions,
  HardenResult,
  HardeningReport,
  LiveReconResult,
  SystemProfile,
} from "./types.js";
import { planRoutes, type AttackRoute } from "../assault/routes.js";
import type { EngagementFinding } from "../core/types.js";

/** ts(): ISO → 파일명(콜론/점 치환) — 리포트 디렉터리 네임. */
function ts(): string {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}

/** HardeningFinding → EngagementFinding 변환(공격경로 모듈 재사용).
 *  capabilitiesOf 는 title+detail 을 정규식 매칭하므로 title=risk(위험 서술),
 *  detail=attack(공격 시나리오, 취약점 용어 포함), evidence=규칙 id(추적성) 로 매핑한다. */
function toEngagementFindings(fs: HardeningFinding[]): EngagementFinding[] {
  return fs.map((f) => ({
    phase: "recon",
    severity: f.severity,
    title: f.risk,
    detail: f.attack,
    evidence: f.id,
  }));
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** 게이트 판정: 발견 목록 → {verdict, reason, exitCode}. */
function judgeGate(findings: HardeningFinding[]): { verdict: GateResult["verdict"]; reason: string; exitCode: number } {
  let critical = 0;
  let high = 0;
  let medium = 0;
  for (const f of findings) {
    if (f.severity === "critical") critical++;
    else if (f.severity === "high") high++;
    else if (f.severity === "medium") medium++;
  }
  if (critical + high > 0) {
    return {
      verdict: "FAIL",
      reason: `critical ${critical}건 + high ${high}건(합 ${critical + high}건) — 출시 차단. ${critical + high}건부터 수정 후 재검사.`,
      exitCode: 1,
    };
  }
  if (medium > 0) {
    return {
      verdict: "PASS_WITH_RISKS",
      reason: `medium ${medium}건 존재 — 출시 가능하나 수정 권장. 리스크 허용 여부 확인 필요.`,
      exitCode: 0,
    };
  }
  return { verdict: "PASS", reason: "critical/high/medium 없음 — 재보안 게이트 통과.", exitCode: 0 };
}

/** countsOf(): 발견 목록 → 심각도별 카운트(GateResult.counts). */
function countsOf(findings: HardeningFinding[]): GateResult["counts"] {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<EngagementFinding["severity"], number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** 설명 없이 --url 만 주어진 경우의 빈 프로필. */
function emptyProfile(name?: string): SystemProfile {
  return {
    name: name ?? "system",
    raw: "",
    components: [],
    ports: [],
    flags: [],
    notes: ["설명 없음 — 규칙 평가는 live cross-check 발견으로만 진행됨"],
  };
}

/** parseFileOrText(): description 문자열 → SystemProfile(file://·로컬 파일 vs 텍스트 설명). */
function parseFileOrText(description: string, name?: string): SystemProfile {
  if (description.startsWith("file://")) return parseProfileFile(description.slice(7));
  const p = path.resolve(description);
  if (existsSync(p) && /\.(json|txt|md)$/i.test(description)) return parseProfileFile(p);
  return describeSystem(description, name);
}

export async function runHarden(opts: HardenOptions): Promise<HardenResult> {
  const startedAt = new Date().toISOString();
  const started = performance.now();

  const transcript: string[] = opts.transcript ?? [];
  const profile: SystemProfile = opts.description ? parseFileOrText(opts.description, opts.name) : emptyProfile(opts.name);
  transcript.push(`[harden] 시작: ${profile.name} — 입력 ${profile.raw.length > 0 ? "설명" : "없음"}, live=${opts.url ?? "없음"}`);

  // 리포트/출력 클로저 — runHarden 시점의 상태(profile, startedAt, transcript, opts)를 캡처.
  const finish = (
    gate: GateResult,
    exitCode: number,
    allFindings: HardeningFinding[],
    live: LiveReconResult | undefined,
    routes: AttackRoute[],
  ): HardenResult => {
    const finishedAt = new Date().toISOString();
    const report: HardeningReport = {
      startedAt,
      finishedAt,
      durationMs: Math.round(performance.now() - started),
      profile,
      live,
      findings: allFindings,
      routes,
      gate,
      transcript,
    };
    const outDir = opts.outDir ?? path.join(homedir(), ".redcell", "harden", ts());
    mkdirSync(outDir, { recursive: true });
    const base =
      opts.reportName ??
      `harden-${(profile.name || "system")
        .replace(/[^\p{L}\p{N}\s-]/gu, "")
        .replace(/\s+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "") || "system"}`;
    const files = [
      path.join(outDir, `${base}.md`),
      path.join(outDir, `${base}.html`),
      path.join(outDir, `${base}.json`),
    ];
    writeFileSync(files[0], toMarkdown(report), "utf-8");
    writeFileSync(files[1], toHtml(report), "utf-8");
    writeFileSync(files[2], toJson(report), "utf-8");
    transcript.push(`[harden] 출력: ${files[0]}`);
    return { report, files, exitCode };
  };

  // Step 1: 하드닝 규칙 평가
  const ruleFindings = assessProfile(profile);
  transcript.push(`[harden] 규칙 평가: ${ruleFindings.length}건 발견`);

  // Step 2: live cross-check(선택)
  let live: LiveReconResult | undefined;
  let liveFindings: HardeningFinding[] = [];
  let liveUnreachable: string | undefined;

  if (opts.url) {
    const out = await runLiveRecon({
      url: opts.url,
      authFile: opts.authFile,
      auth: opts.auth,
      proxy: opts.proxy,
      cookie: opts.cookie,
      log: (line) => transcript.push(line),
    });

    if (out.status === "blocked") {
      // 인가 목록 밖 → fail-closed, 즉시 종료(exitCode 3)
      const reason = `live 재확인 인가 부족 — ${out.reason}. 인가 목록에 대상 호스트를 추가 후 재실행.`;
      transcript.push(`[harden] 차단: ${reason}`);
      const gate: GateResult = { verdict: "FAIL", reason, counts: countsOf(ruleFindings) };
      return finish(gate, 3, ruleFindings, undefined, []);
    }

    if (out.status === "unreachable") {
      liveUnreachable = out.reason;
      transcript.push(`[harden] INCONCLUSIVE: live 도달 불가 — ${out.reason}`);
    } else {
      live = out.result;
      liveFindings = liveFindingsToHardening(profile, out.result.findings);
      transcript.push(`[harden] live cross-check: ${out.result.toolSummaries.length}건 도구 실행, ${out.result.findings.length}건 발견`);
    }
  }

  // Step 3: 통합 발견(중복 제거: 동일 risk 는 rule 우선) + 심각도 정렬
  const allFindings = [...ruleFindings];
  for (const lf of liveFindings) {
    if (!allFindings.some((rf) => rf.risk === lf.risk)) allFindings.push(lf);
  }
  allFindings.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  transcript.push(`[harden] 통합 발견: 규칙 ${ruleFindings.length}건 + live ${liveFindings.length}건 = ${allFindings.length}건`);

  // Step 4: 공격경로 합성(계획 전용 — 실행 없음)
  const routes = planRoutes(toEngagementFindings(allFindings), []);
  transcript.push(`[harden] 공격경로 합성: ${routes.length}개 루트`);

  // Step 5: 게이트 판정
  let gate: GateResult;
  let exitCode: number;
  if (liveUnreachable !== undefined) {
    gate = {
      verdict: "INCONCLUSIVE",
      reason: `live 크로스체크 도달 불가(${liveUnreachable ?? "연결 실패"}) — 설명서 기반 판정만 유효. 수동 확인 후 재실행.`,
      counts: countsOf(allFindings),
    };
    exitCode = 4;
  } else {
    const v = judgeGate(allFindings);
    gate = { verdict: v.verdict, reason: v.reason, counts: countsOf(allFindings) };
    exitCode = v.exitCode;
  }
  transcript.push(`[harden] 게이트 판정: ${gate.verdict} — ${gate.reason}`);

  return finish(gate, exitCode, allFindings, live, routes);
}