/**
 * human-gate.ts — P3 게이트: RedCell vs 인간 주니어 펜테스터 블라인드 비교.
 *
 * 동일 랩 셋(manifest glob)에서 양쪽 산출물을 같은 채점기(lab-score)로 비교한다.
 * 비교 지표(목표 정의 scorecard): 발견 recall · 정확도(FP) · 시간 · 문서 품질.
 *
 *   - recall   : solved(클래스 발견 + verified 착취) 여부
 *   - FP       : findings 중 verified 증거로 실증되지 않은 주장 수(클린 랩은 전체가 FP)
 *   - 시간     : redcell CLI 실행 시간 vs human meta.json 의 duration_ms (선택)
 *   - 문서 품질: report.md 의 섹션(##) 수 (선택 — human report.md 존재 시)
 *
 * 게이트 통과 = 모든 랩에서 4개 지표가 **인간과 동등 이상**(recall ≥, FP ≤, 시간 ≤, 문서 ≥).
 * 인간 산출물이 없는 랩이 있으면 게이트는 실패(블라인드 비교가 성립해야 의미 있음).
 *
 * 실행:
 *   npx tsx bench/human-gate.ts --human <dir>            # human-dir/<lab>/{report.json, report.md, meta.json}
 *   npx tsx bench/human-gate.ts --sim <dir>              # 시뮬레이션: redcell 결과를 human 으로 복제해 게이트 자체 검증
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { parse } from "yaml";
import { scoreLabReport, type LabManifest, type LabScore } from "./lab-score.js";

const ROOT = path.resolve(new URL("..", import.meta.url).pathname);

interface Meta { duration_ms?: number; author?: string; }
interface LabRow {
  lab: string;
  cls: string;
  red: { solved: boolean; verified: number; findings: number; fp: number; ms?: number; doc?: number };
  human: { solved: boolean; verified: number; findings: number; fp: number; ms?: number; doc?: number; present: boolean };
  pass: { recall: boolean; fp: boolean; time: boolean; doc: boolean; data: boolean };
}

function argv(): { labs: string[]; home: string; human: string; sim?: string; jsonOut?: string; times?: Record<string, number> } {
  const a = process.argv.slice(2);
  const labs: string[] = [];
  let home = path.join(ROOT, ".lab-bench");
  let human = "";
  let sim: string | undefined;
  let jsonOut: string | undefined;
  let times: Record<string, number> | undefined;
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--labs") { while (i + 1 < a.length && !a[i + 1].startsWith("--")) labs.push(a[++i]); }
    else if (a[i] === "--home") home = a[++i];
    else if (a[i] === "--human") human = a[++i];
    else if (a[i] === "--sim") sim = a[++i];
    else if (a[i] === "--json") jsonOut = a[++i];
    else if (a[i] === "--times") times = JSON.parse(a[++i]);
  }
  if (!labs.length) labs.push("labs/*/manifest.yaml");
  return { labs, home, human, sim, jsonOut, times };
}

function globManifests(pats: string[]): string[] {
  const files: string[] = [];
  for (const p of pats) {
    const abs = path.isAbsolute(p) ? p : path.join(ROOT, p);
    if (!abs.includes("*")) {
      if (fs.existsSync(abs)) files.push(abs);
      continue;
    }
    const [top] = abs.split("*");
    const dir = path.dirname(top);
    if (!fs.existsSync(dir)) continue;
    const walk = (d: string, depth: number) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) { if (depth < 2) walk(full, depth + 1); continue; }
        if (e.isFile() && e.name.endsWith(".yaml") && matches(full, abs)) files.push(full);
      }
    };
    walk(dir, 0);
  }
  return files;
}
function matches(name: string, pat: string): boolean {
  const re = pat.split("*").map((s) => s.replace(/[.+^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp("^" + re + "$").test(name);
}

function latestReport(dir: string): { rep: any; doc?: number } | null {
  if (!fs.existsSync(dir)) return null;
  const files = (fs.readdirSync(dir, { recursive: true }) as string[])
    .filter((f) => String(f).endsWith("report.json"))
    .sort((a, b) => fs.statSync(path.join(dir, String(a))).mtimeMs - fs.statSync(path.join(dir, String(b))).mtimeMs);
  if (!files.length) return null;
  const best = files[files.length - 1];
  const base = path.dirname(path.join(dir, String(best)));
  let doc: number | undefined;
  const mdP = path.join(base, "report.md");
  if (fs.existsSync(mdP)) {
    const t = fs.readFileSync(mdP, "utf8");
    doc = (t.match(/^#{2,3}\s+/gm) ?? []).length;
  }
  try { return { rep: JSON.parse(fs.readFileSync(path.join(dir, String(best)), "utf8")), doc }; } catch { return null; }
}
function readMeta(dir: string): Meta {
  try { return JSON.parse(fs.readFileSync(path.join(dir, "meta.json"), "utf8")); } catch { return {}; }
}

function metrics(report: any, clean: boolean): { solved: boolean; verified: number; findings: number; fp: number } {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const exposed = Array.isArray(report?.exposed) ? report.exposed : [];
  const verified = exposed.filter((e: any) => e?.verification?.status === "verified").length;
  const fp = clean ? findings.length : Math.max(0, findings.length - verified);
  return { solved: verified > 0 && findings.length > 0, verified, findings: findings.length, fp };
}

async function main(): Promise<void> {
  const { labs, home, human, sim, jsonOut, times } = argv();
  const manFiles = globManifests(labs);
  if (!manFiles.length) { console.error("manifest 없음:", labs); process.exit(2); }

  // --sim: redcell 결과를 human dir 로 복제(게이트 자체 검증용)
  if (sim) {
    for (const mf of manFiles) {
      const lab = path.basename(path.dirname(mf));
      const man = parse(fs.readFileSync(mf, "utf8")) as LabManifest;
      const srcDir = path.join(home, man.name);
      const dstDir = path.join(sim, lab);
      fs.mkdirSync(dstDir, { recursive: true });
      const rels = (fs.readdirSync(srcDir, { recursive: true }) as string[]).filter((f) => /report\.(json|md|html)$/.test(String(f)));
      for (const rel of rels) {
        const s = path.join(srcDir, String(rel));
        const d = path.join(dstDir, String(rel));
        fs.mkdirSync(path.dirname(d), { recursive: true });
        fs.copyFileSync(s, d);
      }
      const meta: Meta = { author: "simulated-human", duration_ms: 600_000 };
      fs.writeFileSync(path.join(dstDir, "meta.json"), JSON.stringify(meta, null, 2));
    }
    console.log(`시뮬레이션: redcell 결과를 "${sim}" 에 복제했습니다.`);
  }
  const humanDir = human || sim!;
  if (!humanDir) { console.error("--human <dir> 또는 --sim <dir> 필요"); process.exit(2); }

  const rows: LabRow[] = [];
  for (const mf of manFiles) {
    const lab = path.basename(path.dirname(mf));
    const man = parse(fs.readFileSync(mf, "utf8")) as LabManifest;
    const clean = (man.expect?.findingText ?? []).length === 0;
    const redDirs = [man.name, lab];
    let redBundle: { rep: any; doc?: number } | null = null;
    for (const d of redDirs) { redBundle = latestReport(path.join(home, d)) ?? redBundle; }
    const red = redBundle ? metrics(redBundle.rep, clean) : { solved: false, verified: 0, findings: 0, fp: 0 };
    let hBundle: { rep: any; doc?: number } | null = null;
    for (const d of redDirs) { hBundle = latestReport(path.join(humanDir, d)) ?? hBundle; }
    const hMeta = readMeta(path.join(humanDir, lab));
    const hDoc = hBundle?.doc;
    const humanMetrics = hBundle ? metrics(hBundle.rep, clean) : { solved: false, verified: 0, findings: 0, fp: 0 };
    const humanPresent = !!hBundle;
    const redDoc = redBundle?.doc ?? 0;
    const rTime = times?.[lab] ?? red.ms;
    rows.push({
      lab, cls: man.class,
      red: { ...red, ms: rTime, doc: redDoc },
      human: { ...humanMetrics, ms: hMeta.duration_ms, doc: hDoc, present: humanPresent },
      pass: {
        recall: humanPresent ? red.solved === humanMetrics.solved || red.solved : false,
        fp: humanPresent ? red.fp <= humanMetrics.fp : false,
        time: !humanPresent || hMeta.duration_ms == null || red.ms == null ? humanPresent : (red.ms ?? Infinity) <= hMeta.duration_ms,
        doc: !humanPresent || hDoc == null || redDoc == null ? humanPresent : redDoc >= hDoc,
        data: humanPresent,
      },
    });
  }

  const all = rows.every((r) => r.pass.data && r.pass.recall && r.pass.fp && r.pass.time && r.pass.doc);
  const W = (s: string, n: number) => s.padEnd(n).slice(0, n);
  console.log("═══ P3 게이트: RedCell vs 인간 주니어 펜테스터 (블라인드, 동일 랩 셋) ═══");
  console.log(W("랩", 16) + W("클래스", 24) + W("recall R/H", 11) + W("FP R/H", 8) + W("시간 R/H", 11) + W("문서 R/H", 10) + "판정");
  for (const r of rows) {
    const fmt = (v?: number) => (v == null ? "-" : String(v));
    console.log(
      W(r.lab, 16) + W(r.cls, 24) +
      W(`${r.red.solved ? "✅" : "❌"}/${r.human.solved ? "✅" : "❌"}`, 11) +
      W(`${r.red.fp}/${r.human.fp}`, 8) +
      W(`${fmt(r.red.ms)}/${fmt(r.human.ms)}`, 11) +
      W(`${fmt(r.red.doc)}/${fmt(r.human.doc)}`, 10) +
      (r.pass.data && r.pass.recall && r.pass.fp && r.pass.time && r.pass.doc ? "✅ 동등 이상" : "❌ 미달"),
    );
  }
  const summary = {
    gate: "P3-human-vs-redcell",
    passed: all,
    rows: rows.map((r) => ({ lab: r.lab, class: r.cls, red: r.red, human: r.human, pass: r.pass })),
  };
  if (jsonOut) fs.writeFileSync(path.join(ROOT, jsonOut), JSON.stringify(summary, null, 2));
  console.log(all ? "\n✅ P3 게이트 통과 — 모든 랩에서 인간과 동등 이상" : "\n❌ P3 게이트 미달(인간 대비 열위 또는 인간 데이터 누락)");
  process.exit(all ? 0 : 1);
}
main();
