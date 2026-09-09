
/**
 * lab-bench.ts — P1 랩 벤치마크 러너.
 *
 * labs/ 아래 manifest.yaml 에 정의된 랩 각각에 대해:
 *   1) 랩 서버 기동(로컬) 또는 기동 생략(external/PortSwigger — --skip-start)
 *   2) URL 하나만 주고 assault 파이프라인 실행(--authorize --no-ai, 결정적 모드)
 *   3) report.json 을 lab-score.ts 로 채점 → 해결/미해결
 *   4) 자율 해결률(solve rate) 집계 → 마크다운 표 + JSON 출력
 *
 * 실행: npx tsx bench/lab-bench.ts                       (로컬 랩 전체)
 *       npx tsx bench/lab-bench.ts --skip-start --labs labs/아래 모든 manifest.yaml  (외부 랩)
 */

import { spawn, spawnSync } from "node:child_process";

import * as fs from "node:fs";
import * as path from "node:path";
import * as net from "node:net";
import { parse } from "yaml";
import { scoreLabReport, type LabManifest, type LabScore } from "./lab-score.js";

const ROOT = path.resolve(new URL("..", import.meta.url).pathname);
const CLI = path.join(ROOT, "src/cli.ts");

function argv(): { labs: string[]; home: string; skipStart: boolean; jsonOut?: string } {
  const a = process.argv.slice(2);
  const labs: string[] = [];
  let home = path.join(ROOT, ".lab-bench");
  let skipStart = false;
  let jsonOut: string | undefined;
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--labs") { while (i + 1 < a.length && !a[i + 1].startsWith("--")) labs.push(a[++i]); }
    else if (a[i] === "--home") home = a[++i];
    else if (a[i] === "--skip-start") skipStart = true;
    else if (a[i] === "--json") jsonOut = a[++i];
    else labs.push(a[i]);
  }
  return { labs: labs.length ? labs : [path.join(ROOT, "labs/*/manifest.yaml")], home, skipStart, jsonOut };
}

function waitPort(port: number, ms = 15000): Promise<boolean> {
  const t0 = Date.now();
  return new Promise((resolve) => {
    const tryOnce = () => {
      const s = net.connect({ host: "127.0.0.1", port });
      s.once("connect", () => { s.destroy(); resolve(true); });
      s.once("error", () => { s.destroy(); if (Date.now() - t0 > ms) resolve(false); else setTimeout(tryOnce, 200); });
    };
    tryOnce();
  });
}

function isPortBusy(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port });
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
  });
}

function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)); }

function fnmatch(name: string, pat: string): boolean {
  const re = pat.split("*").map((s) => s.replace(/[.+^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp("^" + re + "$").test(name);
}

interface Row { lab: string; class: string; source: string; solved: boolean; skipped: boolean; durationMs: number; verifiedExploits: number; findingCount: number; detail: string[]; missing: string[]; error?: string; }

async function main(): Promise<void> {
  const { labs: pats, home, skipStart, jsonOut } = argv();
  const files: string[] = [];
  for (const p of pats) {
    const abs = path.isAbsolute(p) ? p : path.join(ROOT, p);
    if (abs.includes("*")) {
      // 간단한 재귀 글롭: labs/<dir>/manifest.yaml 형태(하위 2단계) 지원
      const [top, pat] = abs.split("*");
      const dir = path.dirname(top);
      const fname = path.basename(top) + "*" + (pat ?? "");
      if (!fs.existsSync(dir)) continue;
      const walk = (d: string, depth: number) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const full = path.join(d, e.name);
          if (e.isDirectory()) { if (depth < 2) walk(full, depth + 1); continue; }
          if (e.isFile() && e.name.endsWith(".yaml") && fnmatch(full, abs)) files.push(full);
        }
      };
      walk(dir, 0);
      void fname;
    } else if (fs.existsSync(abs)) files.push(abs);
  }
  if (!files.length) { console.error("랩 manifest 없음:", pats); process.exit(2); }

  const rows: Row[] = [];
  for (const mf of files) {
    const row: Row = { lab: path.basename(path.dirname(mf)), class: "", source: "", solved: false, skipped: false, durationMs: 0, verifiedExploits: 0, findingCount: 0, detail: [], missing: [], error: undefined };
    try {
      const man = parse(fs.readFileSync(mf, "utf8")) as LabManifest;
      row.class = man.class; row.source = man.source;
      let child: ReturnType<typeof spawn> | undefined;
      if (!skipStart && man.start?.length) {
        if (await isPortBusy(man.port ?? 0)) { row.error = `포트 ${man.port} 이미 사용 중 — 랩 기동 생략`; row.skipped = true; rows.push(row); continue; }
        child = spawn(man.start[0], man.start.slice(1), { cwd: ROOT, stdio: "ignore" });
        if (!(await waitPort(man.port ?? 0))) { row.error = "랩 기동 실패(포트 미응답)"; row.skipped = true; child.kill(); rows.push(row); continue; }
      }
      const t0 = Date.now();
      const homeDir = path.join(home, man.name);
      fs.mkdirSync(homeDir, { recursive: true });
      const extra: string[] = Array.isArray((man as unknown as { assaultArgs?: string[] }).assaultArgs) ? (man as unknown as { assaultArgs: string[] }).assaultArgs : [];
      const run = spawnSync("npx", ["tsx", CLI, "assault", "--url", man.url, "--authorize", "--no-ai", ...extra], {
        cwd: ROOT, env: { ...process.env, REDCELL_HOME: homeDir }, encoding: "utf8", timeout: 300000,
      });
      row.durationMs = Date.now() - t0;
      if (run.status !== 0) {
        row.error = `assault 종료 코드 ${run.status} (${(run.stderr ?? run.stdout ?? "").slice(0, 400)})`;
        row.skipped = true;
        if (child) child.kill();
        rows.push(row); continue;
      }
      const reportFiles = fs
        .readdirSync(homeDir, { recursive: true })
        .filter((f) => String(f).endsWith("report.json"))
        .sort((a, b) => fs.statSync(path.join(homeDir, String(a))).mtimeMs - fs.statSync(path.join(homeDir, String(b))).mtimeMs);
      const reportFile = reportFiles[reportFiles.length - 1];
      if (!reportFile) { row.error = "report.json 없음"; row.skipped = true; if (child) child.kill(); rows.push(row); continue; }
      const rep = JSON.parse(fs.readFileSync(path.join(homeDir, String(reportFile)), "utf8"));
      const sc: LabScore = scoreLabReport(rep, man.expect);
      row.solved = sc.solved;
      row.missing = sc.missing;
      row.detail = sc.detail;
      row.verifiedExploits = (rep.exposed ?? []).filter((e: any) => e.verification?.status === "verified").length;
      row.findingCount = (rep.findings ?? []).length;
      if (child) child.kill();
    } catch (e: any) {
      row.error = String(e?.message ?? e);
      row.skipped = true;
    }
    rows.push(row);
  }

  const attempted = rows.filter((r) => !r.skipped);
  const solved = attempted.filter((r) => r.solved);
  const rate = attempted.length ? (100 * solved.length) / attempted.length : 0;

  console.log("\n═══ RedCell 랩 벤치마크 (자율 해결률) ═══\n");
  console.log(`${"랩".padEnd(22)}${"클래스".padEnd(10)}${"결과".padEnd(12)}${"시간".padEnd(9)}검증착취`);
  console.log("─".repeat(70));
  for (const r of rows) {
    const status = r.skipped ? (r.error ? "SKIP(오류)" : "SKIP") : r.solved ? "✅ 해결" : "❌ 미해결";
    console.log(`${r.lab.padEnd(22)}${r.class.padEnd(10)}${status.padEnd(12)}${((r.durationMs ?? 0) / 1000).toFixed(1) + "s".padEnd(6)}${r.verifiedExploits}`);
    for (const d of r.detail) console.log(`    ✓ ${d}`);
    for (const m of r.missing) console.log(`    ✗ ${m}`);
    if (r.error) console.log(`    ⚠ ${r.error}`);
  }
  console.log(`\n자율 해결률: ${solved.length}/${attempted.length} = ${rate.toFixed(1)}%${attempted.length ? "" : " (시도 랩 없음)"}`);

  if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify({ rate, attempted: attempted.length, solved: solved.length, rows }, null, 2));
  const ok = attempted.length > 0 && rate === 100;
  console.log(ok ? "\n✅ 벤치마크 통과 — 시도한 랩 전부 해결\n" : "\n❌ 벤치마크 기준 미달(전부 해결 필요)\n");
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error("lab-bench 오류:", e); process.exit(2); });
