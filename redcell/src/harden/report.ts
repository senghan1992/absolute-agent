/**
 * Hardening Report — Markdown / HTML / JSON 렌더러.
 *
 * 보고서 구조:
 *   1. 릴리스 게이트 판정 (상단 배너 — 한눈에)
 *   2. 시스템 프로필 (파싱 결과)
 *   3. 발견 내역 (심각도별 그룹, 공격 경로 포함)
 *   4. 우선순위 재보안(복구) 목록 (노력도 기준 정렬)
 *   5. 공격 루트 합성 (이대로 두면 어떤 경로로 탈취되는가)
 *   6. Live cross-check (--url) 섹션
 *   7. 실행 로그
 */
import type { HardeningReport, HardenVerdict } from "./types.js";
import { fmtDur, renderRouteMapMd } from "../assault/report.js";
import { CAPABILITY_KO } from "../assault/routes.js";

const SEV_ICON: Record<string, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "ℹ️" };
const SEV_KO: Record<string, string> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };
const VERDICT_KO: Record<HardenVerdict, string> = {
  PASS: "✅ 통과", PASS_WITH_RISKS: "⚠️ 리스크 허용 하 통과", FAIL: "❌ 차단", INCONCLUSIVE: "⛔ 판단 불가",
};

// ── Markdown ─────────────────────────────────────────────────────────────────

export function toMarkdown(r: HardeningReport): string {
  const p = r.profile;
  const vers = p.components.filter((c) => c.version).map((c) => `${c.label} ${c.version}`);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of r.findings) counts[f.severity as keyof typeof counts] = (counts[f.severity as keyof typeof counts] ?? 0) + 1;
  const hiPlus = counts.critical + counts.high;

  const L: string[] = [];
  L.push(`# 🔒 Hardening Report — ${p.name}`);
  L.push("");
  L.push(`> ## ${VERDICT_KO[r.gate.verdict]}`);
  L.push(`> ${r.gate.reason}`);
  L.push("");
  L.push(`- 실행 ${r.startedAt} → ${r.finishedAt} (${fmtDur(r.durationMs)})`);
  L.push(`- 입력: ${p.raw.length > 120 ? p.raw.slice(0, 120) + "…" : p.raw}`);
  L.push(`- live cross-check: ${r.live ? `\`${r.live.url}\` (발견 ${r.live.findings.length})` : "없음(오프라인)"}`);
  L.push("");
  L.push(`## KPI`);
  L.push("");
  L.push(`| 구분 | 값 |`);
  L.push(`|---|---|`);
  L.push(`| 판정 | ${r.gate.verdict} |`);
  L.push(`| 컴포넌트 | ${p.components.length}종 — ${p.components.map((c) => c.label).join(", ")} |`);
  L.push(`| 포트 | ${p.ports.length ? p.ports.join(", ") : "(미언급)"} |`);
  L.push(`| 발견 | ${r.findings.length}건 (critical ${counts.critical} / high ${counts.high} / medium ${counts.medium} / low ${counts.low}) |`);
  L.push(`| 공격 루트 | ${r.routes.length}개 합성 |`);
  L.push("");

  // 1. 프로필
  L.push(`## 1. 시스템 프로필 (추론)`);
  L.push("");
  L.push(`- **컴포넌트**: ${p.components.length ? p.components.map((c) => `\`${c.label}\``).join(" ") : "(인식 불가)"}${vers.length ? ` (버전: ${vers.join(", ")})` : ""}`);
  L.push(`- **포트**: ${p.ports.length ? p.ports.map((x) => `\`${x}\``).join(" ") : "(미언급)"}`);
  L.push(`- **특징**: ${p.flags.length ? p.flags.join(" / ") : "—"}`);
  if (p.notes.length) {
    L.push(`- **메모**`);
    for (const n of p.notes) L.push(`  - ${n}`);
  }
  L.push("");
  L.push(`<details><summary>원문 입력</summary>`);
  L.push("");
  L.push("```text");
  L.push(p.raw);
  L.push("```");
  L.push("</details>");
  L.push("");

  // 2. 발견
  L.push(`## 2. 발견 내역 (${r.findings.length})`);
  L.push("");
  if (r.findings.length === 0) L.push("_발견 없음._");
  for (const sev of ["critical", "high", "medium", "low"] as const) {
    const group = r.findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    L.push(`### ${SEV_ICON[sev]} ${SEV_KO[sev]} (${group.length})`);
    L.push("");
    L.push("| id | 위험 | 공격 시나리오 |");
    L.push("|---|---|---|");
    for (const f of group) L.push(`| ${f.id} | ${f.risk}${f.cwe ? ` <sub>(${f.cwe})</sub>` : ""} | ${f.attack.replace(/\n+/g, " ")} |`);
    L.push("");
  }

  // 3. 재보안 목록
  L.push(`## 3. 우선순위 재보안(복구) 목록`);
  L.push("");
  if (r.findings.length === 0) L.push("_할 일 없음 — 통과._");
  else {
    const order = { critical: 0, high: 1, medium: 2, low: 3 } as const;
    const eff = (e?: string) => (e === "low" ? 0 : e === "medium" ? 1 : 2);
    const sevKey = (s: string) => (s in order ? (s as keyof typeof order) : "low");
    const sorted = [...r.findings].sort((a, b) => order[sevKey(a.severity)] - order[sevKey(b.severity)] || eff(b.effort) - eff(a.effort));
    L.push("| 우선순위 | id | 수정안 | 노력 | CWE |");
    L.push("|---|---|---|---|---|");
    sorted.forEach((f, i) => L.push(`| P${i + 1} | ${f.id} | ${f.fix.replace(/\n+/g, " ")} | ${f.effort ?? "-"} | ${f.cwe ? `\`${f.cwe}\`` : "-"} |`));
  }
  L.push("");

  // 4. 공격 루트
  L.push(`## 4. 공격 루트 합성 — 이대로 두면 어떻게 탈취되는가`);
  L.push("");
  L.push(renderRouteMapMd(r.routes).split("\n").slice(2).join("\n").replace(/^## /, "### "));
  L.push("");

  // 5. live
  L.push(`## 5. Live Cross-check`);
  L.push("");
  if (r.live) {
    if (r.live.reachable) {
      L.push(`- 대상: \`${r.live.url}\` — 도달 가능`);
      if (Object.keys(r.live.fingerprint).length)
        L.push(`- 지문: ${JSON.stringify(r.live.fingerprint)}`);
      if (r.live.findings.length) {
        L.push(`- live 발견 ${r.live.findings.length}건 → hardening 규칙으로 변환해 §2 에 병합됨`);
        for (const f of r.live.findings.slice(0, 10))
          L.push(`  - [${f.severity}] ${f.title}${f.evidence ? ` — ${f.evidence.replace(/\n+/g, " ").slice(0, 100)}` : ""}`);
      }
      L.push(`- 툴 요약:`);
      for (const s of r.live.toolSummaries) L.push(`  - ${s.replace(/\n+/g, " ").slice(0, 120)}`);
    } else {
      L.push(`- 대상: \`${r.live.url}\` — **미도달** (${r.live.reason ?? "사유 없음"})`);
    }
  } else {
    L.push(`_오프라인 모드 — live cross-check 없음. \`--url\` 로 live 재확인 가능._`);
  }
  L.push("");

  // 6. 게이트
  L.push(`## 6. 릴리스 게이트`);
  L.push("");
  L.push(`- **판정**: ${VERDICT_KO[r.gate.verdict]}`);
  L.push(`- **사유**: ${r.gate.reason}`);
  if (hiPlus > 0)
    L.push(`- ${hiPlus}건의 critical/high 를 해소(PASS 로 전환)하려면 §3 목록의 P1~P${hiPlus} 항목부터 시행하세요.`);
  L.push("");

  // 7. 로그
  L.push(`## 7. 실행 로그`);
  L.push("");
  L.push("```text");
  for (const line of r.transcript.slice(-60)) L.push(line);
  L.push("```");
  L.push("");
  L.push(`_RedCell harden · 규칙기반 결정론 재보안 · 생성 ${r.finishedAt}_`);
  return L.join("\n");
}

// ── JSON ─────────────────────────────────────────────────────────────────────

export function toJson(r: HardeningReport): string {
  return JSON.stringify({
    schema: "harden-report/1",
    verdict: r.gate.verdict,
    verdictReason: r.gate.reason,
    startedAt: r.startedAt,
    finishedAt: r.finishedAt,
    durationMs: r.durationMs,
    profile: r.profile,
    findings: r.findings,
    routes: r.routes,
    live: r.live ?? null,
    transcript: r.transcript,
  }, null, 2);
}

// ── HTML ─────────────────────────────────────────────────────────────────────

const esc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function toHtml(r: HardeningReport): string {
  const p = r.profile;
  const vers = p.components.filter((c) => c.version).map((c) => `${c.label} ${c.version}`);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of r.findings) counts[f.severity as keyof typeof counts] = (counts[f.severity as keyof typeof counts] ?? 0) + 1;
  const sevCls = (s: string) => (["critical", "high"].includes(s) ? "sev-hi" : s === "medium" ? "sev-md" : "sev-lo");
  const order = { critical: 0, high: 1, medium: 2, low: 3 } as const;
  const eff = (e?: string) => (e === "low" ? 0 : e === "medium" ? 1 : 2);
  const sevKey = (s: string) => (s in order ? (s as keyof typeof order) : "low");
  const sorted = [...r.findings].sort((a, b) => order[sevKey(a.severity)] - order[sevKey(b.severity)] || eff(b.effort) - eff(a.effort));

  const findRows = r.findings.map(
    (f) => `<tr class="${sevCls(f.severity)}"><td>${f.id}</td><td>${esc(f.severity)}</td><td>${esc(f.risk)}${f.cwe ? ` <small>(${esc(f.cwe)})</small>` : ""}</td><td>${esc(f.attack.replace(/\n+/g, " "))}</td></tr>`,
  );
  const fixRows = sorted.map(
    (f, i) => `<tr class="${sevCls(f.severity)}"><td><b>P${i + 1}</b></td><td>${f.id}</td><td>${esc(f.fix.replace(/\n+/g, " "))}</td><td>${esc(f.effort ?? "-")}</td><td>${f.cwe ? `<code>${esc(f.cwe)}</code>` : "-"}</td></tr>`,
  );
  const routeBlocks = r.routes.map((rt) => `<div class="path ${rt.goalSeverity === "critical" ? "sev-hi" : "sev-md"}">
    <h4>🎯 ${esc(rt.goal)} <span class="tag">${esc(rt.goalSeverity)}</span></h4>
    <pre class="routemap">${esc([CAPABILITY_KO[rt.entry] ?? rt.entry, ...rt.steps.map((s) => CAPABILITY_KO[s.to] ?? s.to)].join(" ──▶ "))}</pre>
    <ol>${rt.steps.map((s) => `<li><b>${esc(CAPABILITY_KO[s.from] ?? s.from)} → ${esc(CAPABILITY_KO[s.to] ?? s.to)}</b> — ${esc(s.how)}<br><span class="refs">근거: ${esc(s.via)} · 방어: ${esc(s.defense)}</span></li>`).join("")}</ol>
    <p class="attack">💥 ${esc(rt.impact)}</p></div>`).join("");
  const logLines = r.transcript.slice(-80).map((l) => `<div class="log">${esc(l)}</div>`).join("");

  return `<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hardening — ${esc(p.name)}</title>
<style>
:root{--bg:#0b0f14;--panel:#121821;--line:#1f2a38;--fg:#d7e0ea;--dim:#8b98a5;--hi:#ff5470;--md:#ffb454;--lo:#4fd1a0;--accent:#38bdf8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 "Pretendard",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
header{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:20px}
h1{font-size:22px;margin:0 0 6px}h2{font-size:16px;margin:34px 0 12px;color:var(--accent);border-left:3px solid var(--accent);padding-left:8px}
h4{margin:12px 0 6px}code{background:#0a0e13;border:1px solid var(--line);padding:1px 5px;border-radius:4px;font-size:12px}
pre{background:#0a0e13;border:1px solid var(--line);border-radius:6px;padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap}
.meta{color:var(--dim);font-size:12px}
.verdict{font-size:30px;font-weight:800;padding:14px 18px;border-radius:10px;margin:14px 0;border:1px solid var(--line)}
.v-pass{color:var(--lo);border-color:var(--lo)}.v-risks{color:var(--md);border-color:var(--md)}.v-fail{color:var(--hi);border-color:var(--hi)}.v-inc{color:var(--dim)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.kpi-v{font-size:24px;font-weight:700;color:var(--accent)}.kpi-l{font-size:12px;color:var(--dim);margin-top:2px}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
th{color:var(--dim);text-align:left;border-bottom:1px solid var(--line);padding:6px 8px}
td{border-bottom:1px solid #161f2a;padding:6px 8px;vertical-align:top}
.sev-hi td:first-child{color:var(--hi)}.sev-md td:first-child{color:var(--md)}.sev-lo td:first-child{color:var(--lo)}
.tag{font-size:11px;border:1px solid var(--line);border-radius:10px;padding:1px 8px;color:var(--dim)}
.path{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;padding:10px 14px;margin:10px 0}
.attack{color:var(--md);font-size:12px;margin:8px 0 0}.refs{color:var(--dim);font-size:12px}
.routemap{font-family:ui-monospace,Menlo,monospace;color:var(--accent);margin:6px 0}
.log{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--dim);border-bottom:1px solid #141c26;padding:1px 0}
details summary{cursor:pointer;color:var(--accent)}
footer{color:var(--dim);font-size:11px;margin-top:40px;border-top:1px solid var(--line);padding-top:10px}
</style></head><body><div class="wrap">
<header><h1>🔒 Hardening Report — ${esc(p.name)}</h1>
<div class="verdict ${r.gate.verdict === "PASS" ? "v-pass" : r.gate.verdict === "PASS_WITH_RISKS" ? "v-risks" : r.gate.verdict === "FAIL" ? "v-fail" : "v-inc"}">${VERDICT_KO[r.gate.verdict]}</div>
<div class="meta">${esc(r.gate.reason)}<br>실행 ${esc(r.startedAt)} → ${esc(r.finishedAt)} (${fmtDur(r.durationMs)}) · ${r.live ? "live cross-check" : "오프라인"}</div></header>
<div class="kpis">
<div class="kpi"><div class="kpi-v">${r.findings.length}</div><div class="kpi-l">발견</div></div>
<div class="kpi"><div class="kpi-v">${counts.critical + counts.high}</div><div class="kpi-l">critical+high</div></div>
<div class="kpi"><div class="kpi-v">${r.routes.length}</div><div class="kpi-l">공격 루트</div></div>
<div class="kpi"><div class="kpi-v">${p.components.length}</div><div class="kpi-l">컴포넌트</div></div>
</div>
<h2>1. 시스템 프로필</h2>
<table><tr><th>항목</th><th>값</th></tr>
<tr><td>컴포넌트</td><td>${p.components.map((c) => `<code>${esc(c.label)}</code>`).join(" ") || "(인식 불가)"}</td></tr>
<tr><td>버전</td><td>${vers.map((v) => `<code>${esc(v)}</code>`).join(" ") || "—"}</td></tr>
<tr><td>포트</td><td>${p.ports.map((x) => `<code>${esc(String(x))}</code>`).join(" ") || "(미언급)"}</td></tr>
<tr><td>특징</td><td>${esc(p.flags.join(" / ") || "—")}</td></tr>
</table>
${p.notes.length ? `<details><summary>추론 메모</summary><ul>${p.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></details>` : ""}
<h2>2. 발견 내역 (${r.findings.length})</h2>
${r.findings.length === 0 ? "<p>발견 없음.</p>" : `<table><tr><th>id</th><th>등급</th><th>위험</th><th>공격 시나리오</th></tr>${findRows.join("")}</table>`}
<h2>3. 우선순위 재보안 목록</h2>
${r.findings.length === 0 ? "<p>할 일 없음 — 통과.</p>" : `<table><tr><th>우선순위</th><th>id</th><th>수정안</th><th>노력</th><th>CWE</th></tr>${fixRows.join("")}</table>`}
<h2>4. 공격 루트 합성</h2>
${routeBlocks || "<p>합성 가능한 루트 없음.</p>"}
<h2>5. Live Cross-check</h2>
${r.live ? (r.live.reachable
  ? `<p>대상 <code>${esc(r.live.url)}</code> 도달 — 지문 <code>${esc(JSON.stringify(r.live.fingerprint))}</code></p>
     <ul>${r.live.findings.slice(0, 12).map((f) => `<li class="${sevCls(f.severity)}">[${esc(f.severity)}] ${esc(f.title)}</li>`).join("")}</ul>`
  : `<p class="v-inc">미도달: ${esc(r.live.reason ?? "사유 없음")}</p>`) : "<p>오프라인 모드 — live cross-check 없음.</p>"}
<h2>6. 실행 로그</h2>
${logLines}
<footer>_RedCell harden · 규칙기반 결정론 재보안 · ${esc(r.finishedAt)}_</footer>
</div></body></html>`;
}
