/**
 * 전투 보고 렌더러 — markdown / self-contained HTML / JSON.
 *
 * HTML 은 단일 파일이라 그대로 공유 가능하다: 인라인 CSS + <details> 폴드, JS 불필요.
 * 다크 "미션 컨트롤" 스타일. 출력 경로는 실행 시 콘솔에 인쇄된다.
 */

import type { AssaultReport, AttackPath, DefenseItem, EvidenceItem, ToolOutcome } from "./types.js";
import { verificationBadge } from "./verify.js";

export function fmtDur(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}초`;
  return `${Math.floor(s / 60)}분 ${s % 60}초`;
}

const SEV_BADGE: Record<string, string> = {
  critical: "[CRITICAL]",
  high: "[HIGH]",
  medium: "[MED]",
  low: "[LOW]",
  info: "[INFO]",
};

const CAT_KO: Record<string, string> = {
  secret: "자격증명",
  pii: "개인정보",
  schema: "스키마/명세",
  config: "설정/진단",
  backup: "백업/소스",
  error: "오류누설",
  endpoint: "이면경로",
  exploit: "익스플로잇",
};

// ── Markdown ─────────────────────────────────────────────────────────────────

export function toMarkdown(r: AssaultReport): string {
  const L: string[] = [];
  L.push(`# 🎯 전투 보고 — ${r.target.host}:${r.target.port}`);
  L.push("");
  L.push(`> 대상: \`${r.target.url}\``);
  L.push(`> 실행: ${r.startedAt} → ${r.finishedAt} (${fmtDur(r.durationMs)})`);
  L.push(`> 인가: \`${r.meta.authPath}\` (${r.meta.authKind}) · AI 해석: ${r.meta.model}`);
  L.push(`> 판정: **${r.verdict}** — ${r.verdictReason}`);
  L.push("");

  // 1. 매니페스트
  L.push(`## 🧬 탈취 가능 정보 매니페스트 (${r.exposed.length}건)`);
  L.push("");
  if (r.exposed.length === 0) {
    L.push("_확인된 탈취 가능 데이터 없음._");
  } else {
    L.push("| id | 등급 | 분류 | 항목 | 위치 |");
    L.push("|---|---|---|---|---|");
    for (const e of r.exposed) {
      L.push(`| ${e.id} | ${SEV_BADGE[e.severity]} | ${CAT_KO[e.category] ?? e.category} | ${e.label} | \`${e.target}\` |`);
    }
    L.push("");
    for (const e of r.exposed) {
      L.push(`### ${e.id} — ${e.label}`);
      L.push("");
      L.push(`- **분류:** ${CAT_KO[e.category] ?? e.category} · **등급:** ${e.severity} · **출처:** ${e.source}`);
      L.push(`- **위치:** \`${e.target}\``);
      if (e.itemCount !== undefined) L.push(`- **노출 항목 수:** ${e.itemCount}`);
      if (e.verification) L.push(`- **검증:** ${verificationBadge(e.verification.status)} — ${e.verification.proof}`);
      L.push("");
      L.push("```");
      L.push(e.sample.length > 0 ? e.sample : "(증거 샘플 없음 — 목록/노출 자체가 증거)");
      L.push("```");
      L.push("");
      L.push(`> 🔓 공격자 입장: ${e.attack}`);
      L.push("");
    }
  }

  // 2. 공격 경로
  L.push(`## ⚔️ 공격 경로 (${r.attackPaths.length})`);
  L.push("");
  for (const p of r.attackPaths) {
    L.push(`### ${p.source === "ai" ? "🤖" : "🔧"} ${p.label} — ${SEV_BADGE[p.severity]}`);
    L.push("");
    p.chain.forEach((s, i) => L.push(`${i + 1}. ${s}`));
    if (p.evidenceRefs.length) L.push("");
    for (const ref of p.evidenceRefs) L.push(`   - 증거: ${ref}`);
    L.push("");
  }

  // 3. 발견
  L.push(`## 🚨 발견 내역 (${r.findings.length})`);
  L.push("");
  if (r.findings.length === 0) {
    L.push("_미탐._");
  } else {
    L.push("| 심각도 | 툴 | 제목 | 근거 |");
    L.push("|---|---|---|---|");
    for (const f of r.findings) {
      L.push(`| ${SEV_BADGE[f.severity]} | ${f.phase} | ${f.title} | ${(f.detail ?? "").slice(0, 60)} |`);
    }
    L.push("");
  }

  // 4. 방어
  L.push(`## 🛡️ 방어 권고 (${r.defense.length})`);
  L.push("");
  for (const d of r.defense) {
    L.push(`- **${SEV_BADGE[d.severity]} ${d.control}** — ${d.detail}`);
  }
  L.push("");

  // 5. 요약
  L.push(`## 📋 전투 요약`);
  L.push("");
  L.push(r.narrative);
  L.push("");

  // 6. 커버리지
  L.push(`## 📡 커버리지`);
  L.push("");
  L.push(`- 툴 실행: ${r.outcomes.length}건 (단계: ${Object.entries(r.stages).map(([s, v]) => `${s}=${v.status}(${v.toolsRun})`).join(", ")})`);
  L.push(`- 취약점 클래스 점검: ${r.coverage.vulnClassesTested.length > 0 ? r.coverage.vulnClassesTested.join(", ") : "없음"}`);
  L.push(`- 인증 표면: ${r.coverage.authScanned ? "점검됨" : "미점검(자격증명 없음)"} · 도달 가능: ${r.coverage.reachable ? "예" : "아니오"}`);
  L.push("");

  // 7. 전사
  L.push(`## 🧾 전사 (최근 ${Math.min(r.transcript.length, 60)}행)`);
  L.push("");
  for (const line of r.transcript.slice(-60)) L.push(`    ${line}`);
  L.push("");
  L.push("---");
  L.push(`_RedCell assault · ${r.meta.command} · redaction ${r.meta.redact ? "ON" : "OFF"}_`);
  return L.join("\n");
}

// ── HTML (self-contained, dark mission control) ──────────────────────────────

const esc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function toHtml(r: AssaultReport): string {
  const sevCls = (s: string) => (["critical", "high"].includes(s) ? "sev-hi" : s === "medium" ? "sev-md" : "sev-lo");
  const target = r.target;
  const origin = `${target.scheme}://${target.host}${target.port !== 80 && target.port !== 443 ? ":" + target.port : ""}${target.path}`;

  const kpi = (label: string, value: string, sub: string) =>
    `<div class="kpi"><div class="kpi-v">${value}</div><div class="kpi-l">${label}</div><div class="kpi-s">${sub}</div></div>`;

  const evRows = r.exposed.map(
    (e: EvidenceItem) => `<tr class="${sevCls(e.severity)}">
      <td>${e.id}</td><td>${esc(e.severity)}</td><td>${esc(CAT_KO[e.category] ?? e.category)}</td>
      <td>${esc(e.label)}</td><td><code>${esc(e.target)}</code></td>
      <td><details><summary>샘플 ${e.redacted ? "🔒 redacted" : ""}</summary><pre>${esc(e.sample || "(샘플 없음)")}</pre>
      ${e.verification ? `<p class="verify ver-${esc(e.verification.status)}">${verificationBadge(e.verification.status)} — ${esc(e.verification.proof)}</p>` : ""}
      <p class="attack">🔓 ${esc(e.attack)}</p></details></td></tr>`,
  );

  const pathBlocks = r.attackPaths.map(
    (p: AttackPath) => `<div class="path ${sevCls(p.severity)}">
      <h4>${p.source === "ai" ? "🤖" : "🔧"} ${esc(p.label)} <span class="tag">${esc(p.severity)}</span></h4>
      <ol>${p.chain.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
      ${p.evidenceRefs.length ? `<p class="refs">증거: ${p.evidenceRefs.map((x) => `<code>${x}</code>`).join(" ")}</p>` : ""}
    </div>`,
  );

  const findRows = r.findings.map(
    (f) => `<tr class="${sevCls(f.severity)}"><td>${esc(f.severity)}</td><td>${esc(f.phase)}</td><td>${esc(f.title)}</td><td>${esc((f.detail ?? "").slice(0, 90))}</td></tr>`,
  );

  const defItems = r.defense.map(
    (d: DefenseItem) => `<li class="${sevCls(d.severity)}"><b>${esc(d.control)}</b> — ${esc(d.detail)}</li>`,
  );

  const stageRows = Object.entries(r.stages)
    .map(([s, v]) => `<tr><td>${esc(s)}</td><td>${esc(v.status)}</td><td>${v.toolsRun}</td><td>${v.findings}</td><td>${fmtDur(v.durationMs)}</td></tr>`)
    .join("");

  const logLines = r.transcript.slice(-120).map((l) => `<div class="log">${esc(l)}</div>`).join("");

  return `<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>전투 보고 — ${esc(target.host)}:${target.port}</title>
<style>
:root{--bg:#0b0f14;--panel:#121821;--line:#1f2a38;--fg:#d7e0ea;--dim:#8b98a5;--hi:#ff5470;--md:#ffb454;--lo:#4fd1a0;--accent:#38bdf8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 "Pretendard",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:20px}
h1{font-size:22px;margin:0 0 6px}h2{font-size:16px;margin:34px 0 12px;color:var(--accent);border-left:3px solid var(--accent);padding-left:8px}
h3,h4{margin:14px 0 6px}code{background:#0a0e13;border:1px solid var(--line);padding:1px 5px;border-radius:4px;font-size:12px}
pre{background:#0a0e13;border:1px solid var(--line);border-radius:6px;padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap}
.meta{color:var(--dim);font-size:12px}.kv{color:var(--accent)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.kpi-v{font-size:26px;font-weight:700;color:var(--accent)}.kpi-l{font-size:12px;color:var(--dim);margin-top:2px}.kpi-s{font-size:11px;color:var(--dim)}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}
th{color:var(--dim);text-align:left;border-bottom:1px solid var(--line);padding:6px 8px}
td{border-bottom:1px solid #161f2a;padding:6px 8px;vertical-align:top}
.sev-hi td:first-child,.sev-hi td:nth-child(2){color:var(--hi)}.sev-md td:first-child,.sev-md td:nth-child(2){color:var(--md)}.sev-lo td:first-child,.sev-lo td:nth-child(2){color:var(--lo)}
.tag{font-size:11px;border:1px solid var(--line);border-radius:10px;padding:1px 8px;color:var(--dim)}
.path{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;padding:10px 14px;margin:10px 0}
.attack{color:var(--md);font-size:12px;margin:8px 0 0}
.verify{font-size:12px;margin:8px 0 0;padding:4px 8px;border-radius:4px;border:1px solid var(--line)}
.verify.ver-verified{color:var(--lo);border-color:var(--lo)}
.verify.ver-partial{color:var(--md);border-color:var(--md)}
.verify.ver-unverified{color:var(--dim);border-color:var(--line)}
.refs{color:var(--dim);font-size:12px}
ul.defs li{margin:6px 0;list-style:none;padding:8px 10px;background:var(--panel);border:1px solid var(--line);border-radius:6px}
.narrative{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px;white-space:pre-wrap}
.log{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--dim);border-bottom:1px solid #141c26;padding:1px 0}
details summary{cursor:pointer;color:var(--accent)}
footer{color:var(--dim);font-size:11px;margin-top:40px;border-top:1px solid var(--line);padding-top:10px}
</style></head><body><div class="wrap">
<header><h1>🎯 전투 보고 — ${esc(target.host)}:${target.port}</h1>
<div class="meta">대상 <span class="kv">${esc(origin)}</span> · 판정 <span class="kv">${esc(r.verdict)}</span> — ${esc(r.verdictReason)}<br>
실행 ${esc(r.startedAt)} → ${esc(r.finishedAt)} (${fmtDur(r.durationMs)}) · 인가 \`${esc(r.meta.authPath)}\` · AI: ${esc(r.meta.model)}</div>
</header>
<div class="kpis">
${kpi("툴 실행", String(r.outcomes.length), `단계 ${Object.keys(r.stages).length}개`)}
${kpi("발견", String(r.findings.length), `${r.findings.filter((f) => f.severity === "high" || f.severity === "critical").length}건 high+`)}
${kpi("탈취 가능 정보", String(r.exposed.length), `${r.exposed.filter((e) => e.severity === "high" || e.severity === "critical").length}건 high+`)}
${kpi("공격 경로", String(r.attackPaths.length), `방어 권고 ${r.defense.length}`)}
</div>
<h2>🧬 탈취 가능 정보 매니페스트</h2>
${r.exposed.length === 0 ? "<p>확인된 탈취 가능 데이터 없음.</p>" : `<table><tr><th>id</th><th>등급</th><th>분류</th><th>항목</th><th>위치</th><th>샘플</th></tr>${evRows.join("")}</table>`}
<h2>⚔️ 공격 경로</h2>
${pathBlocks.join("")}
<h2>🚨 발견 내역</h2>
${r.findings.length === 0 ? "<p>미탐.</p>" : `<table><tr><th>심각도</th><th>단계</th><th>제목</th><th>근거</th></tr>${findRows.join("")}</table>`}
<h2>🛡️ 방어 권고</h2>
${r.defense.length ? `<ul class="defs">${defItems.join("")}</ul>` : "<p>권고 없음.</p>"}
<h2>📋 전투 요약</h2>
<div class="narrative">${esc(r.narrative)}</div>
<h2>📡 실행 단계</h2>
<table><tr><th>단계</th><th>상태</th><th>툴</th><th>발견</th><th>소요</th></tr>${stageRows}</table>
<h2>🧾 전사</h2>
${logLines}
<footer>_RedCell assault · ${esc(r.meta.command)} · 모델 ${esc(r.meta.model)} · redaction ${r.meta.redact ? "ON" : "OFF"} · full-exposure ${r.meta.fullExposure ? "ON" : "OFF"}_</footer>
</div></body></html>`;
}

// ── JSON ─────────────────────────────────────────────────────────────────────

export function toJson(r: AssaultReport): string {
  return JSON.stringify(r, null, 2);
}

/** 실행 로그 한 줄(transcript 에 기록). */
export function logLine(tool: string, m: string): string {
  return `[${new Date().toISOString().slice(11, 19)}] ${tool.padEnd(18)} ${m}`;
}
