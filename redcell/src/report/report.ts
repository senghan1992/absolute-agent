/**
 * report — engagement 결과를 Markdown 리포트로 변환.
 * 화이트해커 결과물의 핵심은 "재현 가능하고 방어에 쓰이는 보고서"다.
 */

import type { EngagementLog, EngagementFinding } from "../core/types.js";

const SEV_ORDER: EngagementFinding["severity"][] = ["critical", "high", "medium", "low", "info"];

export function toMarkdown(log: EngagementLog): string {
  const lines: string[] = [];
  const t = log.target;
  lines.push(`# RedCell Engagement Report`);
  lines.push("");
  lines.push(`- 대상: \`${t.host}${t.port ? ":" + t.port : ""}\``);
  lines.push(`- 핑거프린트: ${fmtFp(log)}`);
  lines.push(`- 재사용한 학습(playbook): ${log.usedPlaybooks.length}건`);
  lines.push(`- 새로 학습한 playbook: ${log.distilled.length}건`);
  lines.push("");

  lines.push(`## 요약(Findings)`);
  if (log.findings.length === 0) {
    lines.push("_유의미한 발견 없음._");
  } else {
    const sorted = [...log.findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    lines.push("| 심각도 | 단계 | 제목 | 근거 |");
    lines.push("| --- | --- | --- | --- |");
    for (const f of sorted) {
      lines.push(`| ${badge(f.severity)} | ${f.phase} | ${esc(f.title)} | ${esc(f.evidence ?? "-")} |`);
    }
  }
  lines.push("");

  const actionable = log.findings.filter((f) => f.severity !== "info");
  if (actionable.length > 0) {
    lines.push(`## 상세 및 방어 권고`);
    for (const f of actionable) {
      lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(f.detail);
      if (f.evidence) lines.push(`\n> 근거: ${f.evidence}`);
      lines.push(`\n권고: ${remediationHint(f)}`);
      lines.push("");
    }
  }

  lines.push(`## 실행 로그(Transcript)`);
  lines.push("```");
  lines.push(...log.transcript);
  lines.push("```");

  lines.push("");
  lines.push(`> 본 리포트는 인가된 대상에 대한 테스트 결과입니다. 데이터 추출은 취약점 증명(PoC) 최소 범위로 제한되었습니다.`);
  return lines.join("\n");
}

function fmtFp(log: EngagementLog): string {
  const fp = log.fingerprint;
  const parts = [fp.service, fp.version, ...(fp.tech ?? [])].filter(Boolean);
  return parts.length ? "`" + parts.join(" / ") + "`" : "미상";
}

function badge(s: EngagementFinding["severity"]): string {
  return { critical: "🔴 CRIT", high: "🟠 HIGH", medium: "🟡 MED", low: "🔵 LOW", info: "⚪ INFO" }[s];
}

function esc(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function remediationHint(f: EngagementFinding): string {
  const t = f.title.toLowerCase();
  if (t.includes("sql")) return "파라미터화 쿼리/ORM 사용, 최소권한 DB 계정, 입력 검증. (OWASP A03)";
  if (t.includes("xss")) return "출력 인코딩, CSP 적용, 신뢰 못할 입력의 DOM 삽입 금지. (OWASP A03)";
  if (t.includes("버전") || t.includes("version") || t.includes("탐지")) return "불필요한 배너/버전 노출 최소화, 최신 패치 유지.";
  return "해당 컴포넌트를 최신 패치로 갱신하고 노출 표면을 축소하세요.";
}
