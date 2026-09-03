/**
 * report — engagement 결과를 Markdown 리포트로 변환.
 * 화이트해커 결과물의 핵심은 "재현 가능하고 방어에 쓰이는 보고서"다.
 */

import type { EngagementLog, EngagementFinding, Coverage, GateVerdict } from "../core/types.js";
import { deriveChains } from "./chains.js";
import { digestReport, signDigest, type Provenance, type WaivedFinding } from "./provenance.js";

const SEV_ORDER: EngagementFinding["severity"][] = ["critical", "high", "medium", "low", "info"];

const VERDICT_BADGE: Record<GateVerdict, string> = {
  clean: "🟢 PASS(clean)",
  findings: "🔴 FAIL(findings)",
  inconclusive: "🟡 INCONCLUSIVE",
};

export interface ReportOptions {
  /** 리포트 출처(서명 리포트). 있으면 출처 섹션 + 무결성 다이제스트를 붙인다. */
  provenance?: Provenance;
  /** 정식 수용된 발견(waiver). 있으면 "수용된 위험" 섹션에 별도 표기(숨김 아님). */
  waived?: WaivedFinding[];
  /** 리포트 서명 키(옵션 HMAC). 없으면 무서명 다이제스트만. */
  signingKey?: string;
}

export function toMarkdown(log: EngagementLog, opts: ReportOptions = {}): string {
  const lines: string[] = [];
  const t = log.target;
  lines.push(`# RedCell Engagement Report`);
  lines.push("");
  lines.push(`- 대상: \`${t.host}${t.port ? ":" + t.port : ""}\``);
  lines.push(`- 핑거프린트: ${fmtFp(log)}`);
  lines.push(`- 재사용한 학습(playbook): ${log.usedPlaybooks.length}건`);
  lines.push(`- 새로 학습한 playbook: ${log.distilled.length}건`);
  lines.push("");

  // 게이트 판정/커버리지 — "발견 0"과 "안 봄"을 구분해 거짓 안전을 막는다.
  if (log.verdict && log.coverage) {
    lines.push(...gateSection(log.verdict, log.verdictReason, log.coverage));
    lines.push("");
  }

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

  // 공격 체인(발견 조합) — 방어 우선순위 판단용.
  const chains = deriveChains(log.findings);
  if (chains.length > 0) {
    lines.push(`## 공격 체인(조합 위험)`);
    for (const c of chains) {
      lines.push(`### ${badge(c.severity)} ${esc(c.title)}`);
      lines.push(`- 구성: ${c.links.map((l) => esc(l)).join(" + ")}`);
      lines.push(`- 영향: ${esc(c.impact)}`);
      lines.push(`- 방어: ${esc(c.defense)}`);
      lines.push("");
    }
  }

  const actionable = log.findings.filter((f) => f.severity !== "info");
  if (actionable.length > 0) {
    lines.push(`## 상세 및 방어 권고`);
    for (const f of actionable) {
      lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(f.detail);
      if (f.evidence) lines.push(`\n> 근거: ${f.evidence}`);
      lines.push(`\n예상 영향(피해 반경): ${impactHint(f)}`);
      lines.push(`\n권고: ${remediationHint(f)}`);
      lines.push("");
    }
  }

  // 정식 수용된 위험(waiver) — 숨기지 않고 승인자·사유·만료와 함께 별도로 남긴다.
  if (opts.waived && opts.waived.length > 0) {
    lines.push(`## 수용된 위험(Accepted Risk / Waived)`);
    lines.push(`_아래 발견은 승인자가 정식으로 위험을 수용해 게이트 판정에서 제외되었습니다(무효화가 아닌 수용)._`);
    lines.push("");
    lines.push("| 심각도 | 제목 | 승인자 | 만료 | 사유 | 티켓 |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    for (const w of opts.waived) {
      const f = w.finding;
      lines.push(
        `| ${badge(f.severity)} | ${esc(f.title)} | ${esc(w.waiver.approved_by)} | ${esc(w.waiver.expires)} | ${esc(w.waiver.reason)} | ${esc(w.waiver.ticket ?? "-")} |`,
      );
    }
    lines.push("");
  }

  lines.push(`## 실행 로그(Transcript)`);
  lines.push("```");
  lines.push(...log.transcript);
  lines.push("```");

  lines.push("");
  lines.push(`> 본 리포트는 인가된 대상에 대한 테스트 결과입니다. 데이터 추출은 취약점 증명(PoC) 최소 범위로 제한되었습니다.`);

  // 출처/무결성(서명 리포트) — 본문 다이제스트를 마지막에 붙인다(다이제스트는 위 본문 전체를 커버).
  if (opts.provenance) {
    const body = lines.join("\n");
    const digest = digestReport(body, opts.provenance);
    const sig = signDigest(digest, opts.signingKey);
    lines.push(...provenanceSection(opts.provenance, digest, sig));
  }
  return lines.join("\n");
}

/** 리포트 출처 + 무결성 다이제스트 섹션. 배포된 리포트의 위변조 검증 근거. */
function provenanceSection(p: Provenance, digest: string, sig: { algo: string; value: string }): string[] {
  const out: string[] = [];
  out.push("");
  out.push(`## 리포트 출처·무결성(Provenance)`);
  out.push(`- 툴: ${esc(p.tool)} v${esc(p.version)}${p.toolCommit ? ` (commit ${esc(p.toolCommit)})` : ""}`);
  out.push(`- 룰셋 해시: \`${esc(p.rulesetHash)}\` (탐지 툴 표면 지문)`);
  out.push(`- 대상 참조: ${p.targetRef ? "`" + esc(p.targetRef) + "`" : "미지정(운영자 target_ref 권장)"}`);
  out.push(`- Engagement: ${esc(p.engagement)}`);
  out.push(`- 인가자(authorized_by): ${esc(p.authorizedBy)}`);
  out.push(`- 운영자(operator): ${p.operator ? esc(p.operator) : "미지정"}`);
  out.push(`- 생성 시각: ${esc(p.generatedAt)}`);
  out.push(`- 무결성 다이제스트(SHA-256): \`${digest}\``);
  out.push(`- 서명: \`${sig.algo}\` = \`${sig.value}\``);
  out.push(`> 검증: 위 본문(이 섹션 제외)과 출처 메타로 다이제스트를 재계산해 일치를 확인하세요.`);
  return out;
}

/**
 * 게이트 판정 + 커버리지 섹션. clean 은 "검사한 표면 한정"임을 항상 함께 못박는다(거짓 안전 방지).
 */
function gateSection(verdict: GateVerdict, reason: string | undefined, cov: Coverage): string[] {
  const out: string[] = [];
  out.push(`## 게이트 판정: ${VERDICT_BADGE[verdict]}`);
  if (reason) out.push(`- 사유: ${esc(reason)}`);
  out.push(
    `- 커버리지: 도달=${cov.reachable ? "예" : "아니오"}, 실행 툴=${cov.toolsRun}/${cov.toolsTotal}, ` +
      `발견 엔드포인트=${cov.endpointsDiscovered}, 익스플로잇 계열=${cov.vulnClassesTested.length}종, ` +
      `인증 표면=${cov.authScanned ? "점검함" : "미점검"}, 요청오류=${cov.requestErrors}, ` +
      `모드=${cov.deterministic ? "결정적 전수(--full)" : "밴딧 탐색"}`,
  );
  // 커버리지 한계 면책은 판정과 무관하게 항상 출력한다(거짓 안전 방지 — clean 이든 findings 든
  // "여기서 안 나온 것 = 안전"이 아니다). 판정별로 문구만 맞춘다.
  if (verdict === "clean") {
    out.push(
      `- ⚠️ 주의: 이 PASS 는 위에 측정된 계열·표면에 한한 결과이며 전체 안전을 보증하지 않습니다. ` +
        `저장형/2차 취약점, 비즈니스 로직, 의존성 CVE(SCA), 인증·세션 심층, 클라이언트(SPA) 표면은 이 도구 범위 밖입니다. ` +
        `수동 펜테스트·SCA·인증/로직 리뷰를 병행하세요.`,
    );
  } else {
    out.push(
      `- ⚠️ 주의: 이 결과는 위에 측정된 계열·표면에 한한 것입니다. 발견을 모두 해소해도 "전체 안전"은 아닙니다 — ` +
        `저장형/2차 취약점, 비즈니스 로직, 의존성 CVE(SCA), 인증·세션 심층, 클라이언트(SPA) 표면은 이 도구 범위 밖입니다. ` +
        `수동 펜테스트·SCA·인증/로직 리뷰를 병행하세요.`,
    );
  }
  if (!cov.deterministic) {
    out.push(`- ℹ️ 재현성: 밴딧 탐색 모드는 실행마다 커버리지가 달라질 수 있습니다. 게이트 판정에는 --full(결정적 전수)로 재실행하세요.`);
  }
  return out;
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

/**
 * 예상 영향/피해 반경(blast radius). 툴이 직접 준 impact 를 우선 쓰고,
 * 없으면 취약점 유형별 기본 영향 서술로 보강한다. (서술만 — 실제 피해는 내지 않음)
 */
function impactHint(f: EngagementFinding): string {
  if (f.impact) return f.impact;
  const t = f.title.toLowerCase();
  if (t.includes("sql")) return "DB 인증 우회·전체 테이블 덤프·자격증명 탈취 가능 → 계정 탈취/데이터 유출로 확산.";
  if (t.includes("xss")) return "피해자 브라우저에서 세션 쿠키·토큰 탈취, 요청 위조, 관리자 계정 장악으로 확산.";
  if (t.includes("ssti") || t.includes("command") || t.includes("커맨드")) return "서버에서 임의 코드 실행 → 호스트 장악·내부망 측면이동·데이터 전면 유출.";
  if (t.includes("traversal") || t.includes("lfi") || t.includes("경로")) return "설정/자격증명 파일·소스코드 열람 → 추가 침투용 비밀 획득.";
  if (t.includes("ssrf")) return "내부 서비스·클라우드 메타데이터 접근 → 임시 자격증명 탈취·내부망 정찰.";
  if (t.includes("idor") || t.includes("접근") || t.includes("권한")) return "타 사용자 데이터 대량 열람·변조 → 대규모 개인정보 유출.";
  if (t.includes("redirect")) return "신뢰 도메인을 미끼로 한 피싱·OAuth 토큰 탈취 신뢰도 상승.";
  if (t.includes("cors")) return "악성 사이트가 피해자 세션으로 인증 API 를 교차출처 호출 → 데이터 유출.";
  if (t.includes("secret") || t.includes("비밀") || t.includes("노출")) return "노출된 키/토큰으로 인증 표면·클라우드 자원에 직접 접근.";
  if (t.includes("jwt")) return "토큰 위조로 임의 사용자·관리자 사칭 → 인증 전면 우회.";
  if (t.includes("csrf")) return "피해자 권한으로 상태변경(송금·설정변경·비밀번호 변경) 강제 실행.";
  if (t.includes("upload")) return "웹셸 업로드 시 원격 코드 실행으로 확산될 수 있음(포함/실행 경로 존재 시).";
  if (t.includes("xxe")) return "내부 파일 열람·SSRF·서비스 거부로 확산 가능.";
  if (t.includes("method") || t.includes("메서드")) return "위험 메서드 활성 시 콘텐츠 변조·XST 로 인증정보 탈취 가능.";
  if (t.includes("host")) return "비밀번호 재설정 링크 변조·캐시 포이즈닝으로 계정 탈취·대량 사용자 영향.";
  if (t.includes("pollution") || t.includes("오염")) return "파라미터 파싱 불일치로 접근통제·WAF 우회 가능.";
  return "노출 표면 확대로 후속 공격의 발판이 될 수 있음.";
}

function remediationHint(f: EngagementFinding): string {
  const t = f.title.toLowerCase();
  if (t.includes("sql")) return "파라미터화 쿼리/ORM 사용, 최소권한 DB 계정, 입력 검증. (OWASP A03)";
  if (t.includes("xss")) return "출력 인코딩, CSP 적용, 신뢰 못할 입력의 DOM 삽입 금지. (OWASP A03)";
  if (t.includes("버전") || t.includes("version") || t.includes("탐지")) return "불필요한 배너/버전 노출 최소화, 최신 패치 유지.";
  return "해당 컴포넌트를 최신 패치로 갱신하고 노출 표면을 축소하세요.";
}
