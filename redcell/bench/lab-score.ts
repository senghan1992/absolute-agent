
/**
 * lab-score.ts — P1 랩 벤치마크 채점 엔진.
 *
 * "랩을 풀었다(solved)"의 정의: 해당 랩의 정답(manifest expect)대로
 * 취약점 클래스가 발견되고, 그 발견이 **검증(실증) 단계까지 올라가야** 한다.
 *   - 클래스 미발견        → 미해결(FN, 놓침)
 *   - 발견했지만 검증 실패  → 미해결(가능성만, 실증 없음)
 *   - 발견 + verified + proof 조건 충족 → 해결
 *
 * 로컬 랩/PortSwigger 랩 공통으로 사용한다(출처 불문).
 */

export interface LabExpect {
  /** finding.title 에 포함되어야 할 문자열(대소문자 무시). */
  findingText: string[];
  /** 참조하는 증거가 verification.status === "verified" 이어야 하는가. */
  verified: boolean;
  /** verified 증거의 proof 에 포함되어야 할 문자열. */
  proofContains?: string[];
  /** verified 증거가 가져야 할 evidence.category (예: error, secret). */
  evidenceCategory?: string;
  /** 클린 랩(정답 = 취약점 없음): 발견 0 + verified 증거 0 이어야 해결. */
  clean?: boolean;
}

export interface LabManifest {
  name: string;
  class: string;
  source: "local" | "portswigger" | string;
  port?: number;
  start?: string[];
  url: string;
  expect: LabExpect;
}

export interface LabScore {
  manifestName: string;
  solved: boolean;
  missing: string[];      // 충족 못한 기대 조건
  detail: string[];       // 일치한 증거 요약
  hasVerified: boolean;
}

export function scoreLabReport(report: { findings: Array<{ title: string; evidenceRefs?: string[] }>; exposed?: Array<{ id: string; verification?: { status: string; proof?: string } }> }, expect: LabExpect): LabScore {
  const exposed = report.exposed ?? [];
  const byId = new Map(exposed.map((e) => [e.id, e]));
  const missing: string[] = [];
  const detail: string[] = [];
  const lower = (s: string) => s.toLowerCase();

  // 0) 클린 랩(negative control): 발견·verified 증거 모두 없어야 정답
  if (expect.clean) {
    const serious = (report.findings ?? []).filter((f) => { const s = (f as any).severity ?? ""; return s === "high" || s === "critical"; });
    const cleanOk = serious.length === 0 && !(report.exposed ?? []).some((e) => e.verification?.status === "verified");
    if (!cleanOk) missing.push("클린 랩에서 high/critical 발견 또는 검증 증거 발생(오탐/FP)");
    return { manifestName: "clean", solved: cleanOk, missing, detail, hasVerified: false };
  }

  // 1) 클래스 발견
  const matched: Array<{ title: string; evidenceRefs?: string[] }> = [];
  for (const f of report.findings ?? []) {
    const t = f.title ?? "";
    if (expect.findingText.some((k) => lower(t).includes(lower(k)))) matched.push(f);
  }
  if (matched.length === 0) missing.push(`클래스 미발견 (기대: ${expect.findingText.join("|")})`);

  // 2) 검증(실증) — (a) 발견이 직접 참조하는 증거(evidenceRefs) 또는
  //    (b) 기대 카테고리(evidenceCategory)의 증거 중 verified + proof 조건을 충족해야 한다.
  const refs = matched.flatMap((f) => (f as any).evidenceRefs ?? []);
  let verifiedEvs = [...new Set(refs)].map((id) => byId.get(id)).filter((e): e is NonNullable<typeof e> => !!e && e.verification?.status === "verified");
  if (expect.evidenceCategory) {
    const catVerified = exposed.filter((e) => ((e as any).category ?? "") === expect.evidenceCategory && e.verification?.status === "verified");
    if (catVerified.length) verifiedEvs = catVerified;
  }
  const hasVerified = verifiedEvs.length > 0;
  if (expect.verified && !hasVerified) missing.push("검증(verified) 증거 없음 — 가능성 단계에 머묾");

  let proofOk = true;
  for (const want of expect.proofContains ?? []) {
    if (!verifiedEvs.some((e) => (e.verification!.proof ?? "").includes(want))) {
      proofOk = false;
      missing.push(`proof 에 "${want}" 없음`);
    }
  }

  const gotProofs = verifiedEvs.map((e) => e.verification!.proof ?? "").filter(Boolean);
  if (gotProofs.length) detail.push(`검증된 착취 ${gotProofs.length}건: ${gotProofs[0]}`);
  if (matched.length) detail.push(`클래스 발견 ${matched.length}건 (예: ${matched[0].title})`);

  return { manifestName: expect.findingText[0] ?? "", solved: missing.length === 0 && proofOk, missing, detail, hasVerified };
}
