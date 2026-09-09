
import { describe, it, expect } from "vitest";
import { scoreLabReport, type LabExpect } from "../bench/lab-score.js";

const expectSql: LabExpect = { findingText: ["SQL Injection"], verified: true, proofContains: ["UNION 실증"] };
const rep = (findings: any[], exposed: any[]) => ({ findings, exposed });

describe("lab-score (P1 랩 해결 채점)", () => {
  it("클래스 발견 + verified + proof 충족 → solved", () => {
    const r = scoreLabReport(rep(
      [{ id: "f1", title: "SQL Injection 취약점 신호 (error-based, param=q)", evidenceRefs: ["ev06"] }],
      [{ id: "ev06", verification: { status: "verified", proof: "UNION 실증: MySQL/MariaDB 8.0.40 (컬럼 1개) — 검증된 착취" } }],
    ), expectSql);
    expect(r.solved).toBe(true);
    expect(r.missing).toEqual([]);
    expect(r.hasVerified).toBe(true);
  });

  it("클래스 미발견 → 미해결(FN)", () => {
    const r = scoreLabReport(rep([{ id: "f1", title: "민감 파일 노출", evidenceRefs: ["ev01"] }], []), expectSql);
    expect(r.solved).toBe(false);
    expect(r.missing.some((m) => m.includes("클래스 미발견"))).toBe(true);
  });

  it("발견했지만 검증 실패(가능성만) → 미해결", () => {
    const r = scoreLabReport(rep(
      [{ id: "f1", title: "SQL Injection 취약점 신호 (error-based, param=q)", evidenceRefs: ["ev06"] }],
      [{ id: "ev06", verification: { status: "marker", proof: "신호만 확인" } }],
    ), expectSql);
    expect(r.solved).toBe(false);
    expect(r.missing.some((m) => m.includes("검증(verified)"))).toBe(true);
  });

  it("proof 조건 불충족 → 미해결", () => {
    const r = scoreLabReport(rep(
      [{ id: "f1", title: "SQL Injection 취약점 신호 (error-based, param=q)", evidenceRefs: ["ev06"] }],
      [{ id: "ev06", verification: { status: "verified", proof: "SQLSTATE 오류 문자열 확인" } }],
    ), expectSql);
    expect(r.solved).toBe(false);
    expect(r.missing.some((m) => m.includes("UNION 실증"))).toBe(true);
  });
});

describe("lab-score clean lab (negative control)", () => {
  it("발견 0 + verified 증거 0 → solved(오탐 없음)", () => {
    const r = scoreLabReport(rep([], []), { clean: true });
    expect(r.solved).toBe(true);
  });
  it("medium 이하 설정 노트만 있으면 → solved", () => {
    const r = scoreLabReport(rep([{ id: "f1", severity: "medium", title: "보안 헤더 누락" }], []), { clean: true });
    expect(r.solved).toBe(true);
  });
  it("verified 증거라도 생기면 → 미해결(FP)", () => {
    const r = scoreLabReport(rep([], [{ id: "ev01", verification: { status: "verified", proof: "x" } }]), { clean: true });
    expect(r.solved).toBe(false);
    expect(r.missing.some((m) => m.includes("오탐"))).toBe(true);
  });
});
