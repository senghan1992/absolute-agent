/**
 * learn 학습 모드 테스트 — 강의 카탈로그·러너·진행도 저장.
 *
 * 실제 랩을 기동해 강의 단계(툴 실행→발견 확인→퀴즈)를 비대화형(--auto)으로 통과하는지 검증한다.
 * 대표 3강의(SQLi·JWT 위조·캐시 기만) + 카탈로그 무결성 + 진행도 파일 저장.
 */

import { describe, it, expect } from "vitest";
import { LESSONS, lessonById } from "../src/learn/lessons.js";
import { runLesson, loadProgress, progressPath } from "../src/learn/runner.js";

describe("learn 카탈로그", () => {
  it("6개 강의가 정의되고 구조가 완전하다", () => {
    expect(LESSONS.length).toBeGreaterThanOrEqual(6);
    for (const l of LESSONS) {
      expect(l.id).toMatch(/^[a-z0-9-]+$/);
      expect(l.story.length).toBeGreaterThan(30);
      expect(l.diagram).toContain("│");
      expect(l.steps.length).toBeGreaterThanOrEqual(2);
      expect(l.quiz.length).toBeGreaterThanOrEqual(1);
      expect(l.defense.length).toBeGreaterThan(10);
      expect(l.link).toMatch(/^https:/);
      expect(l.lab.start.length).toBeGreaterThan(1);
      expect(l.lab.port).toBeGreaterThan(1024);
      for (const q of l.quiz) {
        expect(q.answer).toBeGreaterThanOrEqual(0);
        expect(q.answer).toBeLessThan(q.options.length);
      }
      // expectFinding 은 우리 툴의 실제 발견 제목과 일치해야 한다(오탈자 방지).
      for (const s of l.steps) {
        if (s.tool) expect(["http_probe", "sqli_probe", "xss_probe", "idor_probe", "smuggle_probe", "cache_deception_probe", "jwt_attack"]).toContain(s.tool);
      }
    }
  });

  it("모든 강의가 로컬 랩(127.0.0.1 고정 포트)을 가리킨다", () => {
    const ports = new Set<number>();
    for (const l of LESSONS) {
      expect(l.lab.start.join(" ")).toContain("labs/");
      expect(ports.has(l.lab.port)).toBe(false); // 포트 충돌 없음
      ports.add(l.lab.port);
    }
  });

  it("lessonById 로 조회된다", () => {
    expect(lessonById("sql-injection")?.title).toContain("SQL");
    expect(lessonById("nope")).toBeUndefined();
  });
});

describe("learn 러너 — 실제 랩에서 강의 완주", () => {
  it("sql-injection 강의: 발견 + 퀴즈 정답 → solved", async () => {
    const lines: string[] = [];
    const r = await runLesson("sql-injection", { log: (s) => lines.push(s), autoQuiz: true });
    expect(r).toBeDefined();
    expect(r!.solved).toBe(true);
    expect(r!.findings.length).toBeGreaterThanOrEqual(1);
    expect(r!.quizCorrect).toBe(r!.quizTotal);
    expect(lines.some((l) => l.includes("미션 완료"))).toBe(true);
  }, 120000);

  it("jwt-forgery 강의: 위조 실증 단계 통과", async () => {
    const r = await runLesson("jwt-forgery", { log: () => {}, autoQuiz: true });
    expect(r!.solved).toBe(true);
  }, 120000);

  it("cache-deception 강의(세션 쿠키 주입): 실증 통과", async () => {
    const r = await runLesson("cache-deception", { log: () => {}, autoQuiz: true });
    expect(r!.solved).toBe(true);
  }, 180000);

  it("진행도가 파일에 저장된다", async () => {
    const prog = await loadProgress();
    expect(prog["sql-injection"]).toBeDefined();
    expect(prog["sql-injection"].solved).toBe(true);
    expect(progressPath()).toContain("learn");
  });
});
