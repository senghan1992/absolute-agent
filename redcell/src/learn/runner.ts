/**
 * learn 러너 — 강의를 실제로 진행한다.
 *
 *   랩 기동(로컬, labs/) → 단계별 실행(설명 → 툴 실행 → 관찰 해설) → 퀴즈 → 진행도 저장
 *
 * 안전: 강의는 labs/ 의 로컬 랩(127.0.0.1)에서만 동작한다. 외부 대상은 아예 받지 않는다.
 * 진행도는 ~/.redcell/learn/progress.json 에 누적된다(continual learning 의 학습자 버전).
 */

import { spawn, type ChildProcess } from "node:child_process";
import net from "node:net";
import { promises as fs } from "node:fs";
import path from "node:path";
import { DefaultToolBox } from "../tools/toolbox.js";
import type { ToolContext } from "../core/types.js";
import { newJar, type CookieJar } from "../net/http-client.js";
import { redcellHome } from "../config.js";
import { LESSONS, lessonById, type Lesson } from "./lessons.js";

export interface LearnResult {
  lessonId: string;
  title: string;
  /** expectFinding 이 붙은 단계를 전부 충족했는가. */
  solved: boolean;
  stepsRun: number;
  findings: string[];
  quizCorrect: number;
  quizTotal: number;
}

export interface LearnOptions {
  /** 출력 콜백(기본 console.log). 테스트에서 수집용으로 대체. */
  log?: (line: string) => void;
  /** 퀴즈 자동 정답(비대화형). */
  autoQuiz?: boolean;
  /** 퀴즈 답변 주입(테스트). 부족하면 0 번 선택. */
  quizAnswers?: number[];
  /** 랩 기동/종료 스킵(이미 기동된 랩 재사용). */
  keepServer?: boolean;
}

const ROOT = path.resolve(new URL("../..", import.meta.url).pathname);

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

// ── 진행도 ───────────────────────────────────────────────────────────────────

export interface LessonProgress {
  solved: boolean;
  quizCorrect: number;
  quizTotal: number;
  attempts: number;
  ts: string;
}

export function progressPath(): string {
  return path.join(redcellHome(), "learn", "progress.json");
}

export async function loadProgress(): Promise<Record<string, LessonProgress>> {
  try {
    return JSON.parse(await fs.readFile(progressPath(), "utf8")) as Record<string, LessonProgress>;
  } catch {
    return {};
  }
}

async function saveProgress(id: string, p: LessonProgress): Promise<void> {
  const all = await loadProgress();
  all[id] = p;
  await fs.mkdir(path.dirname(progressPath()), { recursive: true });
  await fs.writeFile(progressPath(), JSON.stringify(all, null, 2), "utf8");
}

/** 진행도 요약 한 줄(목록 표시용). */
export function progressMark(prog: Record<string, LessonProgress> | undefined, id: string): string {
  if (!prog || !prog[id]) return "  ⬜";
  return prog[id].solved ? "  ✅" : `  🔄(${prog[id].attempts}회)`;
}

// ── 세션 쿠키(인증 표면 강의용) ────────────────────────────────────────────────

function jarWithCookie(origin: string, cookie: string): CookieJar {
  const jar = newJar();
  const m = jar.store.get(origin) ?? new Map<string, string>();
  for (const pair of cookie.split(",")) {
    const eq = pair.indexOf("=");
    if (eq > 0) m.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
  jar.store.set(origin, m);
  return jar;
}

// ── 강의 실행 ────────────────────────────────────────────────────────────────

export async function runLesson(id: string, opts: LearnOptions = {}): Promise<LearnResult | undefined> {
  const lesson = lessonById(id);
  if (!lesson) return undefined;
  const log = opts.log ?? ((s: string) => console.log(s));
  let child: ChildProcess | undefined;

  log("");
  log("═".repeat(72));
  log(`🎓 ${lesson.title}  [${lesson.level}] ${lesson.klass}`);
  log("═".repeat(72));
  log("");
  log(lesson.story);
  log("");
  log(lesson.diagram);
  log("");

  try {
    // 1) 랩 기동(이미 살아 있으면 재사용).
    if (!opts.keepServer && !(await isPortBusy(lesson.lab.port))) {
      child = spawn(lesson.lab.start[0], lesson.lab.start.slice(1), { cwd: ROOT, stdio: "ignore" });
      if (!(await waitPort(lesson.lab.port))) {
        log(`⚠️ 랩 기동 실패(포트 ${lesson.lab.port} 미응답) — 강의를 진행할 수 없습니다.`);
        return undefined;
      }
    } else if (!opts.keepServer) {
      log(`(포트 ${lesson.lab.port} 가 이미 열려 있어 실행 중인 랩을 재사용합니다)`);
    }

    // 2) 단계 실행.
    const toolbox = new DefaultToolBox();
    const scheme = "http";
    const origin = `${scheme}://127.0.0.1:${lesson.lab.port}`;
    const ctx: ToolContext = {
      target: { host: "127.0.0.1", port: lesson.lab.port },
      rps: 200,
      jar: lesson.cookie ? jarWithCookie(origin, lesson.cookie) : undefined,
    };
    const findings: string[] = [];
    let stepsRun = 0;
    let expected = 0;

    for (const step of lesson.steps) {
      log(`\n▶ ${step.title}`);
      log(`  ${step.explain}`);
      if (!step.tool) {
        log(`  💡 ${step.observe}`);
        continue;
      }
      const tool = toolbox.get(step.tool);
      if (!tool) {
        log(`  ⚠️ 툴 ${step.tool} 이 없어 이 단계를 건너뜁니다.`);
        continue;
      }
      stepsRun++;
      if (step.expectFinding) expected++;
      log(`  ⏳ 실행: ${step.tool} …`);
      let res;
      try {
        res = await tool.run(step.args ?? {}, ctx);
      } catch (e) {
        log(`  ⚠️ 실행 오류: ${(e as Error).message}`);
        continue;
      }
      const d = (res.data ?? {}) as { severity?: string; title?: string; evidence?: string };
      if (res.ok) log(`  🔧 결과: ${res.summary}`);
      const hit = step.expectFinding ? (d.title ?? res.summary).includes(step.expectFinding) : undefined;
      if (hit) {
        findings.push(d.title ?? "");
        log(`  🎯 발견! (${d.severity ?? "?"}) ${d.title}`);
        if (d.evidence) log(`  📎 증거: ${d.evidence.slice(0, 300)}`);
      } else if (step.expectFinding) {
        log(`  ❌ 이 단계에서 기대한 발견(${step.expectFinding})이 나오지 않았습니다. ${res.summary.slice(0, 160)}`);
      }
      log(`  💡 관찰 포인트: ${step.observe}`);
    }

    const solved = expected === 0 || findings.length >= expected;

    // 3) 퀴즈.
    let quizCorrect = 0;
    if (lesson.quiz.length > 0) {
      log(`\n📝 확인 퀴즈 (${lesson.quiz.length}문제)`);
      for (let i = 0; i < lesson.quiz.length; i++) {
        const q = lesson.quiz[i];
        log(`\n  Q${i + 1}. ${q.q}`);
        q.options.forEach((o, j) => log(`     ${j + 1}) ${o}`));
        let pick = -1;
        if (opts.autoQuiz) {
          pick = (opts.quizAnswers?.[i] ?? q.answer + 1) - 1; // quizAnswers 는 1-based, q.answer 는 0-based
          log(`  → (자동) ${pick + 1} 선택`);
        } else {
          pick = (await askNumber(`  → 번호 선택: `, q.options.length)) - 1;
        }
        if (pick === q.answer) {
          quizCorrect++;
          log(`  ✅ 정답! ${q.explain}`);
        } else {
          log(`  ❌ 아쉽네요. 정답은 ${q.answer + 1}) ${q.options[q.answer]} — ${q.explain}`);
        }
      }
    }

    // 4) 정리 + 진행도 저장.
    log("");
    log("─".repeat(72));
    log(solved ? `🏁 미션 완료 — 이 취약점을 직접 뚫어봤습니다!` : `📌 미션 진행 — 발견 ${findings.length}/${expected}. 다시 시도해 보세요.`);
    log(`🛡️ 방어법: ${lesson.defense}`);
    log(`📚 더 읽기: ${lesson.link}`);
    log("─".repeat(72));
    log("");

    const prev = (await loadProgress())[id];
    await saveProgress(id, {
      solved,
      quizCorrect,
      quizTotal: lesson.quiz.length,
      attempts: (prev?.attempts ?? 0) + 1,
      ts: new Date().toISOString(),
    });

    return { lessonId: id, title: lesson.title, solved, stepsRun, findings, quizCorrect, quizTotal: lesson.quiz.length };
  } finally {
    if (child && !opts.keepServer) child.kill();
  }
}

/** 대화형 번호 입력(readline). */
async function askNumber(prompt: string, max: number): Promise<number> {
  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    for (;;) {
      const raw = (await rl.question(prompt)).trim();
      const n = Number(raw);
      if (Number.isInteger(n) && n >= 1 && n <= max) return n;
      process.stdout.write(`  1~${max} 번호를 입력하세요.\n`);
    }
  } finally {
    rl.close();
  }
}

/** 강의 목록 출력(진행도 포함). */
export async function listLessons(log: (s: string) => void = console.log): Promise<void> {
  const prog = await loadProgress();
  log("🎓 RedCell 해킹 학습 — 인가된 로컬 랩에서 안전하게 뚫어보기\n");
  for (const l of LESSONS) {
    log(`${progressMark(prog, l.id)} ${l.id.padEnd(20)} [${l.level}] ${l.title} (${l.klass})`);
  }
  log("\n시작: redcell learn start <강의id>   예: redcell learn start sql-injection");
  log("안전: 모든 강의는 labs/ 의 로컬 랩(127.0.0.1)에서만 동작합니다 — 외부 대상 불가.");
}
