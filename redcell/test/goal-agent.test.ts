/**
 * GoalAgent + goal-tools 테스트 — 작업형 목표("목록을 파일로 뽑아줘") 수행 검증.
 *
 *  - fetch_page: 페이지 본문 텍스트·링크·파일 링크 추출
 *  - download_file: 바이너리 원본 보존 저장
 *  - write_output: 산출물 디렉터리 밖 경로 조작 차단
 *  - GoalAgent 루프: 모델 주도로 읽기→추적→저장 → 산출물 파일 생성, done+추궁 종료
 */

import { describe, it, expect, afterAll, beforeAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import { GoalAgent } from "../src/core/goal-agent.js";
import { fetchPage, downloadFile, writeOutput } from "../src/tools/goal-tools.js";
import type { ToolContext, ModelAdapter } from "../src/core/types.js";

const PASS_ROWS = ["김철수,합격", "이영희,합격", "박민지,합격"];
const PDF_BYTES = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x00, 0xff, 0xfe, 0x80, 0x90]); // %PDF-1.7 + 비-UTF8 바이트

let server: http.Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    if (u.pathname === "/") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(`<html><head><title>인사 공지</title></head><body>
        <h1>공지사항</h1>
        <a href="/notice/pass-list">하반기 1차 합격자 발표</a>
        <a href="/files/pass-list.pdf">합격자 명단 PDF</a>
        <a href="https://evil.example.com/x">외부 링크(따라가면 안 됨)</a>
        <style>.x{color:red}</style><script>var a=1;</script>
      </body></html>`);
    }
    if (u.pathname === "/notice/pass-list") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(`<html><body><h2>하반기 1차 합격자 목록</h2>
        <table>${PASS_ROWS.map((r) => { const [n, s] = r.split(","); return `<tr><td>${n}</td><td>${s}</td></tr>`; }).join("")}</table>
      </body></html>`);
    }
    if (u.pathname === "/files/pass-list.pdf") {
      res.setHeader("Content-Type", "application/pdf");
      return res.end(PDF_BYTES);
    }
    // 안전 가드 테스트용: /p<N> 은 매번 다른 내용의 200 페이지(페치마다 새 지표 → 정체가 안 걸린다).
    if (/^\/p\d+$/.test(u.pathname)) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(`<html><body><h1>page ${u.pathname}</h1><a href="/p${Number(u.pathname.slice(2)) + 1}">next</a></body></html>`);
    }
    res.statusCode = 404;
    res.end("nf");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => server.close());

function ctxFor(resultsDir: string): ToolContext {
  return { target: { host: "127.0.0.1", port }, rps: 100, resultsDir };
}

describe("goal-tools", () => {
  it("fetch_page: 본문 텍스트·링크·파일 링크 추출 + 외부 링크 제외", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-tool-"));
    const r = await fetchPage.run({ path: "/" }, ctxFor(dir));
    expect(r.ok).toBe(true);
    const d = r.data as { text: string; links: string[]; files: string[]; pageTitle: string };
    expect(d.pageTitle).toContain("인사 공지");
    expect(d.text).toContain("합격자 발표");
    expect(d.text).not.toContain("var a=1"); // 스크립트 제거
    expect(d.links).toContain("/notice/pass-list");
    expect(d.files).toContain("/files/pass-list.pdf");
    expect(d.links.every((l) => !l.includes("evil.example.com"))).toBe(true); // 오리진 밖 링크 없음
    expect(d.files.every((f) => !f.includes("evil"))).toBe(true);
  });

  it("fetch_page: 표 형태를 텍스트로 보존한다", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-tool-"));
    const r = await fetchPage.run({ path: "/notice/pass-list" }, ctxFor(dir));
    const d = r.data as { text: string };
    expect(d.text).toContain("김철수");
    expect(d.text).toContain("박민지");
  });

  it("download_file: 바이너리 원본을 그대로 저장한다", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-tool-"));
    const r = await downloadFile.run({ url: "/files/pass-list.pdf" }, ctxFor(dir));
    expect(r.ok).toBe(true);
    const saved = (r.data as { savedPath: string }).savedPath;
    const bytes = await fs.readFile(saved);
    expect(bytes.equals(PDF_BYTES)).toBe(true); // 비-UTF8 바이트까지 동일
    expect(saved.startsWith(dir)).toBe(true);
  });

  it("download_file: 오리진 밖 URL 은 거부한다", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-tool-"));
    const r = await downloadFile.run({ url: "https://evil.example.com/x.pdf" }, ctxFor(dir));
    expect(r.ok).toBe(false);
    expect(r.summary).toContain("오리진 밖");
  });

  it("write_output: 경로 조작 파일명을 차단하고 디렉터리 안에만 쓴다", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-tool-"));
    const r = await writeOutput.run({ filename: "../escape.txt", content: "x" }, ctxFor(dir));
    const saved = (r.data as { savedPath: string }).savedPath;
    expect(saved.startsWith(path.resolve(dir))).toBe(true);
    await expect(fs.readFile(path.join(dir, "..", "escape.txt"), "utf8")).rejects.toThrow();
    // 정상 저장
    const ok = await writeOutput.run({ filename: "list.csv", content: "a,b\n1,2" }, ctxFor(dir));
    expect(ok.ok).toBe(true);
    expect(await fs.readFile((ok.data as { savedPath: string }).savedPath, "utf8")).toBe("a,b\n1,2");
  });
});

describe("GoalAgent — 작업형 목표 루프", () => {
  function authFor(): AuthorizationFile {
    return {
      engagement: { name: "goal-test", authorized_from: "2026-01-01", authorized_until: "2999-12-31", authorized_by: "test" },
      scope: { allow: [{ host: "127.0.0.1" }] },
      limits: { max_requests_per_second: 100 },
    };
  }

  it("모델 주도로 읽기→추적→파일 저장까지 수행하고 산출물을 낸다", async () => {
    const resultsDir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-run-"));
    const replies = [
      { tool: "fetch_page", args: { path: "/" }, rationale: "공지 페이지 읽기" },
      { tool: "fetch_page", args: { path: "/notice/pass-list" }, rationale: "합격자 목록 페이지 추적" },
      { tool: "write_output", args: { filename: "pass-list.csv", content: PASS_ROWS.join("\n") }, rationale: "목록을 파일로 저장" },
      { done: true, reason: "목표 달성" },
      { done: true, reason: "추궁에서도 달성 확정" },
    ];
    const model: ModelAdapter = { complete: async () => JSON.stringify(replies.shift() ?? { done: true }) };
    const agent = new GoalAgent({ guard: new ScopeGuard(authFor()), model, resultsDir, maxMinutes: 2 });
    const r = await agent.run({ host: "127.0.0.1", port }, "하반기 1차 합격자 목록을 파일로 뽑아줘");

    expect(r.achieved).toBe(true);
    expect(r.artifacts.length).toBe(1);
    const content = await fs.readFile(r.artifacts[0], "utf8");
    expect(content).toContain("김철수");
    expect(content).toContain("박민지");
    expect(r.summary).toContain("산출물");
    expect(r.log.transcript.some((l) => l.includes("[산출물]"))).toBe(true);
  });

  it("모델이 파일을 안 만들고 끝내도 최종 종합이 정리본을 만든다", async () => {
    const resultsDir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-run-"));
    let n = 0;
    const model: ModelAdapter = {
      complete: async (req) => {
        n++;
        // 1번째: 페이지 읽기, 2번째: done, 3번째(추궁): done → 4번째(종합): 정리본 생성
        if (n === 1) return JSON.stringify({ tool: "fetch_page", args: { path: "/notice/pass-list" }, rationale: "읽기" });
        if (req.prompt.includes("정리한 최종 산출물")) {
          return JSON.stringify({ filename: "pass-list.md", content: "# 합격자 목록\n- 김철수\n- 이영희" });
        }
        return JSON.stringify({ done: true, reason: "읽기 완료" });
      },
    };
    const agent = new GoalAgent({ guard: new ScopeGuard(authFor()), model, resultsDir, maxMinutes: 2 });
    const r = await agent.run({ host: "127.0.0.1", port }, "합격자 목록 정리해줘");
    expect(r.artifacts.length).toBe(1);
    expect(await fs.readFile(r.artifacts[0], "utf8")).toContain("김철수");
  });

  it("안전 가드: 미친 모델(끝없는 제안)도 총 액션 상한에서 멈춘다", async () => {
    const resultsDir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-goal-run-"));
    let n = 0;
    const model: ModelAdapter = {
      complete: async () => JSON.stringify({ tool: "fetch_page", args: { path: `/p${++n}` }, rationale: "계속" }),
    };
    const agent = new GoalAgent({ guard: new ScopeGuard(authFor()), model, resultsDir, maxTotalActions: 5, maxMinutes: 1 });
    const r = await agent.run({ host: "127.0.0.1", port }, "끝없는 수집");
    const actions = r.log.transcript.filter((l) => l.startsWith("[목표] → fetch_page"));
    expect(actions.length).toBeLessThanOrEqual(5);
    expect(r.log.transcript.some((l) => l.includes("안전 가드"))).toBe(true);
  });
});
