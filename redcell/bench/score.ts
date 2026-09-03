/**
 * 벤치마크 채점 코어 — CLI 러너(bench.ts)와 회귀 테스트(test/bench.test.ts)가 공유한다.
 */

import { startApp } from "./vulnapp.js";
import type { Tool, ToolContext } from "../src/core/types.js";
import { DefaultToolBox } from "../src/tools/toolbox.js";

export type Sev = "info" | "low" | "medium" | "high" | "critical";
const RANK: Record<Sev, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export function rank(s: unknown): number {
  return typeof s === "string" && s in RANK ? RANK[s as Sev] : -1;
}

export interface Case {
  tool: string;
  args: Record<string, unknown>;
  klass: string;
  /** 이 심각도 이상으로 탐지해야 "진짜 탐지"로 인정. */
  minSev: Sev;
  /**
   * "vuln"(기본): 취약앱에서 탐지=TP, 견고앱에서 탐지=FP.
   * "decoy": 취약해 보이지만 실제로는 정상인 미끼 경로(공개 카탈로그·로그인 스플래시 등).
   *   두 앱 어디서든 탐지하면 FP 로 센다(정상 동작을 취약으로 오탐하는지 감시).
   */
  kind?: "vuln" | "decoy";
}

export const CASES: Case[] = [
  { tool: "xss_probe", args: { path: "/search", param: "q" }, klass: "Reflected XSS", minSev: "high" },
  { tool: "sqli_probe", args: { path: "/item", param: "id" }, klass: "SQL Injection", minSev: "high" },
  { tool: "ssti_probe", args: { path: "/tpl", param: "name" }, klass: "SSTI", minSev: "high" },
  { tool: "cmdi_probe", args: { path: "/ping", param: "host" }, klass: "Command Injection", minSev: "high" },
  { tool: "path_traversal", args: { path: "/download", param: "file" }, klass: "Path Traversal/LFI", minSev: "high" },
  { tool: "open_redirect", args: { path: "/go", param: "url" }, klass: "Open Redirect", minSev: "medium" },
  { tool: "ssrf_probe", args: { path: "/fetch", param: "url" }, klass: "SSRF", minSev: "high" },
  { tool: "idor_probe", args: { path: "/api/orders/1000" }, klass: "IDOR", minSev: "high" },
  { tool: "cors_audit", args: { path: "/api/data" }, klass: "CORS Misconfig", minSev: "high" },
  { tool: "graphql_probe", args: { path: "/graphql" }, klass: "GraphQL Introspection", minSev: "medium" },
  { tool: "secret_scan", args: {}, klass: "Exposed Secrets", minSev: "high" },
  { tool: "header_audit", args: {}, klass: "Missing Sec Headers", minSev: "medium" },
  { tool: "cookie_audit", args: { path: "/" }, klass: "Insecure Cookie", minSev: "medium" },
  { tool: "jwt_audit", args: { path: "/" }, klass: "Weak JWT", minSev: "high" },
  { tool: "csrf_audit", args: { path: "/transfer" }, klass: "CSRF", minSev: "medium" },
  { tool: "upload_probe", args: { path: "/upload" }, klass: "Unrestricted Upload", minSev: "low" },
  { tool: "xxe_probe", args: { path: "/xml" }, klass: "XXE", minSev: "medium" },
  { tool: "http_method_audit", args: { path: "/" }, klass: "Dangerous HTTP Methods/XST", minSev: "medium" },
  { tool: "host_header_audit", args: { path: "/reset" }, klass: "Host Header Injection", minSev: "high" },
  { tool: "access_control_probe", args: { path: "/admin" }, klass: "Broken Access Control", minSev: "high" },
  { tool: "param_pollution", args: { path: "/hpp", param: "q" }, klass: "HTTP Parameter Pollution", minSev: "medium" },

  // ── 적대적 미끼(decoy) 케이스 — 정상 동작을 취약으로 오탐하지 않는지 감시 ──────────
  // 공개 상품 카탈로그: 인접 id 가 서로 다른 공개 객체를 반환하지만 개인정보가 없다 → IDOR 아님.
  { tool: "idor_probe", args: { path: "/catalog/5" }, klass: "IDOR 미끼(공개 카탈로그)", minSev: "high", kind: "decoy" },
  // 관리자 로그인 스플래시: 제목이 "Admin Dashboard"지만 실제로는 로그인 폼(막힘) → 접근통제 우회 아님.
  { tool: "access_control_probe", args: { path: "/portal" }, klass: "접근통제 미끼(로그인 스플래시)", minSev: "high", kind: "decoy" },
  // SSTI 원문 에코: 입력을 그대로 반사하지만 평가하지 않음(7919*7331 등장, 58053589 미등장) → SSTI 아님.
  // `!includes(EXPR)` 가드 제거가 원문 에코 앱에서 오탐을 만들지 않는지 감시(FN 개선의 FP 트랩).
  { tool: "ssti_probe", args: { path: "/tpl-echo", param: "name" }, klass: "SSTI 미끼(원문 에코)", minSev: "medium", kind: "decoy" },
];

export interface Outcome {
  klass: string;
  tool: string;
  detected: boolean;
  sev: string;
  summary: string;
}

const tools = new DefaultToolBox();

/** 지정 포트의 앱에 모든 케이스를 실행하고 케이스별 탐지 여부를 돌려준다. */
export async function runAgainst(port: number): Promise<Outcome[]> {
  const ctx: ToolContext = { target: { host: "127.0.0.1", port }, rps: 200 };
  const out: Outcome[] = [];
  for (const c of CASES) {
    const tool = tools.get(c.tool) as Tool;
    let detected = false;
    let sev = "-";
    let summary = "";
    try {
      const res = await tool.run(c.args, ctx);
      const data = (res.data ?? {}) as { severity?: string };
      sev = data.severity ?? (res.ok ? "ok/no-data" : "none");
      detected = res.ok && rank(data.severity) >= rank(c.minSev);
      summary = res.summary;
    } catch (e) {
      summary = `ERROR: ${(e as Error).message}`;
    }
    out.push({ klass: c.klass, tool: c.tool, detected, sev, summary });
  }
  return out;
}

export interface BenchResult {
  vuln: Outcome[];
  hard: Outcome[];
  tp: number;
  fn: number;
  fp: number;
  tn: number;
  recall: number;
  precision: number;
  f1: number;
}

/** 취약/견고 앱을 띄우고 전체 케이스를 채점한다. */
export async function scoreBenchmark(): Promise<BenchResult> {
  const vulnApp = await startApp("vuln");
  const hardApp = await startApp("hardened");
  try {
    const vuln = await runAgainst(vulnApp.port);
    const hard = await runAgainst(hardApp.port);
    let tp = 0,
      fn = 0,
      fp = 0,
      tn = 0;
    for (let i = 0; i < CASES.length; i++) {
      if (CASES[i].kind === "decoy") {
        // 미끼: 두 앱 모두 정상이므로 어디서든 탐지하면 FP.
        vuln[i].detected ? fp++ : tn++;
        hard[i].detected ? fp++ : tn++;
      } else {
        vuln[i].detected ? tp++ : fn++;
        hard[i].detected ? fp++ : tn++;
      }
    }
    const precision = tp / (tp + fp || 1);
    const recall = tp / (tp + fn || 1);
    const f1 = (2 * precision * recall) / (precision + recall || 1);
    return { vuln, hard, tp, fn, fp, tn, recall, precision, f1 };
  } finally {
    await vulnApp.close();
    await hardApp.close();
  }
}
