/**
 * rlbench — RLM 에이전트 자기발전(continual harness) 벤치마크.
 *
 * 결정적·오프라인·비용 0 벤치마크: 스크립트 취약 앱(127.0.0.1) + 규칙기반
 * RlMockModel(MockCoder 스타일)로 에피소드를 반복 실행하며 **학습 곡선**을 증명한다.
 *
 *   episode 0 (harness ON) : 발견 → distill → harness 저장 (5 액션 스텝)
 *   episode 1 (harness ON) : recall 로 전술 재사용 → 3 액션 스텝(속도 향상)
 *   harness OFF           : 아무것도 기억하지 못해 매 에피소드 처음부터(5 스텝)
 *
 * 판정(회귀 게이트):
 *   - ON  : ep1 액션 스텝 < ep0 액션 스텝 (학습 곡선 존재)
 *   - ON  : ep1 에 recall 이벤트, ep0 에 distilled 이벤트 발생
 *   - OFF : ep1 액션 스텝 == ep0 액션 스텝 (학습 없음)
 *
 * 실행: npm run bench:rl   (또는 npx tsx bench/rlbench.ts)
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeGuard, type AuthorizationFile } from "../src/scope/scope-guard.js";
import type { ModelAdapter } from "../src/core/types.js";
import type { OrchestratorEvent } from "../src/core/orchestrator.js";
import { RlmAgent } from "../src/rlm/rlm-agent.js";
import { HarnessStore } from "../src/harness/harness-store.js";

/** 유인 페이로드에만 반응하는 취약 앱(결정적). */
function startLab(): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/search") {
      const q = decodeURIComponent(url.searchParams.get("q") ?? "");
      if (q.includes("' OR '1'='1")) {
        res.statusCode = 200;
        res.end("검색 결과: <b>flag_sqli</b> (items: admin)");
        return;
      }
      res.statusCode = 200;
      res.end("검색 결과 없음");
      return;
    }
    if (url.pathname === "/login") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (body.includes("admin=1")) {
          res.setHeader("Set-Cookie", "session=admin; Path=/; HttpOnly");
          res.end("logged in");
          return;
        }
        res.statusCode = 200;
        res.end("login form");
      });
      return;
    }
    if (url.pathname === "/admin") {
      const ck = (req.headers.cookie ?? "").split(";").map((c) => c.trim());
      if (ck.includes("session=admin")) {
        res.statusCode = 200;
        res.end("admin panel: <b>flag_admin</b>");
        return;
      }
      res.statusCode = 403;
      res.end("forbidden");
      return;
    }
    res.setHeader("Server", "nginx/1.18.0");
    res.end("<html><title>shop</title>루트 페이지 — shop</html>");
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ server, port: (server.address() as AddressInfo).port })));
}

function auth(port: number): AuthorizationFile {
  return {
    engagement: { name: "rlbench", authorized_from: "2000-01-01", authorized_until: "2999-12-31", authorized_by: "bench" },
    scope: { allow: [{ host: "127.0.0.1" }] },
    limits: { max_requests_per_second: 500 },
  };
}

/**
 * RlMockModel — 프롬프트(JSON)를 보고 결정적으로 행동하는 규칙 모델(trusted).
 *   - harness_memories 에 SQLi 전술이 회상되면 정찰/열거를 건너뛰고 바로 익스플로잇.
 *   - 아니면 recon → enum → explore → FINAL 순서.
 */
class RlMockModel implements ModelAdapter {
  readonly trusted = true;
  prompts: string[] = [];
  async complete(input: { system: string; prompt: string; json?: boolean }): Promise<string> {
    this.prompts.push(input.prompt);
    let p: any = {};
    try {
      p = JSON.parse(input.prompt);
    } catch {
      return JSON.stringify({ done: true });
    }
    const prev = p.previous_attempts ?? [];
    const step = prev.length;
    // planStep 프롬프트는 harness_memories 를 줄바꿈 문자열로 내장한다 — 배열·문자열 모두 허용.
    const memsRaw = p.harness_memories ?? [];
    const mems = (typeof memsRaw === "string" ? [memsRaw] : memsRaw as string[]).join(" ");
    const recalled = /SQL 인젝션|sqli/i.test(mems);
    const J = (o: unknown) => JSON.stringify(o);
    // 발견된 제목 필터: SQL / 관리자.
    const found = (prev.flatMap((a: any) => (a.findings ?? []) as string[]) as string[]).filter((f) => f?.includes("SQL") || f?.includes("관리자"));
    const finalStep = (): string => J({ code: "print('FINAL: SQL 인젝션과 관리자 인증 우회 탐지 완료')", rationale: "모든 목표 발견 — 종료" });
    if (found.length >= 2) return finalStep();
    if (found.length === 1 && step >= 4) return finalStep();
    const trySqli = (): string =>
      J({
        code:
          "r = rc.get('/search?q=%27%20OR%20%271%27%3D%271')\n" +
          "rc.log('sqli probe status', r.status)\n" +
          "if 'flag_sqli' in r.text:\n" +
          "    rc.finding('SQL 인젝션 — /search?q=', severity='high', evidence='flag_sqli', impact='DB 데이터 탈취')\n" +
          "print('sqli-probe done')",
        rationale: recalled ? "회상된 SQLi 전술 재사용: /search?q= 인젝션 페이로드" : "검색 파라미터 SQLi 프로브",
      });
    const tryAdmin = (): string =>
      J({
        code:
          "rc.post('/login', data={'admin': '1'})\n" +
          "r = rc.get('/admin')\n" +
          "rc.log('admin status', r.status)\n" +
          "if 'flag_admin' in r.text:\n" +
          "    rc.finding('관리자 인증 우회 — /admin 쿠키 위조', severity='critical', evidence='flag_admin', impact='관리자 기능 접근')\n" +
          "print('admin done')",
        rationale: "admin=1 로그인 응답의 세션 쿠키로 /admin 우회",
      });
    if (recalled) {
      switch (step) {
        case 0: return trySqli();
        case 1: return tryAdmin();
        default: return J({ done: true, rationale: "완료" });
      }
    }
    switch (step) {
      case 0:
        return J({
          code: "r = rc.get('/')\nrc.log('recon root', r.status, len(r.text))\nprint('recon done')",
          rationale: "루트 정찰",
        });
      case 1:
        return J({
          code: "r1 = rc.get('/login')\nr2 = rc.get('/admin')\nrc.log('enum login', r1.status, '/admin', r2.status)\nprint('enum done')",
          rationale: "엔드포인트 열거(login/admin)",
        });
      case 2: return trySqli();
      case 3: return tryAdmin();
      default: return J({ done: true, rationale: "완료" });
    }
  }
}

interface EpisodeStats {
  actions: number;
  findings: number;
  recalled: number;
  distilled: number;
  rewards: number;
  verify?: string;
  stepsLog: string[];
}

async function episode(harness: HarnessStore | undefined, port: number, goal: string): Promise<EpisodeStats> {
  const model = new RlMockModel();
  const events: OrchestratorEvent[] = [];
  const agent = new RlmAgent(new ScopeGuard(auth(port)), model, {
    maxIterations: 8,
    isolation: "off",
    harness,
    reflectAfter: 4,
    onEvent: (e) => events.push(e),
  });
  const log = await agent.run({ host: "127.0.0.1", port }, goal);
  const st: EpisodeStats = { actions: 0, findings: log.findings.length, recalled: 0, distilled: 0, rewards: 0, stepsLog: [] };
  for (const e of events) {
    if (e.type === "action") st.actions++;
    if (e.type === "recall") st.recalled = e.count;
    if (e.type === "distilled") st.distilled++;
    if (e.type === "reward") { st.rewards++; st.stepsLog.push(`step${e.step}=+${e.value}`); }
    if (e.type === "verify") st.verify = `${e.verdict}(${Math.round(e.ratio * 100)}%)`;
  }
  st.stepsLog.push(`findings=${st.findings} actions=${st.actions} prompts=${model.prompts.length}`);
  return st;
}

async function main(): Promise<void> {
  const { server, port } = await startLab();
  const goal = "SQL 인젝션과 관리자 인증 우회 탐지";
  try {
    const dir = mkdtempSync(path.join(os.tmpdir(), "rlbench-harness-"));
    console.log("\n═══ rlbench — RLM 자기발전 학습 곡선 ═══\n");
    console.log(`허니팟: 127.0.0.1:${port} (SQLi /search, 관리자 쿠키 우회 /admin)`);
    console.log(`harness 저장소: ${dir}\n`);

    // harness ON — 에피소드마다 저장소를 디스크에서 다시 연다(진짜 지속성).
    const on = { ep0: null as null | EpisodeStats, ep1: null as null | EpisodeStats };
    on.ep0 = await episode(await HarnessStore.open(dir, "127.0.0.1"), port, goal);
    const h1 = await HarnessStore.open(dir, "127.0.0.1");
    const entries = await h1.entries();
    on.ep1 = await episode(h1, port, goal);

    // harness OFF — 동일 모델, 저장소 없음.
    const off0 = await episode(undefined, port, goal);
    const off1 = await episode(undefined, port, goal);

    console.log(`${"에피소드".padEnd(22)}액션스텝  발견  recall  distilled  verify`);
    console.log("─".repeat(66));
    const row = (name: string, s: EpisodeStats) =>
      console.log(`${name.padEnd(22)}${String(s.actions).padEnd(9)}${String(s.findings).padEnd(6)}${String(s.recalled).padEnd(7)}${String(s.distilled).padEnd(11)}${s.verify ?? "-"}`);
    row("ON  ep0 (처음)", on.ep0!);
    row("ON  ep1 (학습 후)", on.ep1!);
    row("OFF ep0 (처음)", off0);
    row("OFF ep1 (반복)", off1);

    console.log(`\n저장된 기억 ${entries.length}건:`);
    for (const e of entries) console.log(`  [${e.kind}:${e.key}] ${e.text.slice(0, 90)} (hit=${e.hits}, win=${e.wins}/fail=${e.fails})`);
    console.log(`\n보상 로그 — ON ep0: ${on.ep0!.stepsLog.join(", ")}`);
    console.log(`보상 로그 — ON ep1: ${on.ep1!.stepsLog.join(", ")}`);

    // 회귀 게이트.
    const curve = on.ep1!.actions < on.ep0!.actions;
    const learned = on.ep1!.recalled >= 1 && on.ep0!.distilled >= 2;
    const static_ = off1.actions === off0.actions;
    const verified = (on.ep0!.verify ?? "").startsWith("achieved") && (on.ep1!.verify ?? "").startsWith("achieved");
    console.log(`\n학습 곡선(ON  ep1<ep0): ${curve ? "✅" : "❌"}  recall·distill 이벤트: ${learned ? "✅" : "❌"}  OFF 정체: ${static_ ? "✅" : "❌"}  verify: ${verified ? "✅" : "❌"}`);
    const ok = curve && learned && static_ && verified;
    console.log(ok ? "\n✅ rlbench 통과 — RLM 에이전트가 에피소드 간 학습한다\n" : "\n❌ rlbench 기준 미달\n");
    process.exit(ok ? 0 : 1);
  } finally {
    server.close();
  }
}

main().catch((e) => {
  console.error("rlbench 오류:", e);
  process.exit(2);
});
