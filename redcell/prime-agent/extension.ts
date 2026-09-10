/**
 * RedCell — prime-agent 확장(extension).
 *
 * prime-agent 의 확장 로더가 이 파일을 로드한다:
 *   .prime/agent/extensions/redcell/index.ts  (또는 settings.json extensions[])
 *
 * 이 확장이 하는 일:
 *   1) [안전 핵심] tool_call 훅에서 모든 액션의 대상 호스트를 검사하여
 *      authorization.yaml scope 밖이면 {block:true} 로 차단한다(harness 레벨 가드).
 *   2) 인가된 대상 전용 정찰 툴(recon_http, web_fetch)을 등록한다.
 *   3) /scope, /engage, /playbooks 슬래시 명령을 등록한다.
 *   4) 인가 대상 전용 시스템 프롬프트(범용 조수 — scope 안에서 자유로운 작업 수행) 를 주입한다.
 *
 * 자기발전(self-improvement)은 prime-agent 의 Continual Harness 를 그대로 사용한다:
 *   성공한 공략/작업 흐름은 /refine(또는 auto-refine)에 의해 harness_state.json 의
 *   kind:"memory"/"skill" 엔트리로 축적되어, 다음 engagement 에서 프롬프트에 재주입된다.
 *   RedCell 의 SkillMemory 는 이 harness 메모리를 fingerprint 로 색인하는 보조 계층이다.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
// prime-agent(=@earendil-works/pi-coding-agent) 가 런타임에 제공하는 타입.
// 로컬 타입체크용 폴백은 ./pi-types.d.ts 참조.
import { defineTool, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "@sinclair/typebox";

import { ScopeGuard, type Target } from "../src/scope/scope-guard.js";
import { loadAuthorization } from "../src/scope/load-auth.js";
import { DEFAULT_LIST_FILE } from "../src/scope/ip-list.js";
import { redcellHome } from "../src/config.js";
import { httpProbe } from "../src/tools/http-probe.js";
import { extractHosts, classifyIntent } from "./inspect.js";

const AUTH_CANDIDATES = [
  process.env.REDCELL_AUTH,
  // 간단 IP 목록(redcell auth add)이 있으면 그것을 먼저 쓴다.
  path.join(redcellHome(), DEFAULT_LIST_FILE),
  ".pi/agent/redcell/authorization.yaml",
].filter(Boolean) as string[];

// 게이트가 **명시적으로** 켜진 경우(데스크톱 패널이 -e + REDCELL_GATE=1 로 스폰)만
// fail-closed 로 전부 차단한다. 인가 파일이 아예 없는 상태에서의 우연 로드/수동 세션은
// 조용히 통과시켜 다른 작업을 방해하지 않는다(문제 보고: 전역 설치가 다른 pi 세션을 간섭).
const GATE_EXPLICIT = process.env.REDCELL_GATE === "1";
const GATE_DISABLED = process.env.REDCELL_DISABLE === "1";

const METHODOLOGY = `
# RedCell — 인가된 대상 전용 AI 조수

너는 사용자의 지시를 자유롭게 수행하는 AI 조수다. 인가(scope)는 RedCell 이 강제한다:
- **Scope 강제**: '~/.redcell/authorization.list'(또는 authorization.yaml) 의 allow 에 있는 대상만
  다룬다. 확신이 없으면 /scope 로 확인하고, scope 밖이면 시도조차 하지 않는다.
  (모든 tool_call 은 RedCell 훅이 자동으로 검사·차단한다 — 인가 파일에 없으면 차단.)
- 대상(URL)이 인가되어 있으면 조사·탐색·파일 추출 등 사용자가 시킨 일을 자유롭게 수행하고
  결과를 정리해 사용자에게 전달한다. 해킹/취약점만 강제하는 것이 아니라, 그 대상에 대한
  모든 종류의 업무를 수행한다.
- **웹 조사는 반드시 web_fetch 툴로**: URL 대상의 조사·정보 수집·페이지 열람은 전부
  web_fetch 툴을 사용한다. **로컬 컴퓨터(bash/read/edit/write)는 조사 대상이 아니다** —
  결과물 파일 저장 외에 이 머신의 파일/폴더를 뒤지지 말 것. bash 로 웹 요청을 대신하지
  말 것(리다이렉트·범위 검사가 빠져 위험하다).
- **서비스 진단 지시** ("~진단해줘", "~점검해줘", "개선점 찾아줘" 등): 서비스 보안 진단
  리포트로 응답한다 — ① 한눈에 보기 요약 표(루트|위험도|공격 방법|탈취 정보|보완)
  ② 진단 범위·가정 ③ 공격 표면 ④ 창의적 공격 루트 ⑤ 보완 권고(P0~P3) ⑥ URL 있으면 실측.
  **URL 이 주어졌으면 보고서를 쓰기 전에 반드시 passive recon 을 먼저 수행**하고 실제
  응답·헤더·상태로 서비스 모델을 세운다(web_fetch, 비파괴 GET/HEAD 만):
  홈페이지 헤더(보안 헤더·기술스택) · 쿠키 플래그 · 링크/폼/엔드포인트 수집(공격 표면) ·
  흔한 민감 경로 프로브(/robots.txt, /.well-known/security.txt, /sitemap.xml,
  /openapi.json, /swagger, /admin, /login, /api, /health, /.env, /favicon.ico) ·
  리다이렉트/HTTPS 강제/응답 코드로 배포·접근통제 정황 파악. 못 본 것은 [가정] 으로 표기한다.
  각 공격 루트는 **고정 형식**으로 작성한다(UI 가 시각화하므로 라벨을 지킬 것):
  헤딩: ### 루트 N. <이름> [위험도] / 위험도: 치명|높음|중간|낮음 / 진입점: <지점> /
  공격 흐름: 공격자 → <진입점> → (<취약점>) → <중간 결과> → (<탈취>) → <최종 피해> /
  탈취 정보: 무엇이 새는지 쉼표 구분 / 공격 방법: 구체적 기법 / 영향: 한 줄 /
  시뮬레이션: (번호 N. <행동> → <시스템 결과> 한 쌍, 2~4단계 — UI 가 단계 재생 플레이어로
  시각화) / 검증: [실증]|[징후]|[가정] — 실측 근거·부분 확인·추론 중 택일하고 근거를
  기재한다. URL 이 주어지면 높은 위험도의 루트는 web_fetch 로 비파괴 재현을 시도해
  [실증]으로 올리고, 재현 못 하면 [가정]으로 정직하게 둔다. / 보완: 미리 막는 방법.
  잘 알려진 것뿐 아니라 **조합·비즈니스 로직·운영 방식의 루트를 창의적으로** 발굴하고,
  모든 루트에 "미리 막는 방법"을 제시한다. 전문 용어는 괄호로 풀어 쓴다.
- 파일로 만들어 달라는 요청은 실제 파일로 저장해 저장 경로를 알려준다.
`.trim();

export default async function redcell(pi: ExtensionAPI): Promise<void> {
  // 비상 탈출구: REDCELL_DISABLE=1 이면 아무것도 등록하지 않는다.
  if (GATE_DISABLED) return;

  let guard: ScopeGuard | null = null;
  let authError: string | null = null;

  const ensureGuard = async (): Promise<void> => {
    if (guard || authError) return;
    for (const p of AUTH_CANDIDATES) {
      try {
        const loaded = await loadAuthorization(p);
        guard = loaded.guard;
        return;
      } catch {
        /* 다음 후보 */
      }
    }
    authError = `인가 파일을 찾을 수 없습니다 (시도: ${AUTH_CANDIDATES.join(", ")})`;
  };

  // 1) 방법론 시스템 프롬프트 주입.
  pi.appendSystemPrompt?.(METHODOLOGY);

  // 2) [안전 핵심] 모든 tool_call 을 scope 로 게이팅.
  pi.on("tool_call", async (event: any, _ctx: ExtensionContext) => {
    await ensureGuard();
    if (authError) {
      // 인가 파일이 어디에도 없으면: 명시 게이트(REDCELL_GATE=1)일 때만 전부 차단(fail-closed),
      // 그 외(우연 로드·수동 pi 세션)는 조용히 통과 — 다른 작업을 방해하지 않는다.
      if (GATE_EXPLICIT) {
        return { block: true, reason: `RedCell: 인가 파일 로드 실패로 모든 액션을 차단합니다. ${authError}` };
      }
      return;
    }
    if (!guard) return; // 이론상 도달 불가

    // 이 호출이 건드리는 대상 호스트들을 추출(전용 툴의 host 인자 + bash/코드 문자열 스캔).
    // pi 0.8x 의 tool_call 이벤트는 {toolName, input:{...}} 형태다.
    const argsStr = JSON.stringify(event?.input ?? event?.arguments ?? event?.args ?? {});
    const toolName = String(event?.toolName ?? event?.name ?? event?.tool ?? "");
    const hosts = extractHosts(argsStr);
    const intent = classifyIntent(toolName, argsStr);

    // 대상이 식별되지 않는 순수 로컬 작업(파일읽기 등)은 통과.
    if (hosts.length === 0) return;

    for (const host of hosts) {
      const target: Target = { host, intent };
      const decision = guard.check(target);
      if (!decision.allowed) {
        return {
          block: true,
          reason: `RedCell scope 위반: ${decision.reason} — authorization.yaml 에 없는 대상이므로 차단합니다.`,
        };
      }
    }
    return; // 모든 대상이 인가됨 → 통과
  });

  // 3) 인가된 대상 전용 정찰 툴.
  pi.registerTool?.(
    defineTool({
      name: "recon_http",
      label: "RedCell HTTP Recon",
      description: "인가된 웹 대상에 GET/HEAD 로 접속해 기술스택을 핑거프린팅한다(비파괴, scope 강제).",
      parameters: Type.Object({
        host: Type.String({ description: "대상 호스트/IP (scope 안이어야 함)" }),
        port: Type.Optional(Type.Number()),
        path: Type.Optional(Type.String({ default: "/" })),
      }),
      async execute(_id, params: { host: string; port?: number; path?: string }) {
        await ensureGuard();
        if (!guard) {
          if (GATE_EXPLICIT) {
            return { content: [{ type: "text", text: `인가 파일 없음: ${authError}` }], details: {}, isError: true } as any;
          }
          return { content: [{ type: "text", text: `RedCell: 인가 게이트가 꺼져 있어 재크 툴을 사용하지 않습니다(설정: REDCELL_GATE=1 + 인가 파일).` }], details: {}, isError: true } as any;
        }
        const target: Target = { host: params.host, port: params.port, intent: "recon" };
        const d = guard.check(target);
        if (!d.allowed) {
          return { content: [{ type: "text", text: `차단: ${d.reason}` }], details: { blocked: true }, isError: true } as any;
        }
        const res = await httpProbe.run({ path: params.path ?? "/" }, { target, rps: guard.requestsPerSecond });
        return {
          content: [{ type: "text", text: res.summary }],
          details: { fingerprint: res.fingerprint, data: res.data },
          isError: !res.ok,
        } as any;
      },
    }),
  );

  // 4) 인가된 웹 대상 전용 페이지 조회 툴 — pi 자체엔 웹 조회 툴이 없어서(코딩 에이전트)
  //     LLM 이 로컬 bash 로 URL 을 치거나 **이 머신의 파일을 뒤지는** 잘못된 흐름이 생긴다.
  //     이 툴로 "URL 입력 → 그 대상만 조사"가 성립한다. 비파괴 GET/HEAD 만 허용,
  //     리다이렉트 홉마다 scope 재검사(다른 origin 도약 차단), 본문 크기 제한.
  const webFetchErr = (msg: string) =>
    ({ content: [{ type: "text", text: msg }], details: { blocked: true }, isError: true }) as any;

  pi.registerTool?.(
    defineTool({
      name: "web_fetch",
      label: "웹 페이지 조회(인가 대상 전용)",
      description:
        "인가된 웹 대상(URL)에 GET/HEAD 를 보내 본문·링크·폼 정보를 읽는다(비파괴, scope 강제). 웹사이트 조사는 반드시 이 툴을 사용한다.",
      parameters: Type.Object({
        url: Type.String({ description: "http(s) URL — 호스트가 인가 목록에 있어야 함" }),
        method: Type.Optional(Type.Union([Type.Literal("GET"), Type.Literal("HEAD")], { default: "GET" })),
        maxBytes: Type.Optional(Type.Integer({ minimum: 1000, maximum: 2_000_000, default: 400_000 })),
      }),
      async execute(_id, params: { url: string; method?: "GET" | "HEAD"; maxBytes?: number }) {
        await ensureGuard();
        if (!guard) {
          return webFetchErr(authError ?? "인가 게이트 준비 안 됨");
        }
        let u: URL;
        try {
          u = new URL(params.url.trim());
        } catch {
          return webFetchErr(`URL 해석 실패: ${params.url}`);
        }
        if (u.protocol !== "http:" && u.protocol !== "https:") {
          return webFetchErr(`http(s) URL 만 허용됩니다: ${u.protocol}//`);
        }
        const method = params.method ?? "GET";
        if (method !== "GET" && method !== "HEAD") {
          return webFetchErr(`허용 메서드는 GET/HEAD 뿐입니다: ${method}`);
        }
        const maxBytes = Math.min(Math.max(params.maxBytes ?? 400_000, 1_000), 2_000_000);
        const hostOf = (x: URL) => x.hostname.replace(/^\[|\]$/g, "");
        const head = guard.check({ host: hostOf(u), intent: "recon" });
        if (!head.allowed) {
          return webFetchErr(`인가되지 않은 대상입니다: ${head.reason}`);
        }

        // 리다이렉트 홉마다 scope 재검사(같은 인가 흐름만 허용, 최대 6홉).
        const hops: string[] = [];
        let cur = u;
        let res: Response | undefined;
        for (let i = 0; i < 6; i++) {
          const d = guard.check({ host: hostOf(cur), intent: "recon" });
          if (!d.allowed) {
            return webFetchErr(`리다이렉트 대상이 인가 범위 밖입니다(차단): ${cur.host}`);
          }
          hops.push(cur.toString());
          try {
            res = await fetch(cur.toString(), {
              method,
              redirect: "manual",
              signal: AbortSignal.timeout(20_000),
              headers: {
                "user-agent": "Mozilla/5.0 (RedCell authorized-agent)",
                accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "accept-language": "ko-KR,ko;q=0.9,en;q=0.8",
              },
            });
          } catch (e) {
            return webFetchErr(`요청 실패: ${e instanceof Error ? e.message : String(e)}`);
          }
          if ([301, 302, 303, 307, 308].includes(res.status)) {
            const loc = res.headers.get("location");
            if (!loc) break;
            let next: URL;
            try {
              next = new URL(loc, cur);
            } catch {
              break;
            }
            if (next.protocol !== "http:" && next.protocol !== "https:") break;
            cur = next;
            continue;
          }
          break;
        }
        if (!res) return webFetchErr("응답을 받지 못했습니다.");

        // 본문 수집(크기 제한).
        let text = "";
        let truncated = false;
        let bytes = 0;
        if (method === "HEAD") {
          bytes = Number(res.headers.get("content-length") ?? 0) || 0;
        } else if (res.body) {
          const reader = res.body.getReader();
          const chunks: Uint8Array[] = [];
          let total = 0;
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
              const room = maxBytes - total;
              if (room <= 0) {
                truncated = true;
                await reader.cancel().catch(() => {});
                break;
              }
              const take = value.subarray(0, Math.min(value.byteLength, room));
              chunks.push(take);
              total += take.byteLength;
              if (take.byteLength < value.byteLength) {
                truncated = true;
                await reader.cancel().catch(() => {});
                break;
              }
            }
          }
          bytes = total;
          text = Buffer.concat(chunks).toString("utf8");
        }

        const ct = (res.headers.get("content-type") ?? "").toLowerCase();
        const isTextual =
          text.length === 0 || /text\//.test(ct) || /json|xml|javascript|svg|form-urlencoded/i.test(ct) || ct === "";
        if (!isTextual) {
          text = `[바이너리 응답 — 본문 생략] (${bytes} bytes, ${ct || "알 수 없음"})`;
        }

        // 링크/폼 추출(마지막 URL 기준 절대화, 중복 제거).
        const links: string[] = [];
        {
          const seen = new Set<string>();
          for (const m of text.slice(0, 300_000).matchAll(/(?:href|src)\s*=\s*["']([^"'#][^"']*)["']/gi)) {
            if (links.length >= 120) break;
            let abs: string;
            try {
              abs = new URL(m[1], cur).toString();
            } catch {
              continue;
            }
            if (seen.has(abs)) continue;
            seen.add(abs);
            links.push(abs);
          }
        }
        const forms: { action: string; method: string }[] = [];
        for (const m of text.matchAll(/<form\b[^>]*>/gi)) {
          if (forms.length >= 30) break;
          const tag = m[0];
          const action = /action\s*=\s*["']([^"']*)["']/i.exec(tag)?.[1] ?? "";
          const methodv = (/method\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1] ?? "get").toLowerCase();
          forms.push({ action, method: methodv });
        }

        const summary = [
          `${res.status} ${res.statusText}`, 
          `URL: ${cur}`, 
          `Content-Type: ${ct || "-"} · bytes: ${bytes}${truncated ? ` (${maxBytes} 초과분 잘림)` : ""}`, 
          `링크 ${links.length}개 · 폼 ${forms.length}개`,
        ].join("\n");
        return {
          content: [{ type: "text", text: `${summary}\n\n${text}` }],
          details: { url: cur.toString(), status: res.status, contentType: ct, bytes, truncated, links, forms, hops },
          isError: res.status >= 400,
        } as any;
      },
    }),
  );

  // 4b) 인가 대상의 여러 경로를 한 번에 프로브하는 정찰 툴 — URL 전용 진단의 공격 표면 확보용.
  //     전부 비파괴 GET/HEAD 이고, 호스트·리다이렉트 홉마다 scope 를 재검사한다.
  pi.registerTool?.(
    defineTool({
      name: "recon_list",
      label: "경로 정찰(인가 대상 전용)",
      description:
        "인가된 웹 대상(호스트)의 여러 경로를 각각 GET/HEAD 로 프로브해 응답 코드·보안 헤더·콘텐츠 타입을 한 번에 조사한다(비파괴, scope 강제). 공격 표면/민감 경로 점검에 사용한다.",
      parameters: Type.Object({
        host: Type.String({ description: "대상 호스트/IP (scope 안이어야 함)" }),
        port: Type.Optional(Type.Number()),
        paths: Type.Array(Type.String(), {
          description: "프로브할 경로 목록 (예: [\"/\", \"/robots.txt\", \"/admin\"]) — 최대 40개",
          maxItems: 40,
        }),
        method: Type.Optional(Type.Union([Type.Literal("GET"), Type.Literal("HEAD")], { default: "GET" })),
      }),
      async execute(_id, params: { host: string; port?: number; paths: string[]; method?: "GET" | "HEAD" }) {
        await ensureGuard();
        if (!guard) {
          return webFetchErr(authError ?? "인가 게이트 준비 안 됨");
        }
        const method = params.method ?? "GET";
        if (method !== "GET" && method !== "HEAD") {
          return webFetchErr(`허용 메서드는 GET/HEAD 뿐입니다: ${method}`);
        }
        const scheme = params.port == null || params.port === 443 || params.port === 8443 ? "https" : "http";
        const portPart = params.port != null && ![80, 443].includes(params.port) ? `:${params.port}` : "";
        const base = `${scheme}://${params.host}${portPart}`;
        const host = params.host.replace(/^\[|\]$/g, "");
        const head = guard.check({ host, intent: "recon" });
        if (!head.allowed) {
          return webFetchErr(`인가되지 않은 대상입니다: ${head.reason}`);
        }
        const paths = [...new Set((params.paths || []).map((p) => (p.startsWith("/") ? p : "/" + p)))].slice(0, 40);
        const rows: string[] = [];
        const findings: any[] = [];
        for (const p of paths) {
          const url = base + p;
          const d = guard.check({ host, intent: "recon" });
          if (!d.allowed) {
            rows.push(`${p} → 차단: ${d.reason}`);
            continue;
          }
          let res: Response;
          try {
            res = await fetch(url, {
              method,
              redirect: "manual",
              signal: AbortSignal.timeout(15_000),
              headers: { "user-agent": "Mozilla/5.0 (RedCell authorized-agent)" },
            });
          } catch (e) {
            rows.push(`${p} → 오류: ${e instanceof Error ? e.message : String(e)}`);
            continue;
          }
          const h = res.headers;
          const types = [
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
          ];
          const present = types.filter((t) => h.has(t));
          const server = h.get("server") ?? "";
          const ctype = (h.get("content-type") ?? "").split(";")[0];
          const noSec = present.length ? present.join(",") : "[보안 헤더 없음]";
          const line = `${res.status} ${p}${ctype ? " · " + ctype : ""}${server ? " · " + server : ""} · ${noSec}`;
          rows.push(line);
          // 후속 분석용 구조화 결과도 남긴다.
          findings.push({ path: p, status: res.status, content_type: ctype, security_headers: present, server });
          if (present.length === 0 && res.status < 400) {
            findings.push({ path: p, note: "보안 헤더 누락(진단 시그널)" });
          }
          // 안전한 폭주 방지
          await new Promise((r) => setTimeout(r, 80));
        }
        return {
          content: [{ type: "text", text: `경로 정찰 결과 (${paths.length}개, ${method}):\n` + rows.join("\n") }],
          details: { host, base, findings },
          isError: false,
        } as any;
      },
    }),
  );

  // 5) 슬래시 명령.
  pi.registerCommand?.("scope", {
    description: "현재 인가(scope) 상태를 출력",
    handler: async (ctx: ExtensionContext) => {
      await ensureGuard();
      const msg = authError
        ? `⛔ 인가 파일 없음/오류: ${authError}`
        : `✅ 인가 로드됨 (간단 IP 목록 우선: ${AUTH_CANDIDATES.join(" > ")})\nRPS 제한: ${guard!.requestsPerSecond}/s`;
      ctx.ui?.info?.(msg) ?? console.log(msg);
    },
  });

  pi.registerCommand?.("playbooks", {
    description: "학습된 playbook 개수 및 목록 요약",
    handler: async (ctx: ExtensionContext) => {
      const dir = path.resolve("redcell/knowledge/playbooks");
      let names: string[] = [];
      try {
        names = (await fs.readdir(dir)).filter((f) => f.endsWith(".json"));
      } catch {
        /* ignore */
      }
      const msg = `📚 playbook ${names.length}건 (${dir})`;
      ctx.ui?.info?.(msg) ?? console.log(msg);
    },
  });
}
