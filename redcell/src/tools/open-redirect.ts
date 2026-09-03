/**
 * open_redirect — 오픈 리다이렉트 탐지 + PoC.
 *
 * next/url/redirect 류 파라미터에 외부 canary 도메인을 넣어, 서버가 그 외부 주소로
 * 30x Location 리다이렉트(또는 meta refresh)를 발생시키는지 본다.
 *   - Location(또는 refresh) 가 canary 오리진으로 향함 → medium
 * canary 는 실제로 방문하지 않는다(리다이렉트 대상만 관찰). 상태변경 없음.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { forge } from "../core/payload-forge.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

const CANARY = "redcell-canary.example.net"; // 실제 접속하지 않는 관찰용 외부 표식
const DEFAULT_PARAMS = ["next", "url", "redirect", "redirect_uri", "return", "returnUrl", "dest", "destination", "continue", "r", "u"];
const DEFAULT_PATHS = ["/"];
const MAX_PARAMS = 8;
const MAX_PATHS = 8;
const MAX_PAYLOADS = 7;

export const openRedirect: Tool = {
  name: "open_redirect",
  description: "리다이렉트 파라미터에 외부 canary 를 넣어 오픈 리다이렉트를 탐지한다. 외부 오리진으로 30x/meta 리다이렉트 시 medium.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const payloads = pickPayloads(args);

    for (const path of paths) {
      for (const param of params) {
        for (const val of payloads) {
          const url = joinPath(base, withQuery(path, { [param]: val }));
          try {
            const res = await authGet(ctx, url);
            const loc = res.headers["location"] ?? "";
            const viaHeader = res.status >= 300 && res.status < 400 && pointsToCanary(loc);
            const viaMeta = /http-equiv=["']?refresh["']?[^>]*content=["'][^"']*(https?:)?\/\/[^"'/]*redcell-canary/i.test(res.body);
            if (viaHeader || viaMeta) {
              return {
                ok: true,
                summary: `오픈 리다이렉트 확인: ${path} 의 param '${param}' → 외부 ${CANARY} (${viaHeader ? "Location " + res.status : "meta refresh"})`,
                fingerprint: { indicators: [`open-redirect ${path}?${param}`] },
                data: {
                  severity: "medium",
                  title: `Open Redirect (param=${param})`,
                  evidence: viaHeader ? `HTTP ${res.status} Location: ${loc}` : "meta refresh 로 외부 도메인 이동",
                  param,
                },
              };
            }
          } catch {
            /* 무시 */
          }
        }
      }
    }
    return { ok: false, summary: `오픈 리다이렉트 미탐지 (paths=${paths.join(",")}, params=${params.join(",")})` };
  },
};

function pointsToCanary(loc: string): boolean {
  if (!loc) return false;
  try {
    // 절대/프로토콜상대 모두 커버.
    const u = new URL(loc, "http://placeholder.invalid");
    return u.hostname.endsWith("redcell-canary.example.net");
  } catch {
    return loc.includes(CANARY);
  }
}

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
    if (ps.length) return ps.slice(0, MAX_PARAMS);
  }
  return DEFAULT_PARAMS.slice(0, MAX_PARAMS);
}

/** args.payloads(플래너/LLM 주입) 우선, 없으면 forge 의 파서혼동 변형(모두 canary 로 향함). */
function pickPayloads(args: Record<string, unknown>): string[] {
  if (Array.isArray(args.payloads)) {
    const ps = args.payloads.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, MAX_PAYLOADS);
  }
  return forge("redirect").slice(0, MAX_PAYLOADS);
}
