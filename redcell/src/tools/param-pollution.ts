/**
 * param_pollution — HTTP 파라미터 오염(HPP) 탐지(안전·비파괴).
 *
 * 같은 파라미터를 두 번 넣어(`?p=A&p=B`) 서버/프레임워크가 이를 어떻게 파싱하는지 본다.
 * 값을 이어붙이거나(둘 다 반영), 앞단(WAF/게이트웨이)과 뒷단(앱)이 서로 다른 값을 채택하면
 * 접근통제·WAF 우회의 근거가 된다.
 *   - 중복 파라미터의 두 값이 모두 응답에 반영(파싱 모호성) → medium
 * 읽기 전용 GET, 무해 마커만 사용.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const A = "RCa" + Math.random().toString(36).slice(2, 6);
const B = "RCb" + Math.random().toString(36).slice(2, 6);
const DEFAULT_PARAMS = ["q", "s", "search", "id", "name", "role", "user", "page", "next", "redirect"];
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 6;
const MAX_PARAMS = 6;

export const paramPollution: Tool = {
  name: "param_pollution",
  description:
    "같은 파라미터를 중복 전송(?p=A&p=B)해 파싱 모호성(HPP)을 탐지한다. 두 값이 모두 반영되면 접근통제/WAF 우회 근거(medium). 읽기 전용.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);

    for (const path of paths) {
      for (const p of params) {
        // 인코딩된 중복 파라미터를 직접 만든다(withQuery 는 키 중복을 못 만들어 수동 조립).
        const qs = `${encodeURIComponent(p)}=${A}&${encodeURIComponent(p)}=${B}`;
        const url = joinPath(base, `${path}${path.includes("?") ? "&" : "?"}${qs}`);
        try {
          const res = await authGet(ctx, url, { cap: 6000 });
          const hasA = res.body.includes(A);
          const hasB = res.body.includes(B);
          if (hasA && hasB) {
            return {
              ok: true,
              summary: `HPP 신호: ${path} 의 '${p}' 중복 시 두 값이 모두 반영(파싱 모호성)`,
              fingerprint: { indicators: [`http-param-pollution ${path}?${p}`] },
              data: {
                severity: "medium",
                title: `HTTP Parameter Pollution (param=${p})`,
                evidence: `${path}?${p}=${A}&${p}=${B} 응답에 두 값(${A}, ${B})이 모두 반영됨`,
                param: p,
                impact:
                  "앞단(WAF/게이트웨이)과 뒷단(앱)이 서로 다른 값을 채택하면 접근통제·필터 우회로 이어져 인가 검사·WAF 룰을 통과시키는 발판이 된다.",
              },
            };
          }
        } catch {
          /* 무시 */
        }
      }
    }
    return { ok: false, summary: `HPP 미탐지 (paths=${paths.join(",")}, params=${params.join(",")})` };
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
    if (ps.length) return ps.slice(0, MAX_PARAMS);
  }
  return DEFAULT_PARAMS.slice(0, MAX_PARAMS);
}
