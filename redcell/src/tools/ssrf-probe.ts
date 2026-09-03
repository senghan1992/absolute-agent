/**
 * ssrf_probe — 서버측 요청 위조(SSRF) 신호 탐지.
 *
 * url/uri/dest 류 파라미터에 내부/메타데이터 주소를 넣어, 서버가 그 주소를 대신
 * 요청한 흔적이 응답에 드러나는지 관찰한다(비블라인드 신호).
 *   - 클라우드 메타데이터(169.254.169.254) 응답 시그니처 반사      → high
 *   - 내부 주소 요청 시 유의미한 상태/본문 변화(fetch 정황)         → medium(가능성)
 * 실제 내부 자원을 대상으로 공격하지 않는다 — 대상 서버의 반사 신호만 본다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { forge } from "../core/payload-forge.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

// 클라우드 메타데이터 "응답"에서 나타나는 시그니처들. 개별로 검사해서, 응답 본문엔
// 있지만 우리가 보낸 URL 문자열엔 없는 시그니처가 하나라도 있으면 실제 fetch 로 본다
// (단순 반사 오탐 방지 — 일부 시그니처는 payload URL 에도 등장하기 때문).
const META_SIGNS = [
  /ami-id/i,
  /instance-id/i,
  /iam\/security-credentials/i,
  /computeMetadata/i,
  /metadata\.google/i,
  /"AccessKeyId"/i,
];
/** 응답 본문에는 있으나 보낸 URL 에는 없는 메타데이터 시그니처가 있으면 true. */
function fetchedMetadata(body: string, sentUrl: string): boolean {
  return META_SIGNS.some((re) => re.test(body) && !re.test(sentUrl));
}
const DEFAULT_PARAMS = ["url", "uri", "target", "dest", "callback", "webhook", "image", "img", "fetch", "load", "proxy", "u"];
const DEFAULT_PATHS = ["/"];
const MAX_PARAMS = 6;
const MAX_PATHS = 8;
const MAX_TARGETS = 8;

export const ssrfProbe: Tool = {
  name: "ssrf_probe",
  description:
    "url/uri 류 파라미터에 내부·클라우드 메타데이터 주소를 넣어 SSRF 신호를 관찰한다. 메타데이터 반사 시 high, 내부요청 정황 시 medium.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const targets = pickTargets(args);

    // 기준(무해 외부값) 응답과 비교하기 위한 베이스라인.
    let possible: { path: string; param: string; note: string } | null = null;

    for (const path of paths) {
      for (const param of params) {
        for (const t of targets) {
          const url = joinPath(base, withQuery(path, { [param]: t }));
          try {
            const res = await authGet(ctx, url);
            // 핵심: 시그니처가 "우리가 보낸 URL 이 그대로 반사된 것"이면 SSRF 가 아니다.
            // (예: computeMetadata 는 payload URL 문자열에도 들어있으므로, 단순 반사
            //  엔드포인트에서 오탐이 난다.) 서버가 실제로 메타데이터를 대신 가져와
            //  그 응답 내용을 돌려준 경우에만 신호로 인정한다.
            if (fetchedMetadata(res.body, t)) {
              return {
                ok: true,
                summary: `SSRF 확인: ${path} 의 param '${param}' 로 클라우드 메타데이터 반사`,
                fingerprint: { indicators: [`ssrf ${path}?${param}`, "cloud-metadata"] },
                data: {
                  severity: "high",
                  title: `SSRF → 클라우드 메타데이터 접근 (param=${param})`,
                  evidence: `메타데이터 시그니처가 응답에 반사됨 (path=${path}, target=${t})`,
                  param,
                },
              };
            }
            // 내부주소 요청 시 200 + 비HTML(프록시 정황)이면 가능성으로 기록.
            if (!possible && res.status === 200 && /json|xml|text\/plain/i.test(res.headers["content-type"] ?? "")) {
              possible = { path, param, note: `내부주소 요청에 ${res.status}/${res.headers["content-type"]} 응답` };
            }
          } catch {
            /* 무시 */
          }
        }
      }
    }

    if (possible) {
      return {
        ok: true,
        summary: `SSRF 가능성: ${possible.path} 의 param '${possible.param}' — ${possible.note}`,
        fingerprint: { indicators: [`ssrf-possible ${possible.path}?${possible.param}`] },
        data: {
          severity: "medium",
          title: `SSRF 가능성 (param=${possible.param})`,
          evidence: `${possible.note} — canary 서버로 아웃바운드 확인 권고`,
          param: possible.param,
        },
      };
    }
    return { ok: false, summary: `SSRF 신호 미탐지 (paths=${paths.join(",")}, params=${params.join(",")})` };
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

/** args.payloads(플래너/LLM 주입) 우선, 없으면 forge 의 내부/메타데이터 + 우회표기 변형. */
function pickTargets(args: Record<string, unknown>): string[] {
  if (Array.isArray(args.payloads)) {
    const ps = args.payloads.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, MAX_TARGETS);
  }
  return forge("ssrf").slice(0, MAX_TARGETS);
}
