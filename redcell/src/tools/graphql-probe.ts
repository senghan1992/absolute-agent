/**
 * graphql_probe — GraphQL introspection 노출 탐지.
 *
 * 잘 알려진 GraphQL 엔드포인트에 최소 introspection 쿼리를 보내(단일 GET/POST),
 * 스키마가 그대로 반환되는지 본다.
 *   - __schema.types 가 노출됨 → medium (공격 표면 전체 문서화 = 열거 가속)
 * 뮤테이션을 실행하지 않는다(읽기 전용 introspection 쿼리만).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, authGet, authPost, withQuery } from "./util.js";

const ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"];
// 최소 introspection: 타입 이름만 요청.
const INTROSPECT = "{__schema{queryType{name} types{name kind}}}";

export const graphqlProbe: Tool = {
  name: "graphql_probe",
  description: "GraphQL 엔드포인트에 introspection 쿼리를 보내 스키마 노출을 탐지한다. __schema 반환 시 medium(공격 표면 문서화).",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const eps = pickEndpoints(args);

    for (const ep of eps) {
      // 1) GET ?query= (많은 서버가 허용)
      const getUrl = joinPath(base, withQuery(ep, { query: INTROSPECT }));
      const bodies: string[] = [];
      try {
        bodies.push((await authGet(ctx, getUrl)).body);
      } catch {
        /* 무시 */
      }
      // 2) POST application/json (표준 GraphQL)
      try {
        bodies.push((await authPost(ctx, joinPath(base, ep), JSON.stringify({ query: INTROSPECT }), { cap: 8000 })).body);
      } catch {
        /* 무시 */
      }

      for (const body of bodies) {
        if (/"__schema"|"queryType"|"types"\s*:\s*\[/.test(body)) {
          const types = countTypes(body);
          return {
            ok: true,
            summary: `GraphQL introspection 노출: ${ep} (${types}개 타입)`,
            fingerprint: { indicators: [`graphql-introspection ${ep}`, "graphql"] },
            data: {
              severity: "medium",
              title: `GraphQL Introspection 노출 (${ep})`,
              evidence: `introspection 쿼리에 스키마 반환(타입 ${types}개) — 전체 공격 표면 문서화`,
              endpoint: ep,
            },
          };
        }
      }
    }
    return { ok: false, summary: `GraphQL introspection 미탐지 (endpoints=${eps.join(",")})` };
  },
};

function countTypes(body: string): number {
  try {
    const doc = JSON.parse(body);
    const types = doc?.data?.__schema?.types;
    return Array.isArray(types) ? types.length : 0;
  } catch {
    return (body.match(/"name"/g) ?? []).length;
  }
}

function pickEndpoints(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps;
  }
  return ENDPOINTS;
}
