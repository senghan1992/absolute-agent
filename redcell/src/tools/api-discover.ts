/**
 * api_discover — 백엔드 API 표면 발견(비파괴 정찰).
 *
 * 목적: 인가된 웹 대상이 실제로 사용하는 backend API 엔드포인트를 찾아낸다.
 *   예) 공모전 페이지에서 "제출 목록"·"평가 정보"를 반환하는 /api/... 경로.
 *
 * 방법(모두 GET, RPS 준수, 무차별 대입 아님):
 *   1) 시작 페이지(args.path || "/") 를 받아 HTML·인라인 스크립트를 읽는다.
 *   2) 같은 오리진의 <script src> 번들을 (상한 내에서) 받아 참조된 경로를 정규식으로 추출.
 *   3) 잘 알려진 API 서술자(openapi/swagger/api-docs/graphql/robots/sitemap)를 확인.
 *   모든 요청은 ctx.target(스코프 검증된 호스트) 기준 same-origin 으로 제한된다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, safeGet } from "./util.js";

/** 능동 확인하는 잘 알려진 API 서술자/진입점(상한 있는 고정 목록 — 무차별 대입 아님). */
const DESCRIPTORS = [
  "/openapi.json",
  "/swagger.json",
  "/swagger/v1/swagger.json",
  "/v2/api-docs",
  "/api-docs",
  "/api",
  "/api/v1",
  "/graphql",
  "/.well-known/security.txt",
  "/robots.txt",
  "/sitemap.xml",
];

/** 발견한 경로 중 "백엔드 데이터 API 같은" 것으로 볼 신호. */
const API_LIKE = /\/(api|v\d+|graphql|rest|backend|service|data|submissions?|entries|teams?|users?|members?|evaluations?|reviews?|scores?|ranking|results?|admin)\b/i;

const MAX_JS = 6; // 받아볼 같은 오리진 스크립트 수 상한
const MAX_ENDPOINTS = 40; // 보고할 엔드포인트 수 상한
const JS_CAP = 120_000; // 스크립트 본문에서 읽을 최대 문자 수

export const apiDiscover: Tool = {
  name: "api_discover",
  description:
    "대상 웹 페이지와 같은 오리진의 JS 번들을 읽어 참조된 backend API 엔드포인트를 추출하고, " +
    "잘 알려진 API 서술자(openapi/swagger/graphql/robots)를 확인한다(GET만, 비파괴, RPS 준수).",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const origin = originOf(base);
    const startPath = typeof args.path === "string" && args.path ? args.path : "/";

    const endpoints = new Set<string>();
    const descriptorsFound: Array<{ path: string; status: number; kind: string }> = [];
    let reqBudget = MAX_JS + DESCRIPTORS.length + 2;

    // 1) 시작 페이지 HTML.
    let scripts: string[] = [];
    try {
      const page = await get(joinPath(base, startPath), ctx.rps, JS_CAP);
      reqBudget--;
      if (page.body) {
        extractEndpoints(page.body).forEach((e) => endpoints.add(e));
        scripts = sameOriginScripts(page.body, base, origin).slice(0, MAX_JS);
      }
    } catch {
      /* 시작 페이지 실패해도 서술자 확인은 계속 */
    }

    // 2) 같은 오리진 JS 번들에서 엔드포인트 추출.
    for (const src of scripts) {
      if (reqBudget <= 0) break;
      try {
        const js = await get(src, ctx.rps, JS_CAP);
        reqBudget--;
        extractEndpoints(js.body).forEach((e) => endpoints.add(e));
      } catch {
        /* 개별 실패 무시 */
      }
    }

    // 3) 잘 알려진 서술자 확인.
    for (const d of DESCRIPTORS) {
      if (reqBudget <= 0) break;
      try {
        const res = await get(joinPath(base, d), ctx.rps, JS_CAP);
        reqBudget--;
        if (res.status !== 404 && res.status !== 0) {
          const ct = res.headers["content-type"] ?? "";
          const kind = classifyDescriptor(d, res.status, ct, res.body);
          descriptorsFound.push({ path: d, status: res.status, kind });
          // openapi/swagger 문서면 그 안에 나열된 경로도 흡수.
          if (kind === "openapi") pathsFromOpenApi(res.body).forEach((e) => endpoints.add(e));
        }
      } catch {
        /* 무시 */
      }
    }

    const list = [...endpoints].filter((e) => API_LIKE.test(e)).slice(0, MAX_ENDPOINTS);
    const found = list.length + descriptorsFound.length;
    const ok = found > 0;

    const indicators = [
      ...list.map((e) => `endpoint ${e}`),
      ...descriptorsFound.map((d) => `descriptor ${d.path} (${d.status}${d.kind !== "other" ? ", " + d.kind : ""})`),
    ];

    // openapi/swagger/graphql 노출은 공격 표면 문서화 → medium, 그 외 발견은 info.
    const docExposed = descriptorsFound.some((d) => d.kind === "openapi" || d.kind === "graphql");
    const severity = docExposed ? "medium" : "info";
    const title = docExposed
      ? `API 명세 노출 (${descriptorsFound.filter((d) => d.kind === "openapi" || d.kind === "graphql").map((d) => d.path).join(", ")})`
      : `backend API 엔드포인트 ${list.length}개 발견`;

    return {
      ok,
      summary: ok
        ? `API 발견: 엔드포인트 ${list.length}개${descriptorsFound.length ? `, 서술자 ${descriptorsFound.length}개` : ""}`
        : "참조된 backend API 를 찾지 못함",
      fingerprint: ok ? { indicators } : undefined,
      data: ok
        ? {
            severity,
            title,
            evidence: indicators.slice(0, 12).join("; "),
            // api_probe 에 넘길 수 있도록 발견 목록을 구조화해 함께 반환.
            endpoints: list,
            descriptors: descriptorsFound,
          }
        : undefined,
    };
  },
};

// ── 내부 유틸 ─────────────────────────────────────────────────────────────────

interface Out {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** 큰 본문(JS 번들)까지 읽되 상한을 두는 안전 GET. 공용 트랜스포트 경유(per-target RPS·프록시·재시도). */
async function get(url: string, rps: number, cap: number): Promise<Out> {
  return safeGet(url, rps, { cap });
}

function originOf(base: string): string {
  try {
    return new URL(base).origin;
  } catch {
    return base;
  }
}

/** HTML 에서 같은 오리진의 <script src> 절대 URL 목록을 만든다. */
function sameOriginScripts(html: string, base: string, origin: string): string[] {
  const urls = new Set<string>();
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      const abs = new URL(m[1], base);
      if (abs.origin === origin && /\.js(\?|$)/i.test(abs.pathname + abs.search || abs.pathname)) {
        urls.add(abs.toString());
      } else if (abs.origin === origin) {
        urls.add(abs.toString());
      }
    } catch {
      /* 잘못된 src 무시 */
    }
  }
  return [...urls];
}

/** HTML/JS 텍스트에서 참조된 경로 문자열을 추출한다. */
function extractEndpoints(text: string): string[] {
  const out = new Set<string>();
  // 1) 명시적 /api/... 계열
  for (const m of text.matchAll(/\/(?:api|v\d+|graphql|rest|backend)\/[A-Za-z0-9_\-./{}:$]+/gi)) {
    out.add(clean(m[0]));
  }
  // 2) 따옴표로 감싼 절대 경로 중 데이터/목록성 신호가 있는 것
  for (const m of text.matchAll(/["'`](\/[A-Za-z0-9_\-./{}:$]{2,})["'`]/g)) {
    const p = clean(m[1]);
    if (API_LIKE.test(p)) out.add(p);
  }
  return [...out];
}

function clean(p: string): string {
  // 쿼리·해시·후행 구두점 제거, 중복 슬래시 정리.
  return p
    .replace(/[?#].*$/, "")
    .replace(/[.,);'"`]+$/, "")
    .replace(/\/{2,}/g, "/");
}

function classifyDescriptor(path: string, status: number, contentType: string, body: string): string {
  // "명세 노출"로 승격(medium)하려면 실제로 스키마/문서가 서빙돼야 한다 — 상태코드와 본문
  // 신호를 함께 본다. GraphQL 엔드포인트가 존재해도 introspection 이 꺼져(400/403/errors)
  // 있으면 노출이 아니다(오탐 방지). 그런 경우 "other" 로 분류돼 medium 승격에서 빠진다.
  const ok2xx = status >= 200 && status < 300;
  if (path.includes("graphql")) {
    const introspects = /"__schema"|"queryType"|"types"\s*:\s*\[|__typename/.test(body);
    const disabled = /introspection.*disabl|"errors"\s*:/i.test(body);
    return ok2xx && introspects && !disabled ? "graphql" : "graphql-endpoint";
  }
  if (/openapi|swagger|api-docs/.test(path)) {
    if (ok2xx && (/json/.test(contentType) || /"openapi"|"swagger"|"paths"\s*:/.test(body))) return "openapi";
  }
  if (path.includes("robots")) return "robots";
  if (path.includes("sitemap")) return "sitemap";
  if (path.includes("security.txt")) return "security.txt";
  return "other";
}

/** openapi/swagger JSON 문서의 paths 키를 흡수(파싱 실패 시 빈 배열). */
function pathsFromOpenApi(body: string): string[] {
  try {
    const doc = JSON.parse(body);
    if (doc && typeof doc.paths === "object") return Object.keys(doc.paths);
  } catch {
    /* 잘린 본문 등 파싱 실패는 무시 */
  }
  return [];
}
