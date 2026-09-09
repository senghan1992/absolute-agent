/**
 * crawl — 얕은 크롤링으로 실제 공격 표면(경로·폼·파라미터)을 발견한다(정찰).
 *
 * 추측한 파라미터 이름 대신 "실제로 존재하는" 링크/폼/쿼리 파라미터를 수집해
 * `endpoint /path?param=` 지표로 남긴다. 이후 인젝션 툴(sqli/xss/…)이 이 실제
 * 파라미터를 표적으로 삼아 정확도가 크게 오른다.
 *
 * 깊이 1, 최대 페이지 소수(RPS 준수). 같은 오리진만 따라간다. 순수 관측(GET).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const HREF_RE = /(?:href|action|src)\s*=\s*["']([^"'#]+)["']/gi;
const FORM_RE = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
const INPUT_NAME_RE = /<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([A-Za-z0-9_.\-\[\]]+)/gi;
// 크롤 폭: 실전 사이트(메뉴·페이지네이션·JS 링크)에서 표면을 제대로 담으려면 홈페이지만
// 돌아서는 안 된다. RPS 준수 하에서 24 페이지 / 64 엔드포인트 까지 수집한다(초기 5/20 은
// prime-agent 같은 자유 탐색 에이전트 대비 수집량이 크게 밀렸던 원인).
const MAX_PAGES = 24;
const MAX_ENDPOINTS = 64;

export const crawl: Tool = {
  name: "crawl",
  description:
    "얕은 크롤링으로 실제 링크·폼·쿼리 파라미터를 수집해 endpoint 지표로 남긴다(추측 대신 실제 표면). 같은 오리진만, GET 관측 전용.",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const seed = typeof args.path === "string" && args.path ? args.path : "/";
    const host = ctx.target.host;

    const toVisit = [seed];
    const visited = new Set<string>();
    const endpoints = new Set<string>(); // "/path" 또는 "/path?param="
    const forms: string[] = [];

    while (toVisit.length && visited.size < MAX_PAGES) {
      const path = toVisit.shift()!;
      if (visited.has(path)) continue;
      visited.add(path);
      let res;
      try {
        res = await authGet(ctx, joinPath(base, path));
      } catch {
        continue;
      }
      const body = res.body;

      // 링크/액션/스크립트 URL 수집 → 같은 오리진 경로만.
      for (const m of body.matchAll(HREF_RE)) {
        const norm = sameOriginPath(m[1], host, path);
        if (!norm) continue;
        const [p, q] = splitQuery(norm);
        if (q.length) {
          for (const param of q) endpoints.add(`${p}?${param}=`);
        } else {
          endpoints.add(p);
        }
        if (!visited.has(p) && !toVisit.includes(p) && toVisit.length < MAX_PAGES) toVisit.push(p);
      }

      // 폼 → action + 입력 파라미터 이름.
      for (const fm of body.matchAll(FORM_RE)) {
        const tag = fm[1] ?? "";
        const inner = fm[2] ?? "";
        const actionRaw = (tag.match(/action\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1] ?? path;
        const action = sameOriginPath(actionRaw, host, path) ?? path;
        const [ap] = splitQuery(action);
        const names = [...inner.matchAll(INPUT_NAME_RE)].map((x) => x[1]);
        forms.push(`${ap}(${names.slice(0, 8).join(",")})`);
        if (names.length) for (const n of names) endpoints.add(`${ap}?${n}=`);
        else endpoints.add(ap);
      }
    }

    const list = [...endpoints].slice(0, MAX_ENDPOINTS);
    if (list.length === 0) {
      return { ok: false, summary: `크롤링: 표면 미발견 (seed=${seed}, ${visited.size}p)` };
    }
    const withParams = list.filter((e) => e.includes("?")).length;
    return {
      ok: true,
      summary: `크롤링: ${visited.size}p 방문, endpoint ${list.length}개(파라미터 ${withParams}) · 폼 ${forms.length}개`,
      fingerprint: { indicators: [...list.map((e) => `endpoint ${e}`), ...forms.map((f) => `form ${f}`)] },
      data: {
        severity: "info",
        title: `공격 표면 수집: ${list.length} endpoints`,
        evidence: `파라미터 보유 endpoint ${withParams}개, 폼 ${forms.length}개 — 인젝션 표적으로 사용`,
      },
    };
  },
};

/** 상대/절대 URL 을 같은 오리진 경로로 정규화. 외부 오리진/비HTTP 는 null. */
function sameOriginPath(raw: string, host: string, fromPath: string): string | null {
  const v = raw.trim();
  if (!v || v.startsWith("mailto:") || v.startsWith("tel:") || v.startsWith("javascript:") || v.startsWith("data:")) return null;
  try {
    const u = new URL(v, `http://${host}${fromPath.startsWith("/") ? "" : "/"}${fromPath}`);
    if (u.hostname !== host) return null; // 외부 오리진 제외
    return u.pathname + (u.search || "");
  } catch {
    return null;
  }
}

/** "/p?a=1&b=2" → ["/p", ["a","b"]] */
function splitQuery(path: string): [string, string[]] {
  const qi = path.indexOf("?");
  if (qi < 0) return [path, []];
  const p = path.slice(0, qi);
  const params = [...new URLSearchParams(path.slice(qi + 1)).keys()];
  return [p, params];
}
