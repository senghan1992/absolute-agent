/**
 * cache_poison_probe — 웹 캐시 포이즈닝(2단계 확인) 탐지. **안전(비파괴) 방법론**.
 *
 * 캐시 포이즈닝은 잘못하면 실제 사용자에게 오염된 응답을 서빙하게 되어 파괴적이다.
 * 그래서 여기서는 표준 안전 기법(cache buster)만 쓴다:
 *   - 매 시도마다 **고유한 cache-buster 쿼리**(?rc_cb=<rand>)를 붙인다 → 우리가 만든
 *     캐시 키는 다른 사용자가 절대 요청하지 않는 고립된 URL 이다(실사용자 무영향).
 *   - 1단계: unkeyed 헤더(X-Forwarded-Host 등)에 canary 를 실어 요청. 응답이 canary 를
 *     반영하고 **캐시 가능**(Cache-Control public/max-age>0, Age, X-Cache 등)한지 본다.
 *   - 2단계: **같은 cache-buster URL** 을 이번엔 헤더 없이 요청. 그래도 canary 가 나오면
 *     = 앞선 오염 응답이 캐시에서 서빙된 것 → 캐시 포이즈닝 확정(high).
 *
 * canary 는 무해한 표식 문자열이며 실제 접속하지 않는다. 고유 키라 blast radius=0.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

/** 캐시가 반영할 만한 대표적 unkeyed 헤더들(있으면 응답에 반영되지만 캐시 키엔 안 들어감). */
const UNKEYED_HEADERS = ["x-forwarded-host", "x-forwarded-scheme", "x-forwarded-proto", "x-forwarded-port", "x-host", "x-original-url"];
const CANARY_HOST = "rc-cache-canary.example.net";
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 6;

export const cachePoisonProbe: Tool = {
  name: "cache_poison_probe",
  description:
    "고유 cache-buster 로 격리된 키에서만, unkeyed 헤더(X-Forwarded-Host 등)가 캐시 가능한 응답에 반영되고 2차 요청에도 캐시로 서빙되는지 확인해 웹 캐시 포이즈닝을 탐지한다(실사용자 무영향, 비파괴). [opt-in 필요]",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    let reflectedButNotCached: { path: string; header: string } | null = null;

    for (const path of paths) {
      for (const header of UNKEYED_HEADERS) {
        const cb = `rc_cb=${rand()}`;
        const url = joinPath(base, addQuery(path, cb));
        const canary = `${CANARY_HOST}`;

        let first;
        try {
          first = await authGet(ctx, url, { headers: { [header]: canary }, cap: 8000 });
        } catch {
          continue;
        }
        // canary 가 응답(본문 절대 URL/링크 또는 Location)에 반영돼야 후보.
        const reflected = reflectsCanary(first.body) || (first.headers["location"] ?? "").includes(canary);
        if (!reflected) continue;

        // 캐시 가능 신호가 있어야 포이즈닝 의미가 있다.
        if (!looksCacheable(first.headers)) {
          reflectedButNotCached = reflectedButNotCached ?? { path, header };
          continue;
        }

        // 2단계: 같은 cache-buster URL 을 헤더 없이 요청 → 캐시에서 오염 응답이 나오면 확정.
        let second;
        try {
          second = await authGet(ctx, url, { cap: 8000 });
        } catch {
          continue;
        }
        const stillPoisoned = reflectsCanary(second.body) || (second.headers["location"] ?? "").includes(canary);
        if (stillPoisoned) {
          return {
            ok: true,
            summary: `웹 캐시 포이즈닝 확정: ${path} 에서 unkeyed 헤더 '${header}' 가 캐시된 응답에 반영(2단계 확인)`,
            fingerprint: { indicators: [`cache-poisoning ${path} ${header}`] },
            data: {
              severity: "high",
              title: `웹 캐시 포이즈닝 (${path}, ${header})`,
              evidence:
                `1차: '${header}: ${canary}' 반영 + 캐시가능(${cacheSignal(first.headers)}); ` +
                `2차: 헤더 없이 같은 URL 요청에도 canary 서빙 — 캐시 오염 확인(격리 cache-buster 키라 실사용자 무영향)`,
              impact:
                "unkeyed 헤더로 오염한 응답이 캐시를 통해 다른 사용자에게 서빙된다 → 저장형 XSS/오픈리다이렉트/컨텐츠 위변조를 캐시 범위 전체로 확산(대규모 세션 탈취·피싱). 캐시 키에 관련 헤더 포함 또는 unkeyed 입력의 응답 반영 제거 필요.",
            },
          };
        }
      }
    }

    if (reflectedButNotCached) {
      return {
        ok: true,
        summary: `unkeyed 헤더 반영(캐시 근거 약함): ${reflectedButNotCached.path} / ${reflectedButNotCached.header}`,
        fingerprint: { indicators: [`unkeyed-reflection ${reflectedButNotCached.path}`] },
        data: {
          severity: "low",
          title: `unkeyed 헤더 반영 (${reflectedButNotCached.path})`,
          evidence: `'${reflectedButNotCached.header}' 값이 응답에 반영되나 캐시 가능 신호는 확인되지 않음 — 캐시 앞단(CDN) 도입 시 포이즈닝 위험`,
          impact: "현재는 캐시 서빙이 확인되지 않았으나, 앞단 캐시/CDN 이 붙으면 즉시 캐시 포이즈닝으로 전환된다. unkeyed 입력의 응답 반영을 제거하라.",
        },
      };
    }
    return { ok: false, summary: `캐시 포이즈닝 미탐지 (paths=${paths.join(",")})` };
  },
};

/** 응답 헤더에 캐시 가능/캐시 히트 신호가 있는가. */
function looksCacheable(h: Record<string, string>): boolean {
  const cc = (h["cache-control"] ?? "").toLowerCase();
  if (/no-store|private/.test(cc)) return false;
  if (/public|s-maxage|max-age=[1-9]/.test(cc)) return true;
  if (h["age"] !== undefined) return true;
  const xc = (h["x-cache"] ?? "").toLowerCase();
  if (/hit|miss/.test(xc)) return true;
  if (h["cf-cache-status"] || h["x-cache-hits"] || h["x-varnish"]) return true;
  return false;
}
function cacheSignal(h: Record<string, string>): string {
  const parts: string[] = [];
  if (h["cache-control"]) parts.push(`Cache-Control: ${h["cache-control"]}`);
  if (h["age"] !== undefined) parts.push(`Age: ${h["age"]}`);
  if (h["x-cache"]) parts.push(`X-Cache: ${h["x-cache"]}`);
  if (h["cf-cache-status"]) parts.push(`CF-Cache-Status: ${h["cf-cache-status"]}`);
  return parts.join(", ") || "캐시 헤더";
}

function reflectsCanary(body: string): boolean {
  const c = CANARY_HOST.replace(/\./g, "\\.");
  return new RegExp(`(?:https?:)?//${c}|(?:href|src|action)\\s*=\\s*["']?[^"'>]*${c}`, "i").test(body);
}

function addQuery(path: string, kv: string): string {
  return `${path}${path.includes("?") ? "&" : "?"}${kv}`;
}
function rand(): string {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}
function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS;
}
