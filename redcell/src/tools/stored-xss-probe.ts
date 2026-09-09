/**
 * stored_xss_probe — 저장형(Stored/2차) XSS 탐지 + 실증. **opt-in** (상태변경 수반).
 *
 * 1) crawl 지표의 폼/파라미터에 마커 페이로드 `<img src=x onerror=RCST<rand>>` 를
 *    POST 로 저장(상태변경 — opt-in 사유).
 * 2) 주입 후 같은 경로 + 링크된 페이지(지표에서 최대 5곳)를 **다른 요청으로** 재 fetch.
 * 3) 다른 요청의 응답에서 마커가 **미이스케이프**(`<img…` 원문)로 등장하면 저장형 확정.
 *
 * FP 방어: 첫 응답(에코)만 있으면 발견하지 않는다 — 반사형은 xss_probe 의 영역.
 * 저장된 값이 이스케이프돼 있으면 클린. 고유 마커로 정적 콘텐츠와 구분.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, authPost, baseUrl, joinPath } from "./util.js";

const MAX_FETCH_PAGES = 5;

export const storedXssProbe: Tool = {
  name: "stored_xss_probe",
  description:
    "폼/파라미터에 무해 마커를 POST 로 저장한 뒤 별도 요청으로 재 fetch 해, 저장형 XSS(미이스케이프 2차 반사)를 실증한다. 상태변경(저장) 수반 — opt-in 필요.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const rand = Math.random().toString(36).slice(2, 8);
    const marker = `RCST${rand}`;
    const payload = `<img src=x onerror=${marker}>`;

    const paths = pickPaths(args);
    const formTargets = buildFormTargets(args, paths);

    for (const ft of formTargets.slice(0, 6)) {
      // 1) 저장(POST) — 폼 필드 중 하나에 마커 페이로드. 숨김 필드는 건드리지 않는다.
      const body = ft.fields
        .map((f) => {
          const v = f.name === ft.injectField ? payload : (f.value ?? "");
          return `${encodeURIComponent(f.name)}=${encodeURIComponent(v)}`;
        })
        .join("&");
      let res;
      try {
        res = await authPost(ctx, joinPath(base, ft.url), body, { contentType: "application/x-www-form-urlencoded", cap: 4000 });
      } catch {
        continue;
      }
      const firstEcho = res.body.includes(marker) || res.body.includes(payload);
      if (!firstEcho && res.status >= 400) continue; // 저장 자체가 거부됨

      // 2) 재 fetch — 저장된 페이지 경로 + 링크된 페이지(최대 MAX_FETCH_PAGES).
      const refetchPages = [...new Set([ft.url, ...paths])].slice(0, MAX_FETCH_PAGES);
      for (const page of refetchPages) {
        let got;
        try {
          got = await authGet(ctx, joinPath(base, page));
        } catch {
          continue;
        }
        // 3) 저장형 확정: **다른 요청**의 응답에 미이스케이프 원문이 실렸을 때.
        if (got.body.includes(payload)) {
          const snippet = got.body.slice(Math.max(0, got.body.indexOf(payload) - 60), got.body.indexOf(payload) + payload.length + 40).replace(/\s+/g, " ");
          return {
            ok: true,
            summary: `저장형 XSS 실증: ${ft.url} 에 저장한 마커가 ${page} 에서 미이스케이프 2차 반사`,
            fingerprint: { indicators: [`stored-xss ${ft.url}`] },
            data: {
              severity: "high",
              title: `Stored XSS (path=${page})`,
              evidence: `저장형 XSS 실증: 제2 요청에서 미이스케이프 저장 반사 (path=${page}) — 폼 ${ft.url} 에 저장 → 렌더: ${snippet}`,
              path: page,
              storedAt: ft.url,
            },
          };
        }
        // 이스케이프돼 저장된 경우(e.g. &lt;img) — 클린, 계속 본다.
      }
    }
    return { ok: false, summary: `저장형 XSS 미탐지 (대상 ${formTargets.length}개 폼/파라미터, 재fetch ${MAX_FETCH_PAGES}페이지)` };
  },
};

interface FormTarget {
  url: string;
  fields: Array<{ name: string; value?: string }>;
  injectField: string;
}

/**
 * args.paths(로 표적화된 경로)와 args.params 를 보고 저장 대상 후보를 만든다.
 * - 폼이 있으면 폼 action + 입력 필드를 그대로 쓴다(실제 저장 지점).
 * - 폼이 없으면 경로+파라미터 조합을 폼처럼 가정해 주입한다.
 */
function buildFormTargets(args: Record<string, unknown>, paths: string[]): FormTarget[] {
  const out: FormTarget[] = [];
  const params = Array.isArray(args.params)
    ? (args.params.filter((x): x is string => typeof x === "string").slice(0, 4))
    : typeof args.param === "string" && args.param
      ? [args.param]
      : ["comment", "message", "content", "title", "name", "q"];
  for (const p of paths) {
    out.push({ url: p, fields: params.map((name) => ({ name })), injectField: params[0] });
  }
  return out;
}

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, 8);
  }
  return ["/"];
}