/**
 * csrf_audit — CSRF 방어 부재 탐지(비파괴, 관측 전용).
 *
 * 페이지의 상태변경 폼(<form method=post>)을 파싱해, 위조 방지 토큰과 SameSite 쿠키
 * 방어가 있는지 본다. 폼을 제출하지 않는다(관측만).
 *   - POST 폼에 anti-CSRF 토큰(hidden token/csrf meta) 없음 → medium
 *   - 세션 쿠키에 SameSite 없음까지 겹치면 실제 악용 가능성 ↑ (근거에 명시)
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const FORM_RE = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
const TOKEN_HINT = /(csrf|xsrf|authenticity_token|__requestverificationtoken|_token|nonce)/i;

export const csrfAudit: Tool = {
  name: "csrf_audit",
  description:
    "상태변경 폼(POST)에 위조 방지 토큰/SameSite 방어가 있는지 관측한다. 방어 부재 시 medium. 폼을 제출하지 않는다(비파괴).",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const path = typeof args.path === "string" && args.path ? args.path : "/";
    try {
      const res = await authGet(ctx, joinPath(baseUrl(ctx.target), path));
      const body = res.body;
      const metaToken = /<meta[^>]+name=["']?csrf-token["']?/i.test(body);
      const setCookie = res.headers["set-cookie"] ?? "";
      const sessionCookie = /(sess|sid|token|auth|jwt|login|phpsessid|jsessionid|connect\.sid)/i.test(setCookie);
      const sameSite = /samesite=(lax|strict)/i.test(setCookie);

      const unprotected: string[] = [];
      let postForms = 0;
      for (const m of body.matchAll(FORM_RE)) {
        const tag = m[0].slice(0, m[0].indexOf(">") + 1);
        const inner = m[1] ?? "";
        if (!/method\s*=\s*["']?post/i.test(tag)) continue; // 상태변경(POST) 폼만
        postForms++;
        const action = (tag.match(/action\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1] ?? path;
        const hasHidden = TOKEN_HINT.test(inner);
        if (!hasHidden && !metaToken) unprotected.push(action);
      }

      if (postForms === 0) {
        return { ok: false, summary: `상태변경(POST) 폼 없음 (path=${path})` };
      }
      if (unprotected.length === 0) {
        return { ok: true, summary: `POST 폼 ${postForms}개 — 위조 방지 토큰 확인됨`, data: { severity: "info", title: "CSRF 토큰 존재", evidence: `${postForms}개 POST 폼에 토큰/메타 확인` } };
      }
      const cookieNote = sessionCookie && !sameSite ? " (세션 쿠키에 SameSite 없음 → 악용 가능성 ↑)" : "";
      return {
        ok: true,
        summary: `CSRF 방어 부재: POST 폼 ${unprotected.length}/${postForms}개에 토큰 없음`,
        fingerprint: { indicators: unprotected.map((a) => `csrf-missing ${a}`) },
        data: {
          severity: "medium",
          title: `CSRF 위조 방지 토큰 부재 (${unprotected.length} forms)`,
          evidence: `토큰 없는 POST 폼 action: ${unprotected.slice(0, 5).join(", ")}${cookieNote}`,
        },
      };
    } catch (e) {
      return { ok: false, summary: `csrf_audit 실패: ${(e as Error).message}` };
    }
  },
};
