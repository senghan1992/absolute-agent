/**
 * cookie_audit — 세션 쿠키 보안 속성 점검.
 *
 * 응답의 Set-Cookie 를 파싱해 세션성 쿠키의 보안 플래그 누락을 본다.
 *   - 세션 쿠키에 HttpOnly 누락        → medium (XSS 로 세션 탈취 표면 확대)
 *   - Secure / SameSite 누락           → low (전송 노출 / CSRF 표면)
 * 비파괴 GET 한 번. 값 자체를 저장/전송하지 않는다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, authGet } from "./util.js";

const SESSIONISH = /(sess|sid|token|auth|jwt|login|phpsessid|jsessionid|connect\.sid)/i;

export const cookieAudit: Tool = {
  name: "cookie_audit",
  description: "Set-Cookie 를 파싱해 세션 쿠키의 HttpOnly/Secure/SameSite 누락을 점검한다. HttpOnly 누락 시 medium.",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const path = typeof args.path === "string" && args.path ? args.path : "/";
    try {
      const res = await authGet(ctx, joinPath(base, path));
      const raw = res.headers["set-cookie"];
      if (!raw) return { ok: false, summary: "Set-Cookie 없음 — 점검할 쿠키가 없습니다." };

      // fetch 는 여러 Set-Cookie 를 콤마로 합칠 수 있어 쿠키 경계를 보수적으로 분리.
      const cookies = splitCookies(raw);
      const issues: string[] = [];
      let worst: "low" | "medium" = "low";
      for (const c of cookies) {
        const name = c.split("=")[0].trim();
        const flags = c.toLowerCase();
        const sessiony = SESSIONISH.test(name);
        const miss: string[] = [];
        if (!/httponly/.test(flags)) {
          miss.push("HttpOnly");
          if (sessiony) worst = "medium";
        }
        if (!/secure/.test(flags)) miss.push("Secure");
        if (!/samesite/.test(flags)) miss.push("SameSite");
        if (miss.length) issues.push(`${name}: ${miss.join("/")} 누락${sessiony ? " (세션성)" : ""}`);
      }

      if (issues.length === 0) return { ok: false, summary: `쿠키 보안 플래그 양호 (${cookies.length}개)` };
      return {
        ok: true,
        summary: `쿠키 플래그 누락 ${issues.length}건: ${issues.join(" | ")}`,
        fingerprint: { indicators: issues.map((i) => `cookie ${i}`) },
        data: {
          severity: worst,
          title: worst === "medium" ? `세션 쿠키 HttpOnly 누락` : `쿠키 보안 플래그 누락`,
          evidence: issues.join("; "),
        },
      };
    } catch (e) {
      return { ok: false, summary: `cookie_audit 실패: ${(e as Error).message}` };
    }
  },
};

/** "a=1; Path=/, b=2; Secure" → ["a=1; Path=/", "b=2; Secure"] (속성 콤마 오분리 최소화). */
function splitCookies(raw: string): string[] {
  // 콤마 뒤에 "이름=" 이 오는 경우만 새 쿠키 경계로 본다(Expires 의 요일 콤마 방어).
  return raw
    .split(/,(?=\s*[A-Za-z0-9!#$%&'*+._`|~-]+=)/)
    .map((s) => s.trim())
    .filter(Boolean);
}
