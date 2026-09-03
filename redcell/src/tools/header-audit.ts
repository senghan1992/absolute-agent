/**
 * header_audit — 보안 헤더 점검(방어적 발견).
 * 누락된 보안 헤더를 저위험 발견으로 보고한다. 순수 관측, 완전 비파괴.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, authGet } from "./util.js";

const EXPECTED: Array<{ header: string; why: string }> = [
  { header: "content-security-policy", why: "XSS/데이터 주입 완화" },
  { header: "strict-transport-security", why: "프로토콜 다운그레이드 방지" },
  { header: "x-frame-options", why: "클릭재킹 방지" },
  { header: "x-content-type-options", why: "MIME 스니핑 방지" },
  { header: "referrer-policy", why: "레퍼러 유출 최소화" },
];

export const headerAudit: Tool = {
  name: "header_audit",
  description: "응답 보안 헤더를 점검해 누락 항목을 방어 관점 발견으로 보고한다(비파괴).",
  intent: "recon",
  async run(_args, ctx: ToolContext): Promise<ToolResult> {
    try {
      const res = await authGet(ctx, baseUrl(ctx.target));
      const missing = EXPECTED.filter((e) => !(e.header in res.headers));
      const ok = true;
      return {
        ok,
        summary: `헤더 점검: 누락 ${missing.length}/${EXPECTED.length}`,
        fingerprint: { indicators: missing.map((m) => `missing ${m.header}`) },
        data: missing.length
          ? {
              severity: missing.length >= 3 ? "medium" : "low",
              title: `보안 헤더 누락 (${missing.map((m) => m.header).join(", ")})`,
              evidence: missing.map((m) => `${m.header}: ${m.why}`).join("; "),
            }
          : { severity: "info", title: "주요 보안 헤더 모두 존재", evidence: "CSP/HSTS/XFO/XCTO/RP 확인" },
      };
    } catch (e) {
      return { ok: false, summary: `헤더 점검 실패: ${(e as Error).message}` };
    }
  },
};
