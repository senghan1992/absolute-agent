/**
 * cors_audit — CORS 설정 오류 탐지.
 *
 * 공격자가 통제하는 Origin 을 헤더로 보내, 서버가 그 Origin 을 그대로 신뢰하는지 본다.
 *   - Access-Control-Allow-Origin 이 요청 Origin 을 반사 + Allow-Credentials: true → high
 *     (인증 쿠키를 실은 교차출처 읽기 가능 = 계정 데이터 탈취 표면)
 *   - ACAO: * (자격증명 없이 전체 허용)                                        → low/medium
 *   - null Origin 신뢰                                                         → medium
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, authGet } from "./util.js";

const EVIL = "https://redcell-evil.example.com";

export const corsAudit: Tool = {
  name: "cors_audit",
  description: "임의 Origin 헤더로 요청해 CORS 신뢰 정책을 점검한다. Origin 반사+credentials 시 high, 와일드카드/null 신뢰 시 medium.",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const path = typeof args.path === "string" && args.path ? args.path : "/";
    const url = joinPath(base, path);

    try {
      const reflect = await authGet(ctx, url, { headers: { Origin: EVIL } });
      const nullRes = await authGet(ctx, url, { headers: { Origin: "null" } });

      const acao = (reflect.headers["access-control-allow-origin"] ?? "").trim();
      const acac = (reflect.headers["access-control-allow-credentials"] ?? "").trim().toLowerCase();
      const nullAcao = (nullRes.headers["access-control-allow-origin"] ?? "").trim();

      if (acao === EVIL && acac === "true") {
        return finding("high", `임의 Origin 반사 + credentials 허용`, `ACAO: ${acao}, ACAC: true — 인증정보 실은 교차출처 읽기 가능`, path);
      }
      if (acao === EVIL) {
        return finding("medium", `임의 Origin 반사`, `ACAO 가 요청 Origin(${EVIL}) 을 반사 — 정책 검토 필요`, path);
      }
      if (nullAcao === "null") {
        return finding("medium", `null Origin 신뢰`, `Origin: null 에 ACAO: null 응답 — sandbox/iframe 우회 표면`, path);
      }
      if (acao === "*") {
        return finding("low", `와일드카드 CORS`, `ACAO: * — 공개 데이터면 무해하나 인증 리소스면 위험`, path);
      }
      return { ok: false, summary: `CORS 설정 이상 없음 (ACAO=${acao || "없음"})` };
    } catch (e) {
      return { ok: false, summary: `cors_audit 실패: ${(e as Error).message}` };
    }
  },
};

function finding(severity: "low" | "medium" | "high", title: string, evidence: string, path: string): ToolResult {
  return {
    ok: true,
    summary: `CORS: ${title}`,
    fingerprint: { indicators: [`cors ${severity} ${path}`] },
    data: { severity, title: `CORS 설정 오류 — ${title}`, evidence },
  };
}
