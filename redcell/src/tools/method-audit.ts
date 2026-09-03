/**
 * http_method_audit — 허용 HTTP 메서드 감사(안전·비파괴).
 *
 * OPTIONS 로 Allow 헤더를 읽어 어떤 메서드가 열려 있는지 확인하고, TRACE 를 보내
 * 요청이 그대로 되돌아오는지(XST, Cross-Site Tracing) 관찰한다. 위험 메서드(PUT/DELETE/
 * PATCH/TRACE/CONNECT)가 열려 있으면 콘텐츠 변조·인증정보 탈취 표면이 된다.
 *   - TRACE 가 요청을 에코 → 높은 위험(XST 로 HttpOnly 쿠키 우회 가능)  → high
 *   - PUT/DELETE/PATCH 노출(Allow) → 콘텐츠 조작 가능성                  → medium
 * ⚠️ PUT/DELETE 로 실제 쓰기/삭제를 시도하지 않는다. OPTIONS/TRACE 관찰만.(비파괴)
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const DANGEROUS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 6;

export const methodAudit: Tool = {
  name: "http_method_audit",
  description:
    "OPTIONS 로 허용 메서드를 열거하고 TRACE 에코(XST)를 관찰한다. 위험 메서드(PUT/DELETE/PATCH/TRACE) 노출 시 콘텐츠 변조·인증정보 탈취 표면. 비파괴(실제 쓰기 시도 없음).",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);

    for (const path of paths) {
      const url = joinPath(base, path);
      try {
        // 1) OPTIONS → Allow 헤더로 메서드 열거.
        const opt = await authGet(ctx, url, { method: "OPTIONS", cap: 500 });
        const allow = (opt.headers["allow"] ?? opt.headers["access-control-allow-methods"] ?? "").toUpperCase();
        const listed = allow
          .split(/[,\s]+/)
          .map((m) => m.trim())
          .filter(Boolean);
        const risky = DANGEROUS.filter((m) => listed.includes(m));

        // 2) TRACE → 요청 에코 여부(XST). 무해 마커 헤더로 반사 확인.
        const marker = "RCXST" + Math.random().toString(36).slice(2, 8);
        let xst = false;
        try {
          const tr = await authGet(ctx, url, { method: "TRACE", headers: { "x-rc-trace": marker }, cap: 2000 });
          xst = tr.status < 400 && tr.body.includes(marker);
        } catch {
          /* TRACE 차단됨 — 정상 */
        }

        if (xst) {
          return {
            ok: true,
            summary: `TRACE 활성(XST): ${path} 가 요청을 그대로 에코 → 교차 사이트 트레이싱 가능`,
            fingerprint: { indicators: [`http-trace-xst ${path}`] },
            data: {
              severity: "high",
              title: `HTTP TRACE 활성 (XST)`,
              evidence: `TRACE ${path} 응답이 요청 헤더(x-rc-trace: ${marker})를 에코함`,
              impact:
                "XST 로 HttpOnly 쿠키까지 스크립트가 읽어낼 수 있어 세션 탈취 방어(HttpOnly)가 무력화 → 계정 장악.",
            },
          };
        }
        if (risky.length > 0) {
          return {
            ok: true,
            summary: `위험 메서드 노출: ${path} Allow=${risky.join(",")} (전체 ${listed.join(",") || "미상"})`,
            fingerprint: { indicators: [`http-methods ${path} ${risky.join("+")}`] },
            data: {
              severity: "medium",
              title: `위험 HTTP 메서드 노출 (${risky.join(",")})`,
              evidence: `OPTIONS ${path} → Allow: ${allow}`,
              impact:
                "PUT/DELETE/PATCH 가 접근통제 없이 열려 있으면 파일·리소스 업로드/변조/삭제로 이어져 콘텐츠 위·변조 및 웹셸 배치 가능.",
            },
          };
        }
      } catch {
        /* 개별 경로 실패 무시 */
      }
    }
    return { ok: false, summary: `위험 메서드/XST 미탐지 (paths=${paths.join(",")})` };
  },
};

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS;
}
