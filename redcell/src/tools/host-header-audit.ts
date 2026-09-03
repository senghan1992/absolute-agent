/**
 * host_header_audit — Host / X-Forwarded-Host 주입 감사(안전·비파괴).
 *
 * 스푸핑한 Host·X-Forwarded-Host 헤더를 보내, 서버가 그 값을 응답 본문의 절대 URL/링크나
 * Location 에 그대로 반영하는지 본다. 반영되면 비밀번호 재설정 링크 변조(재설정 포이즈닝)나
 * 웹 캐시 포이즈닝의 근거가 된다.
 *   - canary 호스트가 절대 URL/링크/Location 에 반영 → high
 * canary 는 관찰용 표식이며 실제로 접속하지 않는다. 단일 GET, 상태변경 없음.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const CANARY = "redcell-canary.example.net";
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 6;

export const hostHeaderAudit: Tool = {
  name: "host_header_audit",
  description:
    "Host/X-Forwarded-Host 를 canary 로 스푸핑해 서버가 절대 URL·링크·Location 에 그대로 반영하는지 탐지한다. 반영 시 비밀번호 재설정 포이즈닝·캐시 포이즈닝 근거(high). 비파괴.",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);

    for (const path of paths) {
      const url = joinPath(base, path);
      try {
        const res = await authGet(ctx, url, {
          headers: { host: CANARY, "x-forwarded-host": CANARY, "x-forwarded-server": CANARY },
          cap: 6000,
        });
        const loc = res.headers["location"] ?? "";
        const inBody = reflectsCanary(res.body);
        const inLoc = loc.includes(CANARY);
        if (inBody || inLoc) {
          return {
            ok: true,
            summary: `Host 헤더 반영: ${path} 가 스푸핑 Host(${CANARY})를 ${inLoc ? "Location" : "본문 절대 URL/링크"}에 반영`,
            fingerprint: { indicators: [`host-header-injection ${path}`] },
            data: {
              severity: "high",
              title: `Host Header Injection (${path})`,
              evidence: inLoc ? `Location: ${loc}` : `본문에 스푸핑 호스트 ${CANARY} 반영: ${snippet(res.body)}`,
              impact:
                "비밀번호 재설정 메일의 링크 호스트가 공격자 도메인으로 바뀌어(재설정 포이즈닝) 피해자가 토큰을 공격자에게 넘김 → 대량 계정 탈취. 캐시 앞단이면 포이즈닝으로 전체 사용자 영향.",
            },
          };
        }
      } catch {
        /* 무시 */
      }
    }
    return { ok: false, summary: `Host 헤더 주입 미탐지 (paths=${paths.join(",")})` };
  },
};

/** 스푸핑 호스트가 절대 URL/링크(스킴+canary 형태)로 반영됐는지 — 단순 텍스트 반사와 구분. */
function reflectsCanary(body: string): boolean {
  return new RegExp(`(?:https?:)?//${CANARY.replace(/\./g, "\\.")}|(?:href|src|action)\\s*=\\s*["']?[^"'>]*${CANARY.replace(/\./g, "\\.")}`, "i").test(body);
}

function snippet(body: string): string {
  const i = body.indexOf(CANARY);
  if (i < 0) return "";
  return body.slice(Math.max(0, i - 30), i + CANARY.length + 10).replace(/\s+/g, " ");
}

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS;
}
