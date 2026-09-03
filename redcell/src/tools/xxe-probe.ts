/**
 * xxe_probe — XML 외부 엔티티(XXE) "처리 가능성" 신호 탐지(안전 변형).
 *
 * XML 을 받는 엔드포인트에 **내부(in-band) 엔티티**를 정의해 보낸다. 응답에 그 엔티티가
 * 확장되어 반사되면, 파서가 DTD/엔티티 처리를 켜둔 것 → 실제 XXE(파일 읽기/SSRF)로
 * 이어질 수 있는 강한 선행 신호다.
 *   - 정의한 엔티티 마커가 확장되어 응답에 등장 → medium (엔티티 처리 활성)
 * 외부 엔티티(file://, http://)는 쓰지 않는다 — 내부 엔티티 확장만 관찰(비파괴·비-SSRF).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authPost, baseUrl, joinPath } from "./util.js";

const MARK = "rcxxe" + Math.random().toString(36).slice(2, 8);
const DEFAULT_PATHS = ["/", "/api", "/xml", "/soap", "/rpc", "/upload"];
const MAX_PATHS = 5;

function payload(): string {
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe "${MARK}">]><root><value>&xxe;</value></root>`;
}

export const xxeProbe: Tool = {
  name: "xxe_probe",
  description:
    "XML 수신 엔드포인트에 내부 엔티티를 보내 엔티티 확장(XXE 처리 가능성)을 탐지한다. 확장 마커가 반사되면 medium. 외부 엔티티는 쓰지 않는다(비파괴).",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const body = payload();

    for (const path of paths) {
      for (const ct of ["application/xml", "text/xml"]) {
        try {
          const res = await authPost(ctx, joinPath(base, path), body, { contentType: ct });
          // 엔티티가 확장돼 마커가 반사됐는가(원문 &xxe; 가 아니라 확장 결과).
          if (res.body.includes(MARK) && !res.body.includes("&xxe;")) {
            return {
              ok: true,
              summary: `XXE 처리 신호: ${path} 에서 XML 내부 엔티티 확장(${ct})`,
              fingerprint: { indicators: [`xxe ${path}`] },
              data: {
                severity: "medium",
                title: `XML External Entity 처리 활성 (${path})`,
                evidence: `내부 엔티티가 확장되어 마커 반사됨 → 외부 엔티티(파일/SSRF) 처리 가능성. 서버측 DTD 비활성 권고.`,
                path,
              },
            };
          }
        } catch {
          /* 개별 실패 무시 */
        }
      }
    }
    return { ok: false, summary: `XXE 처리 신호 미탐지 (paths=${paths.join(",")})` };
  },
};

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS.slice(0, MAX_PATHS);
}
