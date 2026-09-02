/**
 * sqli_probe — SQL Injection "탐지"(detection only) 툴. 최소영향 원칙.
 *
 * 지정 파라미터에 오류 유발 문자(작은따옴표) 하나를 넣어 응답에 DB 오류 시그니처가
 * 나타나는지 관찰한다. 데이터 추출/부울·시간 기반 자동화 없음 — 취약점 존재의
 * PoC 신호만 확보한다. (실제 추출은 운영자가 상황에 맞게 별도 판단)
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, safeGet } from "./util.js";

const DB_ERROR = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysqli?/i,
  /unclosed quotation mark after the character string/i,
  /pg_query\(\)|postgresql.*error/i,
  /sqlite3?::|sqlite error/i,
  /ora-\d{5}/i,
  /odbc.*sql server|microsoft ole db/i,
];

export const sqliProbe: Tool = {
  name: "sqli_probe",
  description: "지정 파라미터에 오류유발 문자 1개를 넣어 SQLi 존재 여부만 탐지한다(추출 없음, 최소영향).",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const path = typeof args.path === "string" ? args.path : "/";
    const param = typeof args.param === "string" ? args.param : "id";
    const base = baseUrl(ctx.target);

    // 기준 응답 vs 오류유발 응답 비교.
    const benign = joinPath(base, `${path}${path.includes("?") ? "&" : "?"}${param}=1`);
    const marker = joinPath(base, `${path}${path.includes("?") ? "&" : "?"}${param}=1'`);

    try {
      const b = await safeGet(benign, ctx.rps);
      const m = await safeGet(marker, ctx.rps);
      const errored = DB_ERROR.find((re) => re.test(m.body) && !re.test(b.body));
      const statusShift = b.status !== m.status;

      if (errored) {
        return {
          ok: true,
          summary: `SQLi 신호 탐지: 파라미터 '${param}' 에서 DB 오류 시그니처`,
          fingerprint: { indicators: ["error-based sqli", `param ${param}`] },
          data: {
            severity: "high",
            title: `SQL Injection 취약점 신호 (param=${param})`,
            evidence: `오류유발 입력에서 DB 오류 노출: ${errored.source.slice(0, 40)}`,
          },
        };
      }
      return {
        ok: false,
        summary: `SQLi 미탐지 (param='${param}', status ${b.status}→${m.status}${statusShift ? " 변화있음" : ""})`,
        data: statusShift
          ? { severity: "low", title: `입력에 따른 상태코드 변화 (param=${param})`, evidence: `${b.status}→${m.status} — 추가 조사 권고` }
          : undefined,
      };
    } catch (e) {
      return { ok: false, summary: `sqli_probe 실패: ${(e as Error).message}` };
    }
  },
};
