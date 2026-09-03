/**
 * ssti_probe — 서버측 템플릿 인젝션(SSTI) 탐지 + 최소 PoC.
 *
 * 여러 템플릿 엔진(Jinja/Twig/Freemarker/Spring-EL/ERB/Velocity)의 산술식 문법을
 * 파라미터에 넣어, 응답에 "그 곱셈의 결과값"이 나타나는지 본다. 자연발생 확률이 낮은
 * 큰 소수의 곱을 써서 오탐을 최소화한다(단순 반사와 구분).
 *   - 산술 평가 결과가 응답에 등장 → high (템플릿 서버측 평가 = RCE 로 이어질 수 있음)
 * 코드 실행/파일 접근은 하지 않는다(산술 평가 신호만).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

const A = 7919;
const B = 7331;
const EXPECT = String(A * B); // 58053589 — 자연 등장 가능성이 매우 낮은 표식
const EXPR = `${A}*${B}`;

/** 엔진별 표현식 템플릿. `EXPR` 자리에 곱셈식을 넣는다. args.payloads 로 추가/대체 가능. */
const TEMPLATES = ["{{EXPR}}", "${EXPR}", "<%= EXPR %>", "#{EXPR}", "*{EXPR}", "${{EXPR}}", "@(EXPR)", "{EXPR}"];
const DEFAULT_PARAMS = ["q", "s", "search", "name", "query", "msg", "message", "template", "tpl", "id"];
const DEFAULT_PATHS = ["/"];
const MAX_PARAMS = 5;
const MAX_PATHS = 8;
const MAX_PAYLOADS = 8;

export const sstiProbe: Tool = {
  name: "ssti_probe",
  description:
    "파라미터에 여러 템플릿 엔진의 산술식을 넣어 서버측 템플릿 인젝션(SSTI)을 탐지한다. 산술 평가 결과가 응답에 나타나면 high. args.payloads 로 커스텀 표현식 주입.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const payloads = pickPayloads(args).map((t) => t.split("EXPR").join(EXPR));

    for (const path of paths) {
      for (const param of params) {
        for (const payload of payloads) {
          const url = joinPath(base, withQuery(path, { [param]: payload }));
          try {
            const res = await authGet(ctx, url);
            // 평가 결과(EXPECT)가 응답에 나타나면 서버측 평가가 일어난 것이다. 곱셈식 원문(EXPR)이
            // "함께" 에코되더라도(예: "입력: 7919*7331 → 결과: 58053589") 결과가 나오면 SSTI 다.
            // 과거엔 `!includes(EXPR)` 로 원문이 반사되면 무조건 배제해, 원문 에코 + 별도 평가를
            // 함께 렌더하는 흔한 템플릿에서 오탐 대신 '미탐(FN)'이 발생했다 → 결과/에코 위치를 분리.
            // 우리는 EXPECT(58053589)를 서버에 보낸 적이 없으므로, 그 등장 자체가 평가 증거다.
            if (res.body.includes(EXPECT)) {
              const alsoEchoed = res.body.includes(EXPR);
              return {
                ok: true,
                summary: `SSTI 신호: ${path} 의 param '${param}' 에서 템플릿 산술 평가(${EXPR}=${EXPECT})`,
                fingerprint: { indicators: [`ssti ${path}?${param}`] },
                data: {
                  // 서버측 템플릿 평가 = 원격 코드 실행으로 직결 → critical.
                  severity: "critical",
                  title: `Server-Side Template Injection (param=${param})`,
                  evidence:
                    `산술식이 서버에서 평가되어 결과 ${EXPECT} 노출 (path=${path}, payload=${payload})` +
                    (alsoEchoed ? " — 원문 에코와 평가 결과가 함께 렌더됨(결과/에코 분리 확인)" : ""),
                  param,
                  impact:
                    "템플릿 엔진에서 표현식이 서버측 평가된다 → 임의 객체 접근·명령 실행(RCE)으로 확대되어 서버 완전 장악에 이를 수 있다.",
                },
              };
            }
          } catch {
            /* 개별 실패 무시 */
          }
        }
      }
    }
    return { ok: false, summary: `SSTI 미탐지 (paths=${paths.join(",")}, params=${params.join(",")})` };
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
  return TEMPLATES.slice(0, MAX_PAYLOADS);
}
