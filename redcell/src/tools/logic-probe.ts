/**
 * logic_probe — 비즈니스 로직 결함 신호 탐지(보수적·읽기 전용·비파괴).
 *
 * 비즈니스 로직 취약점은 앱마다 달라 자동 탐지가 어렵고 오탐이 나기 쉽다. 그래서 이 툴은
 * **아주 보수적**으로만 신호를 남긴다:
 *   - "가격/수량/권한류" 이름의 파라미터(price·amount·qty·total·role·is_admin·discount 등)에
 *     대해서만, GET 으로 **비정상 값**(음수·0·admin·true)을 넣어본다(상태 변경 아님).
 *   - 서버가 검증 없이 그 값을 **그대로 반영**하고(음수 가격 에코 등) 정상 흐름(2xx)을
 *     유지하면, 로직 검증 부재 "신호"로 medium 보고 — 반드시 수동 확인 필요라고 명시한다.
 * 결제/주문을 실제로 완료시키지 않는다(GET·읽기 관찰만). 확신이 없으면 보고하지 않는다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

/** 비즈니스적으로 민감한 파라미터 이름(이게 아니면 건드리지 않는다 → 오탐 억제). */
const SENSITIVE = /^(price|amount|qty|quantity|total|cost|balance|discount|fee|credit|points?|role|is_?admin|admin|priv|level|access)$/i;

interface Case {
  /** 넣어볼 비정상 값. */
  value: string;
  /** 이 값이 위험한 이유(증거 문구). */
  why: string;
}

/** 파라미터 이름별 비정상 값 후보. */
function casesFor(param: string): Case[] {
  if (/^(role|is_?admin|admin|priv|level|access)$/i.test(param)) {
    return [
      { value: "admin", why: "권한 파라미터에 admin 주입" },
      { value: "true", why: "권한 플래그 true 주입" },
    ];
  }
  // 금액/수량류: 음수·0(무료화/환불 유발 로직 결함).
  return [
    { value: "-1", why: "금액/수량에 음수 주입(환불·차감 로직 악용)" },
    { value: "0", why: "금액/수량 0 주입(무료화)" },
  ];
}

const MAX_TARGETS = 8;

export const logicProbe: Tool = {
  name: "logic_probe",
  description:
    "가격/수량/권한류 파라미터에 음수·0·admin 등 비정상 값을 GET 으로 넣어 서버가 검증 없이 반영하는지 관찰한다(읽기 전용). 반영 시 로직 검증 부재 신호(medium, 수동확인 필요). 비파괴. [opt-in 필요]",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const targets = resolveTargets(args); // [{path, param}]
    if (targets.length === 0) {
      return { ok: false, summary: "민감 파라미터(price/qty/role 등)를 가진 경로가 필요합니다(args.paths + args.params 또는 crawl 표면)." };
    }

    for (const t of targets) {
      // 기준값(baseline) — 원본 파라미터를 그대로 둔 응답.
      let baseline;
      try {
        baseline = await authGet(ctx, joinPath(base, t.path), { cap: 8000 });
      } catch {
        continue;
      }
      if (baseline.status >= 500) continue;

      for (const c of casesFor(t.param)) {
        const url = joinPath(base, setParam(t.path, t.param, c.value));
        let res;
        try {
          res = await authGet(ctx, url, { cap: 8000 });
        } catch {
          continue;
        }
        // 조건: (1) 2xx 정상 흐름 유지, (2) 서버가 거부(검증 에러)하지 않음,
        //       (3) 주입한 비정상 값이 응답에 반영됨 & baseline 과 달라짐.
        const ok2xx = res.status >= 200 && res.status < 300;
        const rejected = looksRejected(res.body);
        const reflected = reflectsValue(res.body, t.param, c.value);
        const changed = res.body !== baseline.body;
        if (ok2xx && !rejected && reflected && changed) {
          return {
            ok: true,
            summary: `비즈니스 로직 검증 부재 신호: ${t.path} 의 '${t.param}'=${c.value} 가 검증 없이 반영`,
            fingerprint: { indicators: [`logic ${t.path}?${t.param}`] },
            data: {
              severity: "medium",
              title: `비즈니스 로직 검증 부재 신호 (${t.path}?${t.param})`,
              evidence: `${c.why}: '${t.param}=${c.value}' 요청이 2xx + 비정상 값 반영(${snippet(res.body, c.value)}) — 수동 확인 필요`,
              impact:
                "서버가 금액/수량/권한 값을 신뢰하면, 음수 결제·무료 구매·권한 상승 등으로 이어질 수 있다. 서버측에서 값 범위·소유권·권한을 재검증하라. (본 신호는 반영만 관측한 것으로, 실제 거래 영향은 수동 검증 필요)",
            },
          };
        }
      }
    }
    return { ok: false, summary: `비즈니스 로직 신호 미탐지 (대상 ${targets.length}건, 서버가 비정상 값을 반영/수용하지 않음)` };
  },
};

interface TargetSpec {
  path: string;
  param: string;
}

/** args.paths + args.params 조합에서 "민감 파라미터"만 표적으로 추린다. */
function resolveTargets(args: Record<string, unknown>): TargetSpec[] {
  const paths = Array.isArray(args.paths)
    ? (args.paths.filter((x) => typeof x === "string") as string[])
    : typeof args.path === "string"
      ? [args.path]
      : [];
  const params = Array.isArray(args.params)
    ? (args.params.filter((x) => typeof x === "string") as string[])
    : typeof args.param === "string"
      ? [args.param]
      : [];

  const out: TargetSpec[] = [];
  for (const p of paths) {
    // 경로 자체 쿼리의 파라미터도 후보에 포함.
    const qi = p.indexOf("?");
    const cleanPath = qi >= 0 ? p.slice(0, qi) : p;
    const inlineParams = qi >= 0 ? [...new URLSearchParams(p.slice(qi + 1)).keys()] : [];
    for (const param of [...new Set([...params, ...inlineParams])]) {
      if (SENSITIVE.test(param)) out.push({ path: qi >= 0 ? p : cleanPath, param });
    }
  }
  return out.slice(0, MAX_TARGETS);
}

/** 경로에 파라미터 값을 설정(기존 동일 파라미터는 대체). */
function setParam(path: string, key: string, value: string): string {
  const qi = path.indexOf("?");
  const base = qi >= 0 ? path.slice(0, qi) : path;
  const sp = new URLSearchParams(qi >= 0 ? path.slice(qi + 1) : "");
  sp.set(key, value);
  return `${base}?${sp.toString()}`;
}

/** 서버가 검증 에러/거부로 응답했는지(로직 통과가 아니라 거부면 취약 아님). */
function looksRejected(body: string): boolean {
  return /invalid|error|not allowed|forbidden|거부|오류|유효하지|허용되지|음수|negative not|must be (positive|greater)/i.test(body);
}

/** 주입한 값이 응답에 그대로 반영됐는지(파라미터 문맥 근처). */
function reflectsValue(body: string, key: string, value: string): boolean {
  if (value === "0") {
    // 0 은 흔해서 오탐 위험 → 키 근처에서만 인정.
    return new RegExp(`${escapeRe(key)}["'>:=\\s]{0,4}0\\b`, "i").test(body);
  }
  if (value === "-1") return /-1\b/.test(body);
  return new RegExp(`\\b${escapeRe(value)}\\b`, "i").test(body);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function snippet(body: string, needle: string): string {
  const i = body.indexOf(needle);
  if (i < 0) return body.slice(0, 40).replace(/\s+/g, " ");
  return body.slice(Math.max(0, i - 20), i + needle.length + 20).replace(/\s+/g, " ");
}
