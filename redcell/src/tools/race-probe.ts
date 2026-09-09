/**
 * race_probe — 경쟁 조건(Race Condition) 상태 이중 반영 실증. **opt-in** (상태변경 수반).
 *
 * 민감 파라미터(price/amount/qty/balance/coupon/credit/point/count/total/limit)를 가진
 * POST 가능 엔드포인트 대상:
 *   1) GET baseline 값 B0 파싱(본문 내 숫자 토큰)
 *   2) 단일 POST 1회 → B1 (델타 d1 = B1-B0)
 *   3) 동일 POST **2개 동시** 발사 → B2 (델타 d2 = B2-B1)
 *   d2 ≥ 2·d1 − 허용오차 이고 d1 ≠ 0 일 때만 실증.
 *
 * FP 방어: 파싱 가능한 숫자 토큰이 없거나 d1=0(상태 불변)이면 "징후" 이하로 강등.
 * 원자적 처리 서버는 d2≈d1 → 클린. 총 상태변경 3회(opt-in 승인 범위).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, authPost, baseUrl, joinPath } from "./util.js";
import { mapLimit } from "../net/rate-limiter.js";

/** 민감 파라미터 — 이 이름이 아니면 건드리지 않는다(오탐 억제). */
const SENSITIVE = /(price|amount|qty|quantity|balance|coupon|credit|point|points|count|total|limit|stock|inventory|seat)/i;
const MAX_PATHS = 6;
/** 동시 2요청 발사를 위한 순차 대기(동일 윈도 보장). */
const BURST = 2;

export const raceProbe: Tool = {
  name: "race_probe",
  description:
    "민감 파라미터 POST 엔드포인트에 단일 vs 동시 2요청을 보내 상태 델타가 2배로 반영되는 경쟁 조건을 실증한다(high). 상태변경 3회 수반 — opt-in 필요. 숫자 토큰 파싱 불가/불변 상태면 징후 이하 강등.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const targets = resolveTargets(args);

    for (const t of targets.slice(0, MAX_PATHS)) {
      const url = joinPath(base, t.path);
      // 1) GET baseline — 본문의 숫자 토큰 파싱이 가능해야 진행.
      let b0;
      try {
        b0 = await authGet(ctx, url, { cap: 8000 });
      } catch {
        continue;
      }
      const b0val = parseStateToken(b0.body);
      if (b0val == null) continue; // 파싱 불가 → 스킵(실증 안 함)

      // 2) 단일 POST 1회 → B1.
      const body = formBody(t.param, "1");
      let r1;
      try {
        r1 = await authPost(ctx, url, body, { contentType: "application/x-www-form-urlencoded", cap: 8000 });
      } catch {
        continue;
      }
      const s1 = parseStateToken(r1.body);
      if (s1 == null) continue;

      // 3) 동일 POST 2개 동시 발사 → B2. (상태변경 총 3회)
      //    동시 요청 2개가 각각 "같은 기준값"을 읽고 두 번 차감하는지 관측한다.
      //    두 응답은 뒤따른 두 상태로, 감소 드리프트면 min(더 많이 반영된 쪽) 을
      //    s2 로 삼는다. 원자 서버는 두 응답 모두 1 유닛만 반영해 min = s1 - 1.
      const [ra, rb] = await mapLimit([body, body], BURST, (b) =>
        authPost(ctx, url, b, { contentType: "application/x-www-form-urlencoded", cap: 8000 }),
      );
      const s2a = parseStateToken(ra.body);
      const s2b = parseStateToken(rb.body);
      if (s2a == null || s2b == null) continue;
      // s1 로부터의 드리프트 방향에 따라 "더 많이 반영된" 응답을 고른다:
      // 감소면 min, 증가면 max. (원자 서버는 두 응답이 모두 s1 - 1 이라 같다.)
      const s2 = s1 < b0val ? Math.min(s2a, s2b) : Math.max(s2a, s2b);
      const d1 = s1 - b0val;
      const d2 = s2 - s1;

      // 상태가 뒤로 가지 않는(endpoint 가 계속 진행하는) 서버는 스킵 — 별개 도메인이다.
      if (d1 === 0) continue;

      // 동시 2요청의 "합산" 반영이 단일 1요청의 2배면 상태가 두 번 반영됐다.
      // 비원자 서버: 두 요청이 같은 기준값을 읽어 각각 1씩 차감 → s2 = s1 - 2 (d2 = 2·d1).
      // 원자 서버:   두 요청이 직렬 처리되어 상태가 1씩만 차감 → d2 ≈ d1.
      const tolerance = Math.max(1, Math.abs(d1) * 0.5);
      const doubleApplied =
        Math.abs(d2) >= 2 * Math.abs(d1) - tolerance &&
        Math.abs(d2) > Math.abs(d1) &&
        Math.sign(d1) === Math.sign(d2);
      if (doubleApplied) {
        return {
          ok: true,
          summary: `경쟁 조건 실증: ${t.path} — 동시 2요청으로 상태 이중 반영 (Δ단일=${d1}, Δ동시=${d2})`,
          fingerprint: { indicators: [`race ${t.path}?${t.param}`] },
          data: {
            severity: "high",
            title: `경쟁 조건 (param=${t.param})`,
            evidence: `경쟁 조건 실증: 동시 2요청으로 상태 이중 반영 (Δ단일=${d1}, Δ동시=${d2}) — ${t.path}?${t.param}`,
            param: t.param,
            deltaSingle: d1,
            deltaConcurrent: d2,
          },
        };
      }
      // 실증 조건 미충족 — 징후/무시(원자적 처리 서버는 여기 걸린다).
    }
    return { ok: false, summary: `경쟁 조건 실증 미달 (대상 ${targets.length}건, 원자적 처리 또는 상태 불변)` };
  },
};

interface TargetSpec {
  path: string;
  param: string;
}

/** args.paths + args.params 에서 민감 파라미터 보유 POST 후보만 추린다. */
function resolveTargets(args: Record<string, unknown>): TargetSpec[] {
  const paths = Array.isArray(args.paths)
    ? (args.paths.filter((x): x is string => typeof x === "string").slice(0, MAX_PATHS))
    : typeof args.path === "string" && args.path
      ? [args.path]
      : [];
  const params = Array.isArray(args.params)
    ? (args.params.filter((x): x is string => typeof x === "string").slice(0, 6))
    : typeof args.param === "string" && args.param
      ? [args.param]
      : [];
  const out: TargetSpec[] = [];
  for (const p of paths) {
    const qi = p.indexOf("?");
    const clean = qi >= 0 ? p.slice(0, qi) : p;
    const inline = qi >= 0 ? [...new URLSearchParams(p.slice(qi + 1)).keys()] : [];
    for (const param of [...new Set([...params, ...inline])]) {
      if (SENSITIVE.test(param)) out.push({ path: clean, param });
    }
  }
  return out;
}

function formBody(param: string, val: string): string {
  return `${encodeURIComponent(param)}=${val}`;
}

/** 본문에서 상태 숫자 토큰 파싱 — "밸런스: N" 같은 키-값이나 큰 숫자. */
function parseStateToken(body: string): number | null {
  const kv = /(balance|amount|price|count|total|point|points|qty|quantity|stock|limit|credit)[^:=\d]{0,12}[:=]\s*([+-]?\d{1,12})/i.exec(body);
  if (kv) return Number(kv[2]);
  const n = /[^-\d](-?\d{1,12})[^-\d]/.exec(body);
  return n ? Number(n[1]) : null;
}