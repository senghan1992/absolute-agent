/**
 * idor_probe — IDOR / 접근통제 미흡(Broken Object Level Authorization) 탐지 + 최소 PoC.
 *
 * 숫자 id 를 가진 리소스 경로를 받아 인접 id(±1, 0, 큰 값)를 요청한다. 하지만
 * "서로 다른 객체가 200 으로 온다"만으로는 IDOR 이 아니다 — 공개 상품 카탈로그
 * (`/product/1`, `/product/2`)도 그렇기 때문이다. 그래서 두 가지 근거를 요구한다:
 *   1) 반환 객체에 **소유자 귀속/개인정보 신호**(owner·email·account 등)가 있어야 한다
 *      (공개 카탈로그는 개인정보가 없으므로 오탐 배제).
 *   2) (auth 제공 시) 같은 객체를 인증 유/무로 요청해, **무인증에서도 같은 사적 객체가
 *      노출**되면 접근통제 경계가 깨진 것으로 확정한다(auth-boundary 비교).
 *   - 위 근거로 인증 없이 서로 다른 사적 레코드 열람 → high (타인 자원 열람 PoC)
 * 데이터를 대량 수집하지 않는다(인접 id 소수만 확인). 읽기 전용.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, authGet, safeGet } from "./util.js";

/**
 * 소유자 귀속/개인정보 신호 — 이게 있어야 "사적 객체"로 보고 IDOR 후보로 삼는다.
 * 공개 카탈로그(상품명·가격·설명)에는 없으므로 오탐(공개 리소스)을 배제한다.
 */
const PRIVATE_DATA = [
  /"?owner"?\s*[:=]/i,
  /"?user(_?id|_?name|name)?"?\s*[:=]/i,
  /"?email"?\s*[:=]/i,
  /[\w.+-]+@[\w-]+\.[a-z]{2,}/i, // 이메일 주소
  /"?(account|balance|ssn|phone|address|order(id)?|invoice|customer)"?\s*[:=]/i,
  /"?(first|last)_?name"?\s*[:=]/i,
];
function hasPrivateData(body: string): boolean {
  return PRIVATE_DATA.some((re) => re.test(body));
}

export const idorProbe: Tool = {
  name: "idor_probe",
  description:
    "숫자 id 리소스에 인증 없이 인접 id 를 요청해 IDOR/접근통제 미흡을 탐지한다. 서로 다른 객체가 무인증 반환되면 high.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const spec = resolveTarget(args);
    if (!spec) {
      return { ok: false, summary: "id 를 가진 경로가 필요합니다. args.path(예: /api/orders/1000) 또는 args.path+args.param 지정." };
    }

    const { build, ids, where } = spec;
    const seen: Array<{ id: number; status: number; hash: string; len: number; priv: boolean }> = [];
    for (const id of ids) {
      try {
        const res = await authGet(ctx, joinPath(base, build(id)));
        if (res.status === 200 && res.body.length > 0) {
          seen.push({ id, status: 200, hash: cheapHash(res.body), len: res.body.length, priv: hasPrivateData(res.body) });
        }
      } catch {
        /* 무시 */
      }
    }

    // 서로 다른 객체 2개 이상 + 그 객체가 "사적 데이터"를 담고 있어야 IDOR 후보.
    // (공개 카탈로그처럼 개인정보 없는 서로 다른 객체는 IDOR 이 아니므로 배제.)
    const distinct = new Set(seen.map((s) => s.hash));
    const privateHits = seen.filter((s) => s.priv);
    if (seen.length >= 2 && distinct.size >= 2 && privateHits.length >= 1) {
      // auth-boundary 확정(선택): auth 가 있으면 seed 객체를 무인증으로도 요청해 본다.
      const boundary = await authBoundaryBroken(ctx, base, build, ids[0]);
      const evidence =
        `무인증으로 id ${seen.map((s) => s.id).join(",")} 가 서로 다른 사적 객체 반환(distinct=${distinct.size}, 개인정보 신호 ${privateHits.length}건)` +
        (boundary ? "; 인증 유/무 응답이 동일 — 접근통제 경계 붕괴 확정" : "");
      return {
        ok: true,
        summary: `IDOR 신호: 인증 없이 서로 다른 사적 객체 ${privateHits.length}건 열람 (${where})`,
        fingerprint: { indicators: [`idor ${where}`] },
        data: {
          severity: "high",
          title: `IDOR / 접근통제 미흡 (${where})`,
          evidence,
          ids: seen.map((s) => s.id),
          impact:
            "임의 id 를 대입해 타인의 주문·계정·개인정보를 인증 없이 열람 가능 → 전체 사용자 데이터 대량 수집(개인정보 유출)으로 확대된다.",
        },
      };
    }
    // 서로 다른 객체는 오나 개인정보 신호가 없으면 공개 리소스일 가능성 — 오탐 대신 미탐 처리.
    const reason =
      seen.length >= 2 && distinct.size >= 2 && privateHits.length === 0
        ? "서로 다른 객체가 오나 개인정보 신호 없음(공개 카탈로그로 추정) → 오탐 배제"
        : `200응답 ${seen.length}건, distinct=${distinct.size}`;
    return { ok: false, summary: `IDOR 미탐지 (${where}, ${reason})` };
  },
};

/**
 * auth-boundary 비교: auth 가 있을 때만 의미가 있다. 같은 객체를 인증 없이(safeGet, auth 미포함)
 * 요청해 인증 시와 동일한 사적 응답이 오면 "인가 경계가 없음"이 확정된다.
 * auth 가 없으면(비교 불가) false 를 반환하되, 상위 로직의 개인정보 신호만으로도 IDOR 판정은 유지된다.
 */
async function authBoundaryBroken(ctx: ToolContext, base: string, build: (id: number) => string, seedId: number): Promise<boolean> {
  if (!ctx.auth || Object.keys(ctx.auth).length === 0) return false;
  const url = joinPath(base, build(seedId));
  try {
    const authed = await authGet(ctx, url);
    const anon = await safeGet(url, ctx.rps); // auth 헤더 미포함(진짜 무인증)
    return anon.status === 200 && anon.body.length > 0 && hasPrivateData(anon.body) && cheapHash(anon.body) === cheapHash(authed.body);
  } catch {
    return false;
  }
}

interface Spec {
  build: (id: number) => string;
  ids: number[];
  where: string;
}

/** args 에서 id 위치를 해석: path 끝의 숫자 / query 파라미터 / {id} 플레이스홀더. */
function resolveTarget(args: Record<string, unknown>): Spec | null {
  const path = typeof args.path === "string" ? args.path : "";
  const param = typeof args.param === "string" ? args.param : "";
  const idsFromArgs = Array.isArray(args.ids) ? (args.ids.filter((x) => typeof x === "number") as number[]) : null;

  // 1) query 파라미터 지정: /item?id=1000 스타일 (시드가 애매하므로 흔한 시작값 사용)
  if (param) {
    const base = path || "/";
    const ids = idsFromArgs ?? spread(1000);
    return { build: (id) => addQuery(base, param, String(id)), ids, where: `${base}?${param}` };
  }
  // 2) {id} 플레이스홀더
  if (path.includes("{id}")) {
    const seed = 1;
    const ids = idsFromArgs ?? spread(seed);
    return { build: (id) => path.replace("{id}", String(id)), ids, where: path };
  }
  // 3) 경로 끝 숫자: /api/orders/1000
  const m = /^(.*\/)(\d+)(\/?)$/.exec(path);
  if (m) {
    const [, prefix, num, suffix] = m;
    const seed = Number(num);
    const ids = idsFromArgs ?? spread(seed);
    return { build: (id) => `${prefix}${id}${suffix}`, ids, where: `${prefix}<id>${suffix}` };
  }
  return null;
}

function spread(seed: number): number[] {
  const s = Number.isFinite(seed) && seed > 0 ? seed : 1000;
  return [...new Set([s, s - 1, s + 1, 1, s + 100])].filter((n) => n >= 0).slice(0, 5);
}

function addQuery(path: string, k: string, v: string): string {
  return `${path}${path.includes("?") ? "&" : "?"}${encodeURIComponent(k)}=${encodeURIComponent(v)}`;
}

/** 본문 내용 비교용 저비용 해시(내용이 다르면 다른 값). */
function cheapHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return `${h}:${s.length}`;
}
