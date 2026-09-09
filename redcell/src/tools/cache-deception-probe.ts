/**
 * cache_deception_probe — 웹 캐시 기만(Web Cache Deception) 탐지. **안전(비파괴) 방법론**.
 *
 * 캐시 기만은 "개인 페이지가 정적 파일처럼 보이는 경로로 캐시되어, 다른 사용자가
 * 같은 URL 을 요청하면 피해자의 개인 페이지가 캐시에서 반환되는" 공격이다.
 *
 * 안전 설계 — 피해자는 항상 **우리 자신의 세션**이고 URL 접미사는 매 실행 고유 난수다:
 *   1) P(세션)         → 개인 본문 B 확인(이메일/환영 문구 등 개인 신호).
 *   2) P(무세션)       → 로그인/거부여야 한다. 무세션 P 가 개인 본문을 주면 그건 캐시가
 *                        아니라 접근통제 결함이므로 이 툴의 대상이 아니다(스킵 — 오탐 방지).
 *   3) P/rc<rand>.css(세션) → 서버가 접미사를 무시하고 같은 개인 본문 S 를 반환하는지.
 *   4) P/rc<rand>.css(무세션) → 캐시가 피해자(우리)의 개인 본문 C 를 반환하면 실증(high):
 *                        "정적 확장자 경로 = 공개 캐시 대상" 오판 + 개인 데이터 조합.
 *   → 2)과 4)의 차등(무세션 P=차단 vs 무세션 P'=개인 본문)이 캐시 기만의 결정적 증거다.
 *
 * GET 전용, 상태변경 없음, 고유 접미사라 다른 사용자가 그 URL 을 알 방법이 없다.
 * (캐시 엔트리는 우리 세션 데이터 하나뿐 — blast radius 0.)
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { newJar } from "../net/http-client.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const PROFILE_RE = /(profile|account|\/me(\/|$)|user|member|mypage|my-page|settings|dashboard|admin)/i;
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 4;
const SUFFIXES = ["css", "js"];

/** 본문의 "개인 신호" 마커를 뽑는다(이메일 우선, 환영 문구, 사용자 표시). */
function personalMarkers(body: string): string[] {
  const out: string[] = [];
  const emails = body.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi);
  if (emails) out.push(...emails.slice(0, 2));
  const m = /(안녕하세요[^\n<]{0,60}|welcome[^\n<]{0,60}|님[^가-힣]{0,0})/i.exec(body);
  if (m && m[1].trim().length > 4) out.push(m[1].trim());
  return out;
}

const hasPersonalSignal = (body: string): boolean => personalMarkers(body).length > 0 || /(마이페이지|내 정보|내 계정|profile of|my account)/i.test(body);

/** 같은 개인 본문인지 — 개인 마커 교집합 또는 본문 유사(공백 정규화 일치). */
function samePersonal(a: string, b: string): boolean {
  const na = a.replace(/\s+/g, " ").trim();
  const nb = b.replace(/\s+/g, " ").trim();
  if (na === nb && na.length > 50) return true;
  const ma = personalMarkers(a);
  return ma.some((m) => b.includes(m));
}

const looksCacheable = (h: Record<string, string>): boolean => {
  const cc = (h["cache-control"] ?? "").toLowerCase();
  if (/public|max-age=[1-9]|s-maxage/.test(cc)) return true;
  return h["age"] !== undefined || /hit|miss/i.test(h["x-cache"] ?? "") || !!h["cf-cache-status"];
};

const denied = (r: { status: number; body: string; headers: Record<string, string> }): boolean =>
  r.status >= 400 || (r.status >= 300 && r.status < 400) || /(login|signin|로그인|sign in)/i.test(r.body.slice(0, 2000));

export const cacheDeceptionProbe: Tool = {
  name: "cache_deception_probe",
  description:
    "인증된 개인 페이지가 정적 확장자 접미사 경로(/profile/x.css)로 요청될 때 캐시되는지 확인해 웹 캐시 기만을 탐지한다. 무인증 재요청 차등으로 실증하며, 피해자는 스캐너 자신의 세션뿐이다(고유 접미사, GET 전용, 비파괴).",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const hasSession = Object.keys(ctx.auth ?? {}).length > 0 || ctx.jar != null;
    if (!hasSession) {
      return { ok: false, summary: "인증 세션 없음 — 캐시 기만은 로그인 표면 점검이 필요(스킵)" };
    }
    const base = baseUrl(ctx.target);
    const given = pickPaths(args, []);
    // 개인 페이지 추정 경로 우선.
    const ordered = [...new Set([...given.filter((p) => PROFILE_RE.test(p)), ...given])].slice(0, MAX_PATHS);

    for (const path of ordered) {
      const url = joinPath(base, path);
      // 1) P(세션) → 개인 본문 B.
      let authed;
      try {
        authed = await authGet(ctx, url, { cap: 12000 });
      } catch {
        continue;
      }
      if (authed.status >= 400 || !hasPersonalSignal(authed.body)) continue;

      // 2) P(무세션) → 차단 확인(오탐 방지: 접근통제 결함과 구분).
      let noauth;
      try {
        noauth = await authGet(ctx, url, { cap: 12000, headers: stripAuth(ctx), jar: newJar() });
      } catch {
        continue;
      }
      // 무세션으로도 같은 개인 본문이 나오면 캐시 문제가 아니라 접근통제 결함 — 스킵.
      if (noauth.status < 400 && samePersonal(noauth.body, authed.body)) continue;

      // 3) 접미사 경로(세션) — 서버가 접미사를 무시하고 개인 페이지를 주는지.
      for (const ext of SUFFIXES) {
        const suffix = `rc${Math.random().toString(36).slice(2, 10)}.${ext}`;
        const sep = path.endsWith("/") ? "" : "/";
        const p2 = `${path}${sep}${suffix}`;
        const url2 = joinPath(base, p2);

        let authed2;
        try {
          authed2 = await authGet(ctx, url2, { cap: 12000 });
        } catch {
          continue;
        }
        if (authed2.status >= 400 || !samePersonal(authed2.body, authed.body)) continue;

        // 4) 접미사 경로(무세션) — 캐시가 우리 개인 본문을 반환하는지(실증).
        let noauth2;
        try {
          noauth2 = await authGet(ctx, url2, { cap: 12000, headers: stripAuth(ctx), jar: newJar() });
        } catch {
          continue;
        }
        if (noauth2.status < 400 && samePersonal(noauth2.body, authed.body)) {
          const cacheHint = looksCacheable(authed2.headers) || looksCacheable(noauth2.headers);
          return {
            ok: true,
            summary: `웹 캐시 기만 확정: ${p2} — 무인증 요청에 세션 소유자의 개인 페이지가 캐시에서 반환(2단계 확인)`,
            fingerprint: { indicators: [`cache-deception ${p2}`] },
            data: {
              severity: "high",
              title: `웹 캐시 기만 (${p2})`,
              evidence:
                `캐시 기만 실증: 무인증 요청에 개인 본문 반환 — 보호 경로 ${path}(무세션=차단) vs 접미사 경로 ${p2}` +
                `(무세션=개인 본문 반환). 서버/캐시가 '.${ext}' 경로를 정적 공개 자원으로 분류하면서 개인 응답을 캐시함` +
                (cacheHint ? " (캐시 헤더 확인)" : " (캐시 헤더 미표기 — 무인증 차등으로 실증)"),
              impact:
                "공격자가 피해자에게 이런 URL 을 클릭시키면 캐시에 피해자의 개인 페이지가 저장되고, 같은 URL 을 요청해 개인정보(이메일·이름·계정 정보)를 탈취할 수 있다. 정적 확장자/디렉터리 캐시 규칙에 개인 페이지를 포함하지 않도록 캐시 키·규칙을 정비해야 한다.",
            },
          };
        }
      }
    }
    return { ok: false, summary: `캐시 기만 미탐지 (paths=${ordered.join(",")}) — 접미사 경로가 캐시되지 않거나 개인 페이지 없음` };
  },
};

/** 무세션 요청용 — ctx.auth 를 벗긴 헤더(개별 헤더 지정이 auth 병합보다 우선하는 util 규칙 활용). */
function stripAuth(ctx: ToolContext): Record<string, string> | undefined {
  // authGet 은 개별 headers 를 ctx.auth 위에 덮어쓴다. auth 헤더 키를 빈 값으로 덮어
  // "자격증명 없는" 요청을 만든다(Cookie 는 jar 를 새로 주면 자동 제외).
  const strip: Record<string, string> = {};
  for (const k of Object.keys(ctx.auth ?? {})) strip[k.toLowerCase()] = "";
  return Object.keys(strip).length ? strip : undefined;
}

function pickPaths(args: Record<string, unknown>, discovered: string[]): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return [...new Set([...discovered, ...DEFAULT_PATHS])].slice(0, MAX_PATHS);
}
