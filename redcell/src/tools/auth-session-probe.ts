/**
 * auth_session_probe — 세션/인증 견고성 점검(비파괴·읽기 전용).
 *
 * cookie_audit 가 쿠키 "플래그(HttpOnly/Secure/SameSite)"를 본다면, 이 툴은 세션 자체의
 * **강도와 노출**을 본다:
 *   1) 세션 토큰 엔트로피/예측성 — 서버가 발급한 세션 토큰을 (짧은 간격) 2회 수집해
 *      순차 증가(카운터)·전부 숫자·평문 디코딩(사용자명·타임스탬프)이면 세션 추측/탈취
 *      위험(high). 짧으면서 키스페이스가 극소(엔트로피 부족)일 때만 열거 가능(medium).
 *   2) URL 내 세션 ID 노출 — 응답 링크에 `;jsessionid=`·`?sid=`·`?sessionid=` 등이 있으면
 *      Referer/로그/북마크로 세션이 새어 세션 픽세이션·하이재킹 표면(medium).
 * 상태를 바꾸지 않는다(GET 만). 로그인 세션이 있으면 그 쿠키도 함께 평가한다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const SESSION_NAME = /sess|sid|token|auth|jsessionid|phpsessid|asp\.?net|connect\.sid/i;
const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 4;

export const authSessionProbe: Tool = {
  name: "auth_session_probe",
  description:
    "서버가 발급한 세션 토큰의 엔트로피/예측성(짧음·순차·평문)과 URL 내 세션ID 노출을 점검한다. 약한 세션은 추측/픽세이션으로 계정 탈취(high~medium). 비파괴·읽기 전용.",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);

    // 1) 세션 토큰 2회 수집(같은 경로) — 순차성/재발급 관찰.
    const samples: Array<{ name: string; value: string }> = [];
    let bodyForUrlCheck = "";
    for (const path of paths) {
      const url = joinPath(base, path);
      for (let i = 0; i < 2; i++) {
        try {
          const res = await authGet(ctx, url, { cap: 8000 });
          if (i === 0 && !bodyForUrlCheck) bodyForUrlCheck = res.body;
          for (const c of splitCookies(res.headers["set-cookie"] ?? "")) {
            const name = cookieName(c);
            const value = cookieValue(c);
            if (SESSION_NAME.test(name) && value.length >= 4) samples.push({ name, value });
          }
        } catch {
          /* 무시 */
        }
      }
      if (samples.length >= 2) break;
    }

    // 2) URL 내 세션 ID 노출(응답 링크).
    const urlLeak = urlSessionLeak(bodyForUrlCheck);

    // 토큰 강도 판정.
    if (samples.length >= 1) {
      const s = samples[0];
      const bits = estimateBits(s.value);
      const weak = weakness(s, samples);
      if (weak) {
        return {
          ok: true,
          summary: `약한 세션 토큰: ${s.name} (${weak.why}, ~${bits}bit)`,
          fingerprint: { indicators: [`weak-session ${s.name}`] },
          data: {
            severity: weak.severity,
            title: `약한 세션 토큰 (${s.name})`,
            evidence: `${weak.why}; 토큰 예시=${mask(s.value)} (길이 ${s.value.length}, 추정 ${bits}bit)`,
            impact:
              "세션 토큰을 추측·열거·위조하면 로그인 없이 타인 세션을 탈취해 계정 장악이 가능하다. CSPRNG 기반 128bit+ 토큰, 로그인 시 세션 재발급, 짧은 만료·서버측 무효화를 적용하라.",
          },
        };
      }
    }

    if (urlLeak) {
      return {
        ok: true,
        summary: `URL 내 세션 ID 노출: ${urlLeak.param}`,
        fingerprint: { indicators: [`session-in-url ${urlLeak.param}`] },
        data: {
          severity: "medium",
          title: `세션 ID의 URL 노출 (${urlLeak.param})`,
          evidence: `응답 링크에 세션 식별자 노출: ${urlLeak.sample}`,
          impact:
            "URL 에 실린 세션 ID 는 Referer 헤더·브라우저 히스토리·프록시/서버 로그·공유 링크로 유출되어 세션 하이재킹·픽세이션으로 이어진다. 세션은 HttpOnly 쿠키로만 전달하라.",
        },
      };
    }

    const seen = samples.length ? `세션 토큰 ${samples.length}개 관찰(엔트로피 충분)` : "세션 토큰 미관찰";
    return { ok: false, summary: `세션/인증 취약 신호 미탐지 (${seen})` };
  },
};

/** 토큰 약점 판정: 순차 증가 / 전부 숫자 / 짧음 / 평문 디코딩. */
function weakness(
  s: { name: string; value: string },
  samples: Array<{ name: string; value: string }>,
): { severity: "high" | "medium"; why: string } | null {
  const v = s.value;
  // 순차/거의 동일(카운터 기반) — 두 표본이 인접 정수면 강한 신호.
  if (samples.length >= 2) {
    const a = numify(samples[0].value);
    const b = numify(samples[1].value);
    if (a !== null && b !== null && Math.abs(a - b) <= 3 && a !== b) {
      return { severity: "high", why: "연속 발급 토큰이 순차 증가(카운터 기반) — 완전 예측 가능" };
    }
  }
  if (/^\d+$/.test(v) && v.length <= 12) return { severity: "high", why: "토큰이 전부 숫자이며 짧음(무차별/순차 추측 가능)" };
  const decoded = tryDecodePlain(v);
  if (decoded) return { severity: "high", why: `토큰이 평문 디코딩됨(${decoded})` };
  // 단일 표본의 Shannon 엔트로피는 노이즈가 커서(짧아도 정상인 토큰 존재) 그 자체로는
  // 약점 신호로 삼지 않는다. 정말로 열거 가능한 극소 키스페이스(짧음 + 매우 낮은 엔트로피)
  // 일 때만 보고한다 → 정상적인 짧은 세션ID 오탐 방지, 실제 추측 가능 토큰은 포착.
  if (v.length <= 8 && estimateBits(v) < 32) return { severity: "medium", why: "키스페이스가 매우 작음(짧고 엔트로피 부족 — 열거 가능)" };
  return null;
}

/** 문자열이 정수(또는 접미 카운터)인지 → 순차성 비교용. */
function numify(v: string): number | null {
  if (/^\d+$/.test(v)) return Number(v);
  const m = /(\d{2,})$/.exec(v);
  return m ? Number(m[1]) : null;
}

/** base64/hex 가 사람이 읽는 평문(user=, @, timestamp)으로 풀리면 예측 가능한 토큰. */
function tryDecodePlain(v: string): string | null {
  if (!/^[A-Za-z0-9+/=_-]{6,}$/.test(v)) return null;
  try {
    const b = Buffer.from(v.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    if (/[ -~]{4,}/.test(b) && /(user|name|admin|role|@|\d{10,13}|:)/i.test(b) && printableRatio(b) > 0.8) {
      return b.slice(0, 40).replace(/\s+/g, " ");
    }
  } catch {
    /* not base64 */
  }
  return null;
}
function printableRatio(s: string): number {
  if (!s.length) return 0;
  let p = 0;
  for (const ch of s) if (ch >= " " && ch <= "~") p++;
  return p / s.length;
}

/** Shannon 엔트로피 * 길이 로 대략적 bit 수 추정. */
function estimateBits(v: string): number {
  const freq = new Map<string, number>();
  for (const ch of v) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / v.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * v.length);
}

/** 응답 링크에서 URL 에 실린 세션 식별자 탐지. */
function urlSessionLeak(body: string): { param: string; sample: string } | null {
  const m =
    /;jsessionid=[A-Za-z0-9.]+/i.exec(body) ||
    /[?&](sid|sessionid|session_id|sessionkey|auth_token|token)=[A-Za-z0-9._-]{6,}/i.exec(body);
  if (!m) return null;
  const param = /jsessionid/i.test(m[0]) ? "jsessionid" : (/[?&]([a-z_]+)=/i.exec(m[0])?.[1] ?? "session");
  return { param, sample: m[0].slice(0, 60) };
}

function mask(v: string): string {
  if (v.length <= 8) return v.replace(/.(?=.{2})/g, "*");
  return v.slice(0, 4) + "…" + v.slice(-2);
}

function splitCookies(raw: string): string[] {
  if (!raw) return [];
  return raw.split(/\n|,(?=\s*[A-Za-z0-9_-]+=)/).map((s) => s.trim()).filter(Boolean);
}
function cookieValue(cookie: string): string {
  const eq = cookie.indexOf("=");
  const semi = cookie.indexOf(";");
  const end = semi < 0 ? cookie.length : semi;
  return eq < 0 ? "" : cookie.slice(eq + 1, end).trim();
}
function cookieName(cookie: string): string {
  const eq = cookie.indexOf("=");
  return (eq < 0 ? cookie : cookie.slice(0, eq)).trim();
}
function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS;
}
