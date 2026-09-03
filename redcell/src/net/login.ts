/**
 * 실제 로그인 플로우 — "로그인 뒤" 표면을 정적 헤더가 아니라 진짜 세션으로 점검한다.
 *
 * 폼(application/x-www-form-urlencoded) 또는 JSON 으로 인가된 테스트 계정 자격증명을
 * 로그인 엔드포인트에 제출하고:
 *   - Set-Cookie 세션 쿠키를 쿠키 jar 에 담아 이후 모든 요청에 재전송(세션 유지)
 *   - 필요 시 응답(JSON 본문/헤더/쿠키)에서 토큰을 추출해 Authorization 헤더로 재사용
 *
 * ⚠️ 여기서 쓰는 자격증명은 반드시 운영자가 인가한 "테스트 계정"이어야 한다.
 */

import { httpRequest, newJar, type CookieJar } from "./http-client.js";
import { RateLimiter } from "./rate-limiter.js";

export interface LoginConfig {
  /** 로그인 엔드포인트. 경로("/login") 또는 절대 URL. */
  url: string;
  /** 기본 POST. */
  method?: "POST" | "GET";
  /** 본문 인코딩. 기본 form. */
  type?: "form" | "json";
  /** 제출 필드(자격증명 포함). 인가된 테스트 계정만! */
  fields: Record<string, string>;
  /** 추가 요청 헤더(예: X-CSRF-Token). */
  headers?: Record<string, string>;
  /** 토큰 추출/재전송 방법(쿠키 세션만 쓰면 생략 가능). */
  token?: {
    /** JSON 응답 본문의 점 경로(예: "data.accessToken"). */
    fromJson?: string;
    /** 응답 헤더 이름에서 추출. */
    fromHeader?: string;
    /** jar 에 담긴 쿠키 이름에서 추출. */
    fromCookie?: string;
    /** 재전송할 요청 헤더 이름(기본 "authorization"). */
    sendAs?: string;
    /** 값 접두사(기본: sendAs 가 authorization 이면 "Bearer "). */
    prefix?: string;
  };
  /** 성공 판정(선택). 지정하지 않으면 쿠키/토큰 획득 여부로 판정. */
  success?: { status?: number; bodyIncludes?: string };
}

export interface LoginResult {
  ok: boolean;
  detail: string;
  /** 이후 요청에 실을 세션 쿠키 jar. */
  jar: CookieJar;
  /** 이후 요청에 병합할 인증 헤더(토큰 등). 없으면 빈 객체. */
  headers: Record<string, string>;
}

/**
 * 로그인 수행. base 는 대상 origin(예: "http://127.0.0.1:8080").
 * cfg.url 이 절대 URL 이면 base 를 무시한다.
 */
export async function performLogin(
  base: string,
  cfg: LoginConfig,
  rps: number,
  proxy?: string,
  /**
   * scope 확인 콜백(선택). 로그인 응답이 다른 호스트로 리다이렉트하면 이 콜백으로 scope 를
   * 재확인한다. false 면 추종을 멈춘다(scope 밖으로 자격증명을 실은 요청을 보내지 않음).
   */
  scopeCheck?: (host: string, port: number) => boolean,
): Promise<LoginResult> {
  const jar = newJar();
  const limiter = new RateLimiter(rps);
  const url = /^https?:\/\//i.test(cfg.url) ? cfg.url : joinOrigin(base, cfg.url);
  const method = cfg.method ?? "POST";
  const type = cfg.type ?? "form";

  const body = type === "json" ? JSON.stringify(cfg.fields) : encodeForm(cfg.fields);
  const contentType = type === "json" ? "application/json" : "application/x-www-form-urlencoded";

  const res = await httpRequest(url, {
    method,
    headers: { "content-type": contentType, ...(cfg.headers ?? {}) },
    body: method === "GET" ? undefined : body,
    redirect: "follow", // 로그인 후 리다이렉트를 따라가며 세션 쿠키를 모두 수집
    jar,
    limiter,
    proxy,
    // 호스트가 바뀌는 리다이렉트는 scope 재확인 + Authorization/Cookie 제거(자격증명 유출 방지).
    scopeCheck,
  });

  const headers: Record<string, string> = {};
  let tokenDetail = "";
  if (cfg.token) {
    const raw = extractToken(cfg.token, res.body, res.headers, jar, url);
    if (raw) {
      const sendAs = (cfg.token.sendAs ?? "authorization").toLowerCase();
      const prefix = cfg.token.prefix ?? (sendAs === "authorization" ? "Bearer " : "");
      headers[sendAs] = `${prefix}${raw}`;
      tokenDetail = `, 토큰 획득(${sendAs})`;
    }
  }

  const gotCookie = [...jar.store.values()].some((m) => m.size > 0);
  const ok = judge(cfg.success, res.status, res.body, gotCookie, !!headers["authorization"] || Object.keys(headers).length > 0);
  return {
    ok,
    detail: ok
      ? `로그인 성공(HTTP ${res.status}, 쿠키 ${gotCookie ? "획득" : "없음"}${tokenDetail})`
      : `로그인 실패/미확인(HTTP ${res.status}, 쿠키 ${gotCookie ? "있음" : "없음"})`,
    jar,
    headers,
  };
}

function judge(
  success: LoginConfig["success"],
  status: number,
  body: string,
  gotCookie: boolean,
  gotToken: boolean,
): boolean {
  if (success) {
    if (success.status != null && status !== success.status) return false;
    if (success.bodyIncludes && !body.includes(success.bodyIncludes)) return false;
    return true;
  }
  // 기준 미지정: 세션 쿠키나 토큰을 얻었고 인증 실패(401/403)가 아니면 성공으로 본다.
  return (gotCookie || gotToken) && status !== 401 && status !== 403;
}

function extractToken(
  t: NonNullable<LoginConfig["token"]>,
  body: string,
  headers: Record<string, string>,
  jar: CookieJar,
  url: string,
): string | undefined {
  if (t.fromHeader) {
    const v = headers[t.fromHeader.toLowerCase()];
    if (v) return v;
  }
  if (t.fromCookie) {
    const origin = (() => {
      try {
        const u = new URL(url);
        return `${u.protocol}//${u.host}`;
      } catch {
        return url;
      }
    })();
    const v = jar.store.get(origin)?.get(t.fromCookie);
    if (v) return v;
  }
  if (t.fromJson) {
    try {
      let cur: unknown = JSON.parse(body);
      for (const key of t.fromJson.split(".")) {
        if (cur && typeof cur === "object" && key in (cur as Record<string, unknown>)) {
          cur = (cur as Record<string, unknown>)[key];
        } else {
          return undefined;
        }
      }
      if (typeof cur === "string") return cur;
      if (typeof cur === "number") return String(cur);
    } catch {
      /* JSON 아님 */
    }
  }
  return undefined;
}

function encodeForm(fields: Record<string, string>): string {
  return Object.entries(fields)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

function joinOrigin(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  return `${b}${path.startsWith("/") ? "" : "/"}${path}`;
}
