/** 툴 공용 HTTP 유틸: per-target RPS 준수 + URL 조립 + 프록시/쿠키/재시도 지원 GET/POST. */

import type { Target } from "../scope/scope-guard.js";
import type { ToolContext } from "../core/types.js";
import { httpRequest, type CookieJar } from "../net/http-client.js";
import { RateLimiter } from "../net/rate-limiter.js";

/**
 * 대상(origin)별 RateLimiter. 전역 싱글턴 스로틀은 동시 다중 대상에서 RPS 가
 * 뭉개지는 버그가 있었다 → origin 키로 분리해 대상마다 독립적으로 상한을 건다.
 */
const limiters = new Map<string, RateLimiter>();
function limiterFor(url: string, rps: number): RateLimiter {
  const origin = (() => {
    try {
      const u = new URL(url);
      return `${u.protocol}//${u.host}`;
    } catch {
      return url;
    }
  })();
  let lim = limiters.get(origin);
  if (!lim) limiters.set(origin, (lim = new RateLimiter(rps)));
  return lim;
}

export function baseUrl(target: Target): string {
  const scheme = target.port === 443 || target.port === 8443 ? "https" : "http";
  const port = target.port ? `:${target.port}` : "";
  return `${scheme}://${target.host}${port}`;
}

export function joinPath(base: string, path: string): string {
  return `${base}${path.startsWith("/") ? "" : "/"}${path}`;
}

/** 경로에 쿼리 파라미터를 안전하게 덧붙인다(이미 ? 가 있으면 & 로 이어붙임). */
export function withQuery(path: string, params: Record<string, string>): string {
  const qs = Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
  if (!qs) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${qs}`;
}

export interface FetchOut {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface GetOpts {
  /** HTTP 메서드. GET/HEAD 외 OPTIONS/TRACE/PUT/DELETE 등 임의 메서드도 허용(메서드 감사용). */
  method?: string;
  headers?: Record<string, string>;
  /** 본문에서 읽을 최대 문자 수(기본 6000). */
  cap?: number;
  /** 타임아웃 ms(기본 8000). */
  timeoutMs?: number;
  /** 프록시 URL. 지정 시 이 요청을 프록시 경유(그 외엔 env REDCELL_PROXY). */
  proxy?: string;
  /** 쿠키 jar. 지정 시 세션 유지. */
  jar?: CookieJar;
  /** 리다이렉트 추적 여부(기본 manual). */
  redirect?: "manual" | "follow";
  /** 연결 시점 IP 검증(내부 IP·DNS rebinding 차단). 보통 ctx.validateIp 로 주입된다. */
  validateIp?: (hostname: string, ip: string) => boolean;
}

/**
 * 안전 GET/HEAD. 리다이렉트 수동(기본), per-target RPS, 재시도, 본문 앞부분만.
 * 3번째 인자는 하위호환을 위해 method 문자열 또는 옵션 객체 모두 허용한다.
 */
export async function safeGet(url: string, rps: number, opt: string | GetOpts = "GET"): Promise<FetchOut> {
  const o: GetOpts = typeof opt === "string" ? { method: opt } : opt;
  const res = await httpRequest(url, {
    method: o.method ?? "GET",
    headers: o.headers,
    cap: o.cap,
    timeoutMs: o.timeoutMs,
    redirect: o.redirect ?? "manual",
    proxy: o.proxy,
    jar: o.jar,
    limiter: limiterFor(url, rps),
    validateIp: o.validateIp,
  });
  return { status: res.status, headers: res.headers, body: (o.method ?? "GET") === "HEAD" ? "" : res.body };
}

/**
 * 인증 컨텍스트를 자동으로 실어 보내는 GET.
 * ctx.auth(세션/토큰 헤더) + ctx.jar(쿠키) + ctx.proxy 를 요청에 병합한다 → "로그인 뒤" 표면까지 점검.
 * 개별 툴이 지정한 headers 가 auth 헤더보다 우선한다(툴이 의도적으로 덮어쓸 수 있게).
 */
export async function authGet(ctx: ToolContext, url: string, opt: string | GetOpts = "GET"): Promise<FetchOut> {
  const o: GetOpts = typeof opt === "string" ? { method: opt } : { ...opt };
  const merged = { ...(ctx.auth ?? {}), ...(o.headers ?? {}) };
  o.headers = Object.keys(merged).length ? merged : undefined;
  if (o.proxy === undefined) o.proxy = ctx.proxy;
  if (o.jar === undefined) o.jar = ctx.jar;
  if (o.validateIp === undefined) o.validateIp = ctx.validateIp;
  return safeGet(url, ctx.rps, o);
}

/**
 * 인증 컨텍스트를 실어 보내는 POST(JSON/폼). 인젝션·GraphQL·업로드 탐지에 쓴다.
 * 비파괴 원칙: 상태 변경 의도가 아니라 취약점 신호 관찰 목적의 요청만 보낸다.
 */
export async function authPost(
  ctx: ToolContext,
  url: string,
  body: string,
  opt: { contentType?: string; headers?: Record<string, string>; cap?: number; timeoutMs?: number } = {},
): Promise<FetchOut> {
  const headers = { "content-type": opt.contentType ?? "application/json", ...(ctx.auth ?? {}), ...(opt.headers ?? {}) };
  const res = await httpRequest(url, {
    method: "POST",
    headers,
    body,
    cap: opt.cap,
    timeoutMs: opt.timeoutMs,
    redirect: "manual",
    proxy: ctx.proxy,
    jar: ctx.jar,
    limiter: limiterFor(url, ctx.rps),
    validateIp: ctx.validateIp,
  });
  return { status: res.status, headers: res.headers, body: res.body };
}
