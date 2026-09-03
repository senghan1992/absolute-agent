/**
 * 저수준 HTTP 트랜스포트 — 실전 인게이지먼트에 필요한 것들을 fetch 대신 직접 갖춘다.
 *
 * fetch(전역) 로는 못 하던 것들:
 *   - **프록시**: Burp/ZAP 로 트래픽을 태워 수동 검증/기록(HTTP 절대URI · HTTPS CONNECT 터널)
 *   - **쿠키 jar**: Set-Cookie 를 저장·재전송 → 로그인 세션 유지("로그인 뒤" 표면)
 *   - **재시도/백오프**: 일시적 네트워크 오류에 견딤(실전 안정성)
 *   - **per-target RPS**: 대상별 토큰버킷(전역 싱글턴 스로틀의 동시성 버그 제거)
 *
 * 비파괴/안전 원칙은 상위 툴이 책임진다. 이 계층은 순수 전송만 담당한다.
 */

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { promises as dnsp } from "node:dns";
import { URL } from "node:url";
import { RateLimiter } from "./rate-limiter.js";

export interface CookieJar {
  /** origin(scheme://host:port) → name → value */
  store: Map<string, Map<string, string>>;
}

export function newJar(): CookieJar {
  return { store: new Map() };
}

function originKey(u: URL): string {
  return `${u.protocol}//${u.host}`;
}

/** jar 에 저장된, 이 URL 로 보낼 Cookie 헤더 값(없으면 undefined). */
function cookieHeader(jar: CookieJar | undefined, u: URL): string | undefined {
  if (!jar) return undefined;
  const m = jar.store.get(originKey(u));
  if (!m || m.size === 0) return undefined;
  return [...m.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

/** Set-Cookie 응답들을 jar 에 반영(속성은 무시하고 name=value 만 — 탐지 목적엔 충분). */
function absorbCookies(jar: CookieJar | undefined, u: URL, setCookies: string[]): void {
  if (!jar || setCookies.length === 0) return;
  const key = originKey(u);
  let m = jar.store.get(key);
  if (!m) jar.store.set(key, (m = new Map()));
  for (const sc of setCookies) {
    const first = sc.split(";", 1)[0];
    const eq = first.indexOf("=");
    if (eq <= 0) continue;
    const name = first.slice(0, eq).trim();
    const val = first.slice(eq + 1).trim();
    if (name) m.set(name, val);
  }
}

export interface HttpRequestOpts {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** 본문에서 읽을 최대 문자 수(기본 6000). */
  cap?: number;
  /** 타임아웃 ms(기본 8000). */
  timeoutMs?: number;
  /** "manual"(기본): 3xx 를 따라가지 않음. "follow": 최대 5회 추적. */
  redirect?: "manual" | "follow";
  /** 프록시 URL(예: http://127.0.0.1:8080). env REDCELL_PROXY 로도 지정 가능. */
  proxy?: string;
  /** 쿠키 jar(세션 유지). 지정 시 Set-Cookie 저장 + Cookie 재전송. */
  jar?: CookieJar;
  /** 대상별 RPS 리미터. 지정 시 요청 전 토큰을 소비. */
  limiter?: RateLimiter;
  /** 네트워크 오류 시 재시도 횟수(기본 2). 지수 백오프. */
  retries?: number;
  /** TLS 인증서 검증(기본 false: 실습/사설 인증서 대상 허용). */
  rejectUnauthorized?: boolean;
  /**
   * 리다이렉트 추종 시 각 다음 홉이 scope 안인지 확인하는 콜백(선택).
   * 호스트가 바뀌는 리다이렉트에서 호출된다. false 를 반환하면 추종을 멈추고 현재 3xx 응답을
   * 그대로 돌려준다(scope 밖으로 자격증명을 실은 요청을 보내지 않음). 지정하지 않아도
   * 호스트 변경 시 Authorization/Cookie 는 항상 제거된다(자격증명 유출 방지).
   */
  scopeCheck?: (host: string, port: number) => boolean;
  /**
   * 연결 시점 IP 검증 콜백(선택). 호스트명을 실제 IP 로 해석한 뒤, 그 IP 로 실제 연결하기
   * 전에 호출된다. false 를 반환하면 연결하지 않고 오류를 던진다(내부 IP·DNS rebinding 차단).
   * 통과하면 **해석된 그 IP 로 직접(pinned) 연결**해 TOCTOU(검증 후 재해석) 를 제거한다.
   * (프록시 경유 요청에는 적용하지 않는다 — 그 경우 이름 해석은 프록시가 담당한다.)
   */
  validateIp?: (hostname: string, ip: string) => boolean;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  /** 최종 URL(redirect follow 시 달라질 수 있음). */
  url: string;
}

const DEFAULT_PROXY = () => process.env.REDCELL_PROXY || process.env.HTTPS_PROXY || process.env.HTTP_PROXY || undefined;

/**
 * 한 번의 HTTP 요청(재시도·리다이렉트·프록시·쿠키 포함).
 * node:http/https 를 직접 써서 fetch 로 불가능한 제어를 확보한다.
 */
export async function httpRequest(rawUrl: string, opt: HttpRequestOpts = {}): Promise<HttpResponse> {
  const retries = opt.retries ?? 2;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      // RPS 토큰은 once() 진입 시 소비한다(아래) → 리다이렉트 홉마다 재소비되어 RPS 우회가 없다.
      return await once(rawUrl, opt, 0);
    } catch (e) {
      lastErr = e;
      if (attempt < retries) await sleep(150 * Math.pow(2, attempt)); // 150ms, 300ms, ...
    }
  }
  throw lastErr;
}

async function once(rawUrl: string, opt: HttpRequestOpts, depth: number): Promise<HttpResponse> {
  // 리다이렉트 홉을 포함해 실제 소켓을 여는 매 요청마다 RPS 토큰을 소비한다(폭주/우회 방지).
  if (opt.limiter) await opt.limiter.acquire();
  const u = new URL(rawUrl);
  const method = (opt.method ?? "GET").toUpperCase();
  const cap = opt.cap ?? 6000;
  const timeoutMs = opt.timeoutMs ?? 8000;
  const proxy = opt.proxy ?? DEFAULT_PROXY();

  const headers: Record<string, string> = { ...(opt.headers ?? {}) };
  // 기본 헤더(호출자가 안 넣었으면).
  if (!hasHeader(headers, "user-agent")) headers["user-agent"] = "RedCell/1.0 (+authorized-security-testing)";
  if (!hasHeader(headers, "accept")) headers["accept"] = "*/*";
  const cookie = cookieHeader(opt.jar, u);
  if (cookie && !hasHeader(headers, "cookie")) headers["cookie"] = cookie;
  if (opt.body != null && !hasHeader(headers, "content-length")) {
    headers["content-length"] = String(Buffer.byteLength(opt.body));
  }

  const res = await transport(u, method, headers, opt.body, timeoutMs, proxy, opt.rejectUnauthorized ?? false, cap, opt.validateIp);
  absorbCookies(opt.jar, u, res.setCookies);

  // 리다이렉트 추적(follow, 최대 5회).
  if (opt.redirect === "follow" && res.status >= 300 && res.status < 400 && res.headers["location"] && depth < 5) {
    const nextUrl = new URL(res.headers["location"], u);
    const crossOrigin = originKey(nextUrl) !== originKey(u);
    const nextOpt: HttpRequestOpts = { ...opt };

    if (crossOrigin) {
      // ★ 안전: 호스트(origin)가 바뀌는 리다이렉트.
      // 1) scope 재확인 — scope 밖이면 추종을 멈추고 현재 3xx 를 그대로 반환(자격증명 실은 요청 미발송).
      const nextPort = nextUrl.port ? Number(nextUrl.port) : nextUrl.protocol === "https:" ? 443 : 80;
      if (opt.scopeCheck && !opt.scopeCheck(nextUrl.hostname, nextPort)) {
        return { status: res.status, headers: res.headers, body: res.body, url: u.toString() };
      }
      // 2) Authorization/Cookie 는 다른 호스트로 흘리지 않는다(헤더·jar 모두 제거).
      //    새 호스트용 쿠키는 jar 가 origin 별로 분리 저장하므로, jar 를 떼도 정당한 쿠키는
      //    유실되지 않는다(cross-origin 유출만 차단). 명시 헤더의 Authorization/Cookie 는 제거.
      nextOpt.headers = stripSensitiveHeaders(opt.headers);
      nextOpt.jar = undefined;
    }

    const next = nextUrl.toString();
    // 303 또는 GET/HEAD 로의 리다이렉트는 GET 으로 전환(브라우저 관행).
    if (res.status === 303 || (method !== "GET" && method !== "HEAD")) {
      nextOpt.method = "GET";
      nextOpt.body = undefined;
    }
    return once(next, nextOpt, depth + 1);
  }
  return { status: res.status, headers: res.headers, body: res.body, url: u.toString() };
}

interface RawRes {
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
}

function transport(
  u: URL,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
  proxy: string | undefined,
  rejectUnauthorized: boolean,
  cap: number,
  validateIp: ((hostname: string, ip: string) => boolean) | undefined,
): Promise<RawRes> {
  const isHttps = u.protocol === "https:";
  // 프록시 경유 시 이름 해석은 프록시가 담당하므로 여기서 IP 핀/검증을 하지 않는다.
  if (proxy) return viaProxy(u, method, headers, body, timeoutMs, proxy, rejectUnauthorized, cap, isHttps);
  return direct(u, method, headers, body, timeoutMs, rejectUnauthorized, cap, isHttps, validateIp);
}

async function direct(
  u: URL,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
  rejectUnauthorized: boolean,
  cap: number,
  isHttps: boolean,
  validateIp: ((hostname: string, ip: string) => boolean) | undefined,
): Promise<RawRes> {
  const mod = isHttps ? https : http;
  const reqHeaders = { ...headers };
  let connectHost = u.hostname;
  // 호스트명(비-IP)이면 직접 해석 → 해석된 IP 를 validateIp 로 검증 → 그 IP 로 pinned 연결.
  // 이렇게 하면 "검증한 이름"과 "실제 연결한 IP"가 일치해 DNS rebinding/TOCTOU 가 제거된다.
  if (validateIp && !net.isIP(u.hostname)) {
    let addrs: Array<{ address: string }>;
    try {
      addrs = await dnsp.lookup(u.hostname, { all: true });
    } catch (e) {
      throw new Error(`DNS 해석 실패(${u.hostname}): ${(e as Error).message}`);
    }
    const ok = addrs.find((a) => validateIp(u.hostname, a.address));
    if (!ok) {
      throw new Error(`scope: ${u.hostname} 의 해석된 IP(${addrs.map((a) => a.address).join(",")})가 인가되지 않았습니다 — 내부 IP/DNS rebinding 차단.`);
    }
    connectHost = ok.address;
    // 원래 호스트명을 Host 헤더/SNI 로 보존(IP 로 연결해도 vhost·TLS 가 정상 동작).
    if (!hasHeader(reqHeaders, "host")) reqHeaders["host"] = u.host;
  }
  const options: http.RequestOptions = {
    method,
    hostname: connectHost,
    port: u.port || (isHttps ? 443 : 80),
    path: u.pathname + u.search,
    headers: reqHeaders,
    ...(isHttps ? { rejectUnauthorized, servername: u.hostname } : {}),
  };
  return send(mod, options, body, timeoutMs, cap);
}

/**
 * 프록시 경유. HTTP 대상은 절대-URI 요청라인으로 프록시에 직접 보낸다.
 * HTTPS 대상은 CONNECT 로 터널을 뚫고 그 소켓 위에서 TLS + 요청.
 */
async function viaProxy(
  u: URL,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
  proxy: string,
  rejectUnauthorized: boolean,
  cap: number,
  isHttps: boolean,
): Promise<RawRes> {
  const p = new URL(proxy);
  if (!isHttps) {
    // 평문: 절대 URI 를 요청라인에 실어 프록시로.
    const options: http.RequestOptions = {
      method,
      hostname: p.hostname,
      port: p.port || 80,
      path: u.toString(),
      headers: { ...headers, host: u.host },
    };
    if (p.username) options.headers = { ...options.headers, "proxy-authorization": basicAuth(p) };
    return send(http, options, body, timeoutMs, cap);
  }
  // TLS: CONNECT 터널 → TLS 소켓 → 요청.
  const socket = await connectTunnel(p, u, timeoutMs);
  const tlsSocket = tls.connect({ socket, servername: u.hostname, rejectUnauthorized });
  const options: http.RequestOptions = {
    method,
    path: u.pathname + u.search,
    headers,
    createConnection: () => tlsSocket as unknown as net.Socket,
  };
  return send(https, options, body, timeoutMs, cap);
}

function connectTunnel(p: URL, target: URL, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      method: "CONNECT",
      hostname: p.hostname,
      port: p.port || 80,
      path: `${target.hostname}:${target.port || 443}`,
      headers: p.username ? { "proxy-authorization": basicAuth(p) } : undefined,
      timeout: timeoutMs,
    });
    req.on("connect", (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`프록시 CONNECT 실패: ${res.statusCode}`));
        return;
      }
      resolve(socket);
    });
    req.on("timeout", () => req.destroy(new Error("프록시 CONNECT 타임아웃")));
    req.on("error", reject);
    req.end();
  });
}

function send(
  mod: typeof http | typeof https,
  options: http.RequestOptions,
  body: string | undefined,
  timeoutMs: number,
  cap: number,
): Promise<RawRes> {
  return new Promise((resolve, reject) => {
    const req = mod.request(options, (res) => {
      const chunks: Buffer[] = [];
      let len = 0;
      const capBytes = cap * 4; // 문자 cap 근사(UTF-8 여유)
      res.on("data", (c: Buffer) => {
        if (len < capBytes) {
          chunks.push(c);
          len += c.length;
        }
      });
      res.on("end", () => {
        const h: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (k === "set-cookie") continue; // 아래에서 합쳐 넣는다
          h[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
        }
        const setCookies = (res.headers["set-cookie"] as string[] | undefined) ?? [];
        // set-cookie 를 헤더 맵에도 합쳐 넣는다(cookie_audit 등 기존 툴 호환). jar 는 배열로 별도 처리.
        if (setCookies.length) h["set-cookie"] = setCookies.join(", ");
        resolve({
          status: res.statusCode ?? 0,
          headers: h,
          setCookies,
          body: Buffer.concat(chunks).toString("utf8").slice(0, cap),
        });
      });
      res.on("error", reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`요청 타임아웃(${timeoutMs}ms)`)));
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

function hasHeader(h: Record<string, string>, name: string): boolean {
  return Object.keys(h).some((k) => k.toLowerCase() === name);
}
/** cross-origin 리다이렉트로 넘길 때 자격증명 헤더(Authorization/Cookie)를 제거한다. */
function stripSensitiveHeaders(headers: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (lk === "authorization" || lk === "cookie") continue;
    out[k] = v;
  }
  return out;
}
function basicAuth(u: URL): string {
  return "Basic " + Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64");
}
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
