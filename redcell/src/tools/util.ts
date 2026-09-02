/** 툴 공용 HTTP 유틸: RPS 준수 스로틀 + URL 조립 + 안전한 GET. */

import type { Target } from "../scope/scope-guard.js";

const last = { at: 0 };

/** 인가된 RPS 를 넘지 않도록 호출 간격을 강제 */
export async function throttle(rps: number): Promise<void> {
  const minGap = 1000 / Math.max(1, rps);
  const wait = Math.max(0, last.at + minGap - Date.now());
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  last.at = Date.now();
}

export function baseUrl(target: Target): string {
  const scheme = target.port === 443 || target.port === 8443 ? "https" : "http";
  const port = target.port ? `:${target.port}` : "";
  return `${scheme}://${target.host}${port}`;
}

export function joinPath(base: string, path: string): string {
  return `${base}${path.startsWith("/") ? "" : "/"}${path}`;
}

export interface FetchOut {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** 8초 타임아웃, 리다이렉트 수동, 본문 앞부분만. */
export async function safeGet(url: string, rps: number, method: "GET" | "HEAD" = "GET"): Promise<FetchOut> {
  await throttle(rps);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch(url, { method, redirect: "manual", signal: ctrl.signal });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    const body = method === "HEAD" ? "" : (await res.text()).slice(0, 6000);
    return { status: res.status, headers, body };
  } finally {
    clearTimeout(t);
  }
}
