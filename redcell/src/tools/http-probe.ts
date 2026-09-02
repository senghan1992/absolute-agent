/**
 * http_probe — 안전한 웹 정찰 툴.
 *
 * 오직 GET/HEAD 로 응답 헤더·본문 지표를 관측하여 fingerprint 를 만든다.
 * 파괴적 요청/무차별 대입을 하지 않으며, RPS 제한을 준수한다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import type { Fingerprint } from "../memory/skill-memory.js";

export const httpProbe: Tool = {
  name: "http_probe",
  description: "대상 웹 서비스에 GET/HEAD 로 접속해 헤더/본문 지표로 기술스택을 핑거프린팅한다(비파괴).",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const scheme = ctx.target.port === 443 || ctx.target.port === 8443 ? "https" : "http";
    const port = ctx.target.port ? `:${ctx.target.port}` : "";
    const pathArg = typeof args.path === "string" && args.path ? args.path : "/";
    const url = `${scheme}://${ctx.target.host}${port}${pathArg.startsWith("/") ? "" : "/"}${pathArg}`;

    await throttle(ctx.rps);

    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const res = await fetch(url, { method: "GET", redirect: "manual", signal: ctrl.signal });
      clearTimeout(t);
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      const body = (await res.text()).slice(0, 4000); // 앞부분만
      const fp = fingerprintFrom(headers, body);

      const title = fp.service
        ? `${fp.service}${fp.version ? " " + fp.version : ""} 탐지 (HTTP ${res.status})`
        : `HTTP ${res.status} 응답`;

      return {
        ok: true,
        summary: `${url} → ${res.status}; server=${headers["server"] ?? "?"}; tech=${(fp.tech ?? []).join(",") || "?"}`,
        fingerprint: fp,
        data: {
          severity: "info",
          title,
          evidence: `status=${res.status}, server=${headers["server"] ?? "?"}, x-powered-by=${headers["x-powered-by"] ?? "?"}`,
        },
      };
    } catch (e) {
      return { ok: false, summary: `요청 실패: ${(e as Error).message} (${url})` };
    }
  },
};

function fingerprintFrom(headers: Record<string, string>, body: string): Fingerprint {
  const tech = new Set<string>();
  const indicators: string[] = [];
  let service: string | undefined;
  let version: string | undefined;

  const server = headers["server"];
  if (server) {
    indicators.push(`server: ${server}`);
    const m = server.match(/^([A-Za-z-]+)\/?([\d.]+)?/);
    if (m) {
      service = m[1].toLowerCase();
      version = m[2];
    }
  }
  service = service ?? "http";

  const xpb = headers["x-powered-by"];
  if (xpb) {
    indicators.push(`x-powered-by: ${xpb}`);
    if (/php/i.test(xpb)) tech.add("php");
    if (/asp\.net/i.test(xpb)) tech.add("aspnet");
    if (/express/i.test(xpb)) tech.add("express");
  }
  const cookie = headers["set-cookie"] ?? "";
  if (/phpsessid/i.test(cookie)) tech.add("php");
  if (/jsessionid/i.test(cookie)) tech.add("java");
  if (/csrftoken|django/i.test(cookie)) tech.add("django");
  if (/laravel_session/i.test(cookie)) tech.add("laravel");

  if (/wp-content|wordpress/i.test(body)) tech.add("wordpress");
  if (/drupal/i.test(body)) tech.add("drupal");
  if (/dvwa/i.test(body)) tech.add("dvwa");
  if (/csrf-token|_token/i.test(body)) indicators.push("csrf-token present");

  return { service, version, tech: [...tech], indicators };
}

const last: { at: number } = { at: 0 };
async function throttle(rps: number): Promise<void> {
  const minGap = 1000 / Math.max(1, rps);
  const now = Date.now();
  const wait = Math.max(0, last.at + minGap - now);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  last.at = Date.now();
}
