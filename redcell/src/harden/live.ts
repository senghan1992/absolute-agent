/**
 * harden — 선택적 live 크로스체크(읽기 전용 하위집합).
 *
 * `--url` 이 주어질 때만 작동한다. 모든 요청은 ScopeGuard 를 지나야 하며(최종 판정,
 * fail-closed), 툴은 읽기 전용 8종에만 제한된다 — 인젝션/프록브(폭발) 툴은 절대 실행하지 않는다.
 *
 *   http_probe, header_audit, waf_detect, cookie_audit, jwt_audit, api_discover,
 *   secret_scan, cors_audit
 *
 * 툴에서 발견(title 들)은 원문 그대로 모으며, 공격 가설은 routes(pipeline) 쪽에서
 * capability 매핑을 거쳐 도출한다 — live 단계는 "발견"까지만 한다.
 */
import path from "node:path";
import { newJar } from "../net/http-client.js";
import { DEFAULT_LIST_FILE } from "../scope/ip-list.js";
import { loadAuthorization } from "../scope/load-auth.js";
import { redcellHome } from "../config.js";
import { parseAssaultUrl } from "../assault/url.js";
import { autoArgsFor } from "../assault/args.js";
import { DefaultToolBox } from "../tools/toolbox.js";
import type { EngagementFinding, ToolContext } from "../core/types.js";
import type { Fingerprint } from "../memory/skill-memory.js";
import type { LiveReconResult } from "./types.js";

/** 읽기 전용 하위집합 — harden 모드에서 허용하는 툴 전부. */
const LIVE_TOOLS: readonly string[] = [
  "http_probe", "header_audit", "waf_detect", "cookie_audit",
  "jwt_audit", "api_discover", "secret_scan", "cors_audit",
];

/** 연결 계층 실패(도달 불가)로 볼 툴 요약 패턴(pipeline 과 동일). */
const CONN_ERR = /요청 실패|타임아웃|ECONN|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|ECONNRESET|ECONNREFUSED|socket hang up|연결/i;

export interface LiveOptions {
  /** 크로스체크 대상(http/https). */
  url: string;
  /** 인가 파일. 기본 ~/.redcell/authorization.list — ScopeGuard 로 판정. */
  authFile?: string;
  /** 인증 헤더(선택). */
  auth?: Record<string, string>;
  proxy?: string;
  /** 인가된 테스트 세션 쿠키("sid=abc", 콤마 복수). */
  cookie?: string;
  log?: (text: string) => void;
}

export type LiveOutcome =
  | { status: "ok"; result: LiveReconResult }
  | { status: "blocked"; reason: string }
  | { status: "unreachable"; reason: string };

function mergeFp(a: Fingerprint, b: Fingerprint | undefined): Fingerprint {
  if (!b) return a;
  return {
    service: a.service ?? b.service,
    version: a.version ?? b.version,
    os: a.os ?? b.os,
    tech: [...new Set([...(a.tech ?? []), ...(b.tech ?? [])])],
    indicators: [...new Set([...(a.indicators ?? []), ...(b.indicators ?? [])])],
  };
}

/**
 * 읽기 전용 live 크로스체크 실행.
 * - 인가 밖이면 {status:"blocked"} — 여기서 종료(종료코드 3 담당).
 * - 대상 미도달이면 {status:"unreachable"} — INCONCLUSIVE(종료코드 4 담당).
 */
export async function runLiveRecon(opts: LiveOptions): Promise<LiveOutcome> {
  const log = opts.log ?? (() => {});
  const t = parseAssaultUrl(opts.url);
  const authFile = opts.authFile ?? path.join(redcellHome(), DEFAULT_LIST_FILE);

  const loaded = await loadAuthorization(authFile);
  const guard = loaded.guard;

  const pre = guard.check({ host: t.host, port: t.port, intent: "recon" });
  if (!pre.allowed) {
    log(`SCOPE 차단: ${pre.reason}`);
    return { status: "blocked", reason: pre.reason };
  }

  // 세션: 쿠키 주입(assault 와 동일한 방식) + 프록시.
  let jar;
  if (opts.cookie) {
    jar = newJar();
    const scheme = t.port === 443 || t.port === 8443 ? "https" : "http";
    const origin = `${scheme}://${t.host}${t.port && t.port !== 80 && t.port !== 443 ? `:${t.port}` : ""}`;
    const m = jar.store.get(origin) ?? new Map<string, string>();
    for (const pair of opts.cookie.split(",")) {
      const eq = pair.indexOf("=");
      if (eq > 0) m.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
    jar.store.set(origin, m);
  }

  const ctx: ToolContext = {
    target: { host: t.host, port: t.port, intent: "recon" },
    rps: guard.requestsPerSecond,
    auth: opts.auth,
    jar,
    proxy: opts.proxy,
    validateIp: (h, ip) => guard.checkResolvedIp(h, ip).allowed,
  };

  const box = new DefaultToolBox();
  const fp: Fingerprint = {};
  const findings: EngagementFinding[] = [];
  const toolSummaries: string[] = [];
  const seen = new Set<string>();
  // http_probe 결과(tripwire) — 도달성 판정의 근거.
  let probeOk: boolean | undefined;
  let probeErr = "";

  for (const name of LIVE_TOOLS) {
    const tool = box.get(name);
    if (!tool) continue;
    const args = autoArgsFor(name, fp);
    let res;
    try {
      res = await tool.run(args, ctx);
      if (name === "http_probe") { probeOk = res.ok; probeErr = res.summary; }
    } catch (e) {
      if (name === "http_probe") { probeOk = false; probeErr = String(e); }
      const summary = `${name}: 실행 오류 (${e instanceof Error ? e.message : String(e)})`;
      toolSummaries.push(summary);
      log(summary);
      continue;
    }
    if (res.fingerprint) {
      const merged = mergeFp(fp, res.fingerprint);
      fp.service = merged.service; fp.version = merged.version;
      fp.os = merged.os; fp.tech = merged.tech; fp.indicators = merged.indicators;
    }
    toolSummaries.push(`${name}: ${res.summary}`);
    log(`[${name}] ${res.summary}`);

    // 툴이 data 로 발견을 주면(title 있으면) 수집 — "info" 는 제외.
    const d = res.data as { severity?: EngagementFinding["severity"]; title?: string; evidence?: string; detail?: string; impact?: string } | undefined;
    if (d?.title && d.severity && d.severity !== "info" && !seen.has(d.title)) {
      seen.add(d.title);
      findings.push({
        phase: "recon",
        severity: d.severity,
        title: d.title,
        detail: d.detail ?? res.summary,
        evidence: d.evidence,
        impact: d.impact,
      });
    }
  }

  // 도달성 판정: http_probe 실행 실패(연결 계층)면 "unreachable"(pipeline 과 동일 규칙).
  if (probeOk === undefined || (probeOk === false && CONN_ERR.test(probeErr))) {
    log(`대상 미도달(연결 계층): ${probeErr || "http_probe 미실행"} — INCONCLUSIVE 판정.`);
    return { status: "unreachable", reason: probeErr || "http_probe 미실행" };
  }

  return {
    status: "ok",
    result: {
      url: opts.url,
      host: t.host,
      port: t.port,
      reachable: true,
      findings,
      toolSummaries,
      fingerprint: fp,
    },
  };
}
