/**
 * smuggle_probe — HTTP Request Smuggling(요청 밀반입) 프레이밍 모호성 탐지. **비파괴 차등 방식**.
 *
 * 스머글링은 프론트(프록시/로드밸런서)와 백엔드가 요청 길이(CL)와 청크(TE)를
 * 서로 다르게 해석할 때 성립한다. 실제 "밀반입"을 수행하면 잔여 바이트가 백엔드
 * 연결을 오염시켜 **다른 사용자의 요청까지 망가뜨릴 수 있으므로** 절대 하지 않는다.
 * 대신 관찰만 하는 안전 벡터로 차등을 확인한다:
 *
 *   벡터 1 (CL.TE 스톨)   — Content-Length 가 청크 본문보다 큰 요청. CL-우선 파서는
 *                           "남은 바이트"를 기다려(스톨), TE-우선 파서는 즉시 완료한다.
 *                           RFC 준수 서버는 400 으로 거부 → 클린.
 *   벡터 2 (중복 CL)      — Content-Length 가 서로 다르게 2개. 파서가 큰 값을 고르면 스톨.
 *   벡터 3 (TE 난독화)    — `Transfer-Encoding : chunked`(콜론 공백), 탭, 중복 identity 등
 *                           파서별 해석이 갈리는 변형 간 응답 차등 관찰.
 *
 * 스톨은 "응답이 타임아웃 안에 안 옴"으로 관측하며, 관측 즉시 소켓을 폐기해 서버 자원
 * 낭비를 최소화한다. baseline(정상 GET) 응답 속도와 비교해 느린 서버 오탐을 걸러내고,
 * 스톨은 2회 확인(재시도 상관)해서 통계적 우연을 제거한다. 잔여 바이트를 보내지
 * 않으므로 어떤 파서 순서 조합에서도 연결 오염이 없다(blast radius 0).
 *
 * TLS(443/8443) 대상은 TLS 레코드 처리가 필요해 미지원 — http 대상에서만 동작한다.
 */

import net from "node:net";
import { promises as dnsp } from "node:dns";
import type { Tool, ToolContext, ToolResult } from "../core/types.js";

/** 스톨 판정 예산(ms). baseline 이 이 안에 오면 같은 예산으로 벡터를 판정한다. */
const STALL_MS = 2200;
/** baseline 지연 상한 — 이보다 느리면 "느린 서버"로 스톨 판별을 포기한다(FP 방지). */
const BASELINE_MAX_MS = 1500;

interface RawOut {
  kind: "res" | "stall" | "error";
  status?: number;
  /** 응답 앞부분(증거/디버그용). */
  head?: string;
  ms: number;
  error?: string;
}

/** raw HTTP/1.1 요청을 TCP 로 직접 보낸다(프레이밍 헤더를 조작해야 하므로 fetch 불가). */
function rawOnce(host: string, port: number, raw: string, budgetMs: number, validateIp?: (h: string, ip: string) => boolean): Promise<RawOut> {
  return new Promise((resolve) => {
    let settled = false;
    const t0 = Date.now();
    const finish = (r: RawOut) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* noop */ }
      resolve(r);
    };
    const timer = setTimeout(() => finish({ kind: "stall", ms: Date.now() - t0 }), budgetMs);
    const sock = new net.Socket();
    let buf = "";

    const connect = (ip: string) => {
      sock.connect(port, ip, () => sock.write(raw));
    };

    sock.once("error", (e) => finish({ kind: "error", ms: Date.now() - t0, error: e.message }));
    sock.on("data", (d) => {
      buf += d.toString("utf8");
    });
    sock.once("close", () => {
      // close 도착 = 응답 완료(또는 빈 응답). finish 내부의 settled 가드가 중복 해소를 막는다.
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(buf);
      if (m) finish({ kind: "res", status: Number(m[1]), head: buf.slice(0, 400), ms: Date.now() - t0 });
      else finish({ kind: buf.trim() ? "res" : "error", head: buf.slice(0, 400), ms: Date.now() - t0, error: buf.trim() ? undefined : "빈 응답" });
    });

    // 연결 시점 IP 검증(DNS rebinding/내부 IP 차단) — http-client 와 동일한 규칙.
    if (validateIp && !net.isIP(host)) {
      dnsp.lookup(host, { all: true })
        .then((addrs) => {
          const ok = addrs.find((a) => validateIp(host, a.address));
          if (!ok) {
            finish({ kind: "error", ms: Date.now() - t0, error: `scope: ${host} 의 해석 IP 가 인가되지 않음` });
            return;
          }
          connect(ok.address);
        })
        .catch((e) => finish({ kind: "error", ms: Date.now() - t0, error: `DNS 해석 실패: ${(e as Error).message}` }));
    } else {
      connect(host);
    }
  });
}

const hostHeader = (host: string, port: number): string => (port === 80 || port === 443 ? host : `${host}:${port}`);

/** 벡터 1 — CL.TE 충돌: CL 이 청크 본문(4바이트)보다 2바이트 크다. */
function clTeConflict(host: string, port: number, path: string): string {
  return (
    `POST ${path} HTTP/1.1\r\n` +
    `Host: ${hostHeader(host, port)}\r\n` +
    `Content-Length: 6\r\n` +
    `Transfer-Encoding: chunked\r\n` +
    `Connection: close\r\n` +
    `\r\n` +
    `0\r\n\r\n`
  );
}

/** 벡터 2 — 중복 CL(5, 6): 본문은 5바이트. 6을 고르는 파서는 대기한다. */
function dupCl(host: string, port: number, path: string): string {
  return (
    `POST ${path} HTTP/1.1\r\n` +
    `Host: ${hostHeader(host, port)}\r\n` +
    `Content-Length: 5\r\n` +
    `Content-Length: 6\r\n` +
    `Connection: close\r\n` +
    `\r\n` +
    `0\r\n\r\n`
  );
}

/** 벡터 3 — TE 난독화 변형(본문은 정상 청크 종결). */
const TE_VARIANTS: Array<{ label: string; te: string }> = [
  { label: "colon-space", te: "Transfer-Encoding : chunked" },
  { label: "tab", te: "Transfer-Encoding:\tchunked" },
  { label: "dup-identity", te: "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity" },
];
function teVariant(host: string, port: number, path: string, te: string): string {
  return (
    `POST ${path} HTTP/1.1\r\n` +
    `Host: ${hostHeader(host, port)}\r\n` +
    `${te}\r\n` +
    `Connection: close\r\n` +
    `\r\n` +
    `0\r\n\r\n`
  );
}
/** 정상 청크 요청(TE 기준선). */
function teNormal(host: string, port: number, path: string): string {
  return teVariant(host, port, path, "Transfer-Encoding: chunked");
}

interface PathProbe {
  stalls: number;
  anomalies: string[];
  tolerated: string[];
  result?: ToolResult;
}

export const smuggleProbe: Tool = {
  name: "smuggle_probe",
  description:
    "HTTP Request Smuggling 프레이밍 모호성을 비파괴 차등으로 탐지한다. CL.TE 충돌 스톨·중복 CL·TE 난독화 변형의 응답 차등을 관찰하고, 잔여 바이트를 보내지 않아 백엔드 오염이 없다(연결 즉시 폐기). http 대상 전용.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const host = ctx.target.host;
    const port = ctx.target.port ?? 80;
    if (port === 443 || port === 8443) {
      return { ok: false, summary: "TLS 대상은 미지원(TLS 레코드 프레이밍 필요) — http 대상에서만 동작" };
    }
    const paths = pickPaths(args);
    const vip = ctx.validateIp;

    const toleratedAll: string[] = [];
    for (const path of paths) {
      const r = await probePath(host, port, path, vip);
      if (r.result) return r.result; // 확정(스톨≥2 / 역전 / baseline 실패)
      toleratedAll.push(...r.tolerated);
    }
    if (toleratedAll.length > 0) {
      return {
        ok: true,
        summary: `프레이밍 모호성 수용(거부 안 함): ${toleratedAll.length}건 — 백엔드 파서에 따라 위험 가능`,
        data: {
          severity: "low",
          title: `프레이밍 모호성 수용 (${paths.join(",")})`,
          evidence: `CL+TE 충돌/중복 CL/TE 변형을 400 거부 없이 수용(200) — 프론트가 TE-우선 등 일관 파서로 추정. 백엔드 불일치 여부는 미확인.`,
        },
      };
    }
    return { ok: false, summary: `스머글링 미탐지 (paths=${paths.join(",")}) — 충돌 프레이밍 일관 거부(400) 또는 스톨 없음` };
  },
};

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path.startsWith("/")) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string" && x.startsWith("/"));
    if (ps.length) return [...new Set(ps)].slice(0, 3);
  }
  return ["/"];
}

/** 한 경로에 대한 전체 벡터 관찰. 확정(스톨≥2 또는 역전) 시 result 를 돌려준다. */
async function probePath(host: string, port: number, path: string, vip: ((h: string, ip: string) => boolean) | undefined): Promise<PathProbe> {
  // 0) baseline — 정상 GET. 느린 서버면 스톨 판별 자체를 포기한다(FP 방지).
  const base = await rawOnce(host, port, `GET ${path} HTTP/1.1\r\nHost: ${hostHeader(host, port)}\r\nConnection: close\r\n\r\n`, BASELINE_MAX_MS, vip);
  if (base.kind !== "res") {
    return { stalls: 0, anomalies: [], tolerated: [], result: { ok: false, summary: `baseline 미응답(${base.kind}) — 스머글링 판별 불가` } };
  }

  const stalls: string[] = [];
  const anomalies: string[] = [];
  const tolerated: string[] = [];

  // 1) CL.TE 충돌 스톨(2회 확인).
  for (let i = 0; i < 2; i++) {
    const r = await rawOnce(host, port, clTeConflict(host, port, path), STALL_MS, vip);
    if (r.kind === "stall") stalls.push("CL.TE 충돌에서 백엔드 대기(스톨) 관측");
    else if (r.kind === "res" && r.status === 200) tolerated.push("CL+TE 충돌 수용(200)");
  }

  // 2) 중복 CL 차등.
  const dc = await rawOnce(host, port, dupCl(host, port, path), STALL_MS, vip);
  if (dc.kind === "stall") stalls.push("중복 Content-Length(5,6)에서 대기 관측 — 파서가 큰 값을 선택");
  else if (dc.kind === "res" && dc.status === 200) tolerated.push("중복 Content-Length 수용(200)");

  // 3) TE 난독화 변형 — 정상 청크 기준선과 비교. 400 거부는 정상(안전)이고,
  //    "거부됐어야 할 변형이 수용(200)"일 때만 징후로 센다(오탐 방지).
  //    (스톨이 이미 2회 이상 확정됐으면 추가 관찰 없이 바로 판정한다 — 스캔 시간 단축.)
  const confirmed = stalls.length >= 2;
  const normal = confirmed ? { kind: "res" as const, status: 200, ms: 0, head: "" } : await rawOnce(host, port, teNormal(host, port, path), STALL_MS, vip);
  for (const v of confirmed ? [] : TE_VARIANTS) {
    const r = await rawOnce(host, port, teVariant(host, port, path, v.te), STALL_MS, vip);
    if (r.kind === "stall") stalls.push(`TE 난독화(${v.label})에서 대기 관측`);
    else if (r.kind === "res" && r.status === 200 && normal.kind === "res" && normal.status !== 200) {
      // 역전: 정상 TE 는 거부, 난독화 변형은 수용 — 파서 체인 혼란의 강한 신호.
      anomalies.push(`TE 난독화(${v.label}) 응답 역전: 변형 ${r.status} vs 기준 ${normal.status}`);
    } else if (r.kind === "res" && r.status === 200) {
      tolerated.push(`TE 난독화(${v.label}) 수용(200) — RFC 위반 표기를 해석함`);
    }
  }

  // 판정 — 스톨 2회 이상이면 프레이밍 파서 불일치로 확정.
  if (stalls.length >= 2) {
    return {
      stalls: stalls.length,
      anomalies,
      tolerated,
      result: {
        ok: true,
        summary: `HTTP Request Smuggling 확정: ${path} — 프레이밍 모호성 요청에 대기(스톨) ${stalls.length}건 관측(baseline ${base.ms}ms 정상)`,
        fingerprint: { indicators: [`smuggling ${path}`] },
        data: {
          severity: "high",
          title: `HTTP Request Smuggling (${path})`,
          evidence:
            `스머글링 실증: 프레이밍 모호성으로 백엔드 대기 관측 — ${stalls.join("; ")}. ` +
            `baseline 응답 ${base.ms}ms(정상)와 대비, 모호 요청에서 응답 부재(스톨). 잔여 바이트 미전송으로 연결 오염 없음(비파괴 검증).`,
          impact:
            "프론트와 백엔드가 요청 경계를 다르게 해석하면 공격자가 다른 사용자의 요청을 밀반입시킬 수 있다 → 캐시 오염·인증 우회·세션 탈취·요청 하이재킹으로 확대. 프레이밍 헤더 정규화(CL+TE 동시 거부, 중복 CL 거부, TE 값 검증)가 필요.",
        },
      },
    };
  }
  if (anomalies.length > 0) {
    return {
      stalls: stalls.length,
      anomalies,
      tolerated,
      result: {
        ok: true,
        summary: `TE 난독화 응답 차등: ${anomalies.join(", ")} — 파서별 해석 불일치 징후`,
        fingerprint: { indicators: [`smuggling-te ${path}`] },
        data: {
          severity: "medium",
          title: `TE 난독화 응답 차등 (${path})`,
          evidence: `스머글링 실증: 프레이밍 모호성으로 차등 응답 — ${anomalies.join("; ")}. 파서 체인이 TE 값을 다르게 해석한다(스톨은 미관측).`,
          impact:
            "일부 파서만 특정 TE 표기를 청크로 해석하면 프론트/백엔드 조합에 따라 스머글링으로 발전할 수 있다. TE 헤더 값을 화이트리스트로 정규화하라.",
        },
      },
    };
  }
  return { stalls: stalls.length, anomalies, tolerated };
}
