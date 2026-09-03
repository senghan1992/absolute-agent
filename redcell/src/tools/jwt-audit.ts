/**
 * jwt_audit — JWT(JSON Web Token) 취약 설정 분석(비파괴, 분석 전용).
 *
 * ctx.auth(인가된 세션/베어러)와 응답 Set-Cookie 에서 JWT 형태 토큰을 모아 정적 분석한다.
 *   - alg=none            → critical (서명 미검증 시 위조 가능)
 *   - 약한 HMAC 시크릿      → high (소형 사전으로 서명 재현 성공 = 토큰 위조 가능)
 *   - exp 없음/과도한 수명   → low  (탈취 토큰 장기 악용)
 *   - 민감 클레임 평문 노출   → low
 * 토큰을 위조해 서버로 재전송하지 않는다(로컬 분석만). 시크릿 추정은 소형 사전 오프라인 검증.
 */

import { createHmac } from "node:crypto";
import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g; // header.payload.sig (base64url)
/** 약한 시크릿 소형 사전(오프라인 HMAC 검증용). 흔한 개발/예제 값. */
const WEAK_SECRETS = ["secret", "password", "123456", "changeme", "jwt", "key", "admin", "test", "your-256-bit-secret", "supersecret"];

export const jwtAudit: Tool = {
  name: "jwt_audit",
  description:
    "인증 컨텍스트/Set-Cookie 의 JWT 를 정적 분석한다. alg=none(critical)·약한 HMAC 시크릿(high)·exp 누락(low)·민감 클레임 노출(low)을 보고한다(비파괴).",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const tokens = new Set<string>();
    // 1) 인가된 자격증명에 담긴 토큰.
    for (const v of Object.values(ctx.auth ?? {})) collect(v, tokens);
    // 2) 대상 페이지 Set-Cookie/본문에서 토큰 관찰.
    try {
      const path = typeof args.path === "string" && args.path ? args.path : "/";
      const res = await authGet(ctx, joinPath(baseUrl(ctx.target), path));
      collect(res.headers["set-cookie"] ?? "", tokens);
      collect(res.body, tokens);
    } catch {
      /* 페이지 관찰 실패는 무시(자격증명 토큰만으로도 분석 가능) */
    }

    if (tokens.size === 0) {
      return { ok: false, summary: "분석할 JWT 를 찾지 못함(credentials 또는 응답에 JWT 없음)" };
    }

    const findings: Array<{ severity: string; title: string; evidence: string }> = [];
    for (const tok of tokens) {
      const parsed = parseJwt(tok);
      if (!parsed) continue;
      const { header, payload } = parsed;
      const alg = String(header.alg ?? "").toLowerCase();

      if (alg === "none") {
        findings.push({ severity: "critical", title: "JWT alg=none (서명 미검증 위조 가능)", evidence: `header=${JSON.stringify(header)}` });
      } else if (alg.startsWith("hs")) {
        const weak = crackHs(tok, alg);
        if (weak) {
          findings.push({ severity: "high", title: "JWT 약한 HMAC 시크릿", evidence: `시크릿 '${weak}' 로 서명 재현 성공(${alg}) → 토큰 위조 가능` });
        }
      }
      if (payload.exp == null) {
        findings.push({ severity: "low", title: "JWT 만료(exp) 클레임 없음", evidence: "탈취 시 무기한 사용 가능" });
      } else if (typeof payload.exp === "number" && typeof payload.iat === "number" && payload.exp - payload.iat > 60 * 60 * 24 * 30) {
        findings.push({ severity: "low", title: "JWT 수명 과도(>30일)", evidence: `iat→exp ${Math.round((payload.exp - payload.iat) / 86400)}일` });
      }
      const sensitive = Object.keys(payload).filter((k) => /pass|secret|ssn|card|priv|role|admin/i.test(k));
      if (sensitive.length) {
        findings.push({ severity: "low", title: "JWT 페이로드 민감 클레임", evidence: `평문 클레임: ${sensitive.join(", ")}` });
      }
    }

    if (findings.length === 0) {
      return { ok: true, summary: `JWT ${tokens.size}개 분석 — 취약 설정 미발견` };
    }
    const order = ["critical", "high", "medium", "low", "info"];
    findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    const top = findings[0];
    return {
      ok: true,
      summary: `JWT 분석: ${findings.length}건 (최고 ${top.severity}) — ${top.title}`,
      fingerprint: { indicators: findings.map((f) => `jwt ${f.title}`) },
      data: { severity: top.severity, title: top.title, evidence: findings.map((f) => `[${f.severity}] ${f.title}: ${f.evidence}`).join(" | ") },
    };
  },
};

function collect(s: string, into: Set<string>): void {
  if (!s) return;
  const m = s.match(JWT_RE);
  if (m) for (const t of m) into.add(t);
}

function b64urlToJson(seg: string): Record<string, unknown> | null {
  try {
    const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(b64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function parseJwt(tok: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  const parts = tok.split(".");
  if (parts.length < 2) return null;
  const header = b64urlToJson(parts[0]);
  const payload = b64urlToJson(parts[1]);
  if (!header || !payload) return null;
  return { header, payload };
}

/** 소형 사전으로 HMAC 서명을 오프라인 재현해 약한 시크릿인지 확인. */
function crackHs(tok: string, alg: string): string | null {
  const bits = alg === "hs384" ? "sha384" : alg === "hs512" ? "sha512" : "sha256";
  const [h, p, sig] = tok.split(".");
  if (!sig) return null;
  const signingInput = `${h}.${p}`;
  for (const secret of WEAK_SECRETS) {
    const expected = createHmac(bits, secret).update(signingInput).digest("base64url");
    if (expected === sig) return secret;
  }
  return null;
}
