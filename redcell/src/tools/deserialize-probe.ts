/**
 * deserialize_probe — 안전하지 않은 역직렬화(Insecure Deserialization) 시그니처 탐지(비파괴).
 *
 * 역직렬화 취약점은 "터뜨리는" 순간(gadget chain 실행) 서버에서 RCE 로 이어지므로
 * **실제 페이로드를 던지지 않는다**. 대신 클라이언트가 제어하는 위치(쿠키·파라미터·숨은 폼
 * 필드)에 **직렬화된 객체 blob 이 오가는지**를 시그니처로 관찰한다. 그 자리가 그대로
 * 서버로 돌아가 역직렬화된다면 gadget 만 있으면 RCE 이므로, 클라이언트 제어 위치의
 * 직렬화 blob 은 high(잠재 RCE)로 본다. 응답 본문에서만 보이면 정보노출(low)로 낮춘다.
 *
 * 탐지 시그니처(대표적 포맷):
 *   - Java:   raw `\xac\xed\x00\x05` / base64 `rO0AB`
 *   - PHP:    `O:<len>:"Class":` / `a:<n>:{`
 *   - Python pickle(base64 protocol 2/4): `gAJ`/`gAR`/`gASV` (…\x80\x02 / \x80\x04)
 *   - Ruby Marshal(base64): `BAh`  (\x04\x08)
 *   - .NET ViewState: `__VIEWSTATE` 필드(+ base64) — MAC 미보호면 위험(low~medium)
 * 읽기 전용 GET 만 사용한다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

interface Sig {
  name: string;
  /** base64/문자 표기에서 찾는 정규식(값 앞부분 매칭). */
  re: RegExp;
}

const SIGS: Sig[] = [
  { name: "Java 직렬화", re: /(?:^|[^A-Za-z0-9+/])rO0AB[A-Za-z0-9+/]/ }, // base64(0xACED0005)
  { name: "Java 직렬화(raw)", re: /\xac\xed\x00\x05/ },
  { name: "PHP 직렬화", re: /\bO:\d+:"[^"]+":\d+:\{/ },
  { name: "PHP 직렬화(배열)", re: /\ba:\d+:\{[si]:\d+/ },
  { name: "Python pickle", re: /(?:^|[^A-Za-z0-9+/])gAS[HJVN][A-Za-z0-9+/]|(?:^|[^A-Za-z0-9+/])gAJ[A-Za-z0-9+/]/ },
  { name: "Ruby Marshal", re: /(?:^|[^A-Za-z0-9+/])BAh[A-Za-z0-9+/]{6,}/ },
];

/** 클라이언트 제어 위치에서 나온 값에 직렬화 시그니처가 있으면 그 포맷 이름을 반환. */
function detectSig(value: string): string | null {
  for (const s of SIGS) {
    if (s.re.test(value)) return s.name;
  }
  return null;
}

const DEFAULT_PATHS = ["/"];
const MAX_PATHS = 8;

export const deserializeProbe: Tool = {
  name: "deserialize_probe",
  description:
    "쿠키/파라미터/숨은 폼 필드/응답에서 직렬화 객체 blob(Java rO0/PHP O:/pickle/Ruby Marshal/.NET ViewState)을 탐지한다. 클라이언트 제어 위치면 잠재 RCE(high). 비파괴·읽기 전용.",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    let leak: { where: string; sig: string; sample: string } | null = null;

    for (const path of paths) {
      const url = joinPath(base, path);
      let res;
      try {
        res = await authGet(ctx, url, { cap: 12000 });
      } catch {
        continue;
      }

      // 1) 클라이언트 제어 위치: Set-Cookie 값(다음 요청에 그대로 돌아감).
      const setCookie = res.headers["set-cookie"] ?? "";
      for (const cookie of splitCookies(setCookie)) {
        const val = cookieValue(cookie);
        const sig = detectSig(val);
        if (sig) {
          return clientControlledFinding(sig, `${path} 의 Set-Cookie(${cookieName(cookie)})`, snippet(val), ctx, url);
        }
      }

      // 2) 클라이언트 제어 위치: 숨은 폼 필드/ViewState.
      for (const hf of hiddenFields(res.body)) {
        const sig = detectSig(hf.value);
        if (sig) {
          return clientControlledFinding(sig, `${path} 의 숨은 폼 필드(${hf.name})`, snippet(hf.value), ctx, url);
        }
        if (/^__VIEWSTATE$/i.test(hf.name) && hf.value.length > 40) {
          // ViewState 자체는 정상 기능이지만, MAC 미보호(암호화 안 됨) 시 역직렬화 표면.
          const macOff = !hiddenFields(res.body).some((f) => /__VIEWSTATEGENERATOR|__EVENTVALIDATION/i.test(f.name));
          return {
            ok: true,
            summary: `ASP.NET ViewState 노출 (${path}) — ${macOff ? "무결성 토큰 부재 의심" : "MAC 보호 여부 수동 확인 필요"}`,
            fingerprint: { indicators: [`viewstate ${path}`] },
            data: {
              severity: macOff ? "medium" : "low",
              title: `ASP.NET ViewState 역직렬화 표면 (${path})`,
              evidence: `__VIEWSTATE(${hf.value.length}B)${macOff ? ", __VIEWSTATEGENERATOR/__EVENTVALIDATION 부재(EnableViewStateMac 확인 필요)" : ""}`,
              impact:
                "ViewState 가 MAC 로 보호되지 않으면 조작된 직렬화 페이로드를 주입해 서버측 역직렬화 RCE(예: TypeConfuseDelegate)로 확대될 수 있다. EnableViewStateMac 강제·머신키 회전 필요.",
            },
          };
        }
      }

      // 3) 응답 본문에만 보이는 blob — 정보노출 신호로 기억(더 강한 신호 없으면 마지막에 보고).
      if (!leak) {
        const bodySig = detectSig(res.body);
        if (bodySig) leak = { where: `${path} 응답 본문`, sig: bodySig, sample: snippet(firstMatch(res.body)) };
      }
    }

    if (leak) {
      return {
        ok: true,
        summary: `직렬화 객체 노출: ${leak.sig} blob 이 ${leak.where}에 노출`,
        fingerprint: { indicators: [`serialized-blob ${leak.sig}`] },
        data: {
          severity: "low",
          title: `직렬화 객체 노출 (${leak.sig})`,
          evidence: `${leak.where}: ${leak.sample}`,
          impact:
            "직렬화 blob 이 노출되면 내부 클래스/구조가 드러나고, 같은 값이 서버로 역직렬화되어 돌아가는 경로가 있으면 gadget chain 을 통한 RCE 표면이 된다. 클라이언트 왕복 여부를 수동 확인하라.",
        },
      };
    }
    return { ok: false, summary: `역직렬화 시그니처 미탐지 (paths=${paths.join(",")})` };
  },
};

/** 클라이언트가 제어하는 위치(쿠키/폼 필드)에서 직렬화 blob 발견 → 잠재 RCE(high). */
function clientControlledFinding(sig: string, where: string, sample: string, _ctx: ToolContext, _url: string): ToolResult {
  return {
    ok: true,
    summary: `클라이언트 제어 위치에 직렬화 blob: ${sig} (${where})`,
    fingerprint: { indicators: [`deserialization ${sig}`] },
    data: {
      severity: "high",
      title: `안전하지 않은 역직렬화 표면 (${sig})`,
      evidence: `${where} 에 ${sig} blob: ${sample} — 클라이언트가 값을 제어하므로 서버 역직렬화 시 조작 가능`,
      impact:
        "클라이언트가 제어하는 직렬화 객체가 서버에서 역직렬화되면, 알려진 gadget chain(ysoserial 등)으로 원격코드실행(RCE)·서버 장악이 가능하다. 역직렬화 대상에 서명/무결성 검증을 강제하고, 신뢰 불가 입력의 역직렬화를 금지하라.",
    },
  };
}

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS;
}

/** "set-cookie" 헤더는 여러 쿠키가 개행 또는 ", " 로 합쳐질 수 있다. */
function splitCookies(raw: string): string[] {
  if (!raw) return [];
  return raw.split(/\n|,(?=\s*[A-Za-z0-9_-]+=)/).map((s) => s.trim()).filter(Boolean);
}
function cookieValue(cookie: string): string {
  const eq = cookie.indexOf("=");
  const semi = cookie.indexOf(";");
  const end = semi < 0 ? cookie.length : semi;
  return eq < 0 ? "" : decodeURIComponent(cookie.slice(eq + 1, end));
}
function cookieName(cookie: string): string {
  const eq = cookie.indexOf("=");
  return eq < 0 ? cookie : cookie.slice(0, eq);
}

/** <input type=hidden name=.. value=..> 추출(간이 파서). */
function hiddenFields(body: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  const re = /<input\b[^>]*\btype=["']?hidden["']?[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) && out.length < 40) {
    const tag = m[0];
    const name = /\bname=["']?([^"'\s>]+)/i.exec(tag)?.[1] ?? "";
    const value = /\bvalue=["']?([^"'>]*)/i.exec(tag)?.[1] ?? "";
    if (name) out.push({ name, value });
  }
  return out;
}

function firstMatch(body: string): string {
  for (const s of SIGS) {
    const m = s.re.exec(body);
    if (m) return body.slice(Math.max(0, m.index), m.index + 60);
  }
  return body.slice(0, 60);
}
function snippet(s: string): string {
  return s.slice(0, 60).replace(/\s+/g, " ");
}
