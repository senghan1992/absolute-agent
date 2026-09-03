/**
 * access_control_probe — 접근통제 미흡(Broken Access Control / 강제 브라우징) 탐지.
 *
 * 관리자/내부 전용으로 보이는 경로를 **인증 없이** 요청해, 로그인/403 으로 막히지 않고
 * 특권 콘텐츠(관리 패널·사용자 목록·설정·액추에이터 등)가 그대로 제공되는지 본다.
 * dir_enum 이 "존재"를 찾는다면, 이 툴은 "특권 기능이 무인증으로 노출됨"을 판정한다.
 *   - 특권 경로가 200 + 특권 콘텐츠 시그니처 → high (인증/인가 우회)
 * 읽기 전용 GET 만 사용한다(상태변경 없음).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { safeGet, baseUrl, joinPath } from "./util.js";

const PRIV_PATHS = [
  "/admin",
  "/admin/users",
  "/admin/dashboard",
  "/api/admin",
  "/api/admin/users",
  "/manage",
  "/management",
  "/internal",
  "/actuator",
  "/actuator/env",
  "/console",
  "/dashboard",
];
const MAX_PATHS = 12;

/**
 * 강한 신호 — 로그인 페이지에는 절대 없는 "실제 특권 데이터/기능"의 노출.
 * 이게 있으면 페이지에 로그인 문구가 섞여 있어도 데이터가 새어 나온 것으로 본다.
 */
const STRONG_SIGNALS = [
  /"(users|accounts)"\s*:\s*\[/i, // 실제 사용자/계정 데이터 배열(JSON)
  /"activeProfiles"|management\.endpoint|"propertySources"/i, // spring actuator 덤프
  /\brole\b\s*[:=]\s*["']?admin/i, // 데이터 내 role=admin
  /delete\s*user|ban\s*user|권한\s*변경/i, // 관리 액션 버튼/링크
];
/**
 * 약한 신호 — 관리 UI 헤딩 문구. 로그인 스플래시 제목("Admin Dashboard")과 구별이 안 되므로,
 * 로그인 폼이 함께 있으면 노출로 세지 않는다(오탐 방지).
 */
const WEAK_SIGNALS = [
  /admin\s*(panel|dashboard|console)/i,
  /user\s*management|manage\s*users|사용자\s*관리/i,
];
/** 로그인 벽(막혔음)의 신호. */
const AUTH_WALL = /(sign|log)\s*in|login|authenticate|unauthorized|forbidden|로그인|인증\s*필요/i;
/** 실제 로그인 폼(비밀번호 입력/로그인 액션) — 이게 있으면 "특권 UI 헤딩"은 로그인 스플래시로 본다. */
const LOGIN_FORM = /<input[^>]+type=["']?password|name=["']?password|<form[^>]*\b(login|signin|auth)/i;

export const accessControlProbe: Tool = {
  name: "access_control_probe",
  description:
    "관리자/내부 전용 경로를 무인증으로 요청해 특권 콘텐츠가 그대로 노출되는지(접근통제 우회) 판정한다. 200+특권 시그니처면 high. 읽기 전용.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const hits: Array<{ path: string; sig: string }> = [];

    for (const path of paths) {
      const url = joinPath(base, path);
      try {
        // 인증 우회를 보려면 "진짜 익명" 으로 요청해야 한다. authGet 은 headers 를 비워도
        // ctx.jar(로그인 세션 쿠키)가 http-client 에서 자동 재전송되어 사실상 인증 상태가 된다.
        // 따라서 auth 헤더도 세션 jar 도 싣지 않는 safeGet 을 직접 쓴다(프록시만 유지 — Burp/ZAP 관찰).
        const res = await safeGet(url, ctx.rps, { proxy: ctx.proxy, cap: 6000 });
        // 로그인으로 리다이렉트되거나 401/403 이면 통제가 동작 중.
        if (res.status === 401 || res.status === 403) continue;
        if (res.status >= 300 && res.status < 400) {
          const loc = res.headers["location"] ?? "";
          if (/login|signin|auth/i.test(loc)) continue; // 로그인으로 유도 = 막힘
        }
        if (res.status !== 200) continue;
        const body = res.body;
        // 로그인 스플래시/벽인가? (로그인 폼 존재 또는 인증 요구 문구)
        const isLoginWall = LOGIN_FORM.test(body) || AUTH_WALL.test(body);
        // 강한 신호: 실제 특권 데이터/기능 노출 → 로그인 문구가 섞여 있어도 유출로 확정.
        const strong = STRONG_SIGNALS.find((re) => re.test(body));
        if (strong) {
          hits.push({ path, sig: strong.source });
          continue;
        }
        // 약한 신호(관리 UI 헤딩): 로그인 벽이 아닐 때만 노출로 본다(로그인 스플래시 오탐 배제).
        const weak = WEAK_SIGNALS.find((re) => re.test(body));
        if (weak && !isLoginWall) {
          hits.push({ path, sig: weak.source });
        }
      } catch {
        /* 무시 */
      }
    }

    if (hits.length > 0) {
      const h = hits[0];
      return {
        ok: true,
        summary: `접근통제 우회: 무인증으로 특권 경로 ${hits.map((x) => x.path).join(", ")} 노출`,
        fingerprint: { indicators: hits.map((x) => `broken-access-control ${x.path}`) },
        data: {
          severity: "high",
          title: `Broken Access Control (${h.path})`,
          evidence: `무인증 GET ${h.path} 가 200 + 특권 콘텐츠 시그니처(/${h.sig}/) 반환`,
          paths: hits.map((x) => x.path),
          impact:
            "인증/인가 없이 관리 기능·전체 사용자 데이터에 도달 → 대량 개인정보 열람, 권한 변경·계정 조작으로 서비스 전면 장악 가능.",
        },
      };
    }
    return { ok: false, summary: `무인증 특권 노출 미탐지 (paths=${paths.length}개 점검)` };
  },
};

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return PRIV_PATHS.slice(0, MAX_PATHS);
}
