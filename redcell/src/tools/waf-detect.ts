/**
 * waf_detect — 웹 방화벽(WAF) 탐지·핑거프린팅(정찰).
 *
 * 왜 중요한가: WAF 가 있으면 "평범한 페이로드"는 막힌다. WAF 존재/제조사를 알면
 * PayloadForge 가 인코딩/케이스/주석 삽입 같은 **우회 변형을 앞세우도록** 발산 방향이 바뀐다.
 * (fingerprint 에 `waf:<vendor>` 를 남기면 이후 툴들이 우회 변형을 생성한다.)
 *
 * 방법: 무해 기준요청 vs 공격처럼 보이는 요청을 비교. 후자만 차단(403/406/429/501)되거나
 * WAF 시그니처 헤더/본문이 보이면 WAF 로 판정. 취약점이 아니라 "맥락"이므로 info.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

/** 헤더/본문 시그니처 → 제조사. */
const VENDOR_SIGNS: Array<{ vendor: string; test: (h: Record<string, string>, body: string) => boolean }> = [
  { vendor: "cloudflare", test: (h) => "cf-ray" in h || /cloudflare/i.test(h["server"] ?? "") },
  { vendor: "sucuri", test: (h) => "x-sucuri-id" in h || "x-sucuri-cache" in h },
  { vendor: "akamai", test: (h) => /akamaighost/i.test(h["server"] ?? "") || "x-akamai-transformed" in h },
  { vendor: "imperva-incapsula", test: (h, b) => "x-iinfo" in h || /incap_ses|visid_incap/i.test(h["set-cookie"] ?? "") || /incapsula/i.test(b) },
  { vendor: "f5-big-ip", test: (h) => /big-?ip|f5/i.test(h["server"] ?? "") || /bigipserver/i.test(h["set-cookie"] ?? "") },
  { vendor: "aws-waf", test: (h) => "x-amzn-waf-action" in h || /awselb/i.test(h["set-cookie"] ?? "") },
  { vendor: "mod_security", test: (h, b) => /mod_security|modsecurity/i.test((h["server"] ?? "") + b) },
  { vendor: "fortinet-fortiweb", test: (h) => /fortiweb/i.test(h["server"] ?? "") || /fortiwafsid/i.test(h["set-cookie"] ?? "") },
];

const BLOCK_STATUS = new Set([403, 406, 429, 501, 999]);
/** 공격처럼 보이는 무해 트리거(실제 익스플로잇 아님 — 차단 반응 유도용). */
const TRIGGERS: Record<string, string> = { q: "<script>alert(1)</script>", id: "1' OR '1'='1", file: "../../../../etc/passwd" };
const BLOCK_BODY = /(request blocked|access denied|forbidden|not acceptable|attention required|web application firewall|blocked by|security policy)/i;

export const wafDetect: Tool = {
  name: "waf_detect",
  description:
    "무해 기준요청과 공격처럼 보이는 요청을 비교해 WAF 존재/제조사를 핑거프린팅한다. 이후 툴들이 우회 변형을 생성하도록 fp 에 waf 표식을 남긴다(info).",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const path = typeof args.path === "string" && args.path ? args.path : "/";
    try {
      const baseline = await authGet(ctx, joinPath(base, path));

      // 1) 헤더/본문 시그니처로 제조사 판정(요청이 막히지 않아도 드러날 수 있음).
      let vendor = detectVendor(baseline.headers, baseline.body);

      // 2) 공격성 요청에 대한 차단 반응 관찰.
      let blocked = false;
      for (const [param, val] of Object.entries(TRIGGERS)) {
        const res = await authGet(ctx, joinPath(base, withQuery(path, { [param]: val })));
        if (!vendor) vendor = detectVendor(res.headers, res.body);
        if ((BLOCK_STATUS.has(res.status) && !BLOCK_STATUS.has(baseline.status)) || BLOCK_BODY.test(res.body)) {
          blocked = true;
        }
      }

      if (!vendor && !blocked) {
        return { ok: true, summary: "WAF 흔적 없음(우회 없는 표준 페이로드로 진행 가능)", data: { severity: "info", title: "WAF 미탐지", evidence: "차단 반응/시그니처 없음" } };
      }
      const label = vendor ?? "generic";
      return {
        ok: true,
        summary: `WAF 탐지: ${label}${blocked ? " (공격성 요청 차단 관측)" : ""} — 이후 우회 변형 생성`,
        fingerprint: { indicators: [`waf:${label}`, ...(blocked ? ["waf-blocking"] : [])] },
        data: {
          severity: "info",
          title: `WAF 존재: ${label}`,
          evidence: `${blocked ? "공격 유사 요청이 차단됨. " : ""}이 맥락에 맞춰 인코딩/케이스/주석 우회 변형을 우선한다.`,
        },
      };
    } catch (e) {
      return { ok: false, summary: `waf_detect 실패: ${(e as Error).message}` };
    }
  },
};

function detectVendor(headers: Record<string, string>, body: string): string | null {
  for (const s of VENDOR_SIGNS) {
    try {
      if (s.test(headers, body)) return s.vendor;
    } catch {
      /* 시그니처 테스트 실패 무시 */
    }
  }
  return null;
}
