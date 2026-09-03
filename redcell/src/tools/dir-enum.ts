/**
 * dir_enum — 흔한 경로 열거(디렉터리/파일 탐색).
 *
 * 내장 소형 wordlist 로 200/301/302/403 응답을 찾아 숨겨진 엔드포인트를 발견한다.
 * RPS 를 준수하며, args.wordlist 로 목록을 덮어쓸 수 있다(대형 스캔은 운영자 책임).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, authGet } from "./util.js";

const DEFAULT_WORDLIST = [
  "admin",
  "login",
  "administrator",
  "robots.txt",
  ".git/HEAD",
  "backup",
  "config",
  "api",
  "phpinfo.php",
  "wp-admin",
  "server-status",
  "uploads",
  ".env",
];

const SENSITIVE = /(admin|\.git|\.env|backup|config|phpinfo|server-status)/i;

export const dirEnum: Tool = {
  name: "dir_enum",
  description: "흔한 경로 wordlist 로 숨겨진 엔드포인트를 열거한다(비파괴, RPS 준수).",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const words = Array.isArray(args.wordlist) ? (args.wordlist as string[]) : DEFAULT_WORDLIST;
    const found: Array<{ path: string; status: number }> = [];

    for (const w of words) {
      try {
        const res = await authGet(ctx, joinPath(base, w));
        if ([200, 301, 302, 401, 403].includes(res.status)) found.push({ path: `/${w}`, status: res.status });
      } catch {
        // 개별 실패는 무시하고 계속.
      }
    }

    const sensitive = found.filter((f) => SENSITIVE.test(f.path));
    // 상태코드로 "실제 노출"과 "존재하나 접근통제됨"을 구분한다(오탐 방지의 핵심).
    //   - 200            → 콘텐츠가 실제로 서빙됨 = 노출(medium)
    //   - 401/403        → 경로는 있으나 인증/권한으로 차단됨 = 노출 아님(info)
    //   - 301/302        → 리다이렉트(대개 로그인) = 노출 아님(info)
    const exposed = sensitive.filter((f) => f.status === 200);
    const controlled = sensitive.filter((f) => f.status !== 200);
    const indicators = found.map((f) => `path ${f.path} (${f.status})`);
    const ok = found.length > 0;

    let data: ToolResult["data"];
    if (exposed.length) {
      data = {
        severity: "medium",
        title: `민감 경로 노출 (${exposed.map((s) => s.path).join(", ")})`,
        evidence: exposed.map((s) => `${s.path} → ${s.status}`).join("; "),
      };
    } else if (controlled.length) {
      // 민감 경로가 존재하나 접근통제됨: 경로 열거/존재 확인은 정보 가치가 있으나 취약점 아님.
      data = {
        severity: "info",
        title: `민감 경로 존재(접근통제됨) (${controlled.map((s) => s.path).join(", ")})`,
        evidence: controlled.map((s) => `${s.path} → ${s.status} (인증/권한으로 차단)`).join("; "),
      };
    } else if (ok) {
      data = { severity: "info", title: `엔드포인트 ${found.length}개 발견`, evidence: indicators.join("; ") };
    }

    const sensitiveNote = exposed.length
      ? ` (노출 ${exposed.length})`
      : controlled.length
        ? ` (민감 ${controlled.length}, 접근통제됨)`
        : "";
    return {
      ok,
      summary: `열거 완료: ${found.length}개 발견${sensitiveNote}`,
      fingerprint: ok ? { indicators } : undefined,
      data,
    };
  },
};
