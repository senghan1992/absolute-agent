/**
 * dir_enum — 흔한 경로 열거(디렉터리/파일 탐색).
 *
 * 내장 소형 wordlist 로 200/301/302/403 응답을 찾아 숨겨진 엔드포인트를 발견한다.
 * RPS 를 준수하며, args.wordlist 로 목록을 덮어쓸 수 있다(대형 스캔은 운영자 책임).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, safeGet } from "./util.js";

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
        const res = await safeGet(joinPath(base, w), ctx.rps);
        if ([200, 301, 302, 401, 403].includes(res.status)) found.push({ path: `/${w}`, status: res.status });
      } catch {
        // 개별 실패는 무시하고 계속.
      }
    }

    const sensitive = found.filter((f) => SENSITIVE.test(f.path));
    const indicators = found.map((f) => `path ${f.path} (${f.status})`);
    const ok = found.length > 0;

    return {
      ok,
      summary: `열거 완료: ${found.length}개 발견${sensitive.length ? ` (민감 ${sensitive.length})` : ""}`,
      fingerprint: ok ? { indicators } : undefined,
      data: sensitive.length
        ? {
            severity: "medium",
            title: `민감 경로 노출 (${sensitive.map((s) => s.path).join(", ")})`,
            evidence: sensitive.map((s) => `${s.path} → ${s.status}`).join("; "),
          }
        : ok
          ? { severity: "info", title: `엔드포인트 ${found.length}개 발견`, evidence: indicators.join("; ") }
          : undefined,
    };
  },
};
