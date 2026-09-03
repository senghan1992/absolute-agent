/**
 * upload_probe — 파일 업로드 표면 식별(비파괴, 관측 전용).
 *
 * 페이지에서 파일 업로드 폼(<input type=file>)을 찾아, 클라이언트측 확장자/MIME 제한이
 * 있는지 관측한다. **실제 파일을 업로드하지 않는다** — 위험 표면과 수동 점검 포인트만 표시.
 *   - accept 제한 없는 업로드 폼 → low (서버측 검증 부재 시 위험, 수동 확인 필요)
 *   - 업로드 폼 존재 자체        → info (공격 표면)
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "./util.js";

const FILE_INPUT_RE = /<input\b[^>]*type\s*=\s*["']?file["']?[^>]*>/gi;
const FORM_RE = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;

export const uploadProbe: Tool = {
  name: "upload_probe",
  description:
    "파일 업로드 폼(input type=file)을 찾아 클라이언트측 확장자 제한 유무를 관측한다. accept 제한 없으면 low, 폼 존재는 info. 실제 업로드는 하지 않는다(비파괴).",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const path = typeof args.path === "string" && args.path ? args.path : "/";
    try {
      const res = await authGet(ctx, joinPath(baseUrl(ctx.target), path));
      const body = res.body;
      const forms: Array<{ action: string; accept: string | null; multipart: boolean }> = [];

      for (const fm of body.matchAll(FORM_RE)) {
        const tag = fm[0].slice(0, fm[0].indexOf(">") + 1);
        const inner = fm[1] ?? "";
        const fileInputs = [...inner.matchAll(FILE_INPUT_RE)];
        if (fileInputs.length === 0) continue;
        const action = (tag.match(/action\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1] ?? path;
        const multipart = /enctype\s*=\s*["']?multipart\/form-data/i.test(tag);
        const accept = (fileInputs[0][0].match(/accept\s*=\s*["']?([^"'>]+)/i) ?? [])[1] ?? null;
        forms.push({ action, accept, multipart });
      }

      if (forms.length === 0) {
        return { ok: false, summary: `파일 업로드 폼 없음 (path=${path})` };
      }
      const unrestricted = forms.filter((f) => !f.accept);
      if (unrestricted.length) {
        return {
          ok: true,
          summary: `업로드 표면: ${forms.length}개 폼(확장자 제한 없음 ${unrestricted.length}) — 서버측 검증 수동 확인 권고`,
          fingerprint: { indicators: forms.map((f) => `upload ${f.action}`) },
          data: {
            severity: "low",
            title: `파일 업로드 폼(클라이언트 제한 없음) ${unrestricted.length}개`,
            evidence: `action: ${unrestricted.map((f) => f.action).slice(0, 5).join(", ")} — 위험 확장자/폴리글랏 서버측 차단 여부 수동 점검`,
          },
        };
      }
      return {
        ok: true,
        summary: `업로드 표면: ${forms.length}개 폼(accept 제한 존재)`,
        fingerprint: { indicators: forms.map((f) => `upload ${f.action}`) },
        data: { severity: "info", title: `파일 업로드 폼 ${forms.length}개`, evidence: `accept 제한 존재하나 서버측 검증은 별도 확인 필요` },
      };
    } catch (e) {
      return { ok: false, summary: `upload_probe 실패: ${(e as Error).message}` };
    }
  },
};
