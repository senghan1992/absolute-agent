/**
 * upload_verify — 파일 업로드 저장 + 실행 가능성 실증. **opt-in** (상태변경 수반).
 *
 * multipart 업로드 폼(`<form enctype=multipart>` + `<input type=file>`)을 각 path 에서
 * 직접 파싱하고, 무해 파일 3종을 업로드한다:
 *   - rc-<rand>.txt  : 마커 텍스트 (저장 확인용)
 *   - rc-<rand>.svg  : `<script>RCUP<rand></script>` 포함 SVG (inline 렌더 실행 가능성)
 *   - rc-<rand>.php  : `<?php echo "RCUP<rand>"; ?>` — 실행돼야만 마커 출력
 *
 * 업로드 후 응답/후보 경로에서 저장 URL 을 추출해 재 fetch 한다.
 *   - 저장 + 실행 가능 컨텍스트(svg inline 또는 .php 마커 실행) → high
 *   - 저장만 확인                                              → medium
 * FP 방어: 업로드가 확장자/MIME 검증으로 거부되면(400/에러/마커 없음) 클린.
 * 저장 URL 미확보 시 "저장 확인 불가"로 종료(추측 경로 대량 요청 금지).
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, authPost, baseUrl, joinPath } from "./util.js";

const MAX_PATHS = 6;

export const uploadVerify: Tool = {
  name: "upload_verify",
  description:
    "multipart 업로드 폼에 무해 파일 3종(txt/svg/php)을 올려 저장 + 실행 가능성을 실증한다. 저장+실행 컨텍스트 high, 저장만 medium. 상태변경 수반 — opt-in 필요.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const rand = Math.random().toString(36).slice(2, 8);
    const marker = `RCUP${rand}`;

    const paths = pickPaths(args);
    for (const path of paths) {
      // 1) 업로드 폼 파싱(직접) — multipart + file input 만.
      let page;
      try {
        page = await authGet(ctx, joinPath(base, path), { cap: 8000 });
      } catch {
        continue;
      }
      const forms = parseMultipartForms(page.body, path);
      if (forms.length === 0) continue;

      const form = forms[0];
      const fileField = form.fileField;
      const uploadUrl = form.url;

      // 2) 무해 파일 3종 업로드 순차 — 저장 위치 회수 + 실행 신호 관찰.
      const files: Array<{ name: string; type: string; content: string }> = [
        { name: `rc-${rand}.txt`, type: "text/plain", content: `RCUP marker text ${marker}` },
        { name: `rc-${rand}.svg`, type: "image/svg+xml", content: `<svg xmlns="http://www.w3.org/2000/svg"><script>document.title='${marker}'</script></svg>` },
        { name: `rc-${rand}.php`, type: "application/x-php", content: `<?php echo "RCUP${rand}"; ?>` },
      ];

      let storedUrl: string | null = null;
      let executable = false;
      for (const f of files) {
        const boundary = `----rc${rand}`;
        const uploadBody = buildMultipart(boundary, form.fields, fileField, f);
        let res;
        try {
          res = await authPost(ctx, joinPath(base, uploadUrl), uploadBody, {
            contentType: `multipart/form-data; boundary=${boundary}`,
            cap: 8000,
          });
        } catch {
          continue;
        }
        if (res.status >= 400 || /(invalid|error|거부|reject|not allowed|type|extension)/i.test(res.body)) {
          if (res.body.includes(marker)) {
            // 업로드 자체가 거부된 건 아니고 마커가 보임 — 저장됐을 가능성.
            storedUrl = storedUrl ?? uploadUrl;
          }
          continue; // 확장자/MIME 검증 거부 → 클린
        }
        const echoed = res.body.includes(marker);
        const urlHint = extractStoredUrl(res.body, res.headers, rand);
        if (urlHint || echoed) storedUrl = storedUrl ?? urlHint ?? uploadUrl;
        if (f.name.endsWith(".svg") && urlHint) {
          // svg 저장 후 inline 렌더 확인(별도 fetch).
          const svg = await authGet(ctx, joinPath(base, urlHint), { cap: 4000 });
          if (svg.status === 200 && svg.body.includes(marker) && isInlineRendered(svg.headers)) executable = true;
        }
        if (f.name.endsWith(".php") && urlHint) {
          const php = await authGet(ctx, joinPath(base, urlHint), { cap: 4000 });
          if (php.status === 200 && php.body.includes(marker)) executable = true; // PHP 실행돼야 마커 출력
        }
      }

      if (!storedUrl) {
        return { ok: false, summary: `업로드 실증 없음: ${path} — 저장 URL 을 확인할 수 없음(업로드 거부 또는 응답에 힌트 없음)` };
      }
      const evidence = executable
        ? `업로드 실증: 파일 저장 + 실행 가능 컨텍스트 제공 (url=${storedUrl}) — ${marker}`
        : `업로드 실증: 파일 저장 확인 (url=${storedUrl}) — ${marker}`;
      return {
        ok: true,
        summary: `업로드 ${executable ? "저장+실행" : "저장"} 실증: ${path} → ${storedUrl}`,
        fingerprint: { indicators: [`upload-verified ${storedUrl}`] },
        data: {
          severity: executable ? "high" : "medium",
          title: `제한 없는 파일 업로드 (path=${path})`,
          evidence,
          url: storedUrl,
          executable,
        },
      };
    }
    return { ok: false, summary: `업로드 실증 미탐지 (대상 ${paths.join(",")})` };
  },
};

interface UploadForm {
  url: string;
  fileField: string;
  /** 파일 외 폼 필드(name→value). */
  fields: Array<{ name: string; value?: string }>;
}

function parseMultipartForms(html: string, fallbackPath: string): UploadForm[] {
  const out: UploadForm[] = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  for (const fm of html.matchAll(formRe)) {
    const tag = fm[1] ?? "";
    if (!/enctype\s*=\s*["']?multipart\/form-data/i.test(tag)) continue;
    const inner = fm[2] ?? "";
    const fileInputs = [...inner.matchAll(/<input\b[^>]*type\s*=\s*["']?file["']?[^>]*>/gi)];
    if (fileInputs.length === 0) continue;
    const fileField = (fileInputs[0][0].match(/\bname\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1] ?? "file";
    const action = (tag.match(/\baction\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1] ?? fallbackPath;
    const fields: Array<{ name: string; value?: string }> = [];
    for (const inp of inner.matchAll(/<(?:input|textarea|select)\b[^>]*>/gi)) {
      const nm = (inp[0].match(/\bname\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1];
      if (!nm || nm === fileField) continue;
      const type = ((inp[0].match(/\btype\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1] ?? "text").toLowerCase();
      if (type === "submit" || type === "button") continue;
      const val = (inp[0].match(/\bvalue\s*=\s*["']?([^"'\s>]*)/i) ?? [])[1] ?? "";
      fields.push({ name: nm, value: val });
    }
    const url = action.startsWith("http") ? action : action.startsWith("/") ? action : fallbackPath;
    out.push({ url, fileField, fields });
  }
  return out;
}

function buildMultipart(boundary: string, fields: Array<{ name: string; value?: string }>, fileField: string, file: { name: string; type: string; content: string }): string {
  const parts: string[] = [];
  for (const f of fields) {
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${f.name}"\r\n\r\n${f.value ?? ""}\r\n`);
  }
  parts.push(
    `--${boundary}\r\nContent-Disposition: form-data; name="${fileField}"; filename="${file.name}"\r\n` +
      `Content-Type: ${file.type}\r\n\r\n${file.content}\r\n`,
  );
  parts.push(`--${boundary}--\r\n`);
  return parts.join("");
}

/** 응답/헤더에서 저장 URL 을 추출 — 경로 힌트만(추측 경로 대량 요청 금지). */
function extractStoredUrl(body: string, headers: Record<string, string>, rand: string): string | null {
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = String(v);
  if (h["location"]) {
    const loc = h["location"];
    if (loc.includes("upload") || loc.includes("file") || loc.includes(rand)) return loc;
  }
  const m = body.match(/["'](\/[^"']*(?:uploads?|files?|media|images?|storage)[^"']*)["']/i);
  return m?.[1] ?? null;
}

/** svg 를 inline(html 로) 렌더하는 응답만 실행 가능으로 본다. */
function isInlineRendered(headers: Record<string, string>): boolean {
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = String(v);
  const cd = h["content-disposition"] ?? "";
  return /inline/i.test(cd) && !/attachment/i.test(cd);
}

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return ["/"];
}