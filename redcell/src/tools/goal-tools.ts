/**
 * goal-tools — 목표 지향 태스크용 툴 3종.
 *
 * 취약점 스캔이 아니라 "X 목록을 파일로 뽑아줘" 같은 **작업형 목표**를 수행하기 위한 툴이다.
 * prime-agent(pi)가 하던 "읽기 → 추적 → 저장"을 redcell 엔진이 네이티브로 할 수 있게 한다.
 *
 *   - fetch_page    : 페이지를 읽어 본문 텍스트·링크·파일 링크·폼을 추출(정보 수집의 핵심)
 *   - download_file : 문서/첨부를 바이너리 그대로 산출물 디렉터리에 저장
 *   - write_output  : 추출한 목록/정리본을 파일로 저장(최종 산출물)
 *
 * 안전: 모든 네트워크 액션은 기존 툴과 동일하게 ToolContext 의 RPS·auth·validateIp 를
 * 그대로 타고, 파일 쓰기는 ctx.resultsDir 아래로만 제한된다(경로 조작 차단).
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { httpRequest } from "../net/http-client.js";
import { baseUrl, joinPath } from "./util.js";

const TEXT_CAP = 12000; // 본문 텍스트 캡(모델 컨텍스트 과다 방지)
const MAX_DOWNLOAD_BYTES = 24 * 1024 * 1024; // 24MB(바이트) — 첨부 다운로드 상한
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024; // 2MB — write_output 상한
const FILE_RE = /\.(pdf|hwp|xlsx?|docx?|pptx?|csv|zip|tar\.gz|7z|txt|json|xml|log)(\?[^"'\s]*)?$/i;

/** HTML → 읽기 가능한 텍스트(태그·스크립트 제거, 공백 정리). */
function toText(html: string): string {
  let s = html
    .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, " ");
  // 구조 태그는 줄바꿈으로 바꿔 표/목록 형태를 보존한다.
  s = s.replace(/<\/(tr|p|div|li|h[1-6]|table|section|article)>/gi, "\n");
  s = s.replace(/<\/t[dh]>/gi, " | ");
  s = s.replace(/<br\s*\/?>/gi, "\n");
  s = s.replace(/<[^>]+>/g, " ");
  // 엔티티 최소 디코드
  s = s.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  // 공백 정리(줄 단위)
  s = s
    .split("\n")
    .map((l) => l.replace(/[ \t]+/g, " ").trim())
    .filter((l) => l.length > 0)
    .join("\n");
  return s;
}

/** href/src 링크 추출(같은 오리진만, 앵커 텍스트 포함). */
function extractLinks(html: string, base: string): { links: string[]; files: string[] } {
  const links: string[] = [];
  const files: string[] = [];
  const re = /(?:href|src)\s*=\s*["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  const host = new URL(base).host;
  while ((m = re.exec(html))) {
    let u: URL;
    try {
      u = new URL(m[1], base);
    } catch {
      continue;
    }
    if (u.host !== host) continue; // 오리진 밖 링크는 따르지 않는다(scope 안전)
    const p = u.pathname + (u.search || "");
    if (/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf)(\?|$)/i.test(p)) continue; // 정적 리소스 제외
    if (FILE_RE.test(u.pathname)) files.push(p);
    else links.push(p);
  }
  return { links: [...new Set(links)].slice(0, 40), files: [...new Set(files)].slice(0, 20) };
}

/** 결과 디렉터리 확보 + 안전 파일명 검증(경로 조작 차단). */
async function safeOutPath(ctx: ToolContext, filename: string): Promise<string | null> {
  if (!ctx.resultsDir) return null;
  const name = filename.replace(/[\\/\0]/g, "_").replace(/^\.+/, "_").slice(0, 120);
  if (!name) return null;
  await fs.mkdir(ctx.resultsDir, { recursive: true });
  const full = path.resolve(ctx.resultsDir, name);
  // resolve 결과가 반드시 resultsDir 아래여야 한다.
  if (!full.startsWith(path.resolve(ctx.resultsDir) + path.sep)) return null;
  return full;
}

/** fetch_page — 페이지 본문 텍스트·링크·파일 링크·폼을 추출한다(목표 탐색의 눈). */
export const fetchPage: Tool = {
  name: "fetch_page",
  description:
    "인가된 대상의 페이지를 GET 해서 읽기 가능한 본문 텍스트·같은 오리진 링크 목록·첨부 파일 링크·폼을 추출한다(읽기 전용). 목표에 필요한 정보(목록/공지/다운로드 페이지)를 찾을 때 쓴다. args: path(기본 '/').",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const p = typeof args.path === "string" && args.path ? args.path : "/";
    const url = joinPath(base, p);
    let res;
    try {
      res = await httpRequest(url, {
        headers: { ...(ctx.auth ?? {}) },
        cap: 400_000, // 바이트 근사 cap*4 → 본문 상한(페이지 전체를 보되 무제한은 아님)
        redirect: "follow",
        proxy: ctx.proxy,
        jar: ctx.jar,
        validateIp: ctx.validateIp,
        scopeCheck: () => true, // 오케스트레이터가 대상 자체를 게이트 — 내부 링크 추종만 허용
        timeoutMs: 10000,
        retries: 1,
      });
    } catch (e) {
      return { ok: false, summary: `페이지 접근 실패: ${(e as Error).message}` };
    }
    if (res.status >= 400) return { ok: false, summary: `HTTP ${res.status} — 페이지를 가져오지 못했다 (${p})` };
    const ct = res.headers["content-type"] ?? "";
    if (!/text|html|json|xml/i.test(ct)) {
      return { ok: false, summary: `비-텍스트 응답(${ct}) — download_file 로 받는 것이 맞다 (${p})` };
    }
    const text = toText(res.body).slice(0, TEXT_CAP);
    const { links, files } = extractLinks(res.body, url);
    const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(res.body)?.[1]?.trim() ?? "";
    const forms = [...res.body.matchAll(/<form\b[^>]*action\s*=\s*["']([^"']*)["'][^>]*>/gi)].map((m) => m[1]).slice(0, 8);

    const summary = `${p} 읽음 — 제목: ${title || "(없음)"} · 본문 ${text.length}자 · 링크 ${links.length} · 파일 링크 ${files.length}`;
    return {
      ok: true,
      summary,
      fingerprint: { indicators: [`endpoint ${p}`] },
      data: {
        severity: "info",
        title: `페이지 수집: ${p}`,
        evidence: [
          `title: ${title}`,
          `text:\n${text.slice(0, 3000)}${text.length > 3000 ? "\n…(이하 생략)" : ""}`,
          `links: ${links.slice(0, 25).join(", ")}`,
          files.length ? `file_links: ${files.join(", ")}` : "",
          forms.length ? `forms: ${forms.join(", ")}` : "",
        ].filter(Boolean).join("\n"),
        // 모델이 다음 수를 정하는 데 쓰는 구조화 결과.
        text, links, files, forms, pageTitle: title,
      },
    };
  },
};

/** download_file — 문서/첨부를 바이너리 그대로 산출물 디렉터리에 저장한다. */
export const downloadFile: Tool = {
  name: "download_file",
  description:
    "인가된 대상의 파일(PDF/엑셀/HWP/CSV/ZIP 등)을 바이너리 그대로 산출물 디렉터리에 저장한다. fetch_page 의 files 목록에 있는 것을 내려받을 때 쓴다. args: url(절대 URL 또는 대상 경로), filename(선택). 저장 경로를 돌려준다.",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    if (!ctx.resultsDir) return { ok: false, summary: "산출물 디렉터리가 없습니다(resultsDir 미지정)" };
    const base = baseUrl(ctx.target);
    const raw = String(args.url ?? args.path ?? "");
    if (!raw) return { ok: false, summary: "url 인자가 필요합니다" };
    const url = raw.startsWith("http") ? raw : joinPath(base, raw);
    // 오리진 제한 — 같은 대상으로만(외부 다운로드는 scope 밖 유출 위험).
    try {
      const u = new URL(url);
      if (u.host !== new URL(base).host) {
        return { ok: false, summary: `오리진 밖 다운로드 차단: ${u.host} ≠ ${new URL(base).host}` };
      }
    } catch {
      return { ok: false, summary: "잘못된 URL" };
    }

    let res;
    try {
      res = await httpRequest(url, {
        headers: { ...(ctx.auth ?? {}) },
        cap: MAX_DOWNLOAD_BYTES / 4, // send() 의 cap*4 ≈ 바이트 상한
        binary: true, // 원본 바이트 보존(base64)
        redirect: "follow",
        proxy: ctx.proxy,
        jar: ctx.jar,
        validateIp: ctx.validateIp,
        scopeCheck: () => true,
        timeoutMs: 30000,
        retries: 1,
      });
    } catch (e) {
      return { ok: false, summary: `다운로드 실패: ${(e as Error).message}` };
    }
    if (res.status >= 400) return { ok: false, summary: `HTTP ${res.status} — 다운로드 실패 (${url})` };

    const bytes = Buffer.from(res.body, "base64");
    if (bytes.length === 0) return { ok: false, summary: "빈 파일(0바이트)" };
    const nameFromUrl = decodeURIComponent(new URL(url).pathname.split("/").pop() ?? "file") || "file";
    const fname = typeof args.filename === "string" && args.filename ? args.filename : nameFromUrl;
    const out = await safeOutPath(ctx, fname);
    if (!out) return { ok: false, summary: "안전하지 않은 파일명 — 저장 거부" };
    await fs.writeFile(out, bytes);

    const ct = res.headers["content-type"] ?? "";
    return {
      ok: true,
      summary: `파일 저장: ${out} (${(bytes.length / 1024).toFixed(1)}KB, ${ct})`,
      fingerprint: { indicators: [`download ${url}`] },
      data: {
        severity: "info",
        title: `파일 다운로드: ${fname}`,
        evidence: `${url} → ${out} (${bytes.length} bytes, ${ct})`,
        savedPath: out, bytes: bytes.length,
      },
    };
  },
};

/** write_output — 추출·정리한 결과물을 파일로 저장한다(최종 산출물). */
export const writeOutput: Tool = {
  name: "write_output",
  description:
    "추출한 목록/정리 결과를 산출물 디렉터리에 파일로 저장한다(csv/txt/md/json). 목표의 최종 결과물을 만들 때 쓴다. args: filename, content(저장할 내용), note(선택). 저장 경로를 돌려준다.",
  intent: "recon",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    if (!ctx.resultsDir) return { ok: false, summary: "산출물 디렉터리가 없습니다(resultsDir 미지정)" };
    const filename = String(args.filename ?? "");
    const content = String(args.content ?? "");
    if (!filename) return { ok: false, summary: "filename 인자가 필요합니다" };
    if (!content) return { ok: false, summary: "content 가 비어 있습니다" };
    if (Buffer.byteLength(content) > MAX_OUTPUT_BYTES) {
      return { ok: false, summary: `출력이 너무 큽니다(${MAX_OUTPUT_BYTES} 바이트 상한) — 요약해서 나눠 저장하세요` };
    }
    const out = await safeOutPath(ctx, filename);
    if (!out) return { ok: false, summary: "안전하지 않은 파일명 — 저장 거부" };
    await fs.writeFile(out, content, "utf8");
    return {
      ok: true,
      summary: `산출물 저장: ${out} (${(Buffer.byteLength(content) / 1024).toFixed(1)}KB)`,
      data: {
        severity: "info",
        title: `산출물 작성: ${filename}`,
        evidence: `${out} — ${String(args.note ?? "").slice(0, 120)}`,
        savedPath: out,
      },
    };
  },
};

/** 목표 에이전트 전용 툴박스 — 위 3종 + 기존 관측 툴(crawl/http_probe) 조합은 goal-agent 에서 만든다. */
export const GOAL_TOOLS: Tool[] = [fetchPage, downloadFile, writeOutput];
