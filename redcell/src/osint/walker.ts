/**
 * osint/walker — 결정적 '샅샅이 뒤지기' 딥 다이그 엔진.
 *
 * 시드 URL 에서 같은 오리진 페이지를 BFS 로 깊게 따라서 돌며 사람·기계·서비스 인텔을
 * 수집한다: 이메일·전화·API 경로·시크릿 패턴·스크립트/폼·메타·robots.txt/sitemap.xml.
 * 목표는 취약점 스캔이 아니라 "내가 원하는 정보를 사이트에서 찾아오기"이며,
 * 모든 요청은 safeGet(per-target RPS·프록시·쿠키) + canFetch scope 게이트를 통과해야 한다.
 *
 * 순수 관측(GET)만 수행한다. 상태변경/제출은 하지 않는다.
 */
import type { CookieJar } from "../net/http-client.js";
import { safeGet } from "../tools/util.js";

export interface IntelItem {
  kind: "email" | "phone" | "api" | "secret" | "tech" | "meta" | "endpoint" | "data";
  value: string;
  source: string;
  note?: string;
}

export interface DigPage {
  url: string;
  status: number;
  title: string;
  intel: IntelItem[];
  links: string[]; // 같은 오리진 미방문 링크(frontier 후보)
  scripts: string[]; // JS 파일 URL(같은 오리진)
  forms: string[]; // "action(param1,param2)"
  snippet: string; // 본문 앞부분(모델/보고용)
}

export interface DigResult {
  url: string;
  pages: DigPage[];
  /** 전체 페이지에서 수집한 인텔(중복은 kind+value 로 접힘). */
  intel: IntelItem[];
  /** 아직 방문하지 않은 같은 오리진 URL(계속 다이그 후보). */
  frontier: string[];
  crawled: number;
}

export interface DigOpts {
  rps: number;
  auth?: Record<string, string>;
  jar?: CookieJar;
  proxy?: string;
  validateIp?: (hostname: string, ip: string) => boolean;
  /** scope 게이트: false 면 그 URL 은 요청조차 하지 않는다(기본 전부 허용). */
  canFetch?: (url: string) => boolean;
  maxPages?: number;
  maxDepth?: number;
  onPage?: (p: DigPage) => void;
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const PHONE_RE = /(?:\+?\d{2,3}[-\s.]?)?(?:\(?\d{2,4}\)?[-\s.]?)?\d{3,4}[-\s.]?\d{4}/g;
const SECRET_RE =
  /(?:\b(?:api[_-]?key|apikey|api[_-]?secret|secret|token|password|passwd|authorization|bearer|access[_-]?key|client[_-]?secret|key)\s*[:=]\s*["']?[A-Za-z0-9_\-./+]{12,}|\bAKIA[A-Z0-9]{16,}\b)/gi;
const API_PATH_RE = /\/(?:api|v\d+|graphql|rest|admin|internal|health|status|swagger|openapi\.json|\.env|\.git|config\.json|wp-json|uploads?|backup|debug|dev)\b[^"'\s<]*/gi;
const SKIP_EXT_RE = /\.(png|jpe?g|gif|svg|webp|ico|css|mp4|mp3|zip|woff2?|ttf|pdf|docx?|xlsx?)$/i;
const HREF_RE = /(?:href|action|src)\s*=\s*["']([^"'#]+)["']/gi;
const FORM_RE = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
const INPUT_NAME_RE = /<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([A-Za-z0-9_.\-\[\]]+)/gi;
const SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
const META_RE = /<meta\b[^>]*>/gi;
const LDJSON_RE = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
const COMMENT_RE = /<!--([\s\S]*?)-->/g;

function normHost(u: URL, seed: URL): boolean {
  return u.hostname === seed.hostname && String(u.port || (u.protocol === "https:" ? "443" : "80")) === String(seed.port || (seed.protocol === "https:" ? "443" : "80"));
}

/** 같은 오리진 URL 로 정규화. 외부/비HTTP/파일 다운로드 확장자는 null. */
function sameOrigin(raw: string, base: URL, seed: URL): URL | null {
  const v = raw.trim();
  if (!v || /^(mailto|tel|javascript|data|blob|about|ftp):/i.test(v)) return null;
  try {
    const u = new URL(v, base);
    if (!normHost(u, seed)) return null;
    if (SKIP_EXT_RE.test(u.pathname)) return null;
    return u;
  } catch {
    return null;
  }
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs.filter(Boolean))];
}

function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/** HTML 한 페이지에서 인텔 조각을 뽑는다(순수 함수 — 테스트 대상). */
export function extractPageIntel(html: string, url: string): { intel: IntelItem[]; links: string[]; scripts: string[]; forms: string[]; title: string } {
  const intel: IntelItem[] = [];
  const seen = new Set<string>();
  const add = (kind: IntelItem["kind"], value: string, note?: string) => {
    const key = `${kind}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    const v = value.trim();
    if (v.length > 2 && v.length < 200) intel.push({ kind, value: v, source: url, note });
  };

  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? "").replace(/\s+/g, " ").trim();
  if (title) add("meta", `title: ${clip(title, 120)}`);

  for (const m of html.matchAll(META_RE)) {
    const tag = m[0];
    const name = (tag.match(/name=["']([^"']+)["']/i) ?? [])[1];
    const content = (tag.match(/content=["']([^"']+)["']/i) ?? [])[1];
    if (name && content && /^(description|keywords|generator|author|theme-color)$/i.test(name)) {
      add("meta", `${name.toLowerCase()}: ${clip(content, 140)}`);
    }
  }

  for (const m of html.matchAll(EMAIL_RE)) add("email", m[0].toLowerCase());
  for (const m of html.matchAll(PHONE_RE)) {
    const v = m[0].replace(/[^\d+]/g, "");
    if (v.length >= 10 && v.length <= 14) add("phone", m[0]);
  }
  for (const m of html.matchAll(SECRET_RE)) add("secret", m[0]);
  for (const m of html.matchAll(API_PATH_RE)) {
    const p = m[0];
    if (!/\.(js|css|png|jpg|svg|gif|ico)$/i.test(p)) add("api", p);
  }
  for (const m of html.matchAll(COMMENT_RE)) {
    const c = m[1].replace(/\s+/g, " ").trim();
    if (c && !/^\[if|^<!--/.test(c)) add("data", `comment: ${clip(c, 120)}`, "HTML 주석");
  }
  for (const m of html.matchAll(LDJSON_RE)) {
    try {
      const o = JSON.parse(m[1]);
      const t = o?.["@type"] ?? o?.type;
      const nm = o?.name ?? o?.headline;
      if (t) add("data", `json-ld: ${t}${nm ? " — " + clip(String(nm), 80) : ""}`, "구조화 데이터");
    } catch {
      /* 무시 */
    }
  }
  // 기술 스택 힌트
  const techHints: Array<[RegExp, string]> = [
    [/wp-content|wp-includes|wordpress/i, "WordPress"],
    [/__next\/|next\/static|next\.js/i, "Next.js"],
    [/drupal|sites\/default/i, "Drupal"],
    [/jekyll|github\.io\//i, "Jekyll/GitHub Pages"],
    [/laravel|csrf-token/i, "Laravel"],
    [/django/i, "Django"],
    [/react/i, "React"],
    [/vue\.js|nuxt/i, "Vue/Nuxt"],
  ];
  for (const [re, name] of techHints) {
    if (re.test(html)) add("tech", name);
  }

  const base = new URL(url);
  const links: string[] = [];
  const scripts: string[] = [];
  const forms: string[] = [];
  for (const m of html.matchAll(HREF_RE)) {
    const u = sameOrigin(m[1], base, base);
    if (u) links.push(u.pathname + u.search);
  }
  for (const m of html.matchAll(SCRIPT_SRC_RE)) {
    const u = sameOrigin(m[1], base, base);
    if (u) scripts.push(u.href);
  }
  for (const fm of html.matchAll(FORM_RE)) {
    const tag = fm[1] ?? "";
    const inner = fm[2] ?? "";
    const actionRaw = (tag.match(/action\s*=\s*["']?([^"'\s>]+)/i) ?? [])[1] ?? "";
    const act = actionRaw ? sameOrigin(actionRaw, base, base) : null;
    const names = dedupe([...inner.matchAll(INPUT_NAME_RE)].map((x) => x[1]));
    forms.push(`${act ? act.pathname + act.search : url}(${names.slice(0, 8).join(",")})`);
    if (act) links.push(act.pathname + act.search);
  }
  return { intel, links: dedupe(links), scripts: dedupe(scripts), forms: dedupe(forms), title };
}

/** robots.txt / sitemap.xml 에서 같은 오리진 URL 목록을 뽑는다. */
export function parseRobots(body: string, seed: URL): string[] {
  const out: string[] = [];
  for (const m of body.matchAll(/^(?:Disallow|Allow)\s*:\s*(\S+)/gim)) {
    const raw = m[1];
    let u: URL | null = null;
    if (/^https?:\/\//i.test(raw)) u = sameOrigin(raw, seed, seed);
    else {
      const p = raw.startsWith("/") ? raw : "/" + raw;
      u = sameOrigin(p, seed, seed);
    }
    if (u && u.pathname !== "/") out.push(u.pathname + u.search);
  }
  return dedupe(out);
}

export function parseSitemap(body: string, seed: URL): string[] {
  const out: string[] = [];
  for (const m of body.matchAll(/<loc>([^<]+)<\/loc>/gi)) {
    const u = sameOrigin(m[1], seed, seed);
    if (u) out.push(u.pathname + u.search);
  }
  return dedupe(out);
}

/**
 * 시드부터 같은 오리진을 BFS 로 뒤진다. robots.txt/sitemap.xml 얻어걸림 포함.
 * 모든 요청: safeGet(per-target RPS·쿠키·프록시·리다이렉트 수동) + canFetch 게이트.
 */
export async function deepDig(seedUrl: string, opts: DigOpts): Promise<DigResult> {
  let seed: URL;
  try {
    seed = new URL(seedUrl);
  } catch {
    throw new Error(`잘못된 시드 URL: ${seedUrl}`);
  }
  const maxPages = Math.min(opts.maxPages ?? 30, 80);
  const maxDepth = Math.min(opts.maxDepth ?? 3, 5);
  const canFetch = opts.canFetch ?? (() => true);

  const pages: DigPage[] = [];
  const intel: IntelItem[] = [];
  const seen = new Set<string>();
  const queue: Array<{ url: URL; depth: number }> = [{ url: seed, depth: 0 }];
  const frontierAll = new Set<string>();

  const recordIntel = (items: IntelItem[]) => {
    const key = new Set(intel.map((i) => `${i.kind}:${i.value}`));
    for (const it of items) {
      const k = `${it.kind}:${it.value}`;
      if (!key.has(k)) {
        key.add(k);
        intel.push(it);
      }
    }
  };

  while (queue.length && pages.length < maxPages) {
    const { url, depth } = queue.shift()!;
    const key = url.pathname + url.search;
    if (seen.has(key) || depth > maxDepth) continue;
    if (!canFetch(url.toString())) continue;
    seen.add(key);

    let body = "";
    let status = 0;
    try {
      const res = await safeGet(url.toString(), opts.rps, {
        cap: 200000,
        proxy: opts.proxy,
        jar: opts.jar,
        headers: opts.auth,
        validateIp: opts.validateIp,
        timeoutMs: 8000,
      });
      status = res.status;
      body = res.body;
    } catch (e) {
      status = (e as Error & { code?: string }).code === "ECONNREFUSED" ? 0 : 0;
      continue;
    }
    if (status >= 400 || body.length === 0) continue;

    const { intel: pageIntel, links, scripts, forms, title } = extractPageIntel(body, url.toString());
    recordIntel(pageIntel);
    const page: DigPage = {
      url: url.toString(),
      status,
      title,
      intel: pageIntel,
      links: [],
      scripts,
      forms,
      snippet: clip(body.replace(/<[^>]*>/g, " ").replace(/\s+/g, " "), 800),
    };
    pages.push(page);
    opts.onPage?.(page);

    // robots.txt / sitemap.xml 은 루트에서 1회 얻어걸림(같은 오리진, 깊이 1로).
    if (url.pathname === "/" && pages.length < maxPages) {
      for (const well of [["/robots.txt", parseRobots], ["/sitemap.xml", parseSitemap]] as const) {
        const [p, parser] = well;
        if (canFetch(new URL(p, seed).toString())) {
          try {
            const r = await safeGet(new URL(p, seed).toString(), opts.rps, { cap: 200000, proxy: opts.proxy, jar: opts.jar, headers: opts.auth, validateIp: opts.validateIp, timeoutMs: 6000 });
            if (r.status === 200) {
              for (const lp of parser(r.body, seed)) {
                if (!seen.has(lp) && pages.length < maxPages) queue.push({ url: new URL(lp, seed), depth: 1 });
              }
            }
          } catch {
            /* 무시 */
          }
        }
      }
    }

    for (const lp of links) {
      try {
        const u = new URL(lp, url);
        const kk = u.pathname + u.search;
        if (!seen.has(kk)) {
          if (pages.length + queue.length < maxPages * 2) queue.push({ url: u, depth: depth + 1 });
          frontierAll.add(kk);
        }
      } catch {
        /* 무시 */
      }
    }
  }

  const frontier = [...frontierAll]
    .filter((f) => !seen.has(f))
    .slice(0, 100);
  return { url: seedUrl, pages, intel, frontier, crawled: pages.length };
}