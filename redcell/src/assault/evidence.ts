/**
 * 증거 수집 — [탈취 가능 정보 매니페스트]를 만든다.
 *
 * 모든 툴 결과(fingerprint 지표 + 발견 데이터)에서 "공격자가 실제로 가져갈 수 있는
 * 정보"만 추려 항목화한다. 각 항목은 **증거 샘플**(cap + redact)이지 전량 덤프가 아니다.
 *
 *   - cap: 항목당 최대 문자 수(기본 1500, --evidence-cap 으로 조정). 그 안에서
 *     실제 노출을 증명할 수 있는 최소 단면(파일 앞부분/레코드 1건/오류 문자열)을 남긴다.
 *   - redact: 자격증명·토큰·이메일 등은 기본 마스킹(--no-redact 로 해제).
 *
 * 목적은 "탈취 가능한 데이터가 무엇인지 증명"이지 데이터 자체를 유출하는 것이 아니다.
 */

import type { ToolContext } from "../core/types.js";
import { authGet, baseUrl, joinPath } from "../tools/util.js";
import type { EvidenceCategory, EvidenceItem, ToolOutcome } from "./types.js";

export interface EvidenceOptions {
  /** 항목당 샘플 cap(문자). 기본 1500. */
  cap?: number;
  /** 매니페스트 최대 항목 수. 기본 40. */
  maxItems?: number;
  /** redaction 끄기(--no-redact). 기본 true(마스킹). */
  redact?: boolean;
  /** 툴 결과에서 이미 뽑은 "노출 증거 문자열" 대상 추가 fetch 허용 여부. */
  grab?: (path: string) => Promise<string>;
}

const SECRET_EXT = /(\.env|secret|credential|password|passwd|shadow|htpasswd|\.pem|\.key|token|\.aws|id_rsa)/i;
const BACKUP_EXT = /(\.bak|\.zip|\.tar|\.gz|\.old|\.orig|\.swp|\.sql|\.dump|\.log|backup|archive)/i;
const CONFIG_EXT = /(config|settings|web\.config|phpinfo|\.ini|\.xml|\.yml|\.yaml|\.json|\.properties)/i;
const PII_EXT = /(user|account|customer|order|member|employee|person|student|patient)/i;

export function categoryForPath(p: string): EvidenceCategory {
  if (SECRET_EXT.test(p)) return "secret";
  if (BACKUP_EXT.test(p)) return "backup";
  if (CONFIG_EXT.test(p)) return "config";
  if (PII_EXT.test(p)) return "pii";
  return "endpoint";
}

// ── redaction ────────────────────────────────────────────────────────────────

const SECRET_KEY = /^([A-Za-z_][A-Za-z0-9_]{2,})\s*[:=]\s*(.+)$/;
const EMAIL_RE = /([a-z0-9._%+-]+)@([a-z0-9.-]+\.[a-z]{2,})/gi;
const USERINFO_RE = /(https?:\/\/)([^:\/@\s]+):([^@\s]+)@/gi;
const TOKEN_RE = /\b([A-Za-z0-9_\-]{32,})\b/g;

function maskValue(v: string): string {
  if (v.length <= 6) return "***";
  return v.slice(0, 4) + "…" + v.slice(-2);
}

/**
 * 민감 문자열 마스킹. --no-redact 이면 원본을 그대로 둔다(그래도 cap 은 적용).
 */
export function redactSample(text: string, opts: { redact?: boolean } = {}): string {
  if (opts.redact === false) return text;
  let out = text;
  // 1) 구조 패턴 먼저 마스킹(이메일·URL userinfo·긴 토큰) — key=value 마스킹이
  //    이메일 로컬파트를 값 일부로 남기지 않도록 순서가 중요하다.
  out = out.replace(EMAIL_RE, (_all, local, domain) => `***@${domain}`);
  out = out.replace(USERINFO_RE, (_a, scheme, user, pass) => `${scheme}***:***@`);
  out = out.replace(TOKEN_RE, (tok) => maskValue(tok));
  // 2) KEY=value / KEY: value 형태 — 값 마스킹.
  out = out
    .split(/\r?\n/)
    .map((line) => {
      const m = SECRET_KEY.exec(line);
      if (m && !/^(https?|GET|POST|PUT|DELETE|PATCH|HTTP|status|server|date|content)/i.test(m[1])) {
        return `${m[1]}=${maskValue(m[2].trim())}`;
      }
      return line;
    })
    .join("\n");
  return out;
}

/** 노출 파일 본문 샘플 1회 fetch(증명용, cap 적용). 실패 시 비어 있음. */
export async function grabExposure(
  ctx: ToolContext,
  path: string,
  cap = 1500,
): Promise<{ sample: string; length: number }> {
  try {
    const res = await authGet(ctx, joinPath(baseUrl(ctx.target), path), { cap });
    const body = res.body ?? "";
    return { sample: body.slice(0, cap), length: body.length };
  } catch {
    return { sample: "", length: 0 };
  }
}

// ── 수집 ─────────────────────────────────────────────────────────────────────

interface RawHit {
  category: EvidenceCategory;
  label: string;
  target: string;
  severity: EvidenceItem["severity"];
  attack: string;
  sample?: string;
  itemCount?: number;
  source: string;
}

/** 툴 1건의 fingerprint 지표 → 노출 후보. */
function hitsFromOutcome(o: ToolOutcome): RawHit[] {
  const out: RawHit[] = [];
  const ind = o.fp?.indicators ?? [];
  for (const s of ind) {
    if (s.startsWith("exposed ")) {
      const p0 = s.slice("exposed ".length);
      const p = p0.startsWith("/") ? p0 : "/" + p0;
      out.push({
        category: categoryForPath(p),
        label: `민감 파일 노출: ${p}`,
        target: p,
        severity: o.finding?.severity ?? "high",
        attack: `서버가 ${p} 를 인증 없이 반환 — 포함된 자격증명/데이터를 그대로 가져갈 수 있다.`,
        source: o.tool,
      });
    } else if (s.startsWith("graphql-introspection ")) {
      out.push({
        category: "schema",
        label: `GraphQL 스키마 노출 (introspection)`,
        target: s.slice("graphql-introspection ".length),
        severity: "medium",
        attack: "introspection 쿼리로 전체 스키마(모든 타입·필드)를 읽을 수 있다 → 공격 표면 전체가 문서화됨.",
        source: o.tool,
      });
    } else if (s.startsWith("descriptor ")) {
      const m = /^descriptor (\/\S+) \((\d+)(, (\w+))?\)/.exec(s);
      if (m) {
        const kind = m[4] ?? "other";
        if (kind === "openapi" || kind === "graphql") {
          out.push({
            category: "schema",
            label: `API 명세 노출: ${m[1]} (${kind})`,
            target: m[1],
            severity: "medium",
            attack: `API 문서(${kind})가 공개됨 — 엔드포인트·파라미터·인증 설계를 파악해 정밀 공격에 사용할 수 있다.`,
            source: o.tool,
          });
        }
      }
    }
  }
  return out;
}

/** 발견 심각도가 높은 툴 발견 → 데이터 노출 항목 후보. */
function hitsFromFinding(o: ToolOutcome): RawHit[] {
  const f = o.finding;
  if (!f || f.severity === "info" || f.severity === "low") return [];
  const d = o.data ?? {};
  const ev = typeof d.evidence === "string" ? d.evidence : "";
  // 증거 문자열 앞의 경로 힌트(예: "/search — DB 오류...") 또는 제목 괄호의 경로.
  const pathHint = /^\s*(\/[\w.\-~/?=&%]+)/.exec(ev)?.[1] ?? "";
  const pathFromTitle = (title: string): string => /\(([^)]+)\)\s*$/.exec(title)?.[1] ?? "";
  const pickTarget = (t: unknown): string =>
    (typeof t === "string" && t) || pathHint || pathFromTitle(f.title) || "탐지 엔드포인트";
  switch (o.tool) {
    case "idor_probe": {
      const ids = Array.isArray(d.ids) ? (d.ids as string[]).slice(0, 5) : [];
      return [
        {
          category: "pii",
          label: `사적 데이터 비인가 열람 (IDOR) — ${f.title}`,
          target: pickTarget(d.path),
          severity: f.severity,
          attack:
            typeof d.impact === "string"
              ? d.impact
              : "임의 id 대입으로 타인의 개인 레코드를 인증 없이 열람 가능.",
          sample: ev + (ids.length ? `\n후보 id: ${ids.join(", ")}` : ""),
          itemCount: typeof d.count === "number" ? (d.count as number) : ids.length,
          source: o.tool,
        },
      ];
    }
    case "sqli_probe": {
      if (/error|sql|syntax|exception|stack|trace|mysql|postgres|oracle|sqlite/i.test(ev)) {
        return [
          {
            category: "error",
            label: `DB 오류 문자열 누설 (SQLi 신호)`,
            target: pickTarget(d.path),
            severity: f.severity,
            attack:
              "입력 주입 시 서버가 DB 엔진/쿼리 구조를 오류 문자열로 반환 — 스키마·데이터 추출 공격(UNION 등)의 시작점이다.",
            sample: ev,
            source: o.tool,
          },
        ];
      }
      return [];
    }
    case "graphql_probe": {
      if (typeof d.endpoint === "string") {
        return [
          {
            category: "schema",
            label: `GraphQL 스키마 노출`,
            target: d.endpoint as string,
            severity: f.severity,
            attack: "introspection 쿼리로 전체 스키마를 덤프할 수 있다 → 모든 쿼리·뮤테이션·타입 파악.",
            sample: ev,
            source: o.tool,
          },
        ];
      }
      return [];
    }
    default:
      // dir_enum 민감 경로 노출 등: evidence 문자열에서 path 목록 추출.
      if (o.tool === "dir_enum" && /노출/.test(f.title)) {
        const paths = (ev.match(/[\w.\-~]{1,60}(?=\s*→\s*\d{3})/g) ?? []).slice(0, 4);
        return paths.map((p0) => {
        const p = p0.startsWith("/") ? p0 : "/" + p0;
        return {
          category: categoryForPath(p),
          label: `비인가 접근 가능 경로: ${p}`,
          target: p,
          severity: f.severity,
          attack: `관리/민감 경로 ${p} 가 비인가 상태로 응답 — 이면 기능·데이터에 접근할 수 있다.`,
          sample: ev,
          source: o.tool,
        };
      });
      }
      return [];
  }
}

export interface CollectedEvidence {
  items: EvidenceItem[];
  /** 실제로 본문을 fetch 해 샘플을 받아온 항목 수. */
  grabbed: number;
}

/**
 * 전체 툴 결과 → 탈취 가능 정보 매니페스트.
 * 중복(같은 target+label)은 합치고, cap/redact/항목 상한을 적용한다.
 */
export async function collectEvidence(
  outcomes: ToolOutcome[],
  ctx: ToolContext,
  opts: EvidenceOptions = {},
): Promise<CollectedEvidence> {
  const cap = opts.cap ?? 1500;
  const maxItems = opts.maxItems ?? 40;
  const redact = opts.redact !== false;

  const raw: RawHit[] = [];
  for (const o of outcomes) {
    raw.push(...hitsFromOutcome(o));
    raw.push(...hitsFromFinding(o));
  }

  // 중복 제거: target+label 기준.
  const seen = new Set<string>();
  const items: EvidenceItem[] = [];
  let grabbed = 0;
  let n = 0;
  for (const h of raw) {
    if (n >= maxItems) break;
    const key = `${h.target}|${h.label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    n++;

    let sample = h.sample ?? "";
    // 노출 파일은 진짜 본문 앞부분을 가져와 증명한다(opts.grab 이 있으면 그것 사용).
    if (!sample && h.category !== "schema" && h.category !== "error" && h.category !== "pii" && h.target.startsWith("/")) {
      const g = opts.grab ?? ((p: string) => grabExposure(ctx, p, cap).then((r) => r.sample));
      const got = await g(h.target);
      if (got) grabbed++;
      sample = got;
    }
    items.push({
      id: `ev${String(n).padStart(2, "0")}`,
      category: h.category,
      label: h.label,
      source: h.source,
      target: h.target,
      severity: h.severity,
      sample: redactSample(sample, { redact }).slice(0, cap + 200),
      redacted: redact && /\*\*\*|…/.test(redactSample(sample, { redact })),
      itemCount: h.itemCount,
      attack: h.attack,
    });
  }
  return { items, grabbed };
}
