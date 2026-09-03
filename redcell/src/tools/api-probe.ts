/**
 * api_probe — 발견된 backend API 엔드포인트가 노출하는 정보를 확인(읽기 전용).
 *
 * api_discover 로 찾은 경로(예: /api/submissions)를 GET 해서
 *   - 응답 상태/콘텐츠 타입
 *   - JSON 이면 형태(배열/객체, 레코드 수, 필드명)
 *   - 인증 없이 접근되는 민감/개인정보성 필드 노출 여부
 * 를 요약한다. 오직 GET 만 하며 POST/PUT/DELETE 등 상태변경은 하지 않는다.
 *
 * ctx.target(스코프 검증된 호스트) 기준 same-origin 으로만 요청한다.
 * args.path(단일) 또는 args.paths(배열, 상한 8개)를 받는다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { baseUrl, joinPath, authGet } from "./util.js";

const MAX_PATHS = 8;
/** 노출 시 즉시 위험한 비밀/개인정보 필드(→ high). */
const SECRET_PII = /(password|passwd|secret|token|api[_-]?key|private[_-]?key|ssn|resident|social|phone|mobile|email|address|credit|card|salary|account[_-]?no)/i;
/** 데이터 레코드로 보이는 흔한 식별/속성 필드(노출 자체는 medium 데이터 노출). */
const RECORD_FIELDS = /(^id$|_id$|uuid|title|name|team|submission|entry|user|member|rank|created|updated|score|grade|point|evaluation)/i;

interface Probe {
  path: string;
  status: number;
  contentType: string;
  shape: string;
  count?: number;
  fields: string[];
  sensitive: string[];
  authRequired: boolean;
}

export const apiProbe: Tool = {
  name: "api_probe",
  description:
    "발견된 API 엔드포인트를 GET 해서 노출 정보(JSON 형태·레코드 수·필드명·민감정보 여부)를 확인한다(읽기 전용, 상태변경 없음).",
  intent: "enumerate",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = collectPaths(args).slice(0, MAX_PATHS);
    if (paths.length === 0) {
      return { ok: false, summary: "확인할 경로가 없습니다. args.path 또는 args.paths 를 지정하세요." };
    }

    const probes: Probe[] = [];
    for (const p of paths) {
      try {
        const res = await authGet(ctx, joinPath(base, p));
        probes.push(analyze(p, res.status, res.headers["content-type"] ?? "", res.body));
      } catch (e) {
        probes.push({
          path: p,
          status: 0,
          contentType: "",
          shape: `요청 실패: ${(e as Error).message}`,
          fields: [],
          sensitive: [],
          authRequired: false,
        });
      }
    }

    // 인증 없이 데이터를 반환하는 엔드포인트 중 가장 위험한 것으로 발견 등급 산정.
    const exposed = probes.filter((p) => p.status === 200 && !p.authRequired && (p.count != null || p.fields.length > 0));
    const withPII = exposed.filter((p) => p.sensitive.length > 0);
    const ok = probes.some((p) => p.status > 0);

    let severity: "info" | "low" | "medium" | "high" = "info";
    let title = `API 응답 확인 (${probes.length}개 경로)`;
    if (withPII.length > 0) {
      severity = "high";
      title = `인증 없는 민감정보 노출 (${withPII[0].path})`;
    } else if (exposed.length > 0) {
      severity = "medium";
      title = `인증 없는 데이터 노출 (${exposed[0].path})`;
    } else if (probes.some((p) => p.authRequired)) {
      severity = "info";
      title = `보호된 엔드포인트 확인 (인증 필요)`;
    }

    const evidence = probes
      .map((p) => {
        const bits = [`${p.path} → ${p.status || "ERR"}`];
        if (p.count != null) bits.push(`records=${p.count}`);
        if (p.fields.length) bits.push(`fields=${p.fields.slice(0, 8).join(",")}`);
        if (p.sensitive.length) bits.push(`민감=${p.sensitive.join(",")}`);
        if (p.authRequired) bits.push("auth-required");
        return bits.join(" ");
      })
      .join(" | ");

    return {
      ok,
      summary: exposed.length
        ? `데이터 노출 ${exposed.length}건${withPII.length ? ` (민감 ${withPII.length})` : ""}`
        : `확인 ${probes.length}건 (노출 없음)`,
      fingerprint: ok ? { indicators: probes.map((p) => `probe ${p.path} → ${p.status}`) } : undefined,
      data: ok ? { severity, title, evidence, probes } : undefined,
    };
  },
};

function collectPaths(args: Record<string, unknown>): string[] {
  const out: string[] = [];
  if (Array.isArray(args.paths)) for (const p of args.paths) if (typeof p === "string") out.push(p);
  if (typeof args.path === "string" && args.path) out.push(args.path);
  // 중복 제거, 경로만 허용(다른 호스트의 절대 URL 은 경로로 축약).
  return [...new Set(out.map(toPath).filter(Boolean))] as string[];
}

/** 절대 URL 이 들어오면 경로 부분만 취해 same-origin 을 강제한다. */
function toPath(raw: string): string {
  try {
    if (/^https?:\/\//i.test(raw)) return new URL(raw).pathname + new URL(raw).search;
  } catch {
    /* 무시 */
  }
  return raw.startsWith("/") ? raw : `/${raw}`;
}

function analyze(path: string, status: number, contentType: string, body: string): Probe {
  const authRequired = status === 401 || status === 403;
  const probe: Probe = { path, status, contentType, shape: "", fields: [], sensitive: [], authRequired };

  const looksJson = /json/i.test(contentType) || /^\s*[[{]/.test(body);
  if (!looksJson) {
    probe.shape = status === 200 ? `비-JSON (${contentType || "?"})` : `HTTP ${status}`;
    return probe;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    // 본문이 잘렸을 수 있음 — 배열/객체 여부만이라도 추정.
    probe.shape = /^\s*\[/.test(body) ? "JSON 배열(부분)" : "JSON 객체(부분)";
    scanFields(body, probe);
    return probe;
  }

  if (Array.isArray(parsed)) {
    probe.shape = "JSON 배열";
    probe.count = parsed.length;
    const sample = parsed.find((x) => x && typeof x === "object") as Record<string, unknown> | undefined;
    if (sample) fieldsOf(sample, probe);
  } else if (parsed && typeof parsed === "object") {
    probe.shape = "JSON 객체";
    const obj = parsed as Record<string, unknown>;
    // data/items/results 안의 배열도 흔하다.
    const arr = ["data", "items", "results", "list", "submissions", "entries"]
      .map((k) => obj[k])
      .find((v) => Array.isArray(v)) as unknown[] | undefined;
    if (arr) {
      probe.count = arr.length;
      const sample = arr.find((x) => x && typeof x === "object") as Record<string, unknown> | undefined;
      if (sample) fieldsOf(sample, probe);
    } else {
      fieldsOf(obj, probe);
    }
  } else {
    probe.shape = `JSON ${typeof parsed}`;
  }
  return probe;
}

function fieldsOf(obj: Record<string, unknown>, probe: Probe): void {
  const keys = Object.keys(obj);
  probe.fields = keys.filter((k) => RECORD_FIELDS.test(k) || SECRET_PII.test(k)).slice(0, 16);
  if (probe.fields.length === 0) probe.fields = keys.slice(0, 8);
  probe.sensitive = keys.filter((k) => SECRET_PII.test(k));
}

/** 파싱 실패한 부분 본문에서 키 이름만이라도 훑는다. */
function scanFields(body: string, probe: Probe): void {
  const keys = new Set<string>();
  for (const m of body.matchAll(/["']([A-Za-z_][A-Za-z0-9_]{1,30})["']\s*:/g)) keys.add(m[1]);
  const all = [...keys];
  probe.fields = all.filter((k) => RECORD_FIELDS.test(k) || SECRET_PII.test(k)).slice(0, 16);
  if (probe.fields.length === 0) probe.fields = all.slice(0, 8);
  probe.sensitive = all.filter((k) => SECRET_PII.test(k));
}
