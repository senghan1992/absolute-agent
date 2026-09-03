/**
 * target-map — 정찰(crawl)이 발견한 실제 공격 표면을 인젝션/탐지 툴의 인자로 자동 변환한다.
 *
 * "자기발전형 화이트해커"의 핵심은 정찰→공격의 자동 연결이다. crawl 이 찾은
 * endpoint(`endpoint /path?param=`)를 각 툴의 `paths`/`params` 인자로 매핑해, 운영자가
 * 손으로 경로를 지정하지 않아도 인젝션 툴이 발견된 표면 전체를 스윕하게 한다.
 *
 * AutoPilot(모델 없음)와 MockModel(플래너) 양쪽이 이 로직을 공유해 동작이 일관된다.
 */

/** fingerprint.indicators 에서 crawl 이 남긴 endpoint 문자열("/path" 또는 "/path?param=")을 추출. */
export function endpointsFrom(indicators: string[] = []): string[] {
  const out: string[] = [];
  for (const i of indicators) {
    const m = /^endpoint (\/\S*)/.exec(i);
    if (m) out.push(m[1]);
  }
  return [...new Set(out)];
}

export interface Surface {
  /** 발견된 모든 고유 경로(쿼리 제거). */
  paths: string[];
  /** 쿼리 파라미터를 가진 고유 경로. */
  paramPaths: string[];
  /** 발견된 모든 고유 파라미터 이름. */
  params: string[];
  /** 숫자 id 로 끝나는 경로(IDOR 후보). */
  idPath?: string;
}

/** indicators → 공격 표면 구조화(경로/파라미터/ID 경로 분해). */
export function surfaceFrom(indicators: string[] = [], cap = 8): Surface {
  const endpoints = endpointsFrom(indicators);
  const paths = new Set<string>();
  const paramPaths = new Set<string>();
  const params = new Set<string>();
  let idPath: string | undefined;
  for (const e of endpoints) {
    const qi = e.indexOf("?");
    const path = qi >= 0 ? e.slice(0, qi) : e;
    paths.add(path);
    if (qi >= 0) {
      paramPaths.add(path);
      for (const k of new URLSearchParams(e.slice(qi + 1)).keys()) params.add(k);
    }
    if (!idPath && /\/\d+\/?$/.test(path)) idPath = path;
  }
  return {
    paths: [...paths].slice(0, cap),
    paramPaths: [...paramPaths].slice(0, cap),
    params: [...params].slice(0, cap),
    idPath,
  };
}

/** 발견된 표면 전체를 스윕하도록 paths+params 를 실어주는 인젝션 계열 툴. */
const SWEEP_INJECTION = new Set([
  "sqli_probe",
  "xss_probe",
  "ssti_probe",
  "cmdi_probe",
  "path_traversal",
  "open_redirect",
  "ssrf_probe",
  "param_pollution",
  "logic_probe",
]);
/** 경로만 필요한(파라미터 스윕 불필요) 툴. */
const PATH_ONLY = new Set(["csrf_audit", "upload_probe", "cors_audit", "host_header_audit", "http_method_audit"]);
/** 발견된 경로 전체를 paths 로 받는(단일 경로 아님) 툴. */
const PATHS_SWEEP = new Set(["deserialize_probe", "auth_session_probe", "cache_poison_probe"]);

/**
 * 툴 이름 + 발견된 표면 → 자동 생성 인자.
 * 반환이 비어({}) 있으면 툴 기본값을 쓰라는 뜻(표면 정보가 없거나 불필요).
 */
export function deriveArgs(tool: string, indicators: string[] = []): Record<string, unknown> {
  const s = surfaceFrom(indicators);
  if (s.paths.length === 0) return {};

  if (SWEEP_INJECTION.has(tool)) {
    // 파라미터 있는 경로를 우선 표적으로, 발견된 파라미터명을 모두 스윕.
    const targets = s.paramPaths.length ? s.paramPaths : s.paths;
    const args: Record<string, unknown> = { paths: targets };
    if (s.params.length) args.params = s.params;
    return args;
  }
  if (tool === "idor_probe") {
    const p = s.idPath ?? s.paramPaths[0] ?? s.paths[0];
    return p ? { path: p } : {};
  }
  if (tool === "xxe_probe" || tool === "api_probe" || PATHS_SWEEP.has(tool)) {
    return { paths: s.paths };
  }
  if (PATH_ONLY.has(tool)) {
    return { path: s.paramPaths[0] ?? s.paths[0] };
  }
  return {};
}

/**
 * 운영자가 지정하는 표면 오버라이드(`--target-map <file.json>`).
 * 정찰(crawl)에만 의존하지 않고 아는 경로/파라미터를 직접 주입한다(SPA·인증 뒤 표면 등
 * 자동 크롤이 놓치는 부분 보강). 형식:
 *   { "paths": ["/search"], "params": ["q"], "idPath": "/api/orders/1",
 *     "tools": { "sqli_probe": { "paths": ["/search"], "params": ["q"] } } }
 */
export interface TargetMap {
  paths?: string[];
  params?: string[];
  idPath?: string;
  /** 툴별 인자 직접 지정(가장 높은 우선순위). */
  tools?: Record<string, Record<string, unknown>>;
}

/** 임의 JSON → TargetMap(방어적 검증). 잘못된 형태면 예외. */
export function parseTargetMap(json: unknown): TargetMap {
  if (!json || typeof json !== "object") throw new Error("target-map 은 JSON 객체여야 합니다.");
  const o = json as Record<string, unknown>;
  const strArr = (v: unknown): string[] | undefined =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : undefined;
  const map: TargetMap = {};
  if (o.paths !== undefined) map.paths = strArr(o.paths);
  if (o.params !== undefined) map.params = strArr(o.params);
  if (typeof o.idPath === "string") map.idPath = o.idPath;
  if (o.tools && typeof o.tools === "object") {
    const tools: Record<string, Record<string, unknown>> = {};
    for (const [k, v] of Object.entries(o.tools as Record<string, unknown>)) {
      if (v && typeof v === "object" && !Array.isArray(v)) tools[k] = v as Record<string, unknown>;
    }
    map.tools = tools;
  }
  if (!map.paths?.length && !map.params?.length && !map.idPath && !map.tools) {
    throw new Error("target-map 에 paths/params/idPath/tools 중 하나 이상이 필요합니다.");
  }
  return map;
}

/** TargetMap → deriveArgs 가 읽는 합성 indicators("endpoint /path?param=..."). */
export function indicatorsFromMap(map: TargetMap): string[] {
  const out: string[] = [];
  const q = (map.params ?? []).map((k) => `${encodeURIComponent(k)}=1`).join("&");
  for (const p of map.paths ?? []) {
    out.push(`endpoint ${p}`);
    if (q && !p.includes("?")) out.push(`endpoint ${p}?${q}`);
  }
  if (map.idPath) out.push(`endpoint ${map.idPath}`);
  return [...new Set(out)];
}

/**
 * 툴 → target-map 기반 인자. 우선순위: tools[tool] 직접지정 → 합성표면 deriveArgs.
 * 이 맵으로 만들 인자가 없으면 undefined(호출부가 기존 autoArgsFor 로 폴백).
 */
export function argsFromMap(tool: string, map: TargetMap): Record<string, unknown> | undefined {
  if (map.tools && map.tools[tool]) return map.tools[tool];
  const inds = indicatorsFromMap(map);
  if (inds.length === 0) return undefined;
  const a = deriveArgs(tool, inds);
  return Object.keys(a).length ? a : undefined;
}
