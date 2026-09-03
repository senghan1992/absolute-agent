/**
 * sqli_probe — SQL Injection "탐지"(detection only) 툴. 최소영향 원칙.
 *
 * 한 가지 방법(오류 기반)만 쓰지 않는다. 세 갈래로 발산 탐지한다:
 *   1) error-based : 오류유발 문자로 DB 오류 시그니처 노출 (high)
 *   2) boolean-based blind : 참/거짓 조건의 응답 차이 (high) — 오류를 숨기는 앱 대응
 *   3) time-based blind : 조건부 지연(SLEEP)으로 실행 확인 (high) — 응답이 동일한 앱 대응
 * 데이터 추출은 하지 않는다(존재 신호만). args.payloads 로 커스텀 오류유발 문자열 주입 가능.
 * ctx.auth 가 있으면 인증된 표면까지 점검한다.
 */

import type { Tool, ToolContext, ToolResult } from "../core/types.js";
import { authGet, baseUrl, joinPath, withQuery } from "./util.js";

const DB_ERROR = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysqli?/i,
  /unclosed quotation mark after the character string/i,
  /pg_query\(\)|postgresql.*error/i,
  /sqlite3?::|sqlite error|sqlite_error|no such (table|column)/i, // SQLite(예: Juice Shop 의 SQLITE_ERROR)
  /ora-\d{5}/i,
  /odbc.*sql server|microsoft ole db|system\.data\.sqlclient/i, // MSSQL(.NET 포함)
  /quoted string not properly terminated/i,
  /syntax error at or near/i,
  // 추가 일반화(스택 다양성) — 모두 DB 계층 고유 문자열이라 오탐 위험이 낮다.
  /sqlstate\[\w/i, // PDO/JDBC SQLSTATE
  /pdoexception|pdo::/i,
  /supplied argument is not a valid mysql/i,
  /mysql_fetch_(array|assoc|row)\(\)|mysql_num_rows\(\)/i,
  /valid (mysql|postgresql) result/i,
  /invalid input syntax for (type )?\w+/i, // Postgres 타입 캐스팅 오류
  /npgsql\./i, // Postgres .NET
  /(mongoerror|casterror|bsonerror)/i, // NoSQL(MongoDB)
  /unterminated (quoted )?string/i,
];

/** 오류유발 마커(기본). 다양한 종결 문맥을 노린다. args.payloads 로 대체 가능. */
const DEFAULT_MARKERS = ["'", '"', "')", "';"];
/** 시간 기반: 스택별 지연 함수. 하나라도 지연되면 신호. */
const SLEEP_SECONDS = 3;
const TIME_PAYLOADS = [
  `1' AND SLEEP(${SLEEP_SECONDS})-- -`, // MySQL
  `1'; SELECT pg_sleep(${SLEEP_SECONDS})-- -`, // Postgres
  `1' AND 1=(SELECT 1 FROM PG_SLEEP(${SLEEP_SECONDS}))-- -`,
  `1'; WAITFOR DELAY '0:0:${SLEEP_SECONDS}'-- -`, // MSSQL
];

export const sqliProbe: Tool = {
  name: "sqli_probe",
  description:
    "지정 파라미터에 오류기반·부울맹목·시간맹목 세 갈래로 SQLi 존재를 탐지한다(추출 없음, 최소영향). args.payloads 로 커스텀 페이로드 주입.",
  intent: "exploit",
  async run(args, ctx: ToolContext): Promise<ToolResult> {
    const base = baseUrl(ctx.target);
    const paths = pickPaths(args);
    const params = pickParams(args);
    const markers = pickMarkers(args);

    // crawl 이 찾은 여러 경로×파라미터를 발산적으로 스윕한다. 첫 확정 신호에서 반환.
    let statusShiftEvidence: { param: string; evidence: string } | undefined;
    let lastError: string | undefined;

    for (const path of paths) {
      for (const param of params) {
        const q = (val: string) => joinPath(base, withQuery(path, { [param]: val }));
        try {
          const { out: b, ms: baseMs } = await timed(() => authGet(ctx, q("1")));

          // 1) error-based
          let errored: RegExp | undefined;
          let errMk = "";
          for (const mk of markers) {
            const m = await authGet(ctx, q(`1${mk}`));
            const hit = DB_ERROR.find((re) => re.test(m.body) && !re.test(b.body));
            if (hit) {
              errored = hit;
              errMk = mk;
              break;
            }
          }
          if (errored) {
            return signal(path, param, "error-based", `오류유발 입력('${errMk}')에서 DB 오류 노출: ${errored.source.slice(0, 40)}`);
          }

          // 2) boolean-based blind — 참/거짓 조건의 응답이 유의미하게 갈리는가.
          const tRes = await authGet(ctx, q("1' AND '1'='1"));
          const fRes = await authGet(ctx, q("1' AND '1'='2"));
          if (
            !DB_ERROR.some((re) => re.test(tRes.body) || re.test(fRes.body)) &&
            similar(b.body, tRes.body) &&
            diverged(tRes.body, fRes.body)
          ) {
            return signal(
              path,
              param,
              "boolean-based blind",
              `참 조건 응답(len ${tRes.body.length})과 거짓 조건 응답(len ${fRes.body.length})이 유의미하게 다름`,
            );
          }

          // 3) time-based blind — 조건부 지연이 실제로 실행되는가(마지막 수단, 1회).
          for (const tp of TIME_PAYLOADS) {
            const { ms } = await timed(() => authGet(ctx, q(tp)));
            if (ms - baseMs >= (SLEEP_SECONDS - 0.5) * 1000) {
              return signal(path, param, "time-based blind", `지연 페이로드에서 응답 +${Math.round(ms - baseMs)}ms (기준 ${Math.round(baseMs)}ms)`);
            }
          }

          if (b.status !== tRes.status && !statusShiftEvidence) {
            statusShiftEvidence = { param, evidence: `${path}: ${b.status}→${tRes.status} — 추가 조사 권고` };
          }
        } catch (e) {
          lastError = (e as Error).message;
        }
      }
    }

    if (statusShiftEvidence) {
      return {
        ok: false,
        summary: `SQLi 미탐지 (param='${statusShiftEvidence.param}', 상태코드 변화 관측)`,
        data: { severity: "low", title: `입력에 따른 상태코드 변화 (param=${statusShiftEvidence.param})`, evidence: statusShiftEvidence.evidence },
      };
    }
    return { ok: false, summary: `SQLi 미탐지 (paths=${paths.join(",")}, params=${params.join(",")}, 3갈래 시도)${lastError ? ` — 마지막 오류: ${lastError}` : ""}` };
  },
};

const DEFAULT_PATHS = ["/"];
const DEFAULT_PARAMS = ["id", "q", "search", "user", "name", "page"];
const MAX_PATHS = 8;
const MAX_PARAMS = 6;

function pickPaths(args: Record<string, unknown>): string[] {
  if (typeof args.path === "string" && args.path) return [args.path];
  if (Array.isArray(args.paths)) {
    const ps = args.paths.filter((x): x is string => typeof x === "string");
    if (ps.length) return [...new Set(ps)].slice(0, MAX_PATHS);
  }
  return DEFAULT_PATHS;
}

function pickParams(args: Record<string, unknown>): string[] {
  if (typeof args.param === "string" && args.param) return [args.param];
  if (Array.isArray(args.params)) {
    const ps = args.params.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, MAX_PARAMS);
  }
  return DEFAULT_PARAMS.slice(0, MAX_PARAMS);
}

function signal(path: string, param: string, technique: string, evidence: string): ToolResult {
  return {
    ok: true,
    summary: `SQLi 신호 탐지(${technique}): ${path} 의 파라미터 '${param}'`,
    fingerprint: { indicators: [`sqli:${technique}`, `param ${param}`] },
    data: {
      severity: "high",
      title: `SQL Injection 취약점 신호 (${technique}, param=${param})`,
      evidence: `${path} — ${evidence}`,
    },
  };
}

function pickMarkers(args: Record<string, unknown>): string[] {
  if (Array.isArray(args.payloads)) {
    const ps = args.payloads.filter((x): x is string => typeof x === "string");
    if (ps.length) return ps.slice(0, 6);
  }
  return DEFAULT_MARKERS;
}

async function timed<T>(fn: () => Promise<T>): Promise<{ out: T; ms: number }> {
  const t0 = Date.now();
  const out = await fn();
  return { out, ms: Date.now() - t0 };
}

/** 길이 기준 근사 유사도(±5% 이내면 유사). 정적 페이지 대비 안정적. */
function similar(a: string, b: string): boolean {
  const hi = Math.max(a.length, b.length) || 1;
  return Math.abs(a.length - b.length) / hi <= 0.05;
}

/** 부울 블라인드에서 오탐을 줄이기 위한 절대 최소 차이(바이트). 미세한 지터를 신호로 보지 않는다. */
const ABS_DIVERGENCE = 24;

/**
 * 두 응답이 유의미하게 다른가. 상대(≥10%)와 절대(≥24바이트) 임계를 **함께** 요구한다.
 * 큰 페이지에서 10% 는 수백 바이트라 문제없지만, 작은 페이지에서 10% 가 몇 바이트에 불과해
 * 렌더링 지터를 부울 신호로 오인하던 오탐을 절대 임계가 막는다.
 */
function diverged(a: string, b: string): boolean {
  const hi = Math.max(a.length, b.length) || 1;
  const abs = Math.abs(a.length - b.length);
  return abs / hi >= 0.1 && abs >= ABS_DIVERGENCE;
}
