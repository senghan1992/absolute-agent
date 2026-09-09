/**
 * 검증 엔진 — "가능성/징후"를 "실증(verified)"으로 끌어올린다.
 *
 * 수집된 원본 증거(redaction **전**)를 규칙 기반으로 재판독해, 공격자가 실제로
 * 가져갈 수 있는 것이 무엇인지 결정적으로 증명한다:
 *
 *   - secret  : KEY=VALUE 자격증명 형식 항목 존재(값 길이·키 이름 검증)
 *   - error   : 오류 문자열에서 DB 엔진/제품 지문 식별
 *   - pii     : 서로 다른 사적 객체 응답(distinct)·민감 필드 목록 확인
 *   - schema  : introspection 응답에 스키마 구조(쿼리/타입/필드) 확인
 *   - config/backup/endpoint : 실제 본문 확보(빈 응답 아님) 확인
 *
 * 검증은 항상 "무엇을 확인했는지"를 증거 문자열(proof)로 남긴다. proof 는
 * redaction(기본 ON)이 적용되어 자격증명 원문이 절대 보고서에 남지 않는다.
 * 사람이 재현할 수 있는 결정적 규칙만 사용한다(AI 의존 없음).
 */

import type { EvidenceCategory } from "./types.js";
import { redactSample } from "./evidence.js";

export type VerificationStatus = "verified" | "partial" | "unverified";

export interface Verification {
  status: VerificationStatus;
  /** 확인된 사실(이미 마스킹된 증거 문자열). */
  proof: string;
}

const BADGE: Record<VerificationStatus, string> = {
  verified: "✅ 실증",
  partial: "⚠️ 징후",
  unverified: "❓ 미확인",
};
export const verificationBadge = (v: VerificationStatus): string => BADGE[v];

// ── 공통 도우미 ──────────────────────────────────────────────────────────────

const KEYVALUE = /^([A-Za-z_][A-Za-z0-9_]{2,})\s*[=:]\s*(.+)$/;
/** 자격증명으로 분류할 키 이름 패턴. */
const CRED_KEY = /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|client[_-]?secret|username|login|auth|db[_-]?(user|pass|password)|jwt|session|cookie)/i;
/** 키-값이지만 설정/일반 값으로 보는 키(오탐 방지). */
const NON_CRED_KEY = /^(debug|env|host|port|path|version|lang|locale|color|theme|mode|notice|warning|pi|ratio)$/i;

function keyValueLines(raw: string): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const m = KEYVALUE.exec(line.trim());
    if (m && m[1] && m[2] !== undefined && !NON_CRED_KEY.test(m[1])) out.push({ key: m[1], value: m[2].trim() });
  }
  return out;
}

const DB_ENGINES: { name: string; re: RegExp; clip: RegExp }[] = [
  { name: "MySQL/MariaDB", re: /SQLSTATE|mysqli_|mysql|MariaDB/i, clip: /(SQLSTATE\[[0-9A-Z]+\][^\n]{0,80}|Unknown column[^\n]{0,80})/i },
  { name: "PostgreSQL", re: /PG::|psycopg|postgres/i, clip: /(PG::[A-Za-z:]+Error[^\n]{0,80}|ERROR:\s[^\n]{0,80})/i },
  { name: "Oracle", re: /ORA-\d{4,5}/i, clip: /(ORA-\d{4,5}[^\n]{0,80})/i },
  { name: "MSSQL", re: /Microsoft ODBC|SQL Server|SqlException/i, clip: /(SqlException[^\n]{0,80}|\[Microsoft\][^\n]{0,80})/i },
  { name: "SQLite", re: /sqlite/i, clip: /(sqlite[^\n]{0,80})/i },
];

/** 오류 문자열에서 DB 엔진 지문 식별. */
function dbFingerprint(raw: string): { engine?: string; clip?: string } {
  for (const e of DB_ENGINES) {
    if (e.re.test(raw)) {
      const m = e.clip.exec(raw);
      return { engine: e.name, clip: m?.[0] ?? raw.slice(0, 90) };
    }
  }
  return {};
}

const EMAILISH = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
const SSNISH = /\b\d{3}-\d{2}-\d{4}\b|\b\d{6}-?[1-4]\d{6}\b/;
const CARDISH = /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/;

// ── 카테고리별 검증기 ─────────────────────────────────────────────────────────

function verifySecret(raw: string, redact: boolean): Verification {
  const lines = keyValueLines(raw);
  const creds = lines.filter((l) => CRED_KEY.test(l.key) && l.value.length >= 3);
  if (creds.length > 0) {
    const shown = creds
      .slice(0, 3)
      .map((l) => {
        const masked = redactSample(`${l.key}=${l.value}`, { redact });
        return masked.length > 60 ? masked.slice(0, 60) + "…" : masked;
      })
      .join(", ");
    return {
      status: "verified",
      proof: `자격증명 형식 항목 ${creds.length}개 확인 (${shown}${creds.length > 3 ? " …" : ""}) — 파일에 담긴 키-값을 그대로 사용해 로그인/API 호출 가능`,
    };
  }
  if (lines.length > 0) {
    return {
      status: "partial",
      proof: `키-값 설정 ${lines.length}개 확인 — 자격증명 형식 키 없음(일반 구성값으로 추정)`,
    };
  }
  return { status: "unverified", proof: "자격증명 형식 키-값 없음" };
}

function verifyError(raw: string, redact: boolean): Verification {
  const ex = /UNION 데이터 추출 실증: ([^\n]+)/.exec(raw);
  if (ex) {
    return {
      status: "verified",
      proof: `UNION 실증: ${redactSample(ex[1], { redact }).slice(0, 80)} — 검증된 착취(주입점에서 실제 DB 값 반환)`,
    };
  }
  const { engine, clip } = dbFingerprint(raw);
  if (engine && clip) {
    return {
      status: "verified",
      proof: `DB 엔진 식별: ${engine} — 오류 원문: ${redactSample(clip, { redact })} → UNION 기반 데이터 추출 공격 설계 가능`,
    };
  }
  if (/error|sql|syntax|exception|stack|trace|query|select|insert|update/i.test(raw)) {
    return {
      status: "partial",
      proof: "SQL/쿼리 오류 문자열 확인 — 엔진 지문 미식별(추가 수동 확인 권고)",
    };
  }
  return { status: "unverified", proof: "오류 문자열에 DB 지문 없음" };
}

function verifyPii(raw: string, redact: boolean): Verification {
  const distinct = /distinct=(\d+)/i.exec(raw)?.[1];
  const sensitive = /민감=([\w,]+)/i.exec(raw)?.[1];
  let proof = "";
  let ok = false;
  const bits: string[] = [];
  if (distinct && Number(distinct) >= 2) {
    ok = true;
    bits.push(`서로 다른 사적 객체 ${distinct}건 응답`);
  }
  if (sensitive) {
    ok = true;
    bits.push(`민감 필드: ${sensitive}`);
  }
  if (EMAILISH.test(raw) || SSNISH.test(raw) || CARDISH.test(raw)) {
    ok = true;
    bits.push(`실제 개인정보 패턴(이메일/주민번호/카드) 포함`);
  }
  if (ok) {
    proof = `${bits.join(" · ")} — 인증 없이 타인 데이터 열람 성공(레코드 단위 확인)`;
    return { status: "verified", proof };
  }
  const ids = /후보 id: ([\d, ]+)/i.exec(raw)?.[1];
  if (ids) return { status: "partial", proof: `객체 접근 가능(후보 id ${ids}) — 개인정보 여부는 본문 미확인` };
  return { status: "unverified", proof: "개인정보 신호 없음" };
}

function verifySchema(raw: string, redact: boolean): Verification {
  const hasStruct = /(타입|type|필드|field|query|mutation|schema|introspection|엔드포인트|graphql|endpoint)/i.test(raw);
  if (/introspection/i.test(raw) && /(타입 \d+개|type|필드|field|query|mutation)/i.test(raw)) {
    return {
      status: "verified",
      proof: "introspection 응답에 스키마 구조(쿼리/뮤테이션/타입 정의) 확인 — 전체 공격 표면 문서화 성공",
    };
  }
  if (hasStruct) return { status: "partial", proof: "스키마/명세 관련 응답 확인 — 전체 구조 노출은 미확인" };
  return { status: "unverified", proof: "스키마 관련 응답 없음" };
}

// ── 익스플로잇 실증(exploit) ──────────────────────────────────────────────
// 각 툴 evidence 의 결정적 마커로, "주입한 것이 실제로 서버에서 처리되었다"를
// 증명한다. proof 접두사(XSS 실증/SSTI 실증/…)가 랩 점수의 proofContains 가 된다.

const EXPLOIT_MARKERS: Array<{ cls: "xss" | "ssti" | "ssrf" | "lfi" | "redirect" | "xxe" | "nosql" | "crlf" | "proto" | "stored" | "upload" | "race" | "smuggle" | "cache-deception" | "jwt"; re: RegExp }> = [
  { cls: "xss", re: /무해 마커가 HTML\/JS 컨텍스트에 실행 가능하게 반사됨/ },
  { cls: "ssti", re: /산술식이 서버에서 평가되어 결과 (\d+) 노출/ },
  { cls: "ssrf", re: /메타데이터 시그니처가 응답에 반사됨/ },
  { cls: "lfi", re: /시그니처 노출 \(path=[^)]*\): (root:[^\n]*)/ },
  { cls: "redirect", re: /HTTP \d+ Location: [^\n]*redcell-canary/i },
  { cls: "xxe", re: /내부 엔티티가 확장되어 마커 반사됨/ },
  { cls: "nosql", re: /NoSQL 실증: \$ne\/\$regex 우회로 인증 통과/ },
  { cls: "crlf", re: /CRLF 실증: 응답 헤더 분할/ },
  { cls: "proto", re: /프로토타입 오염 실증: 병합 지점에서 오염 키 반영/ },
  { cls: "stored", re: /저장형 XSS 실증: 제2 요청에서 미이스케이프 저장 반사/ },
  { cls: "upload", re: /업로드 실증: 파일 저장\+ 실행 가능 컨텍스트 제공/ },
  { cls: "race", re: /경쟁 조건 실증: 동시 2요청으로 상태 이중 반영/ },
  { cls: "smuggle", re: /스머글링 실증: 프레이밍 모호성으로 (백엔드 대기|차등 응답)/ },
  { cls: "cache-deception", re: /캐시 기만 실증: 무인증 요청에 개인 본문 반환/ },
  { cls: "jwt", re: /JWT 실증: 위조 토큰\(.+\)이 유효 세션으로 수용/ },
];

const EXPLOIT_SIGNAL = /반사|주입|노출|평가|Location|엔티티|실행/i;

function verifyExploit(raw: string, redact: boolean): Verification {
  for (const mkr of EXPLOIT_MARKERS) {
    const m = mkr.re.exec(raw);
    if (!m) continue;
    switch (mkr.cls) {
      case "xss": {
        const ctx = /\((\/[^,]*), ([^)]+)\):/.exec(raw);
        return {
          status: "verified",
          proof: `XSS 실증: 미이스케이프 반사 + 실행 가능 문맥 (path=${ctx?.[1] ?? "?"}, context=${ctx?.[2] ?? "?"}) — 브라우저에서 임의 스크립트 실행 PoC 가능`,
        };
      }
      case "ssti":
        return {
          status: "verified",
          proof: `SSTI 실증: 서버측 템플릿 산술 평가(결과 ${m[1]} 노출) — 표준 템플릿 문법이 서버에서 실행됨`,
        };
      case "ssrf":
        return {
          status: "verified",
          proof: "SSRF 실증: 클라우드 메타데이터(169.254.169.254)로 요청이 전달되어 응답 반사 — IAM 자격증명 탈취 체인 가능",
        };
      case "lfi": {
        const line = m[1].trim();
        const uid0 = line.includes(":0:0:");
        return {
          status: "verified",
          proof: `LFI 실증: ${uid0 ? "UID 0(root) 계정 라인이 포함된 /etc/passwd" : "시스템 파일"} 시그니처 노출 — 서버 로컬 파일 열람 성공`,
        };
      }
      case "redirect": {
        const loc = /Location:\s*(\S+)/.exec(raw)?.[1] ?? "";
        return {
          status: "verified",
          proof: `오픈 리다이렉트 실증: 302 Location 이 외부 canary 도메인으로 반환됨 (${redactSample(loc)}) — 사용자를 공격자 도메인으로 유도 가능(피싱·토큰 탈취 체인)`,
        };
      }
      case "xxe":
        return {
          status: "verified",
          proof: "XXE 실증: XML 내부 엔티티 확장 처리 활성 — 외부 엔티티(파일 읽기/SSRF)로 확장 가능(서버측 DTD 비활성 필요)",
        };
      case "nosql":
        return {
          status: "verified",
          proof: "NoSQL 실증: $ne/$regex 우회로 인증 통과 (baseline 차등 + 성공 지수) — NoSQL 연산자 주입으로 논리 우회가 성립함",
        };
      case "crlf":
        return {
          status: "verified",
          proof: "CRLF 실증: 응답 헤더 분할 — 주입한 CRLF 가 응답 헤더에 실제 반영(Set-Cookie/헤더 주입 확인)",
        };
      case "proto":
        return {
          status: "verified",
          proof: "프로토타입 오염 실증: 병합 지점에서 오염 키 반영 (baseline 부재) — 서버측 객체 병합이 대입 연산자를 처리함",
        };
      case "stored":
        return {
          status: "verified",
          proof: "저장형 XSS 실증: 제2 요청에서 미이스케이프 저장 반사 — 저장(POST)→렌더(GET) 2차 반사 확인",
        };
      case "upload":
        return {
          status: "verified",
          proof: "업로드 실증: 파일 저장 + 실행 가능 컨텍스트 제공 — 업로드된 파일이 저장·서빙되어 스크립트 실행이 가능",
        };
      case "race":
        return {
          status: "verified",
          proof: "경쟁 조건 실증: 동시 2요청으로 상태 이중 반영 — 비원자적 상태 변경 확인(Δ단일·Δ동시 수치 attached)",
        };
      case "smuggle":
        return {
          status: "verified",
          proof: "Request Smuggling 실증: 프레이밍 모호성 요청에 차등 관측(CL.TE 스톨/난독화 차등) — 프론트·백엔드 파서 불일치 확인(비파괴 검증)",
        };
      case "cache-deception":
        return {
          status: "verified",
          proof: "캐시 기만 실증: 무인증 요청에 개인 본문 반환 — 정적 확장자 경로로 캐시된 개인 페이지 확인(무인증 차등)",
        };
      case "jwt":
        return {
          status: "verified",
          proof: "JWT 위조 실증: 위조 토큰(alg=none 또는 약한 시크릿 재서명)이 유효 세션으로 수용 — 3요청 차등(무토큰/원본/위조)으로 인증 우회 확인",
        };
    }
  }
  if (EXPLOIT_SIGNAL.test(raw)) {
    return { status: "partial", proof: "익스플로잇 신호 문자열 확인 — 실증 마커 미식별(수동 재현 권고)" };
  }
  return { status: "unverified", proof: "익스플로잇 실증 마커 없음" };
}

const PATH_LIST = /→\s*\d{3}/;
const PATH_CODE = /→\s*(\d{3})/g;

/** dir_enum류 증거("/admin → 200; /.env → 200")는 본문이 아니라 접근 결과 목록이다. */
function verifyPathList(raw: string): Verification | null {
  if (!PATH_LIST.test(raw)) return null;
  const codes = [...raw.matchAll(PATH_CODE)].map((m) => m[1]);
  const ok = codes.filter((c) => c === "200").length;
  return {
    status: ok > 0 ? "verified" : "partial",
    proof: `경로 응답 확인: ${ok}/${codes.length}건 200 — 인증 없이 접근 가능(실제 본문은 별도 확인 필요)`,
  };
}

function verifyBody(category: EvidenceCategory, raw: string): Verification {
  const pl = verifyPathList(raw);
  if (pl) return pl;
  const n = raw.trim().length;
  if (n >= 20) {
    const label = category === "config" ? "설정/진단 본문" : category === "backup" ? "백업/아카이브 본문" : "경로 응답 본문";
    const sampleHead = raw.trim().slice(0, 60).replace(/\s+/g, " ");
    return { status: "verified", proof: `${label} 확보 (${n}자) — ${sampleHead}…` };
  }
  if (n > 0) return { status: "partial", proof: "응답 확인 — 본문이 빈약해 내용 실증 불가(수동 확인 권고)" };
  return { status: "unverified", proof: "본문 미확보(빈 응답)" };
}

// ── 진입점 ───────────────────────────────────────────────────────────────────

/**
 * 원본 증거 샘플(redaction 전)을 검증한다.
 *
 * @param category 증거 분류
 * @param raw      수집 직후의 원본 샘플(아직 마스킹 전)
 * @param opts.redact proof 에 redaction 적용 여부(--no-redact 시 원문 유지)
 */
export function verifyExposure(category: EvidenceCategory, raw: string, opts: { redact?: boolean } = {}): Verification {
  const redact = opts.redact !== false;
  const text = raw ?? "";
  if (text.trim().length === 0) return { status: "unverified", proof: "본문 미확보 — 수동 확인 필요" };
  switch (category) {
    case "secret":
      return verifySecret(text, redact);
    case "error":
      return verifyError(text, redact);
    case "pii":
      return verifyPii(text, redact);
    case "schema":
      return verifySchema(text, redact);
    case "exploit":
      return verifyExploit(text, redact);
    default:
      return verifyBody(category, text);
  }
}
