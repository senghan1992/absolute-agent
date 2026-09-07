/**
 * 간단 IP 목록 인가(ip-list) — "내가 입력한 대상 = 인가된 대상" 방식.
 *
 * 정식 Rules of Engagement(YAML)을 작성하기 부담스러울 때, 한 줄에 하나씩
 * 대상(IP/CIDR/도메인)만 적은 파일로 인가를 구성한다. 사람(운영자)이 직접
 * 목록을 관리하며(`redcell auth add/rm/list`), 안전 기본값은 그대로 유지된다:
 *   - deny(!) 는 항상 allow 를 이긴다 (fail-closed)
 *   - 파괴적/DoS 액션 차단, RPS 제한, 내부대역 측면이동 차단 (기본)
 *   - 인가 기간: until 지시자, 또는 기본 실행 시점 +365일
 *
 * 형식 (한 줄에 하나, # 주석):
 *   10.13.37.5            허용 IP
 *   10.13.37.0/24         허용 CIDR
 *   *.vulnlab.local       허용 도메인 (와일드카드)
 *   !10.13.37.1           제외(deny) — allow 에 있어도 최우선 차단
 *   until: 2027-12-31     (선택) 유효기간 종료일 — 없으면 실행 시점 +365일
 *   ports: 80,443,8080    (선택) 허용 포트 — 없으면 전 포트 허용
 */

import { isIPv4, isIPv6 } from "node:net";
import type { AuthorizationFile, ScopeEntry } from "./scope-guard.js";

export interface IpListEntry {
  /** allow(허용) 또는 deny(제외) */
  kind: "allow" | "deny";
  /** 대상 원문(접두사 제거된 값) */
  raw: string;
  type: "host" | "cidr" | "domain";
}

export interface ParsedIpList {
  entries: IpListEntry[];
  /** until 지시자(선택). 없으면 기본 실행 시점 +365일. */
  until?: string;
  /** ports 지시자(선택). 없으면 전체 포트. */
  ports?: number[];
}

const UNTIL_RE = /^until\s*:\s*(\d{4}-\d{2}-\d{2})\s*$/i;
const PORTS_RE = /^ports\s*:\s*([0-9,\s]+)\s*$/i;
/** 호스트명/도메인: 알파벳·숫자·하이픈·점, 와일드카드는 맨 앞 "*." 만. */
const HOSTNAME_RE = /^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/;

export const DEFAULT_LIST_FILE = "authorization.list";
/** 인가 목록 기본 유효기간: until 지시자가 없으면 실행 시점 + 365일. */
export const DEFAULT_VALIDITY_DAYS = 365;

/** 대상 문자열을 파싱해 항목 유형을 판정. 인식 불가/형식 불량이면 예외(fail-closed). */
export function classifyTarget(value: string): { type: "host" | "cidr" | "domain"; raw: string } {
  const v = value.trim();
  if (!v) throw new Error("빈 대상입니다.");
  if (v.includes("/")) {
    const [ip, bits] = v.split("/");
    const b = Number(bits);
    if (!isIPv4(ip) || !/^\d{1,2}$/.test(bits) || b < 0 || b > 32) {
      throw new Error(`잘못된 CIDR: '${v}' — IPv4/CIDR 형식(예: 10.0.0.0/24)이어야 합니다.`);
    }
    return { type: "cidr", raw: v };
  }
  if (isIPv4(v) || isIPv6(v)) return { type: "host", raw: v };
  // 숫자+점만으로 된 문자열이 IP 검증을 통과 못 했다면 호스트명으로 오인하지 않는다.
  if (/^\d+(\.\d+)*$/.test(v)) throw new Error(`잘못된 IP: '${v}'`);
  if (HOSTNAME_RE.test(v)) {
    return { type: v.startsWith("*.") ? "domain" : "host", raw: v };
  }
  throw new Error(`인식할 수 없는 대상: '${v}' — IP, CIDR(10.0.0.0/24), 또는 도메인(*.example.com)만 허용합니다.`);
}

/**
 * IP 목록 텍스트를 파싱한다.
 * 허용 항목이 하나도 없으면 예외(fail-closed) — 인가 없이는 동작하지 않는다.
 */
export function parseIpList(text: string): ParsedIpList {
  const entries: IpListEntry[] = [];
  let until: string | undefined;
  let ports: number[] | undefined;

  let lineNo = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    lineNo++;
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const untilM = UNTIL_RE.exec(line);
    if (untilM) {
      const d = new Date(`${untilM[1]}T00:00:00Z`);
      if (Number.isNaN(d.getTime())) {
        throw new Error(`잘못된 until 날짜: '${untilM[1]}' (YYYY-MM-DD 형식).`);
      }
      until = untilM[1];
      continue;
    }
    const portsM = PORTS_RE.exec(line);
    if (portsM) {
      const nums = portsM[1].split(",").map((s) => Number(s.trim())).filter((n) => Number.isInteger(n) && n > 0 && n <= 65535);
      if (nums.length === 0) {
        throw new Error(`잘못된 ports 지시자: '${line}' — 숫자 포트 목록(예: ports: 80,443,8080).`);
      }
      ports = nums;
      continue;
    }

    let kind: "allow" | "deny" = "allow";
    let v = line;
    if (v.startsWith("!")) {
      kind = "deny";
      v = v.slice(1).trim();
    }
    let cls: { type: "host" | "cidr" | "domain"; raw: string };
    try {
      cls = classifyTarget(v);
    } catch (e) {
      throw new Error(`${(e as Error).message} (${lineNo}번째 줄)`);
    }
    entries.push({ kind, raw: cls.raw, type: cls.type });
  }

  if (!entries.some((e) => e.kind === "allow")) {
    throw new Error("인가 목록에 허용 대상이 하나도 없습니다. redcell auth add <ip> 로 추가하세요.");
  }
  return { entries, until, ports };
}

function toScopeEntry(e: IpListEntry): ScopeEntry {
  if (e.type === "cidr") return { cidr: e.raw };
  if (e.type === "domain") return { domain: e.raw };
  return { host: e.raw };
}

/**
 * IP 목록 텍스트를 정식 AuthorizationFile 로 변환한다.
 * 인가 기간: until 지시자, 없으면 기본 +365일 (사람 운영자가 직접 관리한다고 가정).
 */
export function buildAuthFromIpList(text: string, opts: { now?: Date } = {}): AuthorizationFile {
  const { entries, until, ports } = parseIpList(text);
  const now = opts.now ?? new Date();
  const from = now.toISOString().slice(0, 10);
  const untilDate = until ? new Date(`${until}T23:59:59`) : new Date(now.getTime() + DEFAULT_VALIDITY_DAYS * 24 * 3600 * 1000);

  const allow: ScopeEntry[] = [];
  const deny: ScopeEntry[] = [];
  for (const e of entries) (e.kind === "allow" ? allow : deny).push(toScopeEntry(e));

  return {
    engagement: {
      name: "ip-list",
      authorized_from: from,
      authorized_until: untilDate.toISOString().slice(0, 10),
      authorized_by: "operator (ip-list)",
      operator: "operator",
    },
    scope: { allow, deny },
    ...(ports ? { ports: { allow_tcp: ports } } : {}),
  };
}