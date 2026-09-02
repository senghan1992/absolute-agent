/**
 * ScopeGuard — RedCell의 안전 핵심(safety core).
 *
 * 모든 공격성 액션은 실행 전에 반드시 이 가드를 통과해야 한다.
 * "인가 파일(authorization.yaml)에 명시적으로 허용된 대상"이 아니면 거부한다.
 * deny 는 항상 allow 를 이긴다(fail-closed).
 */

import { isIPv4 } from "node:net";

export interface AuthorizationFile {
  engagement: {
    name: string;
    authorized_from: string;
    authorized_until: string;
    authorized_by: string;
    contact?: string;
  };
  scope: {
    allow: ScopeEntry[];
    deny?: ScopeEntry[];
  };
  ports?: { allow_tcp?: number[] };
  limits?: {
    max_requests_per_second?: number;
    disallow_destructive?: boolean;
    disallow_dos?: boolean;
    disallow_lateral_beyond_scope?: boolean;
  };
  learning?: { persist_playbooks?: boolean; share_findings?: boolean };
}

export interface ScopeEntry {
  host?: string;
  cidr?: string;
  domain?: string; // 와일드카드 허용: "*.example.local"
}

export interface Target {
  /** ip 또는 hostname */
  host: string;
  port?: number;
  /** 액션의 성격 — 파괴적/DoS 여부 판정에 사용 */
  intent?: "recon" | "enumerate" | "exploit" | "post" | "destructive" | "dos";
}

export type Decision =
  | { allowed: true; reason: string }
  | { allowed: false; reason: string };

export class ScopeGuard {
  constructor(private readonly auth: AuthorizationFile) {}

  /** 인가 기간이 유효한지 */
  private withinWindow(now = new Date()): boolean {
    const from = new Date(this.auth.engagement.authorized_from);
    const until = new Date(this.auth.engagement.authorized_until);
    // authorized_until 은 그 날의 끝까지 유효한 것으로 본다.
    until.setHours(23, 59, 59, 999);
    return now >= from && now <= until;
  }

  /** 핵심 판정 함수. 하나라도 어긋나면 fail-closed. */
  check(target: Target, now = new Date()): Decision {
    if (!this.withinWindow(now)) {
      return {
        allowed: false,
        reason: `인가 기간 밖입니다 (${this.auth.engagement.authorized_from} ~ ${this.auth.engagement.authorized_until}). 동작을 거부합니다.`,
      };
    }

    const limits = this.auth.limits ?? {};
    if (target.intent === "destructive" && limits.disallow_destructive !== false) {
      return { allowed: false, reason: "파괴적(destructive) 액션은 인가 파일에서 금지되어 있습니다." };
    }
    if (target.intent === "dos" && limits.disallow_dos !== false) {
      return { allowed: false, reason: "DoS/자원고갈 액션은 인가 파일에서 금지되어 있습니다." };
    }

    // deny 가 allow 를 이긴다.
    for (const entry of this.auth.scope.deny ?? []) {
      if (this.matches(entry, target.host)) {
        return { allowed: false, reason: `대상 ${target.host} 는 deny 목록(${describe(entry)})에 해당합니다.` };
      }
    }

    let allowedHost = false;
    for (const entry of this.auth.scope.allow) {
      if (this.matches(entry, target.host)) {
        allowedHost = true;
        break;
      }
    }
    if (!allowedHost) {
      return {
        allowed: false,
        reason: `대상 ${target.host} 는 인가된 scope 에 없습니다. 권한 있는 대상만 authorization.yaml 에 추가하세요.`,
      };
    }

    // 포트 제한
    const allowTcp = this.auth.ports?.allow_tcp;
    if (target.port != null && allowTcp && allowTcp.length > 0 && !allowTcp.includes(target.port)) {
      return { allowed: false, reason: `포트 ${target.port} 는 허용 포트 목록에 없습니다.` };
    }

    return { allowed: true, reason: `대상 ${target.host}${target.port ? ":" + target.port : ""} 인가 확인됨 (${this.auth.engagement.name}).` };
  }

  private matches(entry: ScopeEntry, host: string): boolean {
    if (entry.host) {
      if (entry.host === host) return true;
    }
    if (entry.domain) {
      if (matchDomain(entry.domain, host)) return true;
    }
    if (entry.cidr && isIPv4(host)) {
      if (ipInCidr(host, entry.cidr)) return true;
    }
    return false;
  }

  get requestsPerSecond(): number {
    return this.auth.limits?.max_requests_per_second ?? 10;
  }
}

function describe(e: ScopeEntry): string {
  return e.host ?? e.cidr ?? e.domain ?? "?";
}

/** "*.example.local" 형태의 와일드카드 도메인 매칭 */
export function matchDomain(pattern: string, host: string): boolean {
  if (pattern === host) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.local"
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return false;
}

/** IPv4 CIDR 포함 여부 */
export function ipInCidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  if (!isIPv4(ip) || !isIPv4(range) || Number.isNaN(bits) || bits < 0 || bits > 32) {
    return false;
  }
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (toInt(ip) & mask) === (toInt(range) & mask);
}

function toInt(ip: string): number {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}
