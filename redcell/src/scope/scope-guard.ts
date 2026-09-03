/**
 * ScopeGuard — RedCell의 안전 핵심(safety core).
 *
 * 모든 공격성 액션은 실행 전에 반드시 이 가드를 통과해야 한다.
 * "인가 파일(authorization.yaml)에 명시적으로 허용된 대상"이 아니면 거부한다.
 * deny 는 항상 allow 를 이긴다(fail-closed).
 */

import { isIPv4 } from "node:net";
import type { LoginConfig } from "../net/login.js";
import type { WaiverEntry } from "../report/provenance.js";

export type { LoginConfig };

export interface AuthorizationFile {
  engagement: {
    name: string;
    authorized_from: string;
    authorized_until: string;
    authorized_by: string;
    contact?: string;
    /** 실행 운영자 — 직무분리(인가자≠실행자) 근거. 리포트 출처에 기록. */
    operator?: string;
    /** 검사 대상의 커밋/빌드 참조(예: git SHA·이미지 태그). 리포트가 어떤 대상 상태를 봤는지 고정. */
    target_ref?: string;
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
  /**
   * 인증 컨텍스트(선택). 운영자가 인가된 계정으로 "로그인 뒤" 표면을 점검하도록
   * 세션 쿠키/토큰/커스텀 헤더를 넣는다. 여기 넣는 자격증명은 인가된 테스트 계정만.
   */
  credentials?: {
    /** Cookie 헤더 값 전체(예: "session=...; csrf=..."). */
    cookie?: string;
    /** Bearer 토큰(Authorization: Bearer <token> 로 전송). */
    bearer?: string;
    /** 임의 추가 헤더(예: X-API-Key). */
    headers?: Record<string, string>;
  };
  /**
   * 실제 로그인 플로우(선택). 정적 쿠키/토큰 대신 인가된 테스트 계정으로 폼/JSON 로그인을
   * 수행해 세션을 획득한다. 획득한 쿠키·토큰은 이후 모든 요청에 재사용된다.
   * 여기 넣는 자격증명은 반드시 인가된 테스트 계정만! (실제 사용자 계정 금지)
   */
  login?: LoginConfig;
  learning?: { persist_playbooks?: boolean; share_findings?: boolean };
  /**
   * 명시적 opt-in 이 필요한 부작용성 프로브를 대상별로 켠다(선택). 예: ["logic_probe", "cache_poison_probe"].
   * 여기 없거나 CLI --enable 로 켜지지 않은 프로브는 자율/모델 드라이버가 실행하지 않는다(안전 기본값).
   */
  optional_probes?: string[];
  /**
   * 정식 위험수용(waiver) 목록(선택). 승인자·사유·만료가 명시된 발견은 게이트에서
   * "수용된 위험"으로 분리된다(숨김이 아님 — 리포트에 별도 표기). 만료된 waiver 는 적용 안 됨.
   */
  waivers?: WaiverEntry[];
  /**
   * 리포트 무결성/서명 설정(선택). 비밀 키는 파일에 저장하지 않고 환경변수 이름만 참조한다.
   */
  report?: { signing_key_env?: string };
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

/** ScopeGuard 결정을 받아 감사 추적에 남기는 싱크(선택). 모든 allow/deny 를 관측한다. */
export interface ScopeAuditSink {
  scope(rec: { host: string; port?: number; intent?: string; allowed: boolean; reason: string }): void;
  resolvedIp(rec: { hostname: string; ip: string; allowed: boolean; reason: string }): void;
}

export class ScopeGuard {
  /** hostname → 최초로 해석된 IP. 같은 engagement 내에서 IP 가 바뀌면 rebinding 으로 간주해 차단. */
  private readonly resolvedPins = new Map<string, string>();
  /** 감사 싱크(선택) — 지정되면 모든 판정이 변조탐지 추적에 기록된다. */
  private sink?: ScopeAuditSink;

  constructor(private readonly auth: AuthorizationFile) {}

  /**
   * 감사 싱크를 붙인다(봉쇄 증거 기록). 안전 핵심 판정을 바꾸지 않으며, 판정 결과만 관측한다.
   * 싱크의 예외는 판정을 막지 않도록 삼킨다(감사 실패가 스캔을 좌우해선 안 됨 — 단, 열기 실패는
   * 상위에서 이미 걸러진다).
   */
  setAuditSink(sink: ScopeAuditSink): void {
    this.sink = sink;
  }

  /** 측면이동/내부대역 확장 금지 여부(기본 ON — 명시적으로 false 라야 꺼진다). */
  private get disallowLateral(): boolean {
    return this.auth.limits?.disallow_lateral_beyond_scope !== false;
  }

  /**
   * 연결 시점(connect-time) IP 검증. 호스트명이 실제로 해석된 IP 를 받아,
   *   1) deny 대상이면 거부,
   *   2) 인가 scope 가 그 IP/CIDR 를 명시적으로 허용하면 통과,
   *   3) 같은 호스트명이 이전과 다른 IP 로 해석되면(rebinding) 거부,
   *   4) 그 외(인가된 "호스트명"으로 도달했으나 IP 는 명시 인가 밖)일 때, disallow_lateral 이면
   *      내부/링크로컬/사설 대역(예: 169.254.169.254 메타데이터, 10/172.16/192.168, ULA)을 거부한다.
   * 이로써 "scope 에 넣은 이름이 내부 IP 로 해석"·DNS rebinding·TOCTOU 를 함께 막는다.
   * (루프백 127/8·::1 은 로컬 테스트 대상으로 흔하므로 자동거부 대상에서 제외한다.)
   */
  checkResolvedIp(hostname: string, ip: string): Decision {
    const d = this._decideResolvedIp(hostname, ip);
    try {
      this.sink?.resolvedIp({ hostname, ip, allowed: d.allowed, reason: d.reason });
    } catch { /* 감사 기록 실패가 판정을 막지 않는다 */ }
    return d;
  }

  private _decideResolvedIp(hostname: string, ip: string): Decision {
    for (const entry of this.auth.scope.deny ?? []) {
      if (this.matches(entry, ip)) {
        return { allowed: false, reason: `해석된 IP ${ip} 는 deny 목록(${describe(entry)})에 해당합니다.` };
      }
    }
    let explicitIp = false;
    for (const entry of this.auth.scope.allow) {
      if (entry.host && entry.host === ip) explicitIp = true;
      else if (entry.cidr && isIPv4(ip) && ipInCidr(ip, entry.cidr)) explicitIp = true;
      if (explicitIp) break;
    }
    const pinned = this.resolvedPins.get(hostname);
    if (pinned && pinned !== ip) {
      return { allowed: false, reason: `DNS rebinding 의심: ${hostname} 이 인가 확인 시점과 다른 IP 로 재해석됨(${pinned} → ${ip}). 차단합니다.` };
    }
    if (!explicitIp && this.disallowLateral && isInternalIp(ip)) {
      return {
        allowed: false,
        reason: `인가된 호스트명 ${hostname} 이 내부/사설/링크로컬 IP ${ip} 로 해석되었습니다 — 측면이동/SSRF/rebinding 방지로 차단합니다(허용하려면 해당 IP/CIDR 를 scope.allow 에 명시하거나 limits.disallow_lateral_beyond_scope=false).`,
      };
    }
    this.resolvedPins.set(hostname, ip);
    return { allowed: true, reason: `해석된 IP ${ip} 인가 확인됨(${hostname}).` };
  }

  /** 인가 기간이 유효한지 */
  private withinWindow(now = new Date()): boolean {
    const from = new Date(this.auth.engagement.authorized_from);
    const until = new Date(this.auth.engagement.authorized_until);
    // authorized_until 은 그 날의 끝까지 유효한 것으로 본다.
    until.setHours(23, 59, 59, 999);
    return now >= from && now <= until;
  }

  /** 핵심 판정 함수. 하나라도 어긋나면 fail-closed. 판정 결과는 감사 싱크에 기록된다. */
  check(target: Target, now = new Date()): Decision {
    const d = this._decide(target, now);
    try {
      this.sink?.scope({ host: target.host, port: target.port, intent: target.intent, allowed: d.allowed, reason: d.reason });
    } catch { /* 감사 기록 실패가 판정을 막지 않는다 */ }
    return d;
  }

  private _decide(target: Target, now = new Date()): Decision {
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

  /**
   * 인가 파일의 credentials 를 요청 헤더 맵으로 변환한다(없으면 undefined).
   * 툴은 ToolContext.auth 로 이 값을 받아 인증된 표면을 점검한다.
   */
  get authHeaders(): Record<string, string> | undefined {
    const c = this.auth.credentials;
    if (!c) return undefined;
    const headers: Record<string, string> = { ...(c.headers ?? {}) };
    if (c.cookie) headers["cookie"] = c.cookie;
    if (c.bearer) headers["authorization"] = `Bearer ${c.bearer}`;
    return Object.keys(headers).length ? headers : undefined;
  }

  /** 인가 파일의 로그인 플로우 설정(없으면 undefined). */
  get loginConfig(): LoginConfig | undefined {
    return this.auth.login;
  }

  /** 정식 위험수용(waiver) 목록. */
  get waivers(): WaiverEntry[] {
    return this.auth.waivers ?? [];
  }

  /** 인가 파일에서 대상별로 켠 opt-in 프로브 목록(없으면 빈 배열). */
  get enabledOptIns(): string[] {
    return this.auth.optional_probes ?? [];
  }

  /** 리포트 서명 키(환경변수 참조). 이름만 파일에 있고 값은 env 에서 읽는다. */
  signingKey(env: NodeJS.ProcessEnv = process.env): string | undefined {
    const name = this.auth.report?.signing_key_env;
    return name ? env[name] : undefined;
  }

  /** 리포트 출처(provenance)에 넣을 engagement 메타. */
  get engagementMeta(): { name: string; authorizedBy: string; operator?: string; targetRef?: string } {
    const e = this.auth.engagement;
    return { name: e.name, authorizedBy: e.authorized_by, operator: e.operator, targetRef: e.target_ref };
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

/**
 * "내부/사설/링크로컬" IP 인가? (측면이동·SSRF·rebinding 자동차단 대상)
 * 루프백(127/8, ::1)은 로컬 테스트 대상으로 흔하므로 여기서 제외한다(자동차단 안 함).
 * 대상: 169.254/16(링크로컬·클라우드 메타데이터), 10/8·172.16/12·192.168/16(RFC1918),
 *       100.64/10(CGNAT), 0.0.0.0/8, IPv6 fe80::/10(링크로컬)·fc00::/7(ULA)·unspecified.
 */
export function isInternalIp(ip: string): boolean {
  // IPv4-mapped IPv6(::ffff:a.b.c.d)는 v4 로 환산.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return isInternalIp(mapped[1]);
  if (isIPv4(ip)) {
    const cidrs = ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "0.0.0.0/8"];
    return cidrs.some((c) => ipInCidr(ip, c));
  }
  const low = ip.toLowerCase();
  if (low === "::" ) return true; // unspecified
  if (low.startsWith("fe8") || low.startsWith("fe9") || low.startsWith("fea") || low.startsWith("feb")) return true; // fe80::/10
  if (low.startsWith("fc") || low.startsWith("fd")) return true; // fc00::/7 ULA
  return false;
}
