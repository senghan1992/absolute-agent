/**
 * audit-log — 변조탐지(tamper-evident) 감사 추적.
 *
 * 공식 보안팀 툴은 "무엇을, 언제, 어떤 인가로, 어디까지 시도했는가"를 사후에 다툴 수 없게
 * 남겨야 한다(법적/규정 준수·사고 상관분석). 이 모듈은 그 기록을 **append-only JSONL** 로,
 * 그리고 **해시 체인**으로 남긴다: 각 항목은 이전 항목의 해시를 품으므로, 중간을 지우거나
 * 고치면 이후 전체 체인이 깨져 검증(verify)에서 드러난다.
 *
 * 핵심 기록원은 ScopeGuard 결정(모든 allow/deny) — "대상 범위를 절대 벗어나지 않았다"는
 * 봉쇄(containment) 증거다. 여기에 engagement 메타·수행 이벤트·발견을 함께 남긴다.
 *
 * 내구성: 항목마다 동기 append(fsync 유도) — 프로세스가 중간에 죽어도 그때까지의 기록은 남는다.
 */

import { appendFileSync, openSync, closeSync, fsyncSync, readFileSync, mkdirSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import os from "node:os";
import path from "node:path";

export const GENESIS_HASH = "0".repeat(64);

export type AuditKind = "engagement" | "scope" | "resolved-ip" | "request" | "finding" | "event" | "end";

export interface AuditEntry {
  /** 기록 시각(ISO8601). */
  ts: string;
  /** 이 파일 안에서 1부터 증가하는 순번(누락 탐지용). */
  seq: number;
  kind: AuditKind;
  /** engagement 이름(교차 상관용). */
  engagement: string;
  /** 종류별 페이로드(범위·요청·발견 등). */
  data: Record<string, unknown>;
  /** 직전 항목의 hash(제네시스는 0*64) — 체인 연결. */
  prevHash: string;
  /** sha256(prevHash + "\n" + canonicalJSON(이 항목에서 hash 를 뺀 것)). */
  hash: string;
}

/** 항목에서 hash 를 제외한 정규화 직렬화(키 정렬) — 해시 계산 입력. */
function canonical(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  const rec = obj as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(rec[k])).join(",") + "}";
}

function hashEntry(prevHash: string, entryNoHash: Omit<AuditEntry, "hash">): string {
  return createHash("sha256").update(prevHash + "\n" + canonical(entryNoHash)).digest("hex");
}

/** 감사 파일 경로: <dir>/<engagement>-<ts>-<rand>.jsonl */
export function auditFilePath(engagement: string, opts: { dir?: string; env?: NodeJS.ProcessEnv; now?: Date } = {}): string {
  const env = opts.env ?? process.env;
  const dir = opts.dir ?? env.REDCELL_AUDIT_DIR ?? path.join(env.REDCELL_HOME ?? path.join(os.homedir(), ".redcell"), "audit");
  const stamp = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, "-");
  const safe = engagement.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 60) || "engagement";
  return path.join(dir, `${safe}-${stamp}-${randomBytes(3).toString("hex")}.jsonl`);
}

export class AuditLog {
  private seq = 0;
  private prevHash = GENESIS_HASH;
  private closed = false;

  private constructor(
    readonly filePath: string,
    private readonly engagement: string,
  ) {}

  /**
   * 감사 로그를 연다(파일/디렉터리 생성). 실패해도 던지지 않고 no-op 로그를 돌려주면 안 된다 —
   * 감사 실패는 "봉쇄 증거 없음"이므로 상위(CLI)가 알 수 있도록 예외를 던진다.
   */
  static open(engagement: string, opts: { dir?: string; env?: NodeJS.ProcessEnv; now?: Date } = {}): AuditLog {
    const filePath = auditFilePath(engagement, opts);
    mkdirSync(path.dirname(filePath), { recursive: true });
    const log = new AuditLog(filePath, engagement);
    log.record("engagement", {
      startedAt: (opts.now ?? new Date()).toISOString(),
      pid: process.pid,
      argv: process.argv.slice(2),
      version: 1,
    });
    return log;
  }

  /** 한 항목을 체인에 추가하고 동기 append 한다. 반환값은 기록된 항목. */
  record(kind: AuditKind, data: Record<string, unknown>): AuditEntry {
    if (this.closed) throw new Error("감사 로그가 이미 닫혔습니다.");
    // 저장 시 JSON.stringify 가 undefined 값 키를 떨어뜨리므로, 해시 입력도 동일하게 정규화한다
    // (그러지 않으면 기록 시 해시와 재파싱 후 검증 해시가 어긋난다).
    const cleanData = JSON.parse(JSON.stringify(data ?? {})) as Record<string, unknown>;
    const base: Omit<AuditEntry, "hash"> = {
      ts: new Date().toISOString(),
      seq: ++this.seq,
      kind,
      engagement: this.engagement,
      data: cleanData,
      prevHash: this.prevHash,
    };
    const hash = hashEntry(this.prevHash, base);
    const entry: AuditEntry = { ...base, hash };
    // 동기 append + fsync 로 내구성 확보(크래시에도 이전 기록 보존).
    const fd = openSync(this.filePath, "a");
    try {
      appendFileSync(fd, JSON.stringify(entry) + "\n");
      try { fsyncSync(fd); } catch { /* fsync 미지원 FS 는 무시 */ }
    } finally {
      closeSync(fd);
    }
    this.prevHash = hash;
    return entry;
  }

  /** ScopeGuard 결정 기록(봉쇄 증거). */
  scope(rec: { host: string; port?: number; intent?: string; allowed: boolean; reason: string }): void {
    this.record("scope", rec as Record<string, unknown>);
  }

  /** 연결 시점 IP 검증 결정 기록. */
  resolvedIp(rec: { hostname: string; ip: string; allowed: boolean; reason: string }): void {
    this.record("resolved-ip", rec as Record<string, unknown>);
  }

  end(summary: Record<string, unknown> = {}): void {
    if (this.closed) return;
    this.record("end", { endedAt: new Date().toISOString(), ...summary });
    this.closed = true;
  }
}

export interface VerifyResult {
  ok: boolean;
  entries: number;
  /** 체인/순번이 처음 깨진 seq(있으면). */
  brokenAtSeq?: number;
  reason?: string;
}

/** 감사 파일의 해시 체인·순번 무결성을 재계산해 변조 여부를 검증한다. */
export function verifyAuditFile(filePath: string): VerifyResult {
  let text: string;
  try {
    text = readFileSync(filePath, "utf8");
  } catch (e) {
    return { ok: false, entries: 0, reason: `파일을 읽을 수 없습니다: ${(e as Error).message}` };
  }
  const lines = text.split("\n").filter((l) => l.trim());
  let prevHash = GENESIS_HASH;
  let expectedSeq = 0;
  for (let i = 0; i < lines.length; i++) {
    let entry: AuditEntry;
    try {
      entry = JSON.parse(lines[i]) as AuditEntry;
    } catch {
      return { ok: false, entries: i, brokenAtSeq: expectedSeq + 1, reason: `${i + 1}번째 줄 JSON 파싱 실패(손상/변조).` };
    }
    expectedSeq++;
    if (entry.seq !== expectedSeq) {
      return { ok: false, entries: i, brokenAtSeq: entry.seq, reason: `순번 불일치(누락/재정렬): 기대 ${expectedSeq}, 실제 ${entry.seq}.` };
    }
    if (entry.prevHash !== prevHash) {
      return { ok: false, entries: i, brokenAtSeq: entry.seq, reason: `이전 해시 불일치(항목 삭제/재정렬).` };
    }
    const { hash, ...noHash } = entry;
    if (hashEntry(prevHash, noHash) !== hash) {
      return { ok: false, entries: i, brokenAtSeq: entry.seq, reason: `해시 불일치(내용 변조).` };
    }
    prevHash = hash;
  }
  return { ok: true, entries: lines.length };
}
