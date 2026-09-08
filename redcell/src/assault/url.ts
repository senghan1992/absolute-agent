/**
 * URL → 공격 대상 변환 + 1플래그 인가(--authorize).
 *
 * assault 의 시작점: "URL 한 줄"을 받아 호스트/포트/시드 경로를 해석한다.
 * 원칙을 하나만 지킨다 — 인가(scope)는 운영자가 입력한 URL 자체다.
 *   - redcell assault --url http://10.13.37.5:8080/app
 *   - --authorize: URL 의 호스트를 개인 인가 목록(~/.redcell/authorization.list)에
 *     기록하고 이번 실행의 인가로 삼는다. 그 순간부터 판단 없이 자동 공격이 시작된다.
 *     (기록은 감사 추적에 남는다 — "내가 입력한 IP 가 곧 인가" 방식, 기존 redcell auth 와 동일)
 *
 * 도구는 도덕 판단을 하지 않는다. 목록에 없으면 차단될 뿐이고(fail-closed),
 * 판단은 전적으로 목록을 쓰는 운영자(사람)의 몫이다.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { classifyTarget } from "../scope/ip-list.js";
import type { AssaultTarget } from "./types.js";

export interface ParsedUrl extends AssaultTarget {
  /** URL 의 쿼리 파라미터(시드 endpoint 로 사용). */
  params: [string, string][];
}

const DEFAULT_PORTS: Record<string, number> = { "http:": 80, "https:": 443 };

/**
 * 사용자 URL → 대상. 형식 오류·http(s) 외 스킴은 즉시 예외(fail-closed).
 * 호스트는 classifyTarget(IP/CIDR/도메인) 규칙에 부합해야 인가 목록과 일관된다.
 */
export function parseAssaultUrl(raw: string): ParsedUrl {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new Error(`올바른 URL 이 아닙니다: '${raw}' — 예: http://10.13.37.5:8080/app?mode=1`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`http/https URL 만 지원합니다: '${raw}' (받은 스킴: ${u.protocol})`);
  }
  if (!u.hostname) throw new Error(`호스트가 없는 URL 입니다: '${raw}'`);
  // 인가 목록과 같은 검증 규칙을 적용한다(형식 불량 호스트는 어떤 경우에도 진행 불가).
  classifyTarget(u.hostname);

  const scheme = u.protocol === "https:" ? "https" : "http";
  const port = u.port ? Number(u.port) : DEFAULT_PORTS[u.protocol];
  const path = u.pathname === "" ? "/" : u.pathname;
  const params: [string, string][] = u.searchParams.size
    ? [...u.searchParams.entries()]
    : [];

  return { url: raw.trim(), scheme, host: u.hostname, port, path, params };
}

/**
 * --authorize: 호스트를 인가 목록 파일에 추가한다(이미 있으면 무해).
 * 기존 redcell auth add 와 같은 규칙(중복 무시, 헤더 유지, fail-closed 포맷).
 */
export async function authorizeTarget(filePath: string, target: AssaultTarget): Promise<{ added: boolean }> {
  const entry = target.host;
  classifyTarget(entry); // 형식 검증 — 잘못된 대상은 기록되지 않는다.

  let raw = "";
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch {
    raw = ""; // 파일 없음 → 새로 만든다.
  }
  const lines = raw.split(/\r?\n/);
  const exists = lines.some((l) => l.trim() === entry);
  if (exists) return { added: false };

  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const header =
    "# RedCell 인가 목록 — 아래에 적힌 대상만 인가됩니다.\n" +
    "# 한 줄에 하나: IP / CIDR / 도메인  ·  ! 접두사 = 제외(allow 를 이김)  ·  # 주석\n" +
    "# 선택 지시자:  until: YYYY-MM-DD  ·  ports: 80,443,8080\n";
  const body = (raw.trim() === "" ? header : raw.endsWith("\n") ? raw : raw + "\n") + entry + "\n";
  await fs.writeFile(filePath, body, "utf8");
  return { added: true };
}
