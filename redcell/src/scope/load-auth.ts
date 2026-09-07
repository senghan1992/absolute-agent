/**
 * 인가 파일 로더 — 두 가지 형식을 자동 감지한다.
 *   1) 정식 Rules of Engagement YAML (engagement/scope/…)
 *   2) 간단 IP 목록 (한 줄에 대상 하나 — src/scope/ip-list.ts)
 * 파일이 없거나 허용 대상이 없으면 예외를 던진다 — 인가 없이는 RedCell 가 절대 동작하지 않는다.
 */

import { promises as fs } from "node:fs";
import { parse } from "yaml";
import { ScopeGuard, type AuthorizationFile } from "./scope-guard.js";
import { buildAuthFromIpList } from "./ip-list.js";

export interface LoadedAuth {
  guard: ScopeGuard;
  kind: "yaml" | "ip-list";
  path: string;
  /** 표시용 요약(scope/auth 명령 출력용). */
  summary: { allows: number; denies: number; until: string; ports?: number[] };
}

export async function loadAuthorization(filePath: string): Promise<LoadedAuth> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch {
    throw new Error(
      `인가 파일을 찾을 수 없습니다: ${filePath}\n` +
        `RedCell 는 인가 없이 동작하지 않습니다. redcell auth add <ip> 로 시작하거나 config/authorization.example.yaml 를 복사하세요.`,
    );
  }

  // YAML 객체(정식 형식)인지 먼저 시도 — 그 외(단순 IP 줄들)는 ip-list 로 해석.
  let yaml: unknown;
  try {
    yaml = parse(raw);
  } catch {
    yaml = undefined; // YAML 아님 → ip-list
  }
  if (yaml && typeof yaml === "object" && !Array.isArray(yaml) && ("engagement" in yaml || "scope" in yaml)) {
    const auth = yaml as AuthorizationFile;
    validate(auth);
    return { guard: new ScopeGuard(auth), kind: "yaml", path: filePath, summary: summarize(auth) };
  }

  const auth = buildAuthFromIpList(raw);
  return { guard: new ScopeGuard(auth), kind: "ip-list", path: filePath, summary: summarize(auth) };
}

function validate(a: AuthorizationFile): void {
  if (!a?.engagement?.authorized_until) throw new Error("인가 파일에 engagement.authorized_until 이 없습니다.");
  if (!a?.scope?.allow || a.scope.allow.length === 0) {
    throw new Error("인가 파일 scope.allow 가 비어 있습니다. 허용 대상이 없으면 아무 것도 할 수 없습니다.");
  }
}

function summarize(a: AuthorizationFile): LoadedAuth["summary"] {
  return {
    allows: a.scope.allow.length,
    denies: a.scope.deny?.length ?? 0,
    until: a.engagement.authorized_until,
    ports: a.ports?.allow_tcp,
  };
}