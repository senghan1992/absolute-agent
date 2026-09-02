/**
 * 인가 파일(authorization.yaml) 로더.
 * 파일이 없으면 예외를 던진다 — 인가 없이는 RedCell 가 절대 동작하지 않는다.
 */

import { promises as fs } from "node:fs";
import { parse } from "yaml";
import { ScopeGuard, type AuthorizationFile } from "./scope-guard.js";

export async function loadAuthorization(pathToYaml: string): Promise<ScopeGuard> {
  let raw: string;
  try {
    raw = await fs.readFile(pathToYaml, "utf8");
  } catch {
    throw new Error(
      `인가 파일을 찾을 수 없습니다: ${pathToYaml}\n` +
        `RedCell 는 인가 없이 동작하지 않습니다. config/authorization.example.yaml 를 복사해 작성하세요.`,
    );
  }
  const auth = parse(raw) as AuthorizationFile;
  validate(auth);
  return new ScopeGuard(auth);
}

function validate(a: AuthorizationFile): void {
  if (!a?.engagement?.authorized_until) throw new Error("인가 파일에 engagement.authorized_until 이 없습니다.");
  if (!a?.scope?.allow || a.scope.allow.length === 0) {
    throw new Error("인가 파일 scope.allow 가 비어 있습니다. 허용 대상이 없으면 아무 것도 할 수 없습니다.");
  }
}
