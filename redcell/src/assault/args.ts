/**
 * 툴 인자 자동 유도(assault 공용).
 *
 * 발견된 fingerprint(엔드포인트/파라미터/스택)를 보고 툴별로 적절한 인자를 만든다.
 * cli.ts 의 autoArgsFor 와 동일한 규칙을 공유한다(원본은 여기로 이동, cli 는 재수출).
 */

import type { Fingerprint } from "../memory/skill-memory.js";
import { forge, type VulnClass } from "../core/payload-forge.js";
import { argsFromMap, type TargetMap } from "../core/target-map.js";

export function autoArgsFor(toolName: string, fp: Fingerprint): Record<string, unknown> {
  const endpoints: string[] = [];
  for (const i of fp.indicators ?? []) {
    const m = /^endpoint (\/\S+)/.exec(i);
    if (m) endpoints.push(m[1]);
  }
  const forgeMap: Record<string, VulnClass> = {
    xss_probe: "xss",
    path_traversal: "lfi",
    open_redirect: "redirect",
    ssrf_probe: "ssrf",
  };
  // 발견된 엔드포인트에서 서로 다른 경로/파라미터 집합을 추출한다.
  // 취약점은 엔드포인트마다 다르므로(예: /tpl→SSTI, /ping→CMDI), 주입 계열
  // 툴에는 발견한 경로·파라미터 전체를 넘겨 발산적으로 스윕하게 한다.
  const paths = [...new Set(endpoints.map((e) => e.split("?")[0]))].slice(0, 12);
  const params = [
    ...new Set(
      endpoints.flatMap((e) => {
        const q = e.split("?")[1];
        return q ? [...new URLSearchParams(q).keys()] : [];
      }),
    ),
  ].filter(Boolean).slice(0, 12);

  if (endpoints.length === 0) {
    // 엔드포인트가 없어도 페이로드 툴은 fp 기반 변형을 실어 발산을 유지한다.
    return forgeMap[toolName] ? { payloads: forge(forgeMap[toolName], fp) } : {};
  }
  const first = endpoints[0];
  const path0 = first.split("?")[0];
  // 주입 계열 툴: 발견한 경로 전체를 스윕(+ 파라미터 힌트). 페이로드는 fp 기반 변형.
  if (forgeMap[toolName]) {
    const a: Record<string, unknown> = { paths, payloads: forge(forgeMap[toolName], fp) };
    if (params.length) a.params = params;
    return a;
  }
  switch (toolName) {
    case "api_probe":
      return { paths };
    case "ssti_probe":
    case "cmdi_probe":
    case "logic_probe":
    case "nosql_probe":
    case "crlf_probe":
    case "proto_pollution_probe":
    case "upload_verify":
    case "race_probe":
    case "stored_xss_probe": {
      const a: Record<string, unknown> = { paths };
      if (params.length) a.params = params;
      return a;
    }
    case "xxe_probe":
    case "deserialize_probe":
    case "auth_session_probe":
    case "cache_poison_probe":
    case "smuggle_probe":
      return { paths };
    case "cache_deception_probe":
      return { paths: paths.length ? paths : ["/"] };
    case "jwt_attack":
      return { paths };
    case "sqli_probe":
      // 주입 계열: 발견한 경로 전체를 스윕(오류 기반 → UNION 실증 추출까지 도달해야 함).
      return { paths, ...(params.length ? { params } : {}) };
    case "cors_audit":
      return { path: path0 };
    case "idor_probe": {
      const idPath = endpoints.find((e) => /\/\d+(\/?$)/.test(e.split("?")[0])) ?? first;
      return { path: idPath.split("?")[0] };
    }
    default:
      return {};
  }
}

/** --target-map 주입을 포함한 최종 args 함수. */
export function makeArgsFor(targetMap?: TargetMap): (tool: string, fp: Fingerprint) => Record<string, unknown> {
  return (tool: string, fp: Fingerprint) => {
    if (targetMap) {
      const fromMap = argsFromMap(tool, targetMap);
      if (fromMap) return fromMap;
    }
    return autoArgsFor(tool, fp);
  };
}
