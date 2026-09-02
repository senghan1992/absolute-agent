/**
 * tool_call 인자/코드에서 "이 액션이 건드리는 대상 호스트"를 추출하고
 * 액션의 성격(intent)을 추정한다. 보수적으로 동작한다:
 * 호스트가 하나라도 잡히면 ScopeGuard 가 전부 검사하므로, 놓치기보다 넓게 잡는다.
 */

import type { Target } from "../src/scope/scope-guard.js";

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
// URL 또는 host:port, 그리고 흔한 네트워크 도구 인자에서의 호스트.
const URL_HOST = /\bhttps?:\/\/([a-z0-9.-]+)(?::\d+)?/gi;
const BARE_DOMAIN = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b/gi;

/** 문자열에서 후보 호스트 목록(중복 제거) 추출 */
export function extractHosts(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(URL_HOST)) found.add(m[1].toLowerCase());
  for (const m of text.matchAll(IPV4)) found.add(m[0]);
  for (const m of text.matchAll(BARE_DOMAIN)) {
    const d = m[1].toLowerCase();
    if (!isNoise(d)) found.add(d);
  }
  // localhost 는 URL_HOST/BARE_DOMAIN 에 안 잡히므로 별도.
  if (/\blocalhost\b/i.test(text)) found.add("localhost");
  return [...found];
}

// package.json, example.com 같은 흔한 비대상 도메인/파일명 잡음 제거.
const NOISE = new Set([
  "example.com",
  "example.org",
  "schema.org",
  "www.w3.org",
  "github.com",
  "githubusercontent.com",
]);
function isNoise(d: string): boolean {
  if (NOISE.has(d)) return true;
  // 파일 확장자처럼 보이는 것(a.json, index.html 등)은 호스트가 아님.
  if (/\.(json|html?|js|ts|py|txt|md|yaml|yml|css|png|jpe?g|svg|lock|toml|cfg|ini|log)$/i.test(d)) return true;
  return false;
}

/** 툴 이름/인자로 액션 성격 추정 → ScopeGuard 의 destructive/dos 판정에 사용 */
export function classifyIntent(toolName: string, argsStr: string): NonNullable<Target["intent"]> {
  const t = `${toolName} ${argsStr}`.toLowerCase();
  if (/\b(hping3|--flood|slowloris|siege|ab -n \d{5,}|stress|fork bomb|:\(\)\{)/.test(t)) return "dos";
  if (/\b(rm -rf|drop\s+table|truncate\s+table|mkfs|dd if=|shred|:>\s|del \/f|format )/.test(t)) return "destructive";
  if (/\b(msfconsole|sqlmap|exploit|payload|reverse shell|nc -e|bind shell)/.test(t)) return "exploit";
  if (/\b(nmap|gobuster|ffuf|dirb|nikto|enum|whatweb|wpscan)/.test(t)) return "enumerate";
  if (/\b(mimikatz|lsass|hashdump|persistence|lateral)/.test(t)) return "post";
  return "recon";
}
