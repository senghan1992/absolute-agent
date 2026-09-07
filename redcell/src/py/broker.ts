/**
 * py/broker — RedCell 의 "absolute-agent" 기반: 에이전트가 직접 쓴 Python 코드를
 * **안전하게** 실행하는 substrate.
 *
 * 근본 목적: 고정 툴박스에서 고르는 대신, 에이전트가 파이썬을 스스로 써가며 여러 공격
 * 방법을 순차적으로 모색한다(prime-agent 의 RLM식 자기발전 루프). 그러려면 임의 코드를
 * 실행해야 하는데, RedCell 의 안전 핵심(ScopeGuard·RPS·비파괴)이 절대 뚫려선 안 된다.
 *
 * 안전 설계(safe-by-construction):
 *   1) 대상과의 모든 HTTP 는 파이썬이 직접 하지 않는다. 파이썬은 로컬 "브로커"(127.0.0.1 의
 *      임시 포트, 1회용 토큰)에게 요청을 넘기고, **Node 가 ScopeGuard.check + httpRequest 로
 *      대신 수행**한다 → scope·RPS·auth·프록시가 기존 경로 그대로 강제된다(우회 불가).
 *   2) **AST 허용목록(allowlist) 샌드박스**: 사용자 코드는 모듈로 직접 실행되지 않는다. 신뢰
 *      되는 runner 가 먼저 사용자 코드를 `ast` 로 파싱해 (a) import 를 안전한 화이트리스트로만
 *      제한하고, (b) eval/exec/compile/open/getattr 등 위험 빌트인 호출과, (c) __class__/
 *      __globals__/__subclasses__ 같은 던더(dunder) 접근을 — 속성/이름뿐 아니라 **문자열
 *      리터럴 안의 던더**와 문자열로 속성경로를 해석하는 동적 게이더(operator.attrgetter·
 *      str.format/format_map·string.Formatter)까지 — 거부한 뒤, (d) 위험 빌트인을 뺀
 *      제한된 __builtins__(가드된 __import__ 포함)로만 exec 한다.
 *      (scanDanger 정규식은 프로세스를 띄우기 전 빠른 1차 거부로 남겨둔다 — 심층방어.)
 *
 *   ⚠️ 정직한 위협모델: in-process AST 허용목록은 알려진 탈출 게이더(문자열-던더·operator·
 *      format 계열)를 닫지만, CPython 인트로스펙션 표면이 넓어 "구성적으로 불가능"을 보장하는
 *      절대 경계는 아니다. **부하를 지는(load-bearing) 보증은 아래 (1)(4)** — 대상 HTTP 는
 *      브로커(ScopeGuard) 경유로만 나가고, stdlib egress 는 fail-closed 다. 신뢰 경계 밖
 *      코드(라이브 LLM 출력·프롬프트 인젝션 가능 입력)를 돌릴 때는 이 계층에만 의존하지 말고
 *      프로세스/OS 레벨 격리(별 인터프리터·seccomp·네임스페이스·컨테이너)를 반드시 병행하라.
 *   3) 격리: 임시 작업 디렉터리 + 타임아웃(SIGKILL) + 출력 상한 + 요청 예산.
 *   4) accidental egress fail-closed: HTTP(S)_PROXY 를 죽은 주소로 설정하고 no_proxy 에
 *      루프백만 허용 → 사용자 코드가 실수로 stdlib 로 외부에 나가면 브로커가 아니라 사망한다.
 *
 * 이 계층은 "실행/전송"만 책임진다. 어떤 코드를 쓸지는 상위 PythonAgent(모델)가 정한다.
 */

import http from "node:http";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { AddressInfo } from "node:net";
import { ScopeGuard, type Target } from "../scope/scope-guard.js";
import { httpRequest, newJar } from "../net/http-client.js";
import { RateLimiter } from "../net/rate-limiter.js";
import type { CookieJar } from "../net/http-client.js";
import type { EngagementFinding } from "../core/types.js";
import { detectIsolation, type IsolationBackend } from "./isolate.js";

export interface PyRunOpts {
  guard: ScopeGuard;
  target: Target;
  /** 인증 헤더(로그인 세션/토큰). 브로커가 대상 요청에 병합한다. */
  auth?: Record<string, string>;
  jar?: CookieJar;
  proxy?: string;
  /** 코드 실행 타임아웃(ms). 기본 15000. */
  timeoutMs?: number;
  /** 브로커가 허용하는 대상 요청 총량(폭주 방지). 기본 80. */
  maxRequests?: number;
  /** stdout/stderr 각각의 문자 상한. 기본 20000. */
  outputCap?: number;
  /** 브로커를 통과한 요청마다 호출(실시간 이벤트/감사용). */
  onRequest?: (info: { method: string; url: string; status?: number; blocked?: string }) => void;
  /** python 실행 파일(기본 python3). */
  python?: string;
  /**
   * OS 격리 정책(기본 "required"). 페이로드는 신뢰불가 코드(LLM 작성)로 간주하므로,
   *   - "required": 동작하는 OS 격리 백엔드가 있어야 실행. 없으면 실행 거부(fail-closed).
   *   - "best-effort": 백엔드가 있으면 쓰고, 없으면 경고와 함께 in-process 샌드박스만으로 실행.
   *   - "off": 격리를 요구하지 않음(신뢰되는 오프라인 코드/테스트 전용).
   */
  isolation?: "required" | "best-effort" | "off";
  /** true 면 코드를 신뢰(오프라인 MockCoder/테스트) — 격리 정책을 우회한다. */
  trusted?: boolean;
}

export interface PyFinding {
  title: string;
  severity: EngagementFinding["severity"];
  evidence?: string;
  impact?: string;
}

export interface PyResult {
  /** 정적 스캔·AST 허용목록 통과 + 프로세스가 정상 종료(exit 0)했는가. */
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  /** 브로커가 실제 대상에 보낸 요청 수. */
  requests: number;
  /** scope/예산 위반으로 브로커가 막은 요청 수. */
  blockedRequests: number;
  /** 코드가 rc.finding(...) 으로 보고한 발견. */
  findings: PyFinding[];
  /** 코드가 rc.log(...) 로 남긴 라인. */
  logs: string[];
  /** 적용된 OS 격리 정보(감사/투명성용). backend=null 이면 격리 없이 실행됨. */
  isolation?: { backend: string | null; warning?: string };
  /**
   * 실행이 거부된 사유(이 경우 ok=false). 두 계층 중 하나:
   *   - 정적 스캔(scanDanger): 프로세스를 띄우기 전 1차 거부 → exitCode=null.
   *   - AST 허용목록(runner): 프로세스는 떴지만 payload 를 exec 하지 않고 거부 → exitCode=0.
   */
  danger?: string;
}

const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);

/**
 * 사용자 코드 정적 위험 스캔. 파괴적 파일작업·scope 우회 직접 네트워크·네이티브 탈출을
 * 차단한다. 대상과의 통신은 반드시 `rc` 헬퍼(브로커 경유)로만 하도록 강제하는 게 목적이다.
 * (완전한 샌드박스가 아니라 심층방어의 한 겹 — 반환값이 있으면 실행하지 않는다.)
 */
export function scanDanger(code: string): string | null {
  const checks: Array<[RegExp, string]> = [
    [/\bshutil\s*\.\s*rmtree\b/, "파일 트리 삭제(shutil.rmtree) 금지"],
    [/\bos\s*\.\s*(remove|unlink|rmdir)\b/, "파일 삭제(os.remove/unlink/rmdir) 금지"],
    [/\brm\s+-rf\b/, "rm -rf 금지"],
    [/\bos\s*\.\s*system\b/, "os.system(쉘 실행) 금지 — 대상 통신은 rc 헬퍼로"],
    [/\b(subprocess|pty|multiprocessing)\b/, "하위 프로세스 실행 금지"],
    [/\bimport\s+socket\b|\bfrom\s+socket\b/, "raw socket 금지(scope 우회 방지) — rc 헬퍼 사용"],
    [/\bimport\s+requests\b|\bfrom\s+requests\b/, "requests 직접 사용 금지(scope 우회 방지) — rc 헬퍼 사용"],
    [/\bhttp\s*\.\s*client\b|\bimport\s+http\.client\b/, "http.client 직접 사용 금지 — rc 헬퍼 사용"],
    [/\burllib\b/, "urllib 직접 사용 금지(scope 우회 방지) — rc 헬퍼 사용"],
    [/\b(ftplib|smtplib|telnetlib|asyncio\s*\.\s*open_connection)\b/, "직접 네트워크 라이브러리 금지"],
    [/\bimport\s+ctypes\b|\bctypes\b/, "ctypes(네이티브 탈출) 금지"],
    [/\bopen\s*\(\s*["']\/(?!tmp\/|proc\/|dev\/null)/, "절대경로 파일 열기 금지(작업 디렉터리 내에서만)"],
  ];
  for (const [re, msg] of checks) {
    if (re.test(code)) return msg;
  }
  return null;
}

/**
 * 사용자 코드 exec 시 허용하는 모듈 화이트리스트(가드된 __import__ 가 이것만 통과시킨다).
 * 네트워크(socket/urllib.request/http/ftplib…)·프로세스(subprocess/os/pty)·네이티브(ctypes)·
 * 역직렬화 실행(pickle/marshal)·파일시스템(shutil/pathlib/tempfile)·인트로스펙션(inspect/gc/
 * importlib)은 전부 빠져 있다. 대상 통신은 오직 rc 헬퍼(브로커 경유)로만 가능하다.
 * urllib 은 파싱 전용 서브모듈(urllib.parse)만 허용하고 urllib.request 는 막는다.
 */
const ALLOWED_PY_MODULES = [
  "json",
  "base64",
  "re",
  "math",
  "random",
  "secrets",
  "string",
  "itertools",
  "functools",
  // operator 는 의도적으로 제외한다: operator.attrgetter/methodcaller 는 문자열 인자로
  // 던더 속성 체인(__class__/__globals__/__subclasses__)에 접근하는 샌드박스 탈출 게이더다.
  "collections",
  "collections.abc",
  "datetime",
  "struct",
  "binascii",
  "hashlib",
  "hmac",
  "html",
  "html.parser",
  "textwrap",
  "uuid",
  "decimal",
  "fractions",
  "statistics",
  "copy",
  "heapq",
  "bisect",
  "zlib",
  "gzip",
  "io",
  "csv",
  "urllib.parse",
];

/**
 * 신뢰되는 runner 스크립트 전문. 순서:
 *   1) rc 헬퍼(브로커 경유 HTTP + finding/log) 를 정상(full) 빌트인으로 정의한다.
 *   2) argv[1] 의 payload.py(에이전트가 쓴 원본 코드)를 읽어 `ast` 로 파싱·검증한다.
 *      - import 는 ALLOWED_PY_MODULES 화이트리스트만 허용(부분/우회 불가). operator 제외.
 *      - eval/exec/compile/open/getattr/__import__ 등 위험 빌트인 호출 금지.
 *      - __class__/__globals__/__subclasses__ 등 던더 접근·참조 금지 + 문자열 리터럴 내 던더
 *        + format/format_map/vformat/get_field 동적 속성접근 게이더 금지(샌드박스 탈출 차단).
 *   3) 위반이면 실행하지 않고 "##RC_DANGER## 사유" 를 출력하고 종료한다.
 *   4) 통과하면 위험 빌트인을 제거한 제한된 __builtins__(가드된 __import__ 포함) 로만 exec.
 *      런타임에도 화이트리스트 밖 모듈은 로드 불가 → AST 검사의 런타임 백스톱.
 * payload 는 절대 모듈로 직접 실행되지 않는다(항상 이 검증을 거친다).
 */
function runnerScript(): string {
  const allowed = JSON.stringify(ALLOWED_PY_MODULES);
  return [
    "import os as _os, sys as _sys, json as _json, base64 as _b64, ast as _ast, builtins as _builtins, re as _re",
    "import urllib.request as _u",
    '_B = _os.environ["RC_BROKER"]; _TK = _os.environ["RC_TOKEN"]',
    "",
    "# ── rc 헬퍼(신뢰 코드, full builtins) : 대상 통신은 전부 로컬 브로커에 위임 ──",
    "class ScopeError(Exception): pass",
    "class Resp:",
    "    def __init__(self, d):",
    '        self.status = d.get("status"); self.headers = d.get("headers", {})',
    '        self.text = d.get("body", ""); self.url = d.get("url")',
    "    def json(self):",
    "        return _json.loads(self.text)",
    "    def __repr__(self):",
    '        return "<Resp %s %s %db>" % (self.status, self.url, len(self.text or ""))',
    "def _call(payload):",
    '    req = _u.Request(_B + "/req", data=_json.dumps(payload).encode(),',
    '                     headers={"x-rc-token": _TK, "content-type": "application/json"})',
    "    with _u.urlopen(req, timeout=40) as r:",
    "        d = _json.loads(r.read().decode())",
    '    if "scopeError" in d: raise ScopeError(d["scopeError"])',
    "    return Resp(d)",
    "class _RC:",
    "    ScopeError = ScopeError",
    "    def http(self, method, path, headers=None, body=None, data=None, json=None, cap=6000, redirect='manual'):",
    "        h = dict(headers or {})",
    "        if json is not None:",
    "            body = _json.dumps(json); h.setdefault('content-type', 'application/json')",
    "        if data is not None:",
    "            from urllib.parse import urlencode",
    "            body = urlencode(data); h.setdefault('content-type', 'application/x-www-form-urlencoded')",
    "        key = 'url' if '://' in path else 'path'",
    "        return _call({'method': method, key: path, 'headers': h, 'body': body, 'cap': cap, 'redirect': redirect})",
    "    def get(self, path, **kw): return self.http('GET', path, **kw)",
    "    def post(self, path, **kw): return self.http('POST', path, **kw)",
    "    def b64e(self, data):",
    "        if isinstance(data, str): data = data.encode()",
    "        return _b64.b64encode(data).decode()",
    "    def b64d(self, s):",
    "        return _b64.b64decode(s + '=' * (-len(s) % 4))",
    "    def finding(self, title, severity='medium', evidence=None, impact=None):",
    "        print('##RC_FINDING## ' + _json.dumps({'title': title, 'severity': severity, 'evidence': evidence, 'impact': impact}), flush=True)",
    "    def log(self, *a):",
    "        print('##RC_LOG## ' + ' '.join(str(x) for x in a), flush=True)",
    "rc = _RC()",
    "",
    "# ── AST 허용목록 검증 ────────────────────────────────────────────────────",
    `_ALLOWED_MODULES = set(${allowed})`,
    // 이름으로 호출 자체를 금지하는 위험 빌트인(제한 builtins 에서도 빠지지만 명확한 사유로 선차단).
    "_FORBIDDEN_CALLS = {'eval','exec','compile','open','__import__','input','breakpoint','getattr','setattr','delattr','globals','locals','vars','memoryview','exit','quit','help','copyright','credits','license','execfile','reload'}",
    // 문자열로 속성 경로를 해석하는 동적 속성접근 게이더(str.format/format_map, string.Formatter
    // 의 vformat/get_field/format_field). 문자열 인자로 던더 체인에 닿을 수 있으므로 메서드
    // 호출 자체를 금지한다(payload 는 f-string 또는 % 포매팅을 쓰면 된다 — 이들은 AST 로 잡힌다).
    "_FORBIDDEN_ATTR_CALLS = {'format','format_map','vformat','get_field','format_field'}",
    // Name 으로 참조 시 허용하는 예외 던더(이외의 던더 이름/속성은 전부 거부).
    "_ALLOWED_DUNDER_NAMES = {'__name__','__doc__'}",
    "_DUNDER_RE = _re.compile(r'__[A-Za-z0-9_]+__')",
    "def _is_dunder(s):",
    "    return isinstance(s, str) and len(s) > 4 and s.startswith('__') and s.endswith('__')",
    "def _validate(src):",
    "    try:",
    "        tree = _ast.parse(src, filename='payload.py')",
    "    except SyntaxError as e:",
    "        return '문법 오류: ' + str(e)",
    "    for node in _ast.walk(tree):",
    "        if isinstance(node, _ast.Import):",
    "            for a in node.names:",
    "                if a.name not in _ALLOWED_MODULES:",
    "                    return 'import 금지(허용 목록 밖): ' + a.name",
    "        elif isinstance(node, _ast.ImportFrom):",
    "            if node.level and node.level > 0:",
    "                return '상대 import 금지'",
    "            if (node.module or '') not in _ALLOWED_MODULES:",
    "                return 'import 금지(허용 목록 밖): ' + str(node.module)",
    "        elif isinstance(node, _ast.Attribute):",
    "            if _is_dunder(node.attr):",
    "                return '던더 속성 접근 금지(샌드박스 탈출 방지): .' + node.attr",
    "            if node.attr in _FORBIDDEN_ATTR_CALLS:",
    "                return '동적 속성접근 메서드 금지(샌드박스 탈출 방지): .' + node.attr + ' — f-string/% 사용'",
    "        elif isinstance(node, _ast.Name):",
    "            if _is_dunder(node.id) and node.id not in _ALLOWED_DUNDER_NAMES:",
    "                return '던더 이름 참조 금지: ' + node.id",
    "        elif isinstance(node, _ast.Constant):",
    "            if isinstance(node.value, str) and _DUNDER_RE.search(node.value):",
    "                return '문자열 리터럴 내 던더 금지(문자열 경유 속성접근 방지): ' + node.value[:40]",
    "        elif isinstance(node, _ast.Call):",
    "            f = node.func",
    "            if isinstance(f, _ast.Name) and f.id in _FORBIDDEN_CALLS:",
    "                return '위험 빌트인 호출 금지: ' + f.id + '(...)'",
    "    return None",
    "",
    "# ── 제한된 __builtins__ (위험 빌트인 제거 + 가드된 __import__) ─────────────",
    "def _guarded_import(name, g=None, l=None, fromlist=(), level=0):",
    "    if level and level > 0:",
    "        raise ImportError('상대 import 금지')",
    "    if name not in _ALLOWED_MODULES:",
    "        raise ImportError('import 금지(허용 목록 밖): ' + name)",
    "    return _builtins.__import__(name, g, l, fromlist, level)",
    "_SAFE_BUILTIN_NAMES = ['abs','all','any','ascii','bin','bool','bytearray','bytes','callable','chr','complex','dict','divmod','enumerate','filter','float','format','frozenset','hasattr','hash','hex','id','int','isinstance','issubclass','iter','len','list','map','max','min','next','object','oct','ord','pow','print','range','repr','reversed','round','set','slice','sorted','str','sum','tuple','type','zip','sorted','True','False','None','NotImplemented','Ellipsis','Exception','BaseException','ValueError','TypeError','KeyError','IndexError','AttributeError','RuntimeError','StopIteration','StopAsyncIteration','ZeroDivisionError','ArithmeticError','OverflowError','FloatingPointError','AssertionError','NotImplementedError','LookupError','NameError','UnicodeError','UnicodeDecodeError','UnicodeEncodeError','OverflowError','RecursionError','KeyboardInterrupt','GeneratorExit','ImportError','ModuleNotFoundError']",
    "_safe_builtins = {}",
    "for _n in _SAFE_BUILTIN_NAMES:",
    "    if hasattr(_builtins, _n): _safe_builtins[_n] = getattr(_builtins, _n)",
    "_safe_builtins['__import__'] = _guarded_import",
    "",
    "# ── payload 로드 → 검증 → 제한 exec ──────────────────────────────────────",
    "_payload_path = _sys.argv[1]",
    "with open(_payload_path, 'r', encoding='utf-8') as _f:",
    "    _src = _f.read()",
    "_bad = _validate(_src)",
    "if _bad is not None:",
    "    print('##RC_DANGER## ' + _bad, flush=True)",
    "    _sys.exit(0)",
    "_sandbox = {'__builtins__': _safe_builtins, 'rc': rc, '__name__': '__rc_payload__', '__doc__': None}",
    "_code = compile(_src, 'payload.py', 'exec')",
    "exec(_code, _sandbox)",
    "",
  ].join("\n");
}

/**
 * 파이썬 코드 하나를 안전하게 실행한다. 대상 HTTP 는 브로커(ScopeGuard)를 반드시 경유한다.
 */
export async function runPython(code: string, opts: PyRunOpts): Promise<PyResult> {
  const timeoutMs = opts.timeoutMs ?? 15000;
  const maxRequests = opts.maxRequests ?? 80;
  const outputCap = opts.outputCap ?? 20000;

  // 1) 정적 위험 스캔 — 걸리면 실행조차 하지 않는다(fail-closed).
  const danger = scanDanger(code);
  if (danger) {
    return { ok: false, stdout: "", stderr: "", exitCode: null, timedOut: false, requests: 0, blockedRequests: 0, findings: [], logs: [], danger };
  }

  // 1.5) OS 격리 정책(fail-closed). 페이로드는 신뢰불가 코드로 간주한다(LLM 작성 + 대상 응답이
  //      프롬프트 인젝션으로 흘러들 수 있음). in-process AST 샌드박스가 탈출되면 호스트 RCE 가
  //      되므로, 신뢰불가 코드는 "동작이 검증된" OS 격리 백엔드가 있어야만 실행한다.
  const isolationMode = opts.isolation ?? "required";
  const trusted = opts.trusted ?? false;
  let backend: IsolationBackend | null = null;
  let isolationWarning: string | undefined;
  if (!trusted && isolationMode !== "off") {
    backend = await detectIsolation();
    if (!backend) {
      if (isolationMode === "required") {
        return {
          ok: false, stdout: "", stderr: "", exitCode: null, timedOut: false, requests: 0, blockedRequests: 0, findings: [], logs: [],
          danger:
            "OS 격리 백엔드(bwrap 등)를 사용할 수 없어 신뢰불가(라이브 모델) 코드 실행을 거부합니다(fail-closed). " +
            "비특권 네임스페이스가 허용된 호스트에서 실행하거나, 신뢰되는 오프라인 코드에 한해 isolation:'off' 를 명시하세요.",
          isolation: { backend: null },
        };
      }
      isolationWarning =
        "OS 격리 백엔드 없음 — in-process AST 샌드박스만으로 실행합니다(best-effort). 신뢰불가 코드에는 권장하지 않습니다.";
    }
  }

  const token = randomBytes(24).toString("hex");
  const limiter = new RateLimiter(opts.guard.requestsPerSecond);
  // 멀티스텝 세션: run 하나 안에서 rc 호출 간 쿠키가 유지되도록 항상 jar 를 둔다(로그인
  // 플로우를 파이썬으로 직접 수행 가능). 세션 jar 가 주어지면 그걸 쓰고, 없으면 run 로컬 jar.
  const jar: CookieJar = opts.jar ?? newJar();
  const scheme = opts.target.port === 443 || opts.target.port === 8443 ? "https" : "http";
  const base = `${scheme}://${opts.target.host}${opts.target.port ? `:${opts.target.port}` : ""}`;
  let requests = 0;
  let blockedRequests = 0;

  // 2) 로컬 scope-가드 브로커 — 파이썬의 모든 대상 요청을 대신 수행한다.
  const server = http.createServer((req, res) => {
    void handleBrokerRequest(req, res);
  });

  async function handleBrokerRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const reply = (obj: unknown, status = 200) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method !== "POST" || req.url !== "/req" || req.headers["x-rc-token"] !== token) {
      reply({ scopeError: "브로커 인증 실패" }, 403);
      return;
    }
    let raw = "";
    for await (const chunk of req) raw += chunk;
    let msg: { method?: string; path?: string; url?: string; headers?: Record<string, string>; body?: string; cap?: number; redirect?: "manual" | "follow" };
    try {
      msg = JSON.parse(raw || "{}");
    } catch {
      reply({ scopeError: "잘못된 요청(JSON 파싱 실패)" });
      return;
    }

    if (requests >= maxRequests) {
      blockedRequests++;
      reply({ scopeError: `요청 예산 초과(${maxRequests}) — 무한/폭주 루프 방지` });
      return;
    }

    // 대상 URL 확정: path 면 대상 base 에 붙이고, 절대 url 이면 그 호스트로.
    let targetUrl: URL;
    try {
      targetUrl = msg.url ? new URL(msg.url) : new URL((msg.path ?? "/").startsWith("/") ? base + (msg.path ?? "/") : base + "/" + (msg.path ?? ""));
    } catch {
      reply({ scopeError: "잘못된 URL" });
      return;
    }
    const port = targetUrl.port ? Number(targetUrl.port) : targetUrl.protocol === "https:" ? 443 : 80;

    // ★ 안전 핵심: 실제 요청 직전 ScopeGuard 재확인(우회 불가). exploit intent 로 판정.
    const decision = opts.guard.check({ host: targetUrl.hostname, port, intent: "exploit" });
    if (!decision.allowed) {
      blockedRequests++;
      opts.onRequest?.({ method: msg.method ?? "GET", url: targetUrl.toString(), blocked: decision.reason });
      reply({ scopeError: `scope 차단: ${decision.reason}` });
      return;
    }

    try {
      const headers = { ...(opts.auth ?? {}), ...(msg.headers ?? {}) };
      const r = await httpRequest(targetUrl.toString(), {
        method: msg.method ?? "GET",
        headers,
        body: msg.body,
        cap: Math.min(msg.cap ?? 6000, 20000),
        redirect: msg.redirect ?? "manual",
        // ★ 안전 핵심: redirect='follow' 로 cross-origin 3xx 를 따라갈 때, 각 다음 홉을
        // ScopeGuard 로 재검증한다(우회 불가). 최초 URL 만 검사하고 내부에서 리다이렉트를
        // 따라가면 scope 밖 호스트(내부/메타데이터)에 도달할 수 있으므로, per-hop 게이트를 건다.
        scopeCheck: (host, port) => opts.guard.check({ host, port, intent: "exploit" }).allowed,
        // 연결 시점 IP 검증: 호스트명이 내부/사설 IP 로 해석되거나 rebinding 되면 차단.
        validateIp: (host, ip) => opts.guard.checkResolvedIp(host, ip).allowed,
        proxy: opts.proxy,
        jar,
        limiter,
        timeoutMs: 8000,
        retries: 1,
      });
      requests++;
      opts.onRequest?.({ method: msg.method ?? "GET", url: targetUrl.toString(), status: r.status });
      reply({ status: r.status, headers: r.headers, body: r.body, url: r.url });
    } catch (e) {
      requests++;
      reply({ status: 0, headers: {}, body: "", url: targetUrl.toString(), error: String((e as Error).message) });
    }
  }

  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const brokerPort = (server.address() as AddressInfo).port;
  const brokerUrl = `http://127.0.0.1:${brokerPort}`;

  // 3) 임시 작업 디렉터리: 신뢰 runner + (별도) payload 를 쓰고 격리 실행.
  //    payload 는 절대 모듈로 직접 실행하지 않는다 — runner 가 AST 검증 후에만 exec 한다.
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-py-"));
  const runnerFile = path.join(dir, "runner.py");
  const payloadFile = path.join(dir, "payload.py");
  await fs.writeFile(runnerFile, runnerScript(), "utf8");
  await fs.writeFile(payloadFile, code, "utf8");

  try {
    // 격리 백엔드가 있으면 실행 argv 를 샌드박스로 감싼다(호스트 FS/프로세스 격리).
    const baseArgv = [opts.python ?? "python3", "-I", runnerFile, payloadFile];
    const argv = backend ? backend.wrap(baseArgv, dir) : baseArgv;
    return await new Promise<PyResult>((resolve) => {
      const child = spawn(argv[0], argv.slice(1), {
        cwd: dir,
        env: {
          // 최소 환경 + 브로커 접속 정보. accidental egress 는 죽은 프록시로 fail-closed,
          // 단 루프백(브로커)은 no_proxy 로 직결.
          PATH: process.env.PATH,
          RC_BROKER: brokerUrl,
          RC_TOKEN: token,
          RC_TARGET: `${opts.target.host}:${opts.target.port ?? ""}`,
          HTTP_PROXY: "http://127.0.0.1:1",
          HTTPS_PROXY: "http://127.0.0.1:1",
          NO_PROXY: "127.0.0.1,localhost",
          PYTHONUNBUFFERED: "1",
          PYTHONDONTWRITEBYTECODE: "1",
          // Windows: 한국어/중국어 로케일에서 stdout 이 cp949/cp936 로 나가 한글이
          // 깨지는 현상 방지 — 항상 UTF-8 로 출력한다.
          PYTHONIOENCODING: "utf-8",
          PYTHONUTF8: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
        // Windows: python 이 별도 콘솔 창을 새로 띄워 깜빡이는 현상 방지(CREATE_NO_WINDOW)
        windowsHide: true,
      });

      let stdout = "";
      let stderr = "";
      let timedOut = false;
      child.stdout.on("data", (c) => {
        if (stdout.length < outputCap) stdout += c.toString();
      });
      child.stderr.on("data", (c) => {
        if (stderr.length < outputCap) stderr += c.toString();
      });

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutMs);

      child.on("error", (err) => {
        clearTimeout(timer);
        resolve({
          ok: false,
          stdout,
          stderr: `python 실행 실패: ${err.message}`,
          exitCode: null,
          timedOut,
          requests,
          blockedRequests,
          findings: [],
          logs: [],
          isolation: { backend: backend?.name ?? null, warning: isolationWarning },
        });
      });

      child.on("close", (codeExit) => {
        clearTimeout(timer);
        const { findings, logs, clean, danger: astDanger } = parseOutput(stdout);
        resolve({
          // AST 허용목록 위반이면 runner 가 정상종료(0)하더라도 실행을 거부한 것이므로 ok=false.
          ok: !timedOut && codeExit === 0 && !astDanger,
          stdout: clean,
          stderr,
          exitCode: codeExit,
          timedOut,
          requests,
          blockedRequests,
          findings,
          logs,
          isolation: { backend: backend?.name ?? null, warning: isolationWarning },
          ...(astDanger ? { danger: astDanger } : {}),
        });
      });
    });
  } finally {
    server.close();
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** stdout 에서 ##RC_FINDING##/##RC_LOG##/##RC_DANGER## 라인을 구조화하고, 나머지는 표시용으로. */
function parseOutput(stdout: string): { findings: PyFinding[]; logs: string[]; clean: string; danger?: string } {
  const findings: PyFinding[] = [];
  const logs: string[] = [];
  const rest: string[] = [];
  let danger: string | undefined;
  for (const raw of stdout.split("\n")) {
    const line = raw.replace(/\r$/, ""); // Windows CRLF 정리
    if (line.startsWith("##RC_FINDING## ")) {
      try {
        const o = JSON.parse(line.slice("##RC_FINDING## ".length));
        const sev = SEVERITIES.has(o.severity) ? o.severity : "medium";
        if (o.title) findings.push({ title: String(o.title), severity: sev, evidence: o.evidence ?? undefined, impact: o.impact ?? undefined });
      } catch {
        /* 손상된 라인은 무시 */
      }
    } else if (line.startsWith("##RC_LOG## ")) {
      logs.push(line.slice("##RC_LOG## ".length));
    } else if (line.startsWith("##RC_DANGER## ")) {
      // runner 의 AST 허용목록 검증이 실행을 거부한 사유(심층방어 2차 계층).
      danger = danger ?? line.slice("##RC_DANGER## ".length);
    } else {
      rest.push(line);
    }
  }
  return { findings, logs, clean: rest.join("\n").trim(), danger };
}
