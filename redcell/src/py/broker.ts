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
import { spawn, type ChildProcess } from "node:child_process";
import readline from "node:readline";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { AddressInfo } from "node:net";
import net from "node:net";
import { lookup as dnsLookup } from "node:dns";
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
  /** 재귀 세션끼리 공유하는 요청 예산(budget.max 절대 한도). 주어지면 maxRequests 대신 쓴다. */
  budget?: { used: number; max: number };
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
  /** runner 의 문법(ast.parse) 오류 — 정책 위반이 아니라 실행 불가 코드. */
  syntax?: string;
  /** rc.memo(...) 로 저장된 기억(REPL 세션). */
  memos?: ReplMem[];
}

/** rc.memo(key, text) 로 저장된 자기발전 기억 한 건. */
export interface ReplMem {
  key: string;
  text: string;
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
  "time",
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
    "# python -I(격리)는 PYTHON* 환경변수를 무시하므로 한국어/중국어 깨짐(cp949/cp936)과",
    "# 블록 버퍼링에 의한 출력 순서 꼬임(재귀 rlm/로그 유실)을 **코드에서** 강제로 해결한다.",
    "_sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)",
    "_sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)",
    "_B = _os.environ[\"RC_BROKER\"]; _TK = _os.environ[\"RC_TOKEN\"]",
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
    "def _call(payload, endpoint='/req'):",
    '    req = _u.Request(_B + endpoint, data=_json.dumps(payload).encode(),',
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
    "    def tcp(self, host, port, payload=None, timeout=5, read=4096):",
    "        # 인가 대상에 대한 원시 TCP 조사(banner/맞춤 프로토콜). 브로커가 host:port 를",
    "        # ScopeGuard 로 검증한 뒤 연결하므로 scope 밖은 ScopeError 가 난다.",
    "        body = None",
    "        if payload is not None:",
    "            if isinstance(payload, str): payload = payload.encode()",
    "            body = _b64.b64encode(payload).decode()",
    "        req = _u.Request(_B + '/tcp', data=_json.dumps({'host': host, 'port': port, 'b64data': body, 'timeout': timeout, 'read': read}).encode(),",
    "                         headers={'x-rc-token': _TK, 'content-type': 'application/json'})",
    "        with _u.urlopen(req, timeout=timeout + 10) as r:",
    "            d = _json.loads(r.read().decode())",
    "        if 'scopeError' in d: raise ScopeError(d['scopeError'])",
    "        if 'error' in d: raise OSError(d['error'])",
    "        return _b64.b64decode(d.get('b64reply') or '')",
    "    def finding(self, title, severity='medium', evidence=None, impact=None):",
    "        print('##RC_FINDING## ' + _json.dumps({'title': title, 'severity': severity, 'evidence': evidence, 'impact': impact}), flush=True)",
    "    def log(self, *a):",
    "        print('##RC_LOG## ' + ' '.join(str(x) for x in a), flush=True)",
    "    def ctx_get(self, key, default=None):",
    "        return _CTX.get(key, default)",
    "    def ctx_set(self, key, value):",
    "        # prompt-as-variable: REPL 의 영구 ctx 변수 갱신(스텝을 넘어 유지됨).",
    "        _CTX[key] = value",
    "    def memo(self, key, text):",
    "        # 자기발전 기억: 엔진이 세션 메모리 파일에 기록해 다음 실행에서 재주입한다.",
    "        print('##RC_MEMO## ' + _b64.b64encode(_json.dumps({'key': key, 'text': text}).encode()).decode(), flush=True)",
    "    def skill(self, name):",
    "        # 절차 스킬 카탈로그 요청: 엔진이 skills/<name>/SKILL.md 본문을 실어 준다.",
    "        print('##RC_SKILL## ' + _b64.b64encode(name.encode('utf-8')).decode(), flush=True)",
    "        _l = _sys.stdin.readline()",
    "        if not _l or not _l.startswith('##RC_SKILL_RESULT## '):",
    "            return '[skill] 스킬을 받지 못했습니다: ' + str(name)",
    "        try:",
    "            return _b64.b64decode(_l[len('##RC_SKILL_RESULT## '):].strip()).decode('utf-8')",
    "        except Exception:",
    "            return '[skill] 스킬 본문 디코딩 실패'",
    "    def rlm_async(self, prompt, max_steps=8, key=None):",
    "        # 병렬 재귀 서브콜(비차단): 즉시 키를 돌려주고 rlm_wait(key) 로 결과를 받는다.",
    "        import uuid as _uuid",
    "        _key = key or _uuid.uuid4().hex[:8]",
    "        _req = _b64.b64encode(_json.dumps({'prompt': prompt, 'max_steps': max_steps}).encode()).decode()",
    "        print('##RC_RLM_ASYNC## ' + _key + ' ' + _req, flush=True)",
    "        return _key",
    "    def rlm_wait(self, key):",
    "        # 병렬 서브콜 결과 대기: 엔진이 하위 에이전트 완료 후 이 줄로 회신한다.",
    "        print('##RC_RLM_WAIT## ' + str(key), flush=True)",
    "        while True:",
    "            _l = _sys.stdin.readline()",
    "            if not _l:",
    "                return '[rlm] 엔진과의 연결이 끊어졌습니다'",
    "            if _l.startswith('##RC_RLM_RESULT## ' + str(key) + ' '):",
    "                try:",
    "                    return _b64.b64decode(_l[len('##RC_RLM_RESULT## ' + str(key) + ' '):].strip()).decode('utf-8')",
    "                except Exception:",
    "                    return '[rlm] 결과 디코딩 실패'",
    "    def rlm(self, prompt, max_steps=8):",
    "        # RLM 재귀 서브콜(동기식, 하위 호환): 엔진 콜백→결과를 값으로 받는다.",
    "        _req = _b64.b64encode(_json.dumps({'prompt': prompt, 'max_steps': max_steps}).encode()).decode()",
    "        print('##RC_RLM## ' + _req, flush=True)",
    "        _l = _sys.stdin.readline()",
    "        if not _l or not _l.startswith('##RC_RLM_RESULT## '):",
    "            return '[rlm] 엔진으로부터 결과를 받지 못했습니다'",
    "        try:",
    "            return _b64.b64decode(_l[len('##RC_RLM_RESULT## '):].strip()).decode('utf-8')",
    "        except Exception:",
    "            return '[rlm] 결과 디코딩 실패'",
    "rc = _RC()",
    "",
    "# ── ctx(prompt-as-variable): 엔진이 주입한 영구 맥락 변수 ──",
    "_CTX = {}",
    "try:",
    "    _ctx_raw = _os.environ.get('RC_CTX', '')",
    "    if _ctx_raw:",
    "        _CTX = _json.loads(_b64.b64decode(_ctx_raw).decode('utf-8'))",
    "except Exception:",
    "    _CTX = {}",
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
    "        print('##RC_SYNTAX## 문법 오류: ' + str(e), flush=True)",
    "        _sys.exit(0)",
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
    "# ── RLM 영구 REPL 모드(RC_REPL=1): stdin 으로 코드를 받아 같은 globals 에 실행 ──",
    "#    스텝을 넘어 변수·ctx 가 지속된다. AST 검증/DANGER 는 1회성과 동일한 심층방어.",
    "if _os.environ.get('RC_REPL') == '1':",
    "    _sandbox = {'__builtins__': _safe_builtins, 'rc': rc, 'rlm': rc.rlm, 'ctx': _CTX, '__name__': '__rc_repl__', '__doc__': None}",
    "    while True:",
    "        _line = _sys.stdin.readline()",
    "        if not _line:",
    "            break",
    "        if not _line.startswith('##RC_RUN## '):",
    "            continue",
    "        try:",
    "            _src = _b64.b64decode(_line[len('##RC_RUN## '):].strip()).decode('utf-8')",
    "        except Exception as _e:",
    "            print('##RC_SYNTAX## base64 디코딩 실패: ' + repr(_e), flush=True)",
    "            print('##RC_RESULT##', flush=True)",
    "            continue",
    "        _bad = _validate(_src)",
    "        if _bad is not None:",
    "            print('##RC_DANGER## ' + _bad, flush=True)",
    "            print('##RC_RESULT##', flush=True)",
    "            continue",
    "        try:",
    "            _code = compile(_src, 'payload.py', 'exec')",
    "            exec(_code, _sandbox)",
    "        except SystemExit:",
    "            pass",
    "        except BaseException as _e:",
    "            print('##RC_EXC## ' + repr(_e)[:400], flush=True)",
    "        print('##RC_RESULT##', flush=True)",
    "    _sys.exit(0)",
    "",
    "# ── payload 로드 → 검증 → 제한 exec(1회성 모드) ──────────────────────────",
    "_payload_path = _sys.argv[1]",
    "with open(_payload_path, 'r', encoding='utf-8') as _f:",
    "    _src = _f.read()",
    "_bad = _validate(_src)",
    "if _bad is not None:",
    "    print('##RC_DANGER## ' + _bad, flush=True)",
    "    _sys.exit(0)",
    "_sandbox = {'__builtins__': _safe_builtins, 'rc': rc, 'rlm': rc.rlm, '__name__': '__rc_payload__', '__doc__': None}",
    "_code = compile(_src, 'payload.py', 'exec')",
    "exec(_code, _sandbox)",
    "",
  ].join("\n");
}

/** 브로커 공유 문맥 — runPython(1회성) 과 ReplSession(영구 REPL) 이 **동일한 게이트**를 쓴다. */
interface BrokerCtx {
  token: string;
  guard: ScopeGuard;
  base: string;
  maxRequests: number;
  /** 재귀 세션끼리 공유하는 절대 요청 예산. 있으면 maxRequests 대신 쓴다. */
  budget?: { used: number; max: number };
  jar: CookieJar;
  proxy?: string;
  limiter: RateLimiter;
  auth?: Record<string, string>;
  counters: { requests: number; blockedRequests: number };
  onRequest?: (info: { method: string; url: string; status?: number; blocked?: string }) => void;
}

/** 예산 소진 여부: 공유 budget 이 있으면 그 한도, 없으면 세션 maxRequests. */
function brokerBudgetExceeded(ctx: BrokerCtx): boolean {
  return ctx.budget ? ctx.budget.used >= ctx.budget.max : ctx.counters.requests >= ctx.maxRequests;
}

function brokerCountRequest(ctx: BrokerCtx): void {
  ctx.counters.requests++;
  if (ctx.budget) ctx.budget.used++;
}

/** 로컬 scope-가드 브로커의 HTTP 요청 처리 — 파이썬이 직접 나가지 못하고 반드시 이 게이트를 통과한다. */
async function handleBrokerRequest(ctx: BrokerCtx, req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const reply = (obj: unknown, status = 200) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  if (req.method !== "POST" || !["/req", "/tcp"].includes(req.url ?? "") || req.headers["x-rc-token"] !== ctx.token) {
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

  if (req.url === "/tcp") {
    await handleTcp(ctx, msg as { host?: unknown; port?: unknown; b64data?: string; timeout?: unknown; read?: unknown }, reply);
    return;
  }

  if (brokerBudgetExceeded(ctx)) {
    ctx.counters.blockedRequests++;
    reply({ scopeError: `요청 예산 초과(${ctx.budget ? ctx.budget.max : ctx.maxRequests}) — 무한/폭주 루프 방지` });
    return;
  }

  // 대상 URL 확정: path 면 대상 base 에 붙이고, 절대 url 이면 그 호스트로.
  let targetUrl: URL;
  try {
    targetUrl = msg.url ? new URL(msg.url) : new URL((msg.path ?? "/").startsWith("/") ? ctx.base + (msg.path ?? "/") : ctx.base + "/" + (msg.path ?? ""));
  } catch {
    reply({ scopeError: "잘못된 URL" });
    return;
  }
  const port = targetUrl.port ? Number(targetUrl.port) : targetUrl.protocol === "https:" ? 443 : 80;

  // ★ 안전 핵심: 실제 요청 직전 ScopeGuard 재확인(우회 불가). exploit intent 로 판정.
  const decision = ctx.guard.check({ host: targetUrl.hostname, port, intent: "exploit" });
  if (!decision.allowed) {
    ctx.counters.blockedRequests++;
    ctx.onRequest?.({ method: msg.method ?? "GET", url: targetUrl.toString(), blocked: decision.reason });
    reply({ scopeError: `scope 차단: ${decision.reason}` });
    return;
  }

  try {
    const headers = { ...(ctx.auth ?? {}), ...(msg.headers ?? {}) };
    const r = await httpRequest(targetUrl.toString(), {
      method: msg.method ?? "GET",
      headers,
      body: msg.body,
      cap: Math.min(msg.cap ?? 6000, 20000),
      redirect: msg.redirect ?? "manual",
      // ★ 안전 핵심: redirect='follow' 로 cross-origin 3xx 를 따라갈 때, 각 다음 홉을
      // ScopeGuard 로 재검증한다(우회 불가). 최초 URL 만 검사하고 내부에서 리다이렉트를
      // 따라가면 scope 밖 호스트(내부/메타데이터)에 도달할 수 있으므로, per-hop 게이트를 건다.
      scopeCheck: (host, port) => ctx.guard.check({ host, port, intent: "exploit" }).allowed,
      // 연결 시점 IP 검증: 호스트명이 내부/사설 IP 로 해석되거나 rebinding 되면 차단.
      validateIp: (host, ip) => ctx.guard.checkResolvedIp(host, ip).allowed,
      proxy: ctx.proxy,
      jar: ctx.jar,
      limiter: ctx.limiter,
      timeoutMs: 8000,
      retries: 1,
    });
    brokerCountRequest(ctx);
    ctx.onRequest?.({ method: msg.method ?? "GET", url: targetUrl.toString(), status: r.status });
    reply({ status: r.status, headers: r.headers, body: r.body, url: r.url });
  } catch (e) {
    brokerCountRequest(ctx);
    reply({ status: 0, headers: {}, body: "", url: targetUrl.toString(), error: String((e as Error).message) });
  }
}

/** /tcp: 인가 대상에 대한 원시 TCP one-shot 조사(banner/맞춤 프로토콜). HTTP 와 동일 게이트. */
async function handleTcp(ctx: BrokerCtx, msg: { host?: unknown; port?: unknown; b64data?: string; timeout?: unknown; read?: unknown }, reply: (obj: unknown, status?: number) => void): Promise<void> {
  const host = String(msg.host ?? "");
  const port = Number(msg.port);
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    reply({ scopeError: "잘못된 host/port" });
    return;
  }
  const timeoutMs = Math.min(Math.max(Number(msg.timeout) || 5, 1), 30) * 1000;
  const readCap = Math.min(Math.max(Number(msg.read) || 4096, 1), 16384);
  if (brokerBudgetExceeded(ctx)) {
    ctx.counters.blockedRequests++;
    reply({ scopeError: `요청 예산 초과(${ctx.budget ? ctx.budget.max : ctx.maxRequests}) — 무한/폭주 루프 방지` });
    return;
  }

  // ★ 안전 핵심: HTTP 와 동일하게 실제 연결 직전 ScopeGuard 재확인(우회 불가).
  const decision = ctx.guard.check({ host, port, intent: "exploit" });
  if (!decision.allowed) {
    ctx.counters.blockedRequests++;
    ctx.onRequest?.({ method: "TCP", url: `tcp://${host}:${port}`, blocked: decision.reason });
    reply({ scopeError: `scope 차단: ${decision.reason}` });
    return;
  }

  let address: string;
  try {
    const ips = await new Promise<Array<{ address: string; family: number }>>((resolve, reject) =>
      dnsLookup(host, { all: true }, (err, addrs) => (err ? reject(err) : resolve(addrs))),
    );
    const ok = ips.find((a) => ctx.guard.checkResolvedIp(host, a.address).allowed);
    if (!ok) {
      ctx.counters.blockedRequests++;
      reply({ scopeError: `scope 차단: ${host} 가 인가 IP 로 해석되지 않습니다` });
      return;
    }
    address = ok.address;
  } catch (e) {
    reply({ error: `DNS 실패: ${(e as Error).message}` });
    return;
  }

  // one-shot 프로브: payload 있으면 half-close(end) 로 전송 후 응답 대기, 없으면 banner 대기.
  const data = typeof msg.b64data === "string" ? Buffer.from(msg.b64data, "base64") : Buffer.alloc(0);
  const sock = net.connect({ host: address, port });
  const chunks: Buffer[] = [];
  let settled = false;
  let drain: NodeJS.Timeout | null = null;
  const killer = setTimeout(() => finish(new Error("timeout")), timeoutMs);
  sock.on("connect", () => {
    if (data.length) sock.end(data);
    else sock.write(Buffer.alloc(0));
  });
  sock.on("data", (c: Buffer) => {
    if (settled) return;
    chunks.push(c);
    const total = chunks.reduce((n, b) => n + b.length, 0);
    if (total >= readCap) return finish();
    if (drain) clearTimeout(drain);
    drain = setTimeout(() => finish(), 250); // 첫 응답 이후 250ms 여유 수신
  });
  sock.on("error", (e) => finish(e));
  sock.on("close", () => finish());
  function finish(err?: Error) {
    if (settled) return;
    settled = true;
    clearTimeout(killer);
    if (drain) clearTimeout(drain);
    sock.destroy();
    brokerCountRequest(ctx);
    ctx.onRequest?.({ method: "TCP", url: `tcp://${host}:${port}`, status: err ? 0 : 200 });
    if (err) reply({ error: String(err.message) });
    else reply({ b64reply: Buffer.concat(chunks).toString("base64") });
  }
}

/** OS 격리 정책 해석 — runPython/ReplSession 공용. fail-closed 판정은 호출자가 한다. */
async function resolveIsolation(opts: {
  isolation?: "required" | "best-effort" | "off";
  trusted?: boolean;
}): Promise<{ backend: IsolationBackend | null; warning?: string }> {
  const isolationMode = opts.isolation ?? "required";
  if (opts.trusted || isolationMode === "off") return { backend: null };
  const backend = await detectIsolation();
  if (!backend && isolationMode === "best-effort") {
    return {
      backend: null,
      warning: "OS 격리 백엔드 없음 — in-process AST 샌드박스만으로 실행합니다(best-effort). 신뢰불가 코드에는 권장하지 않습니다.",
    };
  }
  return { backend };
}

/** ReplSession.step() 결과 — 1회성 PyResult 에 REPL 전용 필드 추가. */
export interface ReplStepResult extends PyResult {
  /** 코드가 예외로 죽었을 때의 예외 요약(print 가 아니고 crash). */
  exc?: string;
  /** REPL 이 타임아웃으로 재시작되어 변수가 초기화됐는가. */
  reset?: boolean;
}

export interface ReplSessionOpts extends PyRunOpts {
  /** 영구 REPL 변수 ctx(prompt-as-variable). 모델이 ctx_get/ctx_set 으로 읽고 쓴다. */
  ctx?: Record<string, unknown>;
  /** 파이썬의 rlm(prompt, max_steps) 재귀 서브콜마다 호출된다 → 결과 문자열을 돌려주면 값으로 반환된다. */
  onRlm?: (req: { prompt: string; max_steps: number }) => Promise<string>;
  /** 파이썬의 rlm_async(prompt, max_steps, key) — 비차단 발신. key 로 완료를 추적한다. */
  onRlmAsync?: (req: { prompt: string; max_steps: number }, key: string) => Promise<void>;
  /** 파이썬의 rlm_wait(key) — 해당 키 하위 에이전트 결과(또는 실패 문자열)를 돌려준다. */
  onRlmWait?: (key: string) => Promise<string>;
  /** 파이썬의 rc.skill(name) — 스킬 본문(SKILL.md)을 돌려준다. */
  onSkill?: (name: string) => Promise<string> | string;
  /** rc.memo(key, text) 마다 호출된다(자기발전 기억 수집). */
  onMemo?: (m: ReplMem) => void;
}

/**
 * ReplSession — RLM(Recursive Language Model) 방식의 **영구 파이썬 REPL**.
 *
 * runPython(1회성) 과 달리 파이썬 프로세스가 살아 있어 globals(변수·ctx) 가 스텝을 넘어
 * 지속된다(prompt-as-variable). 파이썬 코드는 rlm() 재귀 서브콜(##RC_RLM## → 엔진이 하위
 * 에이전트 실행 → 결과를 stdin 으로 회신)과 rc.memo()(##RC_MEMO##) 를 쓸 수 있다.
 * 모든 대상 통신은 runPython 과 **동일한 BrokerCtx 게이트**를 강제한다(우회 불가).
 */
export class ReplSession {
  private child: ChildProcess | null = null;
  private stepBuf: string[] = [];
  private stepResolve: ((lines: string[]) => void) | null = null;
  private stepTimer: NodeJS.Timeout | null = null;
  private closed = false;
  private stderrTail = "";

  private constructor(
    private readonly opts: ReplSessionOpts,
    private readonly backend: IsolationBackend | null,
    private readonly dir: string,
    private readonly runnerFile: string,
    private readonly server: http.Server,
    private readonly ctxBroker: BrokerCtx,
    private readonly brokerUrl: string,
  ) {}

  static async create(opts: ReplSessionOpts): Promise<ReplSession> {
    const maxRequests = opts.maxRequests ?? 80;
    const token = randomBytes(24).toString("hex");
    const limiter = new RateLimiter(opts.guard.requestsPerSecond);
    const jar: CookieJar = opts.jar ?? newJar();
    const scheme = opts.target.port === 443 || opts.target.port === 8443 ? "https" : "http";
    const base = `${scheme}://${opts.target.host}${opts.target.port ? `:${opts.target.port}` : ""}`;
    const counters = { requests: 0, blockedRequests: 0 };
    const ctxBroker: BrokerCtx = {
      token,
      guard: opts.guard,
      base,
      maxRequests,
      budget: opts.budget,
      jar,
      proxy: opts.proxy,
      limiter,
      auth: opts.auth,
      onRequest: opts.onRequest,
      counters,
    };
    const server = http.createServer((req, res) => void handleBrokerRequest(ctxBroker, req, res));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const brokerPort = (server.address() as AddressInfo).port;
    const brokerUrl = `http://127.0.0.1:${brokerPort}`;
    const iso = await resolveIsolation(opts);
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rc-repl-"));
    const runnerFile = path.join(dir, "runner.py");
    await fs.writeFile(runnerFile, runnerScript(), "utf8");
    const session = new ReplSession(opts, iso.backend, dir, runnerFile, server, ctxBroker, brokerUrl);
    session.spawnChild();
    return session;
  }

  private spawnChild(): void {
    const baseArgv = [this.opts.python ?? "python3", "-I", this.runnerFile];
    const argv = this.backend ? this.backend.wrap(baseArgv, this.dir) : baseArgv;
    const child = spawn(argv[0], argv.slice(1), {
      cwd: this.dir,
      env: {
        // 최소 환경 + 브로커 접속 정보. accidental egress 는 죽은 프록시로 fail-closed,
        // 단 루프백(브로커)은 no_proxy 로 직결.
        PATH: process.env.PATH,
        RC_BROKER: this.brokerUrl,
        RC_TOKEN: this.ctxBroker.token,
        RC_TARGET: `${this.opts.target.host}:${this.opts.target.port ?? ""}`,
        RC_REPL: "1",
        RC_CTX: Buffer.from(JSON.stringify(this.opts.ctx ?? {})).toString("base64"),
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
      stdio: ["pipe", "pipe", "pipe"],
      // Windows: python 이 별도 콘솔 창을 새로 띄워 깜빡이는 현상 방지(CREATE_NO_WINDOW)
      windowsHide: true,
    });
    this.child = child;
    const rl = readline.createInterface({ input: child.stdout });
    rl.on("line", (line) => this.onStdoutLine(line));
    child.stderr.on("data", (c) => {
      this.stderrTail = (this.stderrTail + c.toString()).slice(-4000);
    });
    child.on("error", (err) => {
      this.stderrTail += `\n[REPL] python 실행 실패: ${err.message}`;
      this.child = null;
    });
  }

  private onStdoutLine(line: string): void {
    if (this.closed) return;
    const l = line.replace(/\r$/, ""); // Windows CRLF 정리
    if (l.startsWith("##RC_RLM## ")) {
      void this.handleRlm(l);
      return;
    }
    if (l.startsWith("##RC_RLM_ASYNC## ")) {
      void this.handleRlmAsync(l);
      return;
    }
    if (l.startsWith("##RC_RLM_WAIT## ")) {
      void this.handleRlmWait(l);
      return;
    }
    if (l.startsWith("##RC_SKILL## ")) {
      void this.handleSkill(l);
      return;
    }
    this.stepBuf.push(l);
    if (l === "##RC_RESULT##") {
      if (this.stepTimer) clearTimeout(this.stepTimer);
      const lines = this.stepBuf;
      this.stepBuf = [];
      const resolve = this.stepResolve;
      this.stepResolve = null;
      resolve?.(lines);
    }
  }

  /** ##RC_RLM## 요청을 처리: 하위 에이전트 실행 후 결과를 파이썬 stdin 으로 회신. */
  private async handleRlm(line: string): Promise<void> {
    let text = "[rlm] 하위 에이전트 결과 없음";
    try {
      const body = Buffer.from(line.slice("##RC_RLM## ".length).trim(), "base64").toString("utf8");
      const req = JSON.parse(body);
      if (this.opts.onRlm) {
        text = await this.opts.onRlm({ prompt: String(req.prompt ?? ""), max_steps: Number(req.max_steps) || 8 });
      }
    } catch (e) {
      text = `[rlm] 하위 에이전트 오류: ${(e as Error).message}`;
    }
    if (!this.child?.stdin?.writable) return;
    this.child.stdin.write("##RC_RLM_RESULT## " + Buffer.from(text, "utf8").toString("base64") + "\n");
  }

  /** ##RC_RLM_ASYNC## <key> <b64req> — 하위 에이전트를 병렬로 시작(즉시 반환, 결과는 wait 시 회신). */
  private async handleRlmAsync(line: string): Promise<void> {
    const rest = line.slice("##RC_RLM_ASYNC## ".length).trim();
    const sp = rest.indexOf(" ");
    if (sp < 0) return;
    const key = rest.slice(0, sp).trim();
    try {
      const body = Buffer.from(rest.slice(sp + 1).trim(), "base64").toString("utf8");
      const req = JSON.parse(body);
      await this.opts.onRlmAsync?.({ prompt: String(req.prompt ?? ""), max_steps: Number(req.max_steps) || 8 }, key);
    } catch (e) {
      // 해석 실패: 아무것도 등록하지 않는다 — rlm_wait(key) 는 "결과 없음" 을 받는다.
    }
  }

  /** ##RC_RLM_WAIT## <key> — 키에 해당하는 하위 에이전트 결과를 stdin 으로 회신. */
  private async handleRlmWait(line: string): Promise<void> {
    const key = line.slice("##RC_RLM_WAIT## ".length).trim();
    let text = "[rlm] 하위 에이전트 결과 없음";
    try {
      if (this.opts.onRlmWait) text = await this.opts.onRlmWait(key);
    } catch (e) {
      text = `[rlm] 하위 에이전트 오류: ${(e as Error).message}`;
    }
    if (!this.child?.stdin?.writable) return;
    this.child.stdin.write("##RC_RLM_RESULT## " + key + " " + Buffer.from(text, "utf8").toString("base64") + "\n");
  }

  /** ##RC_SKILL## <b64 name> — 스킬 본문을 stdin 으로 회신. */
  private async handleSkill(line: string): Promise<void> {
    let text = "[skill] 스킬을 받지 못했습니다";
    try {
      const name = Buffer.from(line.slice("##RC_SKILL## ".length).trim(), "base64").toString("utf8");
      const body = this.opts.onSkill ? await this.opts.onSkill(name) : "";
      text = body || `[skill] 스킬 없음: ${name}`;
    } catch (e) {
      text = `[skill] 스킬 오류: ${(e as Error).message}`;
    }
    if (!this.child?.stdin?.writable) return;
    this.child.stdin.write("##RC_SKILL_RESULT## " + Buffer.from(text, "utf8").toString("base64") + "\n");
  }

  /** REPL 에 코드 한 스텝을 보내고 결과를 기다린다(순차 실행 전용). */
  async step(code: string): Promise<ReplStepResult> {
    if (this.closed || !this.child) throw new Error("REPL 세션이 닫혔습니다");
    if (this.stepResolve) throw new Error("이전 스텝이 아직 실행 중입니다(순차 실행만 지원)");
    const timeoutMs = this.opts.timeoutMs ?? 20000;
    const counters = this.ctxBroker.counters;
    const isoInfo = { backend: this.backend?.name ?? null };

    // 1차 정적 스캔 — 브로커 게이트와 동일하게 모든 실행 경로에서 fail-closed.
    const danger = scanDanger(code);
    if (danger) {
      return { ok: false, stdout: "", stderr: "", exitCode: null, timedOut: false, requests: counters.requests, blockedRequests: counters.blockedRequests, findings: [], logs: [], danger };
    }

    return await new Promise<ReplStepResult>((resolve) => {
      let done = false;
      const finish = (r: ReplStepResult) => {
        if (done) return;
        done = true;
        if (this.stepTimer) clearTimeout(this.stepTimer);
        resolve(r);
      };
      this.stepResolve = (lines) => {
        const raw = lines.join("\n");
        const { findings, logs, clean, danger, syntax, memos, exc } = parseOutput(raw);
        for (const m of memos ?? []) this.opts.onMemo?.(m);
        finish({
          ok: !danger && !syntax && !exc,
          stdout: clean,
          stderr: this.stderrTail,
          exitCode: null,
          timedOut: false,
          requests: counters.requests,
          blockedRequests: counters.blockedRequests,
          findings,
          logs,
          ...(memos?.length ? { memos } : {}),
          isolation: isoInfo,
          ...(danger ? { danger } : {}),
          ...(syntax ? { syntax } : {}),
          ...(exc ? { exc } : {}),
        });
      };
      this.stepTimer = setTimeout(() => {
        this.stderrTail += "\n[REPL] 스텝 타임아웃 — 프로세스 재시작(변수 초기화됨)";
        this.killChild();
        this.spawnChild();
        const partial = this.stepBuf.join("\n");
        this.stepBuf = [];
        finish({
          ok: false, stdout: partial, stderr: this.stderrTail, exitCode: null, timedOut: true,
          requests: counters.requests, blockedRequests: counters.blockedRequests,
          findings: [], logs: [], isolation: isoInfo, reset: true,
        });
      }, timeoutMs);
      this.child!.stdin!.write("##RC_RUN## " + Buffer.from(code, "utf8").toString("base64") + "\n");
    });
  }

  private killChild(): void {
    if (this.child) {
      try {
        this.child.kill("SIGKILL");
      } catch {
        /* 이미 종료 */
      }
      this.child = null;
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    this.killChild();
    this.server.close();
    await fs.rm(this.dir, { recursive: true, force: true }).catch(() => {});
  }
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
  let backend: IsolationBackend | null = null;
  let isolationWarning: string | undefined;
  const iso = await resolveIsolation({ isolation: isolationMode, trusted: opts.trusted });
  backend = iso.backend;
  isolationWarning = iso.warning;
  if (!backend && !opts.trusted && isolationMode === "required") {
    return {
      ok: false, stdout: "", stderr: "", exitCode: null, timedOut: false, requests: 0, blockedRequests: 0, findings: [], logs: [],
      danger:
        "OS 격리 백엔드(bwrap 등)를 사용할 수 없어 신뢰불가(라이브 모델) 코드 실행을 거부합니다(fail-closed). " +
        "비특권 네임스페이스가 허용된 호스트에서 실행하거나, 신뢰되는 오프라인 코드에 한해 isolation:'off' 를 명시하세요.",
      isolation: { backend: null },
    };
  }

  const token = randomBytes(24).toString("hex");
  const limiter = new RateLimiter(opts.guard.requestsPerSecond);
  // 멀티스텝 세션: run 하나 안에서 rc 호출 간 쿠키가 유지되도록 항상 jar 를 둔다(로그인
  // 플로우를 파이썬으로 직접 수행 가능). 세션 jar 가 주어지면 그걸 쓰고, 없으면 run 로컬 jar.
  const jar: CookieJar = opts.jar ?? newJar();
  const scheme = opts.target.port === 443 || opts.target.port === 8443 ? "https" : "http";
  const base = `${scheme}://${opts.target.host}${opts.target.port ? `:${opts.target.port}` : ""}`;
  const counters = { requests: 0, blockedRequests: 0 };

  // 2) 로컬 scope-가드 브로커 — 파이썬의 모든 대상 요청을 대신 수행한다.
  //    공유 BrokerCtx: 1회성 실행과 REPL 세션이 **동일한 게이트 경로**를 강제한다.
  const ctx: BrokerCtx = {
    token,
    guard: opts.guard,
    base,
    maxRequests,
    budget: opts.budget,
    jar,
    proxy: opts.proxy,
    limiter,
    auth: opts.auth,
    onRequest: opts.onRequest,
    counters,
  };
  const server = http.createServer((req, res) => {
    void handleBrokerRequest(ctx, req, res);
  });

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
          requests: counters.requests,
          blockedRequests: counters.blockedRequests,
          findings: [],
          logs: [],
          isolation: { backend: backend?.name ?? null, warning: isolationWarning },
        });
      });

      child.on("close", (codeExit) => {
        clearTimeout(timer);
        const { findings, logs, clean, danger: astDanger, syntax: astSyntax } = parseOutput(stdout);
        resolve({
          // AST 허용목록 위반이면 runner 가 정상종료(0)하더라도 실행을 거부한 것이므로 ok=false.
          // 문법 오류(astSyntax)는 실행 불가 코드 — 어느 쪽도 실행되지 않았다는 점은 같다.
          ok: !timedOut && codeExit === 0 && !astDanger && !astSyntax,
          stdout: clean,
          stderr,
          exitCode: codeExit,
          timedOut,
          requests: counters.requests,
          blockedRequests: counters.blockedRequests,
          findings,
          logs,
          isolation: { backend: backend?.name ?? null, warning: isolationWarning },
          ...(astDanger ? { danger: astDanger } : {}),
          ...(astSyntax ? { syntax: astSyntax } : {}),
        });
      });
    });
  } finally {
    server.close();
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** stdout 에서 ##RC_FINDING##/##RC_LOG##/##RC_DANGER##/##RC_SYNTAX##/##RC_MEMO##/##RC_EXC##
 * 라인을 구조화하고, 나머지는 표시용으로. */
function parseOutput(stdout: string): {
  findings: PyFinding[];
  logs: string[];
  clean: string;
  danger?: string;
  syntax?: string;
  memos?: ReplMem[];
  exc?: string;
} {
  const findings: PyFinding[] = [];
  const logs: string[] = [];
  const memos: ReplMem[] = [];
  const rest: string[] = [];
  let danger: string | undefined;
  let syntax: string | undefined;
  let exc: string | undefined;
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
    } else if (line.startsWith("##RC_SYNTAX## ")) {
      // 모델이 보낸 코드의 문법 오류(정책 위반 아님). 다음 시도에서 수정하도록 구분해 준다.
      syntax = syntax ?? line.slice("##RC_SYNTAX## ".length);
    } else if (line.startsWith("##RC_DANGER## ")) {
      // runner 의 AST 허용목록 검증이 실행을 거부한 사유(심층방어 2차 계층).
      danger = danger ?? line.slice("##RC_DANGER## ".length);
    } else if (line.startsWith("##RC_MEMO## ")) {
      // self-improving 기억(REPL 전용).
      try {
        const o = JSON.parse(Buffer.from(line.slice("##RC_MEMO## ".length).trim(), "base64").toString("utf8"));
        if (o.key) memos.push({ key: String(o.key), text: String(o.text ?? "") });
      } catch {
        /* 손상된 라인은 무시 */
      }
    } else if (line.startsWith("##RC_EXC## ")) {
      // REPL 스텝 중 코드 예외(정책 위반 아님 — 실행은 됐지만 crash).
      exc = exc ?? line.slice("##RC_EXC## ".length);
    } else if (line === "##RC_RESULT##") {
      // REPL 스텝 경계 마커(프로토콜) — stdout 에 포함하지 않는다.
    } else {
      rest.push(line);
    }
  }
  return { findings, logs, clean: rest.join("\n").trim(), danger, syntax, ...(memos.length ? { memos } : {}), ...(exc ? { exc } : {}) };
}
