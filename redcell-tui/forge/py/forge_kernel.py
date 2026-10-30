#!/usr/bin/env python3
"""REDFORGE 파이썬 커널 — LLM/사람이 쓴 코드를 "그대로" 실행하는 영속 인터프리터.

prime-agent 의 ipython 커널과 같은 역할:
  - 한 번 시작하면 같은 네임스페이스에서 코드를 계속 실행한다 (변수·함수 재사용).
  - stdout/stderr 를 캡처해 구조화된 결과로 돌려준다.
  - 실행 시간 초과를 실제로 끊는다 (SIGALRM 기반).
  - 마지막 표현식의 값을 결과로 반환한다 (IPython 과 동일 동작).

보안: 이 프로세스는 아웃바운드 트래픽 전부에 대해 **인가 게이트**를 거친다.
  socket.getaddrinfo / socket.socket.connect 를 후킹해 인가 목록 밖 목적지로의
  연결을 원천 차단한다. requests·httpx·urllib·http.client 모두 이 경로를 쓴다.
  subprocess / os.system / 파일 쓰기도 막는다 — 점검 전용 샌드박스.

프로토콜: stdin/stdout JSON Lines.
  요청 {"id":1,"op":"exec","code":"...","timeout_ms":5000}
  응답 {"id":1,"ok":true,"stdout":"","stderr":"","result":"","duration_ms":12,...}
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import os
import re
import signal
import socket
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPResponse
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# YAML 서브셋 파서 (pyyaml 이 없는 환경을 위해 자체 구현)
# ─────────────────────────────────────────────────────────────────────────────


def _strip_comment(line: str) -> str:
    out, quote, prev_space = [], None, True
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            prev_space = False
            continue
        if ch == "#" and prev_space:
            break
        prev_space = ch.isspace()
        out.append(ch)
    return "".join(out)


def yaml_load(text: str) -> Any:
    lines = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip())
        lines.append((indent, stripped.strip(), raw))
    value, _ = _parse_block(lines, 0, lines[0][0] if lines else 0)
    return value


def _split_key(body: str):
    quote = None
    for i, ch in enumerate(body):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == ":" and (i + 1 == len(body) or body[i + 1] in " \t"):
            return body[:i].strip().strip("\"'"), body[i + 1:]
    return None, None


def _parse_block(lines, pos, indent):
    if pos >= len(lines):
        return None, pos
    if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
        return _parse_seq(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_map(lines, pos, indent):
    out = {}
    while pos < len(lines):
        cur_indent, body, _ = lines[pos]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise ValueError(f"예상치 못한 들여쓰기: {body}")
        if body.startswith("- ") or body == "-":
            break
        key, rest = _split_key(body)
        if key is None:
            raise ValueError(f"'key: value' 형태가 아님: {body}")
        pos += 1
        if rest.strip():
            out[key] = _scalar(rest.strip())
        elif pos < len(lines) and lines[pos][0] > indent:
            out[key], pos = _parse_block(lines, pos, lines[pos][0])
        else:
            out[key] = None
    return out, pos


def _parse_seq(lines, pos, indent):
    out = []
    while pos < len(lines):
        cur_indent, body, _ = lines[pos]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise ValueError(f"시퀀스 들여쓰기 불일치: {body}")
        if not (body.startswith("- ") or body == "-"):
            break
        rest = body[1:].strip()
        pos += 1
        if not rest:
            if pos < len(lines) and lines[pos][0] > indent:
                item, pos = _parse_block(lines, pos, lines[pos][0])
            else:
                item = None
            out.append(item)
            continue
        key, vrest = _split_key(rest)
        if key is None:
            out.append(_scalar(rest))
            continue
        item = {key: _scalar(vrest.strip()) if vrest.strip() else None}
        while pos < len(lines) and lines[pos][0] > indent:
            more, pos = _parse_map(lines, pos, lines[pos][0])
            if isinstance(more, dict):
                item.update(more)
        out.append(item)
    return out, pos


def _scalar(text: str):
    text = text.strip()
    if not text:
        return None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part) for part in inner.split(",") if part.strip()]
    if len(text) >= 2 and text[0] in "\"'" and text[-1] == text[0]:
        return text[1:-1]
    low = text.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


# ─────────────────────────────────────────────────────────────────────────────
# 인가 스코프 (Rust 게이트와 동일 규칙)
# ─────────────────────────────────────────────────────────────────────────────


class ScopeError(Exception):
    pass


class Scope:
    def __init__(self, doc: dict | None):
        doc = doc or {}
        self.engagement = doc.get("engagement") or {}
        scope = doc.get("scope") or {}
        self.allow = self._rules(scope.get("allow"))
        self.deny = self._rules(scope.get("deny"))
        ports = (doc.get("ports") or {}).get("allow_tcp") or []
        self.ports = {int(p) for p in ports if str(p).isdigit()}
        limits = doc.get("limits") or {}
        rps = limits.get("max_requests_per_second")
        self.max_rps = float(rps) if isinstance(rps, (int, float)) and rps > 0 else None
        self.credentials = doc.get("credentials") or {}
        self.source = doc.get("__source__", "<memory>")

    @staticmethod
    def _rules(items) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for item in items or []:
            if isinstance(item, str):
                out.append(("host", item.strip().lower()))
                continue
            if not isinstance(item, dict):
                continue
            for key in ("host", "ip", "domain", "cidr"):
                val = item.get(key)
                if isinstance(val, str) and val.strip():
                    out.append((key, val.strip().lower()))
        return out

    # -- 규칙 판정 ----------------------------------------------------------
    def _match(self, kind: str, value: str, host: str) -> bool:
        if kind in ("host", "ip"):
            return value == host
        if kind == "domain":
            root = value.lstrip("*.").lstrip(".")
            return host == root or host.endswith("." + root)
        if kind == "cidr":
            try:
                net, bits = value.split("/", 1)
                bits = int(bits)
                if ":" in net:
                    return False  # IPv6 CIDR 은 Rust 게이트에서만 다룬다
                ip = int.from_bytes(socket.inet_aton(host), "big")
                n = int.from_bytes(socket.inet_aton(net), "big")
                mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
                return (ip & mask) == (n & mask)
            except Exception:
                return False
        return False

    def check_host(self, host: str, port: int | None = None) -> None:
        host = (host or "").strip().strip(".").lower()
        if not host:
            raise ScopeError("호스트가 비어 있습니다.")
        self.check_period()
        for kind, value in self.deny:
            if self._match(kind, value, host):
                raise ScopeError(f"{host} 는 deny 규칙에 포함됩니다.")
        if not any(self._match(kind, value, host) for kind, value in self.allow):
            raise ScopeError(f"{host} 는 인가 대상({self.source})이 아닙니다.")
        if port is not None and self.ports and port not in self.ports:
            raise ScopeError(f"포트 {port} 는 허용 포트 목록에 없습니다.")

    def check_period(self) -> None:
        today = time.strftime("%Y-%m-%d")
        frm = self.engagement.get("authorized_from")
        until = self.engagement.get("authorized_until")
        if isinstance(frm, str) and today < frm:
            raise ScopeError(f"인가 시작일({frm}) 전입니다.")
        if isinstance(until, str) and today > until:
            raise ScopeError(f"인가 만료일({until})이 지났습니다.")


# ─────────────────────────────────────────────────────────────────────────────
# 소켓 후킹 — 인가 밖 연결 차단
# ─────────────────────────────────────────────────────────────────────────────


class Guard:
    """scope 밖 아웃바운드 연결을 차단하기 위한 전역 후킹."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self.blocked = 0
        self._install()

    def _install(self) -> None:
        scope = self.scope
        guard = self

        real_getaddrinfo = socket.getaddrinfo
        real_connect = socket.socket.connect
        real_create_connection = socket.create_connection

        def guarded_getaddrinfo(host, port, *args, **kwargs):
            try:
                scope.check_host(host, int(port) if isinstance(port, int) else None)
            except ScopeError as exc:
                guard.blocked += 1
                raise ScopeError(f"연결 차단: {exc}") from exc
            return real_getaddrinfo(host, port, *args, **kwargs)

        def guarded_connect(self_sock, address):
            host, port = address[0], address[1]
            if isinstance(port, int):
                scope.check_host(host, port)
            return real_connect(self_sock, address)

        def guarded_create_connection(address, *args, **kwargs):
            host, port = address[0], address[1]
            if isinstance(port, int):
                scope.check_host(host, port)
            return real_create_connection(address, *args, **kwargs)

        socket.getaddrinfo = guarded_getaddrinfo
        socket.socket.connect = guarded_connect
        socket.create_connection = guarded_create_connection


# ─────────────────────────────────────────────────────────────────────────────
# 파일시스템/프로세스 차단
# ─────────────────────────────────────────────────────────────────────────────


def _lock_dangerous(run_dir: str) -> None:
    import builtins
    import shutil

    def _deny(name):
        def _f(*_a, **_k):
            raise PermissionError(f"{name} 는 점검 샌드박스에서 차단되었습니다.")

        return _f

    for name in ("system", "popen", "remove", "unlink", "rmdir", "execv", "execve", "spawnv"):
        if hasattr(os, name):
            try:
                setattr(os, name, _deny(f"os.{name}"))
            except Exception:
                pass
    for name in ("rmtree", "move", "copy"):
        if hasattr(shutil, name):
            try:
                setattr(shutil, name, _deny(f"shutil.{name}"))
            except Exception:
                pass

    real_open = builtins.open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            target = os.path.abspath(str(file))
            if not target.startswith(os.path.abspath(run_dir) + os.sep):
                raise PermissionError(f"파일 쓰기는 실행 디렉터리({run_dir}) 안에서만 가능합니다.")
        return real_open(file, mode, *args, **kwargs)

    builtins.open = guarded_open


# ─────────────────────────────────────────────────────────────────────────────
# HTTP 클라이언트 (표준 라이브러리만 사용)
# ─────────────────────────────────────────────────────────────────────────────


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _ssl_context() -> ssl.SSLContext | None:
    if os.environ.get("FORGE_INSECURE") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def http_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | bytes | None = None,
    timeout: float = 10.0,
    follow_redirects: bool = False,
    scope: Scope | None = None,
) -> dict:
    """범위 검사 후 단일 HTTP 요청. 결과는 dict."""
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        return {"error": f"URL 파싱 실패: {url}", "status": 0, "body": "", "headers": {}, "len": 0}
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if scope is not None:
        try:
            scope.check_host(parts.hostname, port)
        except ScopeError as exc:
            return {"error": str(exc), "status": 0, "body": "", "headers": {}, "len": 0}

    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method.upper())
    for key, value in (headers or {}).items():
        req.add_header(key, value)

    handlers: list[Any] = []
    if not follow_redirects:
        handlers.append(_NoRedirect())
    ctx = _ssl_context()
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)

    started = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
            resp_headers = dict(resp.headers.items())
            final_url = resp.geturl()
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        status = exc.code
        resp_headers = dict(exc.headers.items()) if exc.headers else {}
        final_url = url
    except Exception as exc:  # 네트워크 오류도 결과로 돌려준다 (크래시 금지)
        elapsed = (time.perf_counter() - started) * 1000
        return {
            "error": f"{type(exc).__name__}: {exc}",
            "status": 0,
            "body": "",
            "headers": {},
            "len": 0,
            "elapsed_ms": round(elapsed, 2),
            "sha256": "",
            "final_url": url,
        }
    elapsed = (time.perf_counter() - started) * 1000
    text = raw.decode("utf-8", errors="replace")
    return {
        "error": None,
        "status": status,
        "headers": resp_headers,
        "body": text,
        "len": len(raw),
        "elapsed_ms": round(elapsed, 2),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "final_url": final_url,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 툴킷 — 커널 네임스페이스에 `forge` 로 노출
# ─────────────────────────────────────────────────────────────────────────────


class Toolkit:
    def __init__(self, scope: Scope, guard: Guard, run_dir: str, base_url: str | None):
        self.scope = scope
        self.guard = guard
        self.run_dir = run_dir
        self.base_url = base_url
        self.notes: list[str] = []
        self.findings: list[dict] = []
        self._cred_headers = self._credential_headers()

    # -- 인가된 자격증명 헤더 ---------------------------------------------
    def _credential_headers(self) -> dict:
        cred = self.scope.credentials or {}
        headers: dict[str, str] = {}
        cookie = cred.get("cookie")
        bearer = cred.get("bearer")
        extra = cred.get("headers") or {}
        if isinstance(cookie, str):
            headers["Cookie"] = cookie
        if isinstance(bearer, str):
            headers["Authorization"] = f"Bearer {bearer}"
        if isinstance(extra, dict):
            for k, v in extra.items():
                headers[str(k)] = str(v)
        return headers

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        if not self.base_url:
            raise ValueError("base_url 이 없습니다. forge.set_base(url) 를 호출하세요.")
        return urllib.parse.urljoin(self.base_url, path)

    # -- 공개 API ----------------------------------------------------------
    def set_base(self, url: str) -> str:
        self.base_url = url
        return f"base_url = {url}"

    def request(self, method: str, path: str, *, headers=None, body=None, timeout: float = 10.0,
                follow_redirects: bool = False) -> dict:
        merged = dict(self._cred_headers)
        merged.update(headers or {})
        return http_request(
            method, self._url(path), headers=merged, body=body,
            timeout=timeout, follow_redirects=follow_redirects, scope=self.scope,
        )

    def get(self, path: str, **kw) -> dict:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> dict:
        return self.request("POST", path, **kw)

    def burst(self, method: str, path: str, payloads, *, headers=None, body_template: str | None = None,
              workers: int = 8, timeout: float = 10.0, delay: float = 0.0) -> list[dict]:
        """여러 페이로드를 병렬로 쏘고 응답 목록을 돌려준다 (스톰의 파이썬 버전)."""
        payloads = list(payloads)
        merged = dict(self._cred_headers)
        merged.update(headers or {})
        url = self._url(path)

        def one(payload) -> dict:
            if delay:
                time.sleep(delay)
            body = body_template.replace("{{payload}}", str(payload)) if body_template else None
            res = http_request(method, url, headers=merged, body=body, timeout=timeout, scope=self.scope)
            res["payload"] = payload
            return res

        with ThreadPoolExecutor(max_workers=max(1, min(workers, 64))) as pool:
            return list(pool.map(one, payloads))

    # -- 페이로드 생성 -----------------------------------------------------
    def mutate(self, values, *, seed: int = 0, rounds: int = 1) -> list[str]:
        """값 목록을 변이해 시도할 페이로드 목록을 만든다 (경계값·인코딩·문자열 조작)."""
        import random

        rng = random.Random(seed)
        base = [str(v) for v in values]
        mutations = [
            lambda s: s,
            lambda s: s + "'",
            lambda s: s + '"',
            lambda s: s + "<",
            lambda s: s + ">",
            lambda s: s + "()",
            lambda s: s + " OR 1=1--",
            lambda s: s + " AND 1=2--",
            lambda s: s + "/*",
            lambda s: s + "%00",
            lambda s: s + "\x00",
            lambda s: s + "../../../../etc/passwd",
            lambda s: s + "{{7*7}}",
            lambda s: s + "${7*7}",
            lambda s: urllib.parse.quote(s),
            lambda s: urllib.parse.quote_plus(s),
            lambda s: s.replace(" ", "+"),
            lambda s: s.upper(),
            lambda s: s.lower(),
            lambda s: s[:-1] if len(s) > 1 else s,
            lambda s: s + "a" * 1,
            lambda s: s + "0",
            lambda s: "0",
            lambda s: "-1",
            lambda s: "1",
            lambda s: "2147483647",
            lambda s: "99999999999999999999",
            lambda s: "[]",
            lambda s: "{}",
            lambda s: "null",
            lambda s: "../../",
            lambda s: "http://127.0.0.1",
        ]
        out: list[str] = []
        for _ in range(max(1, rounds)):
            for value in base:
                for fn in mutations:
                    try:
                        out.append(fn(value))
                    except Exception:
                        continue
                if rng.random() < 0.3:
                    out.append(value + rng.choice(["'", '"', " ", "\\", ";", "%", "$", "`"]))
        seen, uniq = set(), []
        for item in out:
            if item not in seen:
                seen.add(item)
                uniq.append(item)
        return uniq

    # -- 응답 분석 ---------------------------------------------------------
    def analyze(self, response: dict) -> dict:
        """응답에서 신호(에러·스택트레이스·SQL 오류·리다이렉트·비밀 정보)를 뽑는다."""
        body = (response or {}).get("body") or ""
        text = body[:400_000]
        signals: list[str] = []
        patterns = {
            "sql_error": r"(?i)(sql syntax|mysql_fetch|ora-\d{5}|pg_query|sqlite3?\.OperationalError|unclosed quotation mark|you have an error in your sql)",
            "stack_trace": r"(?i)(traceback \(most recent call last\)|java\.lang\.|org\.apache\.|at [\w.$]+\([\w]+\.java:\d+\)|panic:|goroutine \d+|\.py\", line \d+)",
            "debug_leak": r"(?i)(debug mode|xdebug|traceback|internal server error|stack trace|verbose error)",
            "php_error": r"(?i)(warning:|notice:|fatal error:|on line \d+)",
            "path_disclosure": r"(?i)((/var/www|/home/[a-z0-9_]+/|/usr/(local/)?lib/python|/opt/[a-z0-9_.-]+/[a-z0-9_.-]+\.py|[a-z]:\\\\[a-z0-9_\\\\.-]+))",
            "framework_leak": r"(?i)(django\.core\.exceptions|werkzeug|laravel\.framework|springframework|express error|rack::|jinja2)",
            "secret_like": r"(?i)(api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{12,}|secret[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{12,}|password\s*[=:]\s*['\"][^'\"]{4,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
            "email_leak": r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
            "internal_host": r"(?i)\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
            "sqli_marker": r"(?i)(union select|or 1=1|information_schema|sleep\(\d+\)|benchmark\(\d+)",
            "xss_marker": r"(?i)(<script|onerror=|javascript:)",
            "cmd_marker": r"(?i)(; cat /etc/passwd|\|whoami|\$\(id\)|`id`)",
        }
        for name, pattern in patterns.items():
            if re.search(pattern, text):
                signals.append(name)

        json_info = None
        try:
            parsed = json.loads(text)
            json_info = {"type": type(parsed).__name__, "keys": list(parsed)[:40] if isinstance(parsed, dict) else None}
        except Exception:
            pass

        return {
            "signals": signals,
            "status": (response or {}).get("status"),
            "len": len(body),
            "sha256": (response or {}).get("sha256"),
            "json": json_info,
            "title": self._title(text),
            "server": (response or {}).get("headers", {}).get("Server") or (response or {}).get("headers", {}).get("server"),
        }

    @staticmethod
    def _title(text: str) -> str:
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        return m.group(1).strip()[:120] if m else ""

    @staticmethod
    def diff(a: dict, b: dict) -> dict:
        """두 응답 차이를 요약."""
        if not a or not b:
            return {"error": "두 응답이 모두 있어야 합니다."}
        ha = (a.get("headers") or {})
        hb = (b.get("headers") or {})
        header_delta = {k: (ha.get(k), hb.get(k)) for k in set(ha) | set(hb) if ha.get(k) != hb.get(k)}
        body_a = a.get("body") or ""
        body_b = b.get("body") or ""
        return {
            "status": (a.get("status"), b.get("status")),
            "len_delta": (b.get("len", 0) or 0) - (a.get("len", 0) or 0),
            "header_delta": header_delta,
            "identical_body": body_a == body_b,
            "body_head_a": body_a[:400],
            "body_head_b": body_b[:400],
        }

    def note(self, message: str) -> str:
        self.notes.append(str(message))
        return f"note recorded ({len(self.notes)})"

    def finding(self, title: str, severity: str = "medium", evidence=None, remediation: str = "") -> str:
        item = {
            "title": str(title),
            "severity": str(severity).lower(),
            "evidence": evidence,
            "remediation": remediation,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        self.findings.append(item)
        return f"finding recorded ({len(self.findings)})"

    def save(self, name: str, content: str) -> str:
        target = os.path.abspath(os.path.join(self.run_dir, os.path.basename(name)))
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(content)
        return target

    def status(self) -> dict:
        return {
            "base_url": self.base_url,
            "allow": [f"{k}:{v}" for k, v in self.scope.allow],
            "deny": [f"{k}:{v}" for k, v in self.scope.deny],
            "ports": sorted(self.scope.ports),
            "max_rps": self.scope.max_rps,
            "blocked_attempts": self.guard.blocked,
            "notes": len(self.notes),
            "findings": len(self.findings),
            "run_dir": self.run_dir,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 커널 실행부
# ─────────────────────────────────────────────────────────────────────────────


class KernelTimeout(Exception):
    pass


class Kernel:
    def __init__(self, scope: Scope, run_dir: str, base_url: str | None = None):
        self.scope = scope
        self.run_dir = run_dir
        self.guard = Guard(scope)
        _lock_dangerous(run_dir)
        self.toolkit = Toolkit(scope, self.guard, run_dir, base_url)
        self.ns: dict = {"__name__": "__forge__", "forge": self.toolkit}
        self.history: list[str] = []

    def reset(self) -> None:
        self.ns = {"__name__": "__forge__", "forge": self.toolkit}

    def _exec(self, code: str, timeout: float) -> tuple[str, str, str, Any]:
        """(stdout, stderr, result_repr, 값) 반환."""
        stdout, stderr = io.StringIO(), io.StringIO()
        result_repr = ""
        value = None
        try:
            tree = ast.parse(code, mode="exec")
        except SyntaxError as exc:
            return "", f"SyntaxError: {exc}", "", None

        # 마지막 표현식은 값으로 평가한다 (IPython 동작).
        body = tree.body
        last_expr = None
        if body and isinstance(body[-1], ast.Expr):
            last_expr = ast.Expression(body[-1].value)
            body = body[:-1]

        def handler(signum, frame):
            raise KernelTimeout(f"실행 시간 초과 ({timeout}s)")

        old_handler = signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, max(0.05, timeout))
        started = time.perf_counter()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                if body:
                    compiled = compile(ast.Module(body=body, type_ignores=[]), "<forge>", "exec")
                    exec(compiled, self.ns)
                if last_expr is not None:
                    value = eval(compile(last_expr, "<forge>", "eval"), self.ns)
                    print(repr(value))
        except KernelTimeout as exc:
            return stdout.getvalue(), f"{type(exc).__name__}: {exc}", "", None
        except SystemExit as exc:
            return stdout.getvalue(), f"SystemExit: {exc}", "", None
        except Exception:
            return stdout.getvalue(), stderr.getvalue() + traceback.format_exc(), "", None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
            elapsed = (time.perf_counter() - started) * 1000
            self.last_elapsed = elapsed
        return stdout.getvalue(), stderr.getvalue(), result_repr, value

    def handle(self, req: dict) -> dict:
        op = req.get("op", "exec")
        rid = req.get("id", 0)
        try:
            if op == "ping":
                return {"id": rid, "ok": True, "pong": True}
            if op == "shutdown":
                return {"id": rid, "ok": True, "bye": True}
            if op == "reset":
                self.reset()
                return {"id": rid, "ok": True, "reset": True}
            if op == "vars":
                names = sorted(k for k in self.ns if not k.startswith("__"))
                return {"id": rid, "ok": True, "vars": [{"name": n, "type": type(self.ns[n]).__name__} for n in names]}
            if op == "notes":
                return {"id": rid, "ok": True, "notes": self.toolkit.notes, "findings": self.toolkit.findings}
            if op == "status":
                return {"id": rid, "ok": True, "status": self.toolkit.status()}
            if op == "exec":
                code = req.get("code", "") or ""
                timeout = float(req.get("timeout_ms", 10000)) / 1000.0
                self.history.append(code)
                out, err, _repr, value = self._exec(code, timeout)
                return {
                    "id": rid,
                    "ok": not err,
                    "stdout": out,
                    "stderr": err,
                    "result": repr(value) if value is not None else "",
                    "duration_ms": round(getattr(self, "last_elapsed", 0.0), 2),
                }
            return {"id": rid, "ok": False, "error": f"알 수 없는 op: {op}"}
        except Exception as exc:
            return {"id": rid, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> None:
    scope_path = None
    base_url = None
    run_dir = os.path.abspath(os.getcwd())
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--scope" and i + 1 < len(args):
            scope_path = args[i + 1]
            i += 2
        elif args[i] == "--base-url" and i + 1 < len(args):
            base_url = args[i + 1]
            i += 2
        elif args[i] == "--run-dir" and i + 1 < len(args):
            run_dir = os.path.abspath(args[i + 1])
            i += 2
        else:
            i += 1

    doc: dict = {}
    if scope_path and os.path.isfile(scope_path):
        with open(scope_path, "r", encoding="utf-8") as fh:
            try:
                doc = yaml_load(fh.read()) or {}
            except Exception:
                doc = {}
            if isinstance(doc, dict):
                doc["__source__"] = scope_path
    else:
        # 인가 파일 없음 — 커널은 기동하되 모든 요청을 차단한다 (fail-closed).
        doc = {"scope": {"allow": []}, "__source__": "<없음>"}

    scope = Scope(doc)
    os.makedirs(run_dir, exist_ok=True)
    kernel = Kernel(scope, run_dir, base_url)

    sys.stdout.write(json.dumps({"id": 0, "ok": True, "ready": True, "status": kernel.toolkit.status()}) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps({"id": 0, "ok": False, "error": f"JSON 파싱 실패: {exc}"}) + "\n")
            sys.stdout.flush()
            continue
        resp = kernel.handle(req)
        if req.get("op") == "shutdown":
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            break
        sys.stdout.write(json.dumps(resp, ensure_ascii=False, default=str) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
