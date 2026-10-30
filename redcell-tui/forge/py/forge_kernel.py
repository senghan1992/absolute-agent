#!/usr/bin/env python3
"""REDFORGE 파이썬 커널 — 인가된 점검 대상만 건드리는 격리 실행 환경.

prime-agent 의 ipython 커널과 같은 역할:
  - 한 번 시작하면 같은 네임스페이스에서 코드를 계속 실행한다 (변수·함수 재사용).
  - stdout/stderr 를 캡처해 구조화된 결과로 돌려준다.
  - 실행 시간 초과를 실제로 끊는다 (SIGALRM 기반).
  - 마지막 표현식의 값을 결과로 반환한다 (IPython 과 동일 동작).

보안 모델 (이 파일이 보장하는 것):
  1. **import allowlist** — `sys.meta_path` 파인더와 `builtins.__import__` 교체로
     os/socket/subprocess/ctypes/importlib 등 위험 모듈의 import 를 원천 차단한다.
  2. **안전한 builtins** — 샌드박스에는 `SAFE_BUILTINS` 만 주며 exec/compile/input/help 은
     차단, eval 은 표현식만 허용한다.
  3. **소켓 가드** — `_socket.socket` 타입 레벨에서 connect/connect_ex 를 후킹하고
     sendto/sendmsg(UDP) 는 항상 차단한다. DNS 계열(getaddrinfo/gethostbyname/...) 도
     모두 인가 검사를 거치며, 해결된 IP 를 다시 검증한다.
  4. **파일 가드** — builtins.open/io.open/os.open/os.fdopen 을 후킹한다.
     쓰기는 커널 실행 디렉터리 안으로, 읽기는 같은 디렉터리로 제한한다(realpath 추적).
  5. **감사 훅** — `sys.addaudithook` 으로 import/open/exec/socket/os.* 이벤트를
     C 레벨에서 막는다(후킹 함수를 되돌려도 우회 불가).
  6. **RPS 상한** — 토큰 버킷으로 `limits.max_requests_per_second` 를 강제한다.
  7. **자격증명 비노출** — `forge.credentials()` 는 마스킹된 요약만 돌려준다.

프로토콜: stdin/stdout JSON Lines.
  요청 {"id":1,"op":"exec","code":"...","timeout_ms":5000}
  응답 {"id":1,"ok":true,"stdout":"","stderr":"","result":"","duration_ms":12,...}
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import hashlib
import io
import json
import os
import random
import re
import signal
import socket
import ssl
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

try:  # Windows 등에는 없을 수 있다.
    import resource as _resource_mod
except Exception:  # pragma: no cover - 플랫폼 의존
    _resource_mod = None

#: 후킹 전의 원본 참조 — 되돌리기가 성공해도 이 사본으로 다시 설치한다.
_BUILTIN_OPEN = builtins.open
_BUILTIN_IMPORT = builtins.__import__

# ─────────────────────────────────────────────────────────────────────────────
# 모듈 허용/차단 목록 (샌드박스 import 게이트)
# ─────────────────────────────────────────────────────────────────────────────

#: 허용 모듈 루트 (하위 모듈은 차단 목록에 없으면 함께 허용).
ALLOWED_MODULE_ROOTS = frozenset({
    "json", "re", "math", "base64", "hashlib", "binascii", "codecs", "html",
    "string", "random", "statistics", "datetime", "time", "decimal", "fractions",
    "itertools", "collections", "functools", "operator", "textwrap", "unicodedata",
    "typing", "dataclasses", "enum", "pprint", "uuid", "ast", "urllib",
    "copy", "types", "weakref", "xml", "encodings",
})

#: 정확히 허용하는 모듈 (하위 모듈).
ALLOWED_MODULES = frozenset({
    "urllib.parse",
    "xml.etree", "xml.etree.ElementTree",
    "collections.abc",
})

#: 차단 모듈 루트 — import 자체를 금지한다.
BLOCKED_MODULE_ROOTS = frozenset({
    "os", "sys", "subprocess", "ctypes", "multiprocessing", "threading", "pty",
    "fcntl", "signal", "resource", "importlib", "runpy", "code", "codeop",
    "pickle", "marshal", "shutil", "pathlib", "tempfile", "socket", "ssl",
    "http", "mmap", "select", "asyncio", "webbrowser", "cgi", "pdb", "inspect",
    "gc", "platform", "getpass", "builtins", "_socket", "_ssl", "_io",
})

#: 정확히 차단하는 모듈 (상위 루트는 허용되어도 이 이름은 금지).
BLOCKED_MODULES = frozenset({
    "urllib.request", "urllib.error", "http.client", "urllib.response",
    "__main__", "__builtin__", "builtins", "os.path", "posixpath", "ntpath",
    "xml.sax", "xml.dom", "xml.parsers", "importlib.util",
    "importlib.machinery", "importlib.reload", "sysconfig", "site", "pkgutil",
})

#: 표준 라이브러리 내부에서만 lazy import 로 필요한 모듈.
#: (샌드박스에서는 여전히 차단된다 — 내부 프레임 판정으로 구분한다.)
INTERNAL_IMPORT_ALLOW = frozenset({
    "ssl", "encodings", "encodings.idna", "encodings.utf_8", "email.parser",
})

#: 커널 시작 시 미리 적재해 두는 모듈 (허용 목록 + 의존 모듈).
#: 샌드박스에서 import 가 일어나면 `__import__` 후킹이 사후 조회로 막기 전에
#: 이미 sys.modules 에 있어야 내부 의존 import 가 차단 목록에 걸리지 않는다.
PRELOAD_MODULES = (
    "json", "re", "math", "base64", "hashlib", "binascii", "codecs", "html",
    "string", "random", "statistics", "datetime", "time", "decimal", "fractions",
    "itertools", "collections", "collections.abc", "functools", "operator",
    "textwrap", "unicodedata", "typing", "dataclasses", "enum", "pprint", "uuid",
    "ast", "urllib", "urllib.parse", "xml", "xml.etree", "xml.etree.ElementTree",
    "copy", "types", "weakref", "encodings", "encodings.idna", "struct",
)

#: sys.modules 에 남겨 두는 모듈 (인터프리터 안정성 + 내부 lazy import 확보).
KEEP_IN_SYSMODULES = frozenset({
    "builtins", "sys", "__main__", "ssl", "encodings.idna",
})

#: 기본 RPS (인가 파일에 limits.max_requests_per_second 가 없을 때).
DEFAULT_RPS = 5.0

#: forge.burst 상한.
MAX_BURST_WORKERS = 8
MAX_BURST_PAYLOADS = 200

#: 커널 프로세스 메모리 상한 (1 GiB).
DEFAULT_MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024

#: getattr/setattr 로 접근을 막을 내부 introspection 이름.
BLOCKED_ATTRS = frozenset({
    "__globals__", "__closure__", "__code__", "__builtins__", "__subclasses__",
    "__bases__", "__mro__", "__reduce__", "__reduce_ex__", "__getattribute__",
    "__init_subclass__", "__loader__", "__spec__", "__dict__",
})


def _module_allowed(fullname: str) -> bool:
    """모듈 이름이 샌드박스에서 import 가능한지 판정한다."""
    if not fullname or not isinstance(fullname, str):
        return False
    root = fullname.split(".", 1)[0]
    if fullname in BLOCKED_MODULES or root in BLOCKED_MODULE_ROOTS:
        return False
    if fullname in ALLOWED_MODULES:
        return True
    if root in ALLOWED_MODULE_ROOTS:
        return True
    return False


def _module_dangerous(fullname: str) -> bool:
    """표준 라이브러리 내부에서도 로드하면 안 되는 모듈인지 판정한다."""
    if not fullname or not isinstance(fullname, str):
        return False
    root = fullname.split(".", 1)[0]
    return fullname in BLOCKED_MODULES or root in BLOCKED_MODULE_ROOTS


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
        rest = body[2:] if body.startswith("- ") else ""
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
# IP 정규화 — 축약 표기(127.1 / 2130706433) 우회 차단
# ─────────────────────────────────────────────────────────────────────────────


def _canonical_ipv4(text: str) -> str | None:
    """IPv4 축약 표기를 점-구분 4자리로 정규화한다. 실패하면 None."""
    candidate = (text or "").strip()
    if not candidate:
        return None
    if not all(ch.isdigit() or ch == "." for ch in candidate):
        return None
    try:
        packed = socket.inet_aton(candidate)
    except OSError:
        return None
    return ".".join(str(byte) for byte in packed)


def _canonical_ipv6(text: str) -> str | None:
    """IPv6 를 정규화한다. IPv4-mapped(`::ffff:a.b.c.d`) 는 IPv4 로 되돌린다."""
    candidate = (text or "").strip().strip("[]")
    if not candidate or ":" not in candidate:
        return None
    try:
        packed = socket.inet_pton(socket.AF_INET6, candidate)
    except OSError:
        return None
    if packed[:10] == b"\x00" * 10 and packed[10:12] == b"\xff\xff":
        return ".".join(str(byte) for byte in packed[12:16])
    return ":".join(f"{packed[i]:02x}{packed[i + 1]:02x}" for i in range(0, 16, 2))


def canonical_host(text: str) -> str | None:
    """호스트 문자열이 IP 면 정규화된 표기로, 아니면 None 을 돌려준다."""
    value = (text or "").strip().strip("[]").lower()
    if not value:
        return None
    if ":" in value:
        return _canonical_ipv6(value)
    return _canonical_ipv4(value)


def _is_ip_literal(text: str) -> bool:
    return canonical_host(text) is not None


def _ip_to_int(value: str) -> int | None:
    canonical = canonical_host(value)
    if not canonical or ":" in canonical:
        return None
    try:
        return int.from_bytes(bytes(int(part) for part in canonical.split(".")), "big")
    except ValueError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 인가 스코프 (Rust 게이트와 동일 규칙)
# ─────────────────────────────────────────────────────────────────────────────


class ScopeError(Exception):
    pass


#: 자격증명 원본은 프로세스에 상주시키지 않는다.
#: 인가 파일에서 요청 시점에 읽어쓰고, 샌드박스에는 마스킹 요약만 노출한다.


def _mask_credentials(cred) -> dict:
    """인가 파일의 자격증명을 마스킹된 요약으로 바꾼다 (값은 노출하지 않는다)."""
    summary: dict[str, Any] = {}
    if not isinstance(cred, dict):
        return summary
    cookie = cred.get("cookie")
    bearer = cred.get("bearer")
    extra = cred.get("headers") or {}
    if isinstance(cookie, str) and cookie:
        summary["cookie"] = "Cookie: ***"
    if isinstance(bearer, str) and bearer:
        summary["bearer"] = "Authorization: Bearer ***"
    if isinstance(extra, dict):
        names = [f"{key}: ***" for key in extra]
        if names:
            summary["headers"] = names
    return summary


def _read_credential_headers(scope_path: str | None) -> dict:
    """인가 파일에서 자격증명 헤더를 읽는다 — 요청 시점에만 메모리에 존재한다."""
    if not scope_path or not os.path.isfile(scope_path):
        return {}
    try:
        with _BUILTIN_OPEN(scope_path, "r", encoding="utf-8") as fh:
            doc = yaml_load(fh.read()) or {}
    except Exception:
        return {}
    if not isinstance(doc, dict):
        return {}
    cred = doc.get("credentials")
    headers: dict[str, str] = {}
    if not isinstance(cred, dict):
        return headers
    cookie = cred.get("cookie")
    bearer = cred.get("bearer")
    extra = cred.get("headers") or {}
    if isinstance(cookie, str) and cookie:
        headers["Cookie"] = cookie
    if isinstance(bearer, str) and bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if isinstance(extra, dict):
        for key, value in extra.items():
            headers[str(key)] = str(value)
    return headers


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
        # 자격증명 원본은 여기 두지 않는다 — 마스킹 요약만 노출한다.
        self.cred_summary = _mask_credentials(doc.get("credentials"))
        self.source = doc.get("__source__", "<memory>")
        # 요청 시점에 자격증명을 읽어올 원본 인가 파일 경로 (파일이 아니면 None).
        self.cred_path = self.source if isinstance(self.source, str) and os.path.isfile(self.source) else None

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
    def _match(self, kind: str, value: str, host: str, canon: str | None = None) -> bool:
        """인가 규칙과 호스트를 비교한다. IPv4 축약 표기는 정규화 후 비교한다."""
        if canon is None:
            canon = canonical_host(host)
        if kind in ("host", "ip"):
            if value == host:
                return True
            value_canon = canonical_host(value)
            return bool(value_canon and canon and value_canon == canon)
        if kind == "domain":
            root = value.lstrip("*.").lstrip(".")
            if not root:
                return False
            if canon and _is_ip_literal(canon):
                return False  # IP 리터럴은 도메인 규칙에 걸리지 않는다.
            return host == root or host.endswith("." + root)
        if kind == "cidr":
            net, _, bits_text = value.partition("/")
            try:
                bits = int(bits_text)
            except ValueError:
                return False
            net_int = _ip_to_int(net)
            ip_int = _ip_to_int(canon or host)
            if net_int is None or ip_int is None:
                return False
            if bits <= 0:
                mask = 0
            elif bits >= 32:
                mask = 0xFFFFFFFF
            else:
                mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            return (ip_int & mask) == (net_int & mask)
        return False

    def check_host(self, host: str, port: int | None = None) -> None:
        host = (host or "").strip().strip(".").lower() if isinstance(host, str) else ""
        if not host:
            raise ScopeError("호스트가 비어 있습니다.")
        canon = canonical_host(host)
        self.check_period()
        for kind, value in self.deny:
            if self._match(kind, value, host, canon):
                raise ScopeError(f"{host} 는 deny 규칙에 포함됩니다.")
        if not any(self._match(kind, value, host, canon) for kind, value in self.allow):
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

    # -- 요약 ---------------------------------------------------------------
    def summary(self) -> dict:
        return {
            "engagement": self.engagement.get("name") or "",
            "allow": [f"{kind}:{value}" for kind, value in self.allow],
            "deny": [f"{kind}:{value}" for kind, value in self.deny],
            "ports": sorted(self.ports),
            "max_rps": self.max_rps,
            "credentials": dict(self.cred_summary),
            "source": self.source,
        }


class ScopeView:
    """`forge.scope` — 요약 출력과 인가 판정만 노출한다(자격증명 원본 차단)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: Scope):
        object.__setattr__(self, "_scope", scope)

    def __call__(self) -> dict:
        return self.summary()

    def summary(self) -> dict:
        return self._scope.summary()

    def __getattr__(self, name):
        if name.startswith("__") or name in ("credentials", "cred_secret"):
            raise AttributeError(f"'{name}' 는 샌드박스에서 노출되지 않습니다.")
        return getattr(object.__getattribute__(self, "_scope"), name)

    def __repr__(self) -> str:
        return f"<ScopeView {self._scope.source}>"


# ─────────────────────────────────────────────────────────────────────────────
# RPS 제한기 — 토큰 버킷 (Rust scope::RateLimiter 와 동일 규칙)
# ─────────────────────────────────────────────────────────────────────────────


class RateLimiter:
    """토큰 버킷 — `limits.max_requests_per_second` 를 강제한다."""

    def __init__(self, rps: float | None, capacity: float | None = None):
        value = float(rps) if isinstance(rps, (int, float)) and rps and rps > 0 else DEFAULT_RPS
        self.rps = value
        self.capacity = float(capacity) if capacity else max(1.0, min(value, 5.0))
        self.tokens = self.capacity
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rps)

    def try_acquire(self, amount: float = 1.0) -> bool:
        """토큰이 있으면 소비하고 True, 없으면 False."""
        with self._lock:
            self._refill()
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

    def acquire(self, amount: float = 1.0, max_wait: float = 30.0) -> None:
        """토큰이 생길 때까지 기다린다. 기한을 넘으면 ScopeError."""
        deadline = time.monotonic() + max(0.0, max_wait)
        while not self.try_acquire(amount):
            if time.monotonic() >= deadline:
                raise ScopeError(f"RPS 제한 초과 (최대 {self.rps:g}/s).")
            time.sleep(0.05)


# ─────────────────────────────────────────────────────────────────────────────
# 원본 함수 보관 — 후킹의 기준선 (샌드박스가 되돌려도 매 실행마다 재설치한다)
# ─────────────────────────────────────────────────────────────────────────────

_ORIG: dict[str, Any] = {}


def _capture_originals() -> None:
    """샌드박스 가드가 덮어쓰기 전의 원본을 1회만 확보한다."""
    if _ORIG:
        return
    _ORIG.update({
        "builtin_open": _BUILTIN_OPEN,
        "io_open": io.open,
        "os_open": os.open,
        "os_fdopen": os.fdopen,
        "import": _BUILTIN_IMPORT,
        "socket_connect": socket.socket.connect,
        "socket_connect_ex": socket.socket.connect_ex,
        "socket_sendto": getattr(socket.socket, "sendto", None),
        "socket_sendmsg": getattr(socket.socket, "sendmsg", None),
        "socket_getaddrinfo": socket.getaddrinfo,
        "socket_gethostbyname": socket.gethostbyname,
        "socket_gethostbyname_ex": socket.gethostbyname_ex,
        "socket_gethostbyaddr": socket.gethostbyaddr,
        "socket_getnameinfo": socket.getnameinfo,
        "socket_getfqdn": socket.getfqdn,
        "socket_create_connection": socket.create_connection,
        "urlopen": urllib.request.urlopen,
        "build_opener": urllib.request.build_opener,
        "install_opener": urllib.request.install_opener,
    })
    try:  # 저수준 모듈도 함께 후킹 (이전 파이썬에서는 socket.socket 과 동일 객체).
        import _socket  # noqa: PLC0415 - 커널 전용
        _ORIG["low_getaddrinfo"] = _socket.getaddrinfo
        _ORIG["low_gethostbyname"] = _socket.gethostbyname
        _ORIG["low_gethostbyname_ex"] = _socket.gethostbyname_ex
        _ORIG["low_gethostbyaddr"] = _socket.gethostbyaddr
        _ORIG["low_getnameinfo"] = _socket.getnameinfo
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# 샌드박스 가드 — import / 파일 / 소켓 / URL 을 한곳에서 막는다
# ─────────────────────────────────────────────────────────────────────────────

#: 현재 활성화된 가드 ( selftest 에서는 해제해 원본 상태로 되돌린다 ).
_ACTIVE_GUARD: "Guard | None" = None

#: 감사 훅은 한 번만 설치된다(파이썬에서 제거할 수 없다).
_AUDIT_INSTALLED = False


def _require_guard() -> "Guard":
    guard = _ACTIVE_GUARD
    if guard is None:
        raise PermissionError("샌드박스 가드가 활성화되지 않았습니다.")
    return guard


def _blocked_call(name: str):
    def _call(*_args, **_kwargs):
        raise PermissionError(f"{name} 는 점검 샌드박스에서 차단되었습니다.")

    return _call


def _is_sandbox_frame() -> bool:
    """지금 실행 중인 프레임이 사용자 코드(샌드박스)인지 판정한다.

    샌드박스 코드는 항상 `<forge>` 파일명으로 컴파일되므로 위조할 수 없다.
    표준 라이브러리 내부의 lazy import 와 사용자의 import 를 구분하는 데 쓴다.
    """
    try:
        frame = sys._getframe(1)
    except Exception:
        return True
    filename = getattr(frame.f_code, "co_filename", "")
    if isinstance(filename, str) and filename.startswith("<forge"):
        return True
    name = frame.f_globals.get("__name__", "")
    return isinstance(name, str) and name.startswith("__forge")


def _guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    """`builtins.__import__` 교체 — 샌드박스에서는 allowlist 밖 모듈을 차단한다."""
    if _ACTIVE_GUARD is None:
        return _BUILTIN_IMPORT(name, globals, locals, fromlist, level)
    fullname = name if isinstance(name, str) else ""
    if _is_sandbox_frame():
        if level:
            raise ImportError("상대 import 는 샌드박스에서 허용되지 않습니다.")
        if not _module_allowed(fullname):
            raise ImportError(f"'{fullname}' 모듈은 샌드박스에서 사용할 수 없습니다 (import 차단).")
    else:
        # 표준 라이브러리 내부 import — 위험 모듈만 막고 나머지는 허용한다.
        if fullname not in INTERNAL_IMPORT_ALLOW and _module_dangerous(fullname):
            raise ImportError(f"'{fullname}' 모듈은 샌드박스에서 사용할 수 없습니다 (import 차단).")
    return _BUILTIN_IMPORT(name, globals, locals, fromlist, level)


def _guarded_open(file, mode="r", *args, **kwargs):
    """`builtins.open` / `io.open` 교체 — 경로 policy 를 강제한다."""
    guard = _require_guard()
    guard.check_path(file, mode if isinstance(mode, str) else "r")
    return _BUILTIN_OPEN(file, mode, *args, **kwargs)


def _guarded_os_open(path, flags, *args, **kwargs):
    """`os.open` 교체 — 쓰기 플래그를 경로 policy 로 확인한다."""
    guard = _require_guard()
    writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    guard.check_path(path, "w" if writing else "r")
    return _ORIG["os_open"](path, flags, *args, **kwargs)


def _guarded_os_fdopen(fd, mode="r", *args, **kwargs):
    """`os.fdopen` 교체 — fd 대상 경로를 확인할 수 없으면 쓰기를 차단한다."""
    guard = _require_guard()
    writing = any(flag in (mode or "r") for flag in ("w", "a", "x", "+"))
    target = guard.fd_path(fd)
    if target is None:
        if writing:
            raise PermissionError("파일 디스크립터 쓰기는 차단되었습니다.")
        raise PermissionError("파일 디스크립터 읽기는 차단되었습니다.")
    guard.check_path(target, mode if isinstance(mode, str) else "r")
    return _ORIG["os_fdopen"](fd, mode, *args, **kwargs)


def _guarded_connect(self_sock, address):
    """`_socket.socket.connect` 교체 — 인가 대상만 연결한다."""
    guard = _require_guard()
    guard.check_address(address)
    return _ORIG["socket_connect"](self_sock, address)


def _guarded_connect_ex(self_sock, address):
    """`_socket.socket.connect_ex` 교체 — 인가 대상만 연결한다."""
    guard = _require_guard()
    guard.check_address(address)
    return _ORIG["socket_connect_ex"](self_sock, address)


def _guarded_sendto(self_sock, *args, **kwargs):
    """UDP 송신은 항상 차단한다(점검에 필요하지 않다)."""
    raise ScopeError("UDP sendto 는 점검 샌드박스에서 차단되었습니다.")


def _guarded_sendmsg(self_sock, *args, **kwargs):
    """UDP sendmsg 는 항상 차단한다."""
    raise ScopeError("UDP sendmsg 는 점검 샌드박스에서 차단되었습니다.")


def _guarded_getaddrinfo(host, port, *args, **kwargs):
    """`getaddrinfo` 교체 — 인가 검사 + 해결 결과 IP 재검증."""
    guard = _require_guard()
    guard.check_host_argument(host, port)
    results = _ORIG["socket_getaddrinfo"](host, port, *args, **kwargs)
    guard.check_resolved(results)
    return results


def _guarded_low_getaddrinfo(host, port, *args, **kwargs):
    """`_socket.getaddrinfo` 교체 — 저수준 직접 호출도 인가 검사를 거친다."""
    guard = _require_guard()
    guard.check_host_argument(host, port)
    results = _ORIG["low_getaddrinfo"](host, port, *args, **kwargs)
    guard.check_resolved(results)
    return results


def _guarded_gethostbyname(host):
    guard = _require_guard()
    guard.check_host_argument(host, None)
    address = _ORIG["socket_gethostbyname"](host)
    guard.check_resolved_ip(address)
    guard.record_resolved([(0, 0, 0, "", (address, 0))])
    return address


def _guarded_low_gethostbyname(host):
    guard = _require_guard()
    guard.check_host_argument(host, None)
    address = _ORIG["low_gethostbyname"](host)
    guard.check_resolved_ip(address)
    guard.record_resolved([(0, 0, 0, "", (address, 0))])
    return address


def _guarded_gethostbyname_ex(host):
    guard = _require_guard()
    guard.check_host_argument(host, None)
    result = _ORIG["socket_gethostbyname_ex"](host)
    if isinstance(result, tuple) and len(result) >= 3:
        for address in result[2] or []:
            guard.check_resolved_ip(address)
    return result


def _guarded_low_gethostbyname_ex(host):
    guard = _require_guard()
    guard.check_host_argument(host, None)
    result = _ORIG["low_gethostbyname_ex"](host)
    if isinstance(result, tuple) and len(result) >= 3:
        for address in result[2] or []:
            guard.check_resolved_ip(address)
    return result


def _guarded_gethostbyaddr(ip):
    guard = _require_guard()
    guard.check_resolved_ip(ip, require_authorized=True)
    return _ORIG["socket_gethostbyaddr"](ip)


def _guarded_low_gethostbyaddr(ip):
    guard = _require_guard()
    guard.check_resolved_ip(ip, require_authorized=True)
    return _ORIG["low_gethostbyaddr"](ip)


def _guarded_getnameinfo(sockaddr, flags):
    guard = _require_guard()
    address = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else sockaddr
    guard.check_resolved_ip(address, require_authorized=True)
    return _ORIG["socket_getnameinfo"](sockaddr, flags)


def _guarded_low_getnameinfo(sockaddr, flags):
    guard = _require_guard()
    address = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else sockaddr
    guard.check_resolved_ip(address, require_authorized=True)
    return _ORIG["low_getnameinfo"](sockaddr, flags)


def _guarded_getfqdn(name=""):
    guard = _require_guard()
    if name:
        guard.check_host_argument(name, None)
    return _ORIG["socket_getfqdn"](name)


def _guarded_create_connection(address, *args, **kwargs):
    guard = _require_guard()
    guard.check_address(address)
    return _ORIG["socket_create_connection"](address, *args, **kwargs)


def _guarded_urlopen(url, *args, **kwargs):
    """`urllib.request.urlopen` 교체 — http/https 만 허용한다."""
    guard = _require_guard()
    guard.check_url(url)
    opener = guard.build_opener()
    return opener.open(url, *args, **kwargs)


def _guarded_build_opener(*handlers, **kwargs):
    """`urllib.request.build_opener` 교체 — 프록시 무시 + 로컬 파일 핸들러 제거."""
    guard = _require_guard()
    handlers = tuple(h for h in handlers if not isinstance(h, urllib.request.ProxyHandler))
    opener = _ORIG["build_opener"](*handlers, **kwargs)
    opener.handlers = [
        h for h in opener.handlers
        if not isinstance(h, (urllib.request.FileHandler, urllib.request.FTPHandler, urllib.request.DataHandler))
        and not isinstance(h, urllib.request.ProxyHandler)
    ]
    opener.add_handler(urllib.request.ProxyHandler({}))
    return opener


def _guarded_install_opener(opener):
    """opener 교체는 차단한다(_FILE handler 로 로컬 파일을 읽는 우회 방지)."""
    raise PermissionError("urllib opener 교체는 점검 샌드박스에서 차단되었습니다.")


# ─────────────────────────────────────────────────────────────────────────────
# 감사 훅 — C 레벨 이벤트 차단 (후킹 함수를 되돌려도 우회 불가)
# ─────────────────────────────────────────────────────────────────────────────


def _audit_import(guard, args) -> None:
    name = args[0] if args else ""
    if isinstance(name, str) and _module_dangerous(name):
        raise ImportError(f"'{name}' 모듈은 샌드박스에서 사용할 수 없습니다 (import 차단).")


def _audit_open(guard, args) -> None:
    path = args[0] if args else None
    mode = args[1] if len(args) > 1 else None
    flags = args[2] if len(args) > 2 else None
    if isinstance(mode, int):
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        text_mode = "w" if writing else "r"
    elif isinstance(mode, str):
        text_mode = mode
    else:
        text_mode = "r"
    guard.check_path(path, text_mode, allow_kernel=True)


def _audit_compile(guard, args) -> None:
    filename = args[1] if len(args) > 1 else ""
    if not isinstance(filename, str):
        return
    if filename.startswith("<forge") or filename == "<unknown>":
        return  # 커널 자신의 컴파일 / ast.parse 는 허용한다.
    raise PermissionError("코드 컴파일은 점검 샌드박스에서 차단되었습니다.")


def _audit_exec(guard, args) -> None:
    code = args[0] if args else None
    filename = getattr(code, "co_filename", "")
    if isinstance(filename, str) and filename.startswith("<forge"):
        return
    raise PermissionError("코드 실행은 점검 샌드박스에서 차단되었습니다.")


def _audit_socket_connect(guard, args) -> None:
    address = args[1] if len(args) > 1 else None
    guard.check_address(address)


def _audit_socket_getaddrinfo(guard, args) -> None:
    host = args[0] if args else None
    port = args[1] if len(args) > 1 else None
    guard.check_host_argument(host, port)


def _audit_socket_gethostbyname(guard, args) -> None:
    guard.check_host_argument(args[0] if args else None, None)


def _audit_socket_gethostbyname_ex(guard, args) -> None:
    guard.check_host_argument(args[0] if args else None, None)


def _audit_socket_gethostbyaddr(guard, args) -> None:
    guard.check_resolved_ip(args[0] if args else None, require_authorized=True)


def _audit_socket_getnameinfo(guard, args) -> None:
    sockaddr = args[0] if args else None
    address = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else sockaddr
    guard.check_resolved_ip(address, require_authorized=True)


def _audit_socket_sendto(guard, args) -> None:
    raise ScopeError("UDP sendto 는 점검 샌드박스에서 차단되었습니다.")


def _audit_socket_sendmsg(guard, args) -> None:
    raise ScopeError("UDP sendmsg 는 점검 샌드박스에서 차단되었습니다.")


def _audit_urllib_request(guard, args) -> None:
    url = args[0] if args else None
    guard.check_url(url)


_AUDIT_HANDLERS = {
    "import": _audit_import,
    "open": _audit_open,
    "compile": _audit_compile,
    "exec": _audit_exec,
    "socket.connect": _audit_socket_connect,
    "socket.getaddrinfo": _audit_socket_getaddrinfo,
    "socket.gethostbyname": _audit_socket_gethostbyname,
    "socket.gethostbyname_ex": _audit_socket_gethostbyname_ex,
    "socket.gethostbyaddr": _audit_socket_gethostbyaddr,
    "socket.getnameinfo": _audit_socket_getnameinfo,
    "socket.sendto": _audit_socket_sendto,
    "socket.sendmsg": _audit_socket_sendmsg,
    "urllib.Request": _audit_urllib_request,
}


def _audit_hook(event: str, args) -> None:
    """`sys.addaudithook` — 샌드박스가 제거할 수 없는 마지막 방어선."""
    guard = _ACTIVE_GUARD
    if guard is None:
        return
    if event.startswith("os."):
        raise PermissionError(f"'{event}' 작업은 점검 샌드박스에서 차단되었습니다.")
    if event.startswith("ctypes."):
        raise PermissionError(f"'{event}' 작업은 점검 샌드박스에서 차단되었습니다.")
    handler = _AUDIT_HANDLERS.get(event)
    if handler is None:
        return
    handler(guard, args)


# ─────────────────────────────────────────────────────────────────────────────
# Guard — 인가 밖 접근을 차단하는 전역 후킹 관리자
# ─────────────────────────────────────────────────────────────────────────────


class Guard:
    """인가 게이트를 파이썬 레벨에서 강제한다."""

    def __init__(self, scope: Scope, run_dir: str):
        self.scope = scope
        self.run_dir = os.path.abspath(run_dir)
        self.read_roots: list[str] = []
        self.write_roots: list[str] = []
        self.protected: set[str] = set()
        self.blocked = 0
        self.warnings: list[str] = []
        self._resolved_ok: dict[str, float] = {}
        self.limiter = RateLimiter(scope.max_rps)
        self._os_stubs: list[tuple[Any, str, Any]] = []
        self._configure_paths()
        self.install()

    # -- 경로 정책 ----------------------------------------------------------
    def _configure_paths(self) -> None:
        run_real = self._real(self.run_dir)
        self.read_roots = [run_real]
        self.write_roots = [run_real]
        script = os.path.abspath(__file__)
        self.protected = {self._real(script)}
        # 실행 디렉터리에 놓인 커널 스크립트 사본도 덮어쓸 수 없다 (커널 자살 방지).
        bundled = os.path.join(self.run_dir, "forge_kernel.py")
        if os.path.isfile(bundled):
            self.protected.add(self._real(bundled))
        # 커널 내부에서만 읽는 인가 파일 (요청 시점 자격증명 로딩용).
        cred_path = getattr(self.scope, "cred_path", None)
        self.kernel_read_paths = {self._real(cred_path)} if cred_path else set()
        # 파이썬 설치 디렉터리의 코드 파일만 읽기를 허용한다.
        # (표준 라이브러리의 lazy import 가 .pyc 를 읽어야 한다 — 비밀 파일은 포함되지 않는다)
        self.code_roots = []
        for prefix in {sys.prefix, sys.base_prefix, sys.exec_prefix}:
            try:
                real = os.path.realpath(prefix)
            except Exception:
                continue
            if real and real not in self.code_roots:
                self.code_roots.append(real)

    @staticmethod
    def _real(path) -> str:
        try:
            return os.path.realpath(os.path.abspath(os.fspath(path)))
        except TypeError:
            return os.path.abspath(str(path))

    @staticmethod
    def _within(target: str, root: str) -> bool:
        return target == root or target.startswith(root.rstrip(os.sep) + os.sep)

    def fd_path(self, fd) -> str | None:
        """fd 가 가리키는 실제 경로(/proc/self/fd) — 없으면 None."""
        try:
            link = os.readlink(f"/proc/self/fd/{int(fd)}")
        except Exception:
            return None
        if not link.startswith("/"):
            return None
        return link

    def check_path(self, path, mode: str = "r", allow_kernel: bool = False) -> None:
        """파일 접근 경로 policy — 쓰기는 실행 디렉터리, 읽기는 같은 디렉터리로 제한.

        `allow_kernel` 는 커널 내부 읽기(인가 파일의 자격증명)만 예외로 허용한다.
        샌드박스가 `open()` 을 쓰는 경로에는 절대 적용되지 않는다.
        """
        writing = any(flag in (mode or "r") for flag in ("w", "a", "x", "+"))
        if isinstance(path, int):
            target = self.fd_path(path)
            if target is None:
                raise PermissionError("파일 디스크립터 접근은 차단되었습니다.")
        else:
            target = self._real(path)
        if writing:
            # 커널 스크립트(및 사본)는 덮어쓸 수 없다 — 샌드박스가 커널을 죽이면 안 된다.
            if target in self.protected or (
                os.path.basename(target) == "forge_kernel.py"
                and any(self._within(target, root) for root in self.write_roots)
            ):
                raise PermissionError(f"커널 스크립트({target}) 는 덮어쓸 수 없습니다.")
            if not any(self._within(target, root) for root in self.write_roots):
                raise PermissionError(f"파일 쓰기는 실행 디렉터리({self.run_dir}) 안에서만 가능합니다: {path}")
            return
        if allow_kernel and target in self.kernel_read_paths:
            return
        if not any(self._within(target, root) for root in self.read_roots):
            if not self._is_code_file(target):
                raise PermissionError(f"파일 읽기는 실행 디렉터리({self.run_dir}) 안에서만 가능합니다: {path}")

    def _is_code_file(self, target: str) -> bool:
        """파이썬 설치 디렉터리의 코드 파일(라이브러리 lazy import 용)인지 확인한다."""
        if os.path.splitext(target)[1].lower() not in (".py", ".pyc", ".so", ".pyd"):
            return False
        return any(self._within(target, root) for root in self.code_roots)

    # -- 인가 판정 ----------------------------------------------------------
    def check_host_argument(self, host, port) -> None:
        """DNS 질의 대상 호스트를 인가 목록과 대조한다."""
        if host is None:
            self.blocked += 1
            raise ScopeError("연결 차단: 호스트를 지정하지 않은 질의는 허용되지 않습니다.")
        if isinstance(host, bytes):
            host = host.decode("utf-8", errors="replace")
        if not isinstance(host, str):
            self.blocked += 1
            raise ScopeError(f"연결 차단: 지원하지 않는 호스트 형식 {type(host).__name__}")
        try:
            self.scope.check_host(host, port if isinstance(port, int) else None)
        except ScopeError as exc:
            self.blocked += 1
            raise ScopeError(f"연결 차단: {exc}") from exc

    def check_address(self, address) -> None:
        """connect 대상 주소를 검증한다 (AF_UNIX 등 튜플이 아닌 주소는 차단)."""
        if not isinstance(address, (tuple, list)) or len(address) < 2:
            self.blocked += 1
            raise ScopeError("연결 차단: 유니소켓 등 지원하지 않는 주소 형식입니다.")
        host, port = address[0], address[1]
        if isinstance(host, bytes):
            host = host.decode("utf-8", errors="replace")
        if not isinstance(host, str):
            self.blocked += 1
            raise ScopeError("연결 차단: 모든 인터페이스(0.0.0.0) 로의 연결은 허용되지 않습니다.")
        if canonical_host(host):
            # IP 리터럴 — 명시적으로 인가되었거나, 인가된 호스트에서 해석된 주소여야 한다.
            self.check_resolved_ip(host, require_authorized=True)
            if isinstance(port, int) and self.scope.ports and port not in self.scope.ports:
                self.blocked += 1
                raise ScopeError(f"포트 {port} 는 허용 포트 목록에 없습니다.")
            return
        self.check_host_argument(host, port if isinstance(port, int) else None)

    def check_resolved_ip(self, ip, require_authorized: bool = False) -> None:
        """IP 주소가 인가 범위 안인지 확인한다."""
        if not isinstance(ip, str) or not ip:
            self.blocked += 1
            raise ScopeError("연결 차단: 해석할 수 없는 주소입니다.")
        canonical = canonical_host(ip)
        if canonical is None:
            self.blocked += 1
            raise ScopeError(f"연결 차단: 해석할 수 없는 주소입니다: {ip}")
        for kind, value in self.scope.deny:
            if self.scope._match(kind, value, canonical, canonical):
                self.blocked += 1
                raise ScopeError(f"연결 차단: {ip} 는 deny 규칙에 포함됩니다.")
        for kind, value in self.scope.allow:
            if self.scope._match(kind, value, canonical, canonical):
                return
        if self._forbidden_ip(canonical):
            self.blocked += 1
            raise ScopeError(f"연결 차단: {ip} 는 사용할 수 없는 주소입니다.")
        if self._is_resolved_ok(canonical):
            return
        if require_authorized:
            self.blocked += 1
            raise ScopeError(f"연결 차단: {ip} 는 인가 대상이 아닙니다.")

    def _is_resolved_ok(self, canonical: str) -> bool:
        """인가된 호스트가 DNS 로 해석한 주소인지 확인한다 (60초 캐시)."""
        expiry = self._resolved_ok.get(canonical)
        if expiry is None:
            return False
        if expiry < time.monotonic():
            self._resolved_ok.pop(canonical, None)
            return False
        return True

    def record_resolved(self, results) -> None:
        """인가된 호스트의 해석 결과를 기록한다 — 그 주소로의 연결만 허용된다."""
        expiry = time.monotonic() + 60.0
        for item in results or []:
            sockaddr = item[4] if isinstance(item, (tuple, list)) and len(item) >= 5 else None
            if not isinstance(sockaddr, (tuple, list)) or not sockaddr:
                continue
            canonical = canonical_host(sockaddr[0])
            if canonical:
                self._resolved_ok[canonical] = expiry

    @staticmethod
    def _forbidden_ip(canonical: str) -> bool:
        """인가 목록에 IP 규칙이 없을 때에도 절대 쓰면 안 되는 주소.

        미지정 주소·링크 로컬(메타데이터 169.254.169.254)·멀티캐스트·브로드캐스트.
        루프백(127.0.0.0/8)은 인가된 도메인이 그 주소로 해석되는 정상적인
        랩 환경(localhost)까지 막으므로 여기서 제외한다 — IP 규칙이 있는
        스코프에서는 위의 엄격 분기에서 차단된다.
        """
        if canonical in ("0.0.0.0", "::", "255.255.255.255"):
            return True
        if canonical.startswith("169.254."):
            return True
        if canonical.startswith("224.") or canonical.startswith("239.") or canonical.startswith("ff"):
            return True
        return False

    def check_resolved(self, results) -> None:
        """getaddrinfo 결과의 모든 sockaddr 를 검증하고 해석 결과를 기록한다."""
        for item in results or []:
            sockaddr = item[4] if isinstance(item, (tuple, list)) and len(item) >= 5 else None
            if not isinstance(sockaddr, (tuple, list)) or not sockaddr:
                self.blocked += 1
                raise ScopeError("연결 차단: 유니소켓 등 지원하지 않는 주소 형식입니다.")
            address = sockaddr[0]
            canonical = canonical_host(address)
            if canonical is None:
                self.blocked += 1
                raise ScopeError(f"연결 차단: 해석할 수 없는 주소입니다: {address}")
            for kind, value in self.scope.deny:
                if self.scope._match(kind, value, canonical, canonical):
                    self.blocked += 1
                    raise ScopeError(f"연결 차단: {address} 는 deny 규칙에 포함됩니다.")
            if self._forbidden_ip(canonical):
                self.blocked += 1
                raise ScopeError(f"연결 차단: {address} 는 사용할 수 없는 주소입니다.")
        self.record_resolved(results)

    # -- URL ----------------------------------------------------------------
    def check_url(self, url) -> None:
        """URL 은 http/https 만 허용한다 (file/ftp/gopher/data 차단)."""
        raw = url if isinstance(url, str) else getattr(url, "full_url", None)
        if not isinstance(raw, str):
            raise ScopeError("URL 파싱 실패: 유효하지 않은 URL 입니다.")
        parts = urllib.parse.urlsplit(raw)
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ScopeError(f"스킴 '{scheme or '없음'}' 은 허용되지 않습니다 (http/https 만 가능).")
        host = parts.hostname
        if not host:
            raise ScopeError(f"URL 파싱 실패: {raw}")
        port = parts.port or (443 if scheme == "https" else 80)
        try:
            self.scope.check_host(host, port)
        except ScopeError as exc:
            self.blocked += 1
            raise ScopeError(f"연결 차단: {exc}") from exc

    def build_opener(self):
        """프록시 무시 + 로컬 파일 핸들러가 없는 opener."""
        return _guarded_build_opener()

    # -- 후킹 설치/복구 -----------------------------------------------------
    def install(self) -> None:
        """모든 후킹을 원본 기준으로 다시 설치한다."""
        global _ACTIVE_GUARD, _AUDIT_INSTALLED
        _capture_originals()
        # 허용 모듈을 미리 적재한다 (lazy import 가 차단 목록에 걸리지 않도록).
        _preload_allowed_modules()
        _ACTIVE_GUARD = self

        builtins.open = _guarded_open
        io.open = _guarded_open
        os.open = _guarded_os_open
        os.fdopen = _guarded_os_fdopen
        builtins.__import__ = _guarded_import

        socket.socket.connect = _guarded_connect
        socket.socket.connect_ex = _guarded_connect_ex
        if getattr(socket.socket, "sendto", None) is not None:
            socket.socket.sendto = _guarded_sendto
        if getattr(socket.socket, "sendmsg", None) is not None:
            socket.socket.sendmsg = _guarded_sendmsg
        socket.getaddrinfo = _guarded_getaddrinfo
        socket.gethostbyname = _guarded_gethostbyname
        socket.gethostbyname_ex = _guarded_gethostbyname_ex
        socket.gethostbyaddr = _guarded_gethostbyaddr
        socket.getnameinfo = _guarded_getnameinfo
        socket.getfqdn = _guarded_getfqdn
        socket.create_connection = _guarded_create_connection
        self._patch_lowlevel_socket()

        urllib.request.urlopen = _guarded_urlopen
        urllib.request.build_opener = _guarded_build_opener
        urllib.request.install_opener = _guarded_install_opener

        self._stub_os_functions()

        if not _AUDIT_INSTALLED:
            sys.addaudithook(_audit_hook)
            _AUDIT_INSTALLED = True

        # 이미 로드된 차단 모듈은 캐시에서 제거한다(우회 경로 차단).
        _purge_blocked_modules()

    def _patch_lowlevel_socket(self) -> None:
        """`_socket` 모듈의 DNS 함수도 후킹한다 (이전 파이썬 호환).

        저수준 모듈을 직접 호출해도 인가 검사를 우회하지 못하게 한다.
        3.13+ 에서는 확장 타입이라 대입이 불가능하므로 조용히 넘어간다 —
        이 경우 C 레벨 감사 훅(`socket.getaddrinfo` 이벤트)이 대신 막는다.
        """
        try:
            import _socket  # noqa: PLC0415 - 커널 전용
        except Exception:
            return
        for name, hook in (
            ("getaddrinfo", _guarded_low_getaddrinfo),
            ("gethostbyname", _guarded_low_gethostbyname),
            ("gethostbyname_ex", _guarded_low_gethostbyname_ex),
            ("gethostbyaddr", _guarded_low_gethostbyaddr),
            ("getnameinfo", _guarded_low_getnameinfo),
        ):
            try:
                setattr(_socket, name, hook)
            except Exception:
                continue

    def _stub_os_functions(self) -> None:
        """os 의 파괴적/실행 함수를 차단한다 (감사 훅과 이중 보호)."""
        if self._os_stubs:
            return
        for name in ("system", "popen", "remove", "unlink", "rmdir", "removedirs", "rename",
                     "replace", "execv", "execve", "execvp", "execvpe", "spawnv", "spawnl",
                     "spawnve", "fork", "posix_spawn", "putenv", "unsetenv", "chmod", "chown",
                     "truncate", "symlink", "link", "startfile"):
            if hasattr(os, name):
                self._os_stubs.append((os, name, getattr(os, name)))
                try:
                    setattr(os, name, _blocked_call(f"os.{name}"))
                except Exception:
                    self._os_stubs.pop()

    def uninstall(self) -> None:
        """후킹을 원본으로 되돌린다 (selftest 정리용)."""
        global _ACTIVE_GUARD
        for owner, name, original in self._os_stubs:
            try:
                setattr(owner, name, original)
            except Exception:
                pass
        self._os_stubs = []
        if not _ORIG:
            return
        builtins.open = _ORIG["builtin_open"]
        io.open = _ORIG["io_open"]
        os.open = _ORIG["os_open"]
        os.fdopen = _ORIG["os_fdopen"]
        builtins.__import__ = _ORIG["import"]
        socket.socket.connect = _ORIG["socket_connect"]
        socket.socket.connect_ex = _ORIG["socket_connect_ex"]
        if _ORIG.get("socket_sendto") is not None:
            socket.socket.sendto = _ORIG["socket_sendto"]
        if _ORIG.get("socket_sendmsg") is not None:
            socket.socket.sendmsg = _ORIG["socket_sendmsg"]
        socket.getaddrinfo = _ORIG["socket_getaddrinfo"]
        socket.gethostbyname = _ORIG["socket_gethostbyname"]
        socket.gethostbyname_ex = _ORIG["socket_gethostbyname_ex"]
        socket.gethostbyaddr = _ORIG["socket_gethostbyaddr"]
        socket.getnameinfo = _ORIG["socket_getnameinfo"]
        socket.getfqdn = _ORIG["socket_getfqdn"]
        socket.create_connection = _ORIG["socket_create_connection"]
        try:  # 저수준 모듈 원복
            import _socket  # noqa: PLC0415 - 커널 전용
            for name, key in (
                ("getaddrinfo", "low_getaddrinfo"),
                ("gethostbyname", "low_gethostbyname"),
                ("gethostbyname_ex", "low_gethostbyname_ex"),
                ("gethostbyaddr", "low_gethostbyaddr"),
                ("getnameinfo", "low_getnameinfo"),
            ):
                if key in _ORIG:
                    setattr(_socket, name, _ORIG[key])
        except Exception:
            pass
        urllib.request.urlopen = _ORIG["urlopen"]
        urllib.request.build_opener = _ORIG["build_opener"]
        urllib.request.install_opener = _ORIG["install_opener"]
        _ACTIVE_GUARD = None

    def verify(self) -> list[str]:
        """후킹이 교체되었는지 확인하고, 교체되었으면 다시 설치한다."""
        checks = [
            ("builtins.open", builtins.open, _guarded_open),
            ("io.open", io.open, _guarded_open),
            ("os.open", os.open, _guarded_os_open),
            ("os.fdopen", os.fdopen, _guarded_os_fdopen),
            ("builtins.__import__", builtins.__import__, _guarded_import),
            ("socket.socket.connect", socket.socket.connect, _guarded_connect),
            ("socket.socket.connect_ex", socket.socket.connect_ex, _guarded_connect_ex),
            ("socket.getaddrinfo", socket.getaddrinfo, _guarded_getaddrinfo),
            ("socket.gethostbyname", socket.gethostbyname, _guarded_gethostbyname),
            ("socket.gethostbyname_ex", socket.gethostbyname_ex, _guarded_gethostbyname_ex),
            ("socket.gethostbyaddr", socket.gethostbyaddr, _guarded_gethostbyaddr),
            ("socket.getnameinfo", socket.getnameinfo, _guarded_getnameinfo),
            ("socket.getfqdn", socket.getfqdn, _guarded_getfqdn),
            ("socket.create_connection", socket.create_connection, _guarded_create_connection),
            ("urllib.request.urlopen", urllib.request.urlopen, _guarded_urlopen),
            ("urllib.request.build_opener", urllib.request.build_opener, _guarded_build_opener),
        ]
        if getattr(socket.socket, "sendto", None) is not None:
            checks.append(("socket.socket.sendto", socket.socket.sendto, _guarded_sendto))
        if getattr(socket.socket, "sendmsg", None) is not None:
            checks.append(("socket.socket.sendmsg", socket.socket.sendmsg, _guarded_sendmsg))
        changed = [name for name, current, expected in checks if current is not expected]
        if changed:
            self.install()
            self.warnings.append("샌드박스가 후킹 함수를 교체했습니다: " + ", ".join(changed))
        return changed

    def status(self) -> dict:
        return {
            "blocked_attempts": self.blocked,
            "warnings": list(self.warnings),
            "rps_limit": self.limiter.rps,
            "read_roots": list(self.read_roots),
            "write_roots": list(self.write_roots),
        }


# ─────────────────────────────────────────────────────────────────────────────
# import 게이트 — 메타패스 파인더 + sys.modules 정리
# ─────────────────────────────────────────────────────────────────────────────


class _DenyFinder:
    """`sys.meta_path` 파인더 — 차단 모듈의 import 를 ImportError 로 만든다."""

    def find_spec(self, fullname, path=None, target=None):
        if _module_dangerous(fullname):
            raise ImportError(f"'{fullname}' 모듈은 샌드박스에서 사용할 수 없습니다 (import 차단).")
        return None

    def find_module(self, fullname, path=None):  # 구버전 호환 (사용되지 않음)
        if _module_dangerous(fullname):
            raise ImportError(f"'{fullname}' 모듈은 샌드박스에서 사용할 수 없습니다 (import 차단).")
        return None


def _preload_allowed_modules() -> None:
    """허용 모듈을 미리 적재한다(샌드박스 실행 중 import 로 인한 실패 방지)."""
    for name in PRELOAD_MODULES:
        try:
            _BUILTIN_IMPORT(name)
        except Exception:
            continue


def _purge_blocked_modules() -> None:
    """이미 로드된 차단 모듈을 sys.modules 에서 제거한다."""
    for name in list(sys.modules.keys()):
        root = name.split(".", 1)[0]
        if name in KEEP_IN_SYSMODULES:
            continue
        if root in BLOCKED_MODULE_ROOTS or name in BLOCKED_MODULES:
            try:
                del sys.modules[name]
            except Exception:
                continue


def _install_import_gate() -> None:
    """메타패스 파인더를 설치하고 모듈 캐시를 정리한다."""
    _preload_allowed_modules()
    finder = _DenyFinder()
    if not any(isinstance(f, _DenyFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, finder)
    _purge_blocked_modules()


# ─────────────────────────────────────────────────────────────────────────────
# 안전builtins — 샌드박스에 노출할 전역 함수 집합
# ─────────────────────────────────────────────────────────────────────────────


def _restricted_getattr(obj, name, *args):
    """내부 introspection 속성 접근을 막는다."""
    if isinstance(name, str) and name in BLOCKED_ATTRS:
        raise PermissionError(f"'{name}' 속성은 샌드박스에서 접근할 수 없습니다.")
    return getattr(obj, name, *args) if args else getattr(obj, name)


def _restricted_setattr(obj, name, value):
    if isinstance(name, str) and (name.startswith("__") or name in BLOCKED_ATTRS):
        raise PermissionError(f"'{name}' 속성은 샌드박스에서 변경할 수 없습니다.")
    return setattr(obj, name, value)


def _restricted_delattr(obj, name):
    if isinstance(name, str) and (name.startswith("__") or name in BLOCKED_ATTRS):
        raise PermissionError(f"'{name}' 속성은 샌드박스에서 삭제할 수 없습니다.")
    return delattr(obj, name)


def _check_eval_ast(tree: ast.AST) -> None:
    """eval 로 실행될 식에서 위험한 이름/속성을 걷어낸다."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in BLOCKED_ATTRS:
            raise PermissionError(f"'{node.attr}' 속성은 샌드박스에서 접근할 수 없습니다.")
        if isinstance(node, ast.Name) and node.id in BLOCKED_ATTRS:
            raise PermissionError(f"'{node.id}' 는 샌드박스에서 사용할 수 없습니다.")


def _safe_eval(source, globals=None, locals=None):
    """eval 래퍼 — 표현식만 허용한다."""
    if not isinstance(source, str):
        raise TypeError("eval 은 문자열만 받습니다.")
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        raise SyntaxError(f"eval 은 표현식만 허용합니다: {exc}") from exc
    _check_eval_ast(tree)
    namespace = dict(globals or {})
    namespace["__builtins__"] = SAFE_BUILTINS
    code = compile(tree, "<forge-eval>", "eval")
    return eval(code, namespace, locals)


def _build_safe_builtins() -> dict:
    """샌드박스에 노출할 builtins 사전을 만든다."""
    safe: dict[str, Any] = {
        "print": print,
        "len": len, "range": range, "enumerate": enumerate, "zip": zip,
        "sorted": sorted, "reversed": reversed, "sum": sum, "min": min, "max": max,
        "abs": abs, "round": round, "divmod": divmod, "pow": pow,
        "int": int, "float": float, "str": str, "bool": bool, "complex": complex,
        "list": list, "dict": dict, "set": set, "tuple": tuple, "frozenset": frozenset,
        "bytes": bytes, "bytearray": bytearray,
        "isinstance": isinstance, "issubclass": issubclass, "type": type,
        "id": id, "hash": hash, "repr": repr, "format": format,
        "chr": chr, "ord": ord, "bin": bin, "hex": hex, "oct": oct,
        "callable": callable, "hasattr": hasattr,
        "iter": iter, "next": next, "map": map, "filter": filter,
        "any": any, "all": all,
        "dir": dir, "vars": vars,
        "getattr": _restricted_getattr, "setattr": _restricted_setattr,
        "delattr": _restricted_delattr,
        "open": _guarded_open,
        "input": _blocked_call("input"),
        "help": _blocked_call("help"),
        "exec": _blocked_call("exec"),
        "compile": _blocked_call("compile"),
        "eval": _safe_eval,
        "__import__": _guarded_import,
        "__build_class__": builtins.__build_class__,
        "slice": slice, "property": property, "staticmethod": staticmethod,
        "classmethod": classmethod, "super": super, "object": object,
        "NotImplemented": NotImplemented, "Ellipsis": Ellipsis,
    }
    for name in (
        "Exception", "ArithmeticError", "AssertionError", "AttributeError",
        "BufferError", "EOFError", "ImportError", "IndexError", "KeyError",
        "LookupError", "MemoryError", "NameError", "NotImplementedError",
        "OSError", "OverflowError", "ReferenceError", "RuntimeError",
        "StopIteration", "StopAsyncIteration", "SyntaxError", "IndentationError",
        "TabError", "SystemError", "TypeError", "ValueError", "Warning",
        "ZeroDivisionError", "UnicodeError", "UnicodeDecodeError",
        "UnicodeEncodeError", "FloatingPointError", "ConnectionError",
        "TimeoutError", "PermissionError", "FileNotFoundError", "IsADirectoryError",
        "NotADirectoryError", "FileExistsError", "InterruptedError",
        "BrokenPipeError", "ConnectionResetError", "ConnectionAbortedError",
    ):
        safe[name] = getattr(builtins, name)
    return safe


SAFE_BUILTINS: dict[str, Any] = _build_safe_builtins()


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
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ScopeError(f"스킴 '{scheme or '없음'}' 은 허용되지 않습니다 (http/https 만 가능).")
    port = parts.port or (443 if scheme == "https" else 80)
    if scope is not None:
        try:
            scope.check_host(parts.hostname, port)
        except ScopeError as exc:
            return {"error": str(exc), "status": 0, "body": "", "headers": {}, "len": 0}

    # RPS 상한 — 요청마다 토큰 1개를 소비한다.
    guard = _ACTIVE_GUARD
    if guard is not None:
        guard.limiter.acquire()

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
    # build_opener 가 ProxyHandler({}) 를 강제하므로 환경변수 프록시는 무시된다.
    opener = _guarded_build_opener(*handlers)

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
        self._scope = scope
        self._scope_view = ScopeView(scope)
        self.guard = guard
        self.run_dir = run_dir
        self.base_url = base_url
        self.notes: list[str] = []
        self.findings: list[dict] = []

    @property
    def scope(self) -> ScopeView:
        """`forge.scope` — 요약/판정만 노출하는 뷰."""
        return self._scope_view

    # -- 인가된 자격증명 헤더 ---------------------------------------------
    def _credential_headers(self) -> dict:
        """인가 대상 호스트에만 붙일 자격증명 헤더.

        원본 값은 요청 시점에 인가 파일에서 읽어오므로 프로세스 globals 에
        남지 않는다(샌드박스가 커널 전역을 훑어도 평문 자격증명이 나오지 않는다).
        """
        return _read_credential_headers(self._scope.cred_path)

    def _host_authorized(self, url: str) -> bool:
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            return False
        host = parts.hostname
        if not host:
            return False
        port = parts.port or (443 if (parts.scheme or "").lower() == "https" else 80)
        try:
            self._scope.check_host(host, port)
        except ScopeError:
            return False
        return True

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

    def credentials(self) -> dict:
        """마스킹된 자격증명 요약 — 값은 절대 노출하지 않는다."""
        return dict(self._scope.cred_summary)

    def creds(self) -> dict:
        """`forge.credentials()` 의 별칭 (구버전 호환)."""
        return self.credentials()

    def request(self, method: str, path: str, *, headers=None, body=None, timeout: float = 10.0,
                follow_redirects: bool = False) -> dict:
        url = self._url(path)
        merged: dict[str, str] = {}
        # 자격증명은 인가 대상 호스트에만 붙인다.
        if self._host_authorized(url):
            merged.update(self._credential_headers())
        merged.update(headers or {})
        try:
            return http_request(
                method, url, headers=merged, body=body,
                timeout=timeout, follow_redirects=follow_redirects, scope=self._scope,
            )
        except ScopeError as exc:
            return {"error": str(exc), "status": 0, "body": "", "headers": {}, "len": 0}

    def get(self, path: str, **kw) -> dict:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> dict:
        return self.request("POST", path, **kw)

    def burst(self, method: str, path: str, payloads, *, headers=None, body_template: str | None = None,
              workers: int = 8, timeout: float = 10.0, delay: float = 0.0) -> list[dict]:
        """여러 페이로드를 병렬로 쏘고 응답 목록을 돌려준다 (스톰의 파이썬 버전)."""
        payloads = list(payloads)[:MAX_BURST_PAYLOADS]
        worker_count = max(1, min(int(workers or 1), MAX_BURST_WORKERS))
        url = self._url(path)
        merged: dict[str, str] = {}
        if self._host_authorized(url):
            merged.update(self._credential_headers())
        merged.update(headers or {})

        def one(payload) -> dict:
            if delay:
                time.sleep(delay)
            body = body_template.replace("{{payload}}", str(payload)) if body_template else None
            try:
                res = http_request(method, url, headers=merged, body=body, timeout=timeout, scope=self._scope)
            except ScopeError as exc:
                res = {"error": str(exc), "status": 0, "body": "", "headers": {}, "len": 0}
            res["payload"] = payload
            return res

        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            return list(pool.map(one, payloads))

    # -- 페이로드 생성 -----------------------------------------------------
    def mutate(self, values, *, seed: int = 0, rounds: int = 1) -> list[str]:
        """값 목록을 변이해 시도할 페이로드 목록을 만든다 (경계값·인코딩·문자열 조작)."""
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
            "internal_host": r"(?i)\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
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

    def finish(self) -> dict:
        """점검 종료 요약 — 노트·파인딩·상태를 함께 돌려준다."""
        return {
            "notes": list(self.notes),
            "findings": list(self.findings),
            "base_url": self.base_url,
            "status": self.status(),
        }

    def save(self, name: str, content: str) -> str:
        target = os.path.abspath(os.path.join(self.run_dir, os.path.basename(name)))
        with _BUILTIN_OPEN(target, "w", encoding="utf-8") as fh:
            fh.write(content)
        return target

    def status(self) -> dict:
        scope = self._scope
        return {
            "base_url": self.base_url,
            "allow": [f"{kind}:{value}" for kind, value in scope.allow],
            "deny": [f"{kind}:{value}" for kind, value in scope.deny],
            "ports": sorted(scope.ports),
            "max_rps": scope.max_rps,
            "rps_limit": self.guard.limiter.rps,
            "blocked_attempts": self.guard.blocked,
            "warnings": list(self.guard.warnings),
            "notes": len(self.notes),
            "findings": len(self.findings),
            "run_dir": self.run_dir,
            "credentials": dict(scope.cred_summary),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 커널 실행부
# ─────────────────────────────────────────────────────────────────────────────


class KernelTimeout(Exception):
    pass


def _limit_memory(limit_bytes: int = DEFAULT_MEMORY_LIMIT_BYTES) -> None:
    """커널 프로세스 메모리를 제한한다 (무시될 수 있으므로 예외로 감싼다)."""
    if _resource_mod is None:
        return
    try:
        soft, hard = _resource_mod.getrlimit(_resource_mod.RLIMIT_AS)
        target = int(limit_bytes)
        new_hard = target if hard == _resource_mod.RLIM_INFINITY else min(hard, target)
        new_soft = target if soft == _resource_mod.RLIM_INFINITY else min(soft, target)
        _resource_mod.setrlimit(_resource_mod.RLIMIT_AS, (new_soft, new_hard))
    except Exception:
        return


class Kernel:
    def __init__(self, scope: Scope, run_dir: str, base_url: str | None = None):
        self.scope = scope
        self.run_dir = run_dir
        # import 게이트를 먼저 설치한다(후킹보다 먼저 — 원본을 확보해야 한다).
        _capture_originals()
        _install_import_gate()
        self.guard = Guard(scope, run_dir)
        _limit_memory()
        self.toolkit = Toolkit(scope, self.guard, run_dir, base_url)
        self.ns: dict = self._new_ns()
        self.history: list[str] = []
        self.last_elapsed = 0.0

    def _new_ns(self) -> dict:
        return {
            "__name__": "__forge__",
            "forge": self.toolkit,
            # exec 가 전체 builtins 를 주입하지 않도록 안전 사전을 명시한다.
            "__builtins__": SAFE_BUILTINS,
        }

    def reset(self) -> None:
        self.ns = self._new_ns()

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
            last_expr = ast.Expression(body=body[-1].value)
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
        except BaseException:  # 샌드박스가 커널 프로세스를 죽이지 못하게 한다.
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
                # 사용자 코드가 후킹을 되돌렸다면 다시 설치하고 경고를 남긴다.
                changed = self.guard.verify()
                if changed:
                    err = (err + "\n[샌드박스 경고] 후킹 재설치: " + ", ".join(changed) + "\n").lstrip("\n")
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


# ─────────────────────────────────────────────────────────────────────────────
# 자체 점검 (selftest) — `python3 py/forge_kernel.py --selftest`
# ─────────────────────────────────────────────────────────────────────────────


def _selftest() -> int:
    """샌드박스 가드 자체를 검증한다. 프로세스를 오염시키지 않도록 끝나면 되돌린다."""
    results: list[tuple[str, bool, str]] = []

    def record(name: str, fn) -> None:
        try:
            fn()
            results.append((name, True, ""))
        except AssertionError as exc:
            results.append((name, False, str(exc)))
        except Exception as exc:
            results.append((name, False, f"{type(exc).__name__}: {exc}"))

    run_dir = tempfile.mkdtemp(prefix="forge-selftest-")
    doc = {
        "engagement": {"name": "selftest", "authorized_until": "2099-12-31"},
        "scope": {"allow": [{"host": "127.0.0.1"}], "deny": [{"host": "10.0.0.1"}]},
        "ports": {"allow_tcp": [80, 443, 8080]},
        "limits": {"max_requests_per_second": 2},
        "credentials": {"cookie": "sid=SECRET", "bearer": "SECRET-TOKEN"},
    }
    scope = Scope(doc)
    kernel = Kernel(scope, run_dir, None)
    guard = kernel.guard

    def run_sandbox(code: str) -> dict:
        """샌드박스 안에서 코드를 실행하고 응답을 돌려준다."""
        return kernel.handle({"id": 1, "op": "exec", "code": code, "timeout_ms": 5000})

    def expect_blocked(label: str, code: str, needle: str) -> None:
        resp = run_sandbox(code)
        stderr = resp.get("stderr") or ""
        if needle not in stderr:
            raise AssertionError(f"{label}: '{needle}' 가 나타나지 않았습니다 → {stderr[:200]!r}")

    try:
        def check_import_blocked() -> None:
            for module in ("subprocess", "ctypes", "importlib", "os", "sys", "socket", "pathlib", "pickle"):
                expect_blocked(f"{module} import", f"import {module}", "ImportError")

        def check_os_system_blocked() -> None:
            expect_blocked("os.system", "import os\nos.system('echo pwned')", "ImportError")
            try:
                os.system("echo pwned")
            except PermissionError:
                return
            except Exception as exc:
                raise AssertionError(f"os.system 이 다른 오류로 통과했습니다: {exc}")
            raise AssertionError("os.system 이 차단되지 않았습니다.")

        def check_file_scheme_blocked() -> None:
            expect_blocked("urllib.request import", "import urllib.request", "ImportError")
            try:
                urllib.request.urlopen("file:///etc/passwd")
            except ScopeError:
                return
            except Exception as exc:
                raise AssertionError(f"file:// 차단이 다른 오류로 발생했습니다: {exc}")
            raise AssertionError("file:// URL 이 차단되지 않았습니다.")

        def check_out_of_scope_connect() -> None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(("169.254.169.254", 80))
            except ScopeError:
                pass
            except Exception as exc:
                raise AssertionError(f"범위 밖 connect 가 다른 오류로 발생했습니다: {exc}")
            else:
                raise AssertionError("범위 밖 TCP connect 가 차단되지 않았습니다.")
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            expect_blocked(
                "DNS 터널(gethostbyname)",
                "import socket\nsocket.gethostbyname('evil.example.com')",
                "ImportError",
            )

        def check_write_outside_run_dir() -> None:
            outside = os.path.join(run_dir, "..", "forge-selftest-outside.txt")
            try:
                open(outside, "w")
            except PermissionError:
                pass
            else:
                raise AssertionError("실행 디렉터리 밖 쓰기가 차단되지 않았습니다.")
            inside = os.path.join(run_dir, "inside.txt")
            with open(inside, "w", encoding="utf-8") as fh:
                fh.write("ok")
            # 커널 스크립트 사본은 만들지도 덮어쓸 수도 없다.
            script_copy = os.path.join(run_dir, "forge_kernel.py")
            for mode in ("w", "a"):
                try:
                    open(script_copy, mode)
                except PermissionError:
                    continue
                raise AssertionError(f"커널 스크립트 {mode} 쓰기가 차단되지 않았습니다.")
            try:
                open("/etc/passwd")
            except PermissionError:
                pass
            else:
                raise AssertionError("허용 밖 파일 읽기가 차단되지 않았습니다.")
            expect_blocked("샌드박스 파일 읽기", "open('/etc/passwd').read()", "PermissionError")

        def check_ipv4_shorthand() -> None:
            scope.check_host("127.1", 80)          # 127.0.0.1 로 정규화되어 허용
            scope.check_host("2130706433", 8080)    # 10진 표기도 동일하게 허용
            strict = Scope({
                "engagement": {"authorized_until": "2099-12-31"},
                "scope": {"allow": [{"host": "10.0.0.1"}], "deny": [{"host": "10.0.0.1"}]},
            })
            try:
                strict.check_host("10.1", None)
            except ScopeError:
                pass
            else:
                raise AssertionError("축약 표기(10.1) 가 deny 규칙을 우회했습니다.")

        def check_rps_limit() -> None:
            limiter = RateLimiter(2)
            if not limiter.try_acquire():
                raise AssertionError("첫 번째 토큰 획득에 실패했습니다.")
            if not limiter.try_acquire():
                raise AssertionError("두 번째 토큰 획득에 실패했습니다.")
            if limiter.try_acquire():
                raise AssertionError("RPS 제한이 적용되지 않았습니다.")
            if guard.limiter.rps != 2.0:
                raise AssertionError(f"scope.max_rps 가 반영되지 않았습니다: {guard.limiter.rps}")
            before = guard.limiter.tokens
            run_sandbox("import socket")  # 토큰을 쓰지 않는 실행 → 변화 없어야 한다
            if guard.limiter.tokens > before:
                raise AssertionError("토큰이 아닌 실행에서 RPS 토큰이 소비되었습니다.")

        def check_credentials_masked() -> None:
            summary = scope.cred_summary
            if "SECRET" in json.dumps(summary):
                raise AssertionError("자격증명 원본이 노출되었습니다.")
            if summary.get("cookie") != "Cookie: ***":
                raise AssertionError(f"자격증명 마스킹 형식이 다릅니다: {summary}")
            try:
                getattr(scope, "credentials")
            except AttributeError:
                pass
            else:
                raise AssertionError("scope.credentials 가 그대로 노출됩니다.")
            resp = run_sandbox("print(forge.credentials())")
            if "SECRET" in (resp.get("stdout") or ""):
                raise AssertionError("forge.credentials() 가 원본 값을 노출했습니다.")

        def check_safe_builtins() -> None:
            for name in ("exec", "compile", "input", "help"):
                try:
                    SAFE_BUILTINS[name]()
                except PermissionError:
                    continue
                raise AssertionError(f"{name} 이 차단되지 않았습니다.")
            if SAFE_BUILTINS["eval"]("1+1") != 2:
                raise AssertionError("eval 이 동작하지 않습니다.")
            expect_blocked("샌드박스 exec", "exec('x = 1')", "PermissionError")
            expect_blocked("샌드박스 compile", "compile('x = 1', '<s>', 'exec')", "PermissionError")

        def check_hook_reinstall() -> None:
            """샌드박스가 후킹을 되돌려도 다음 실행 전에 다시 설치되어야 한다."""
            before = builtins.open
            builtins.open = _BUILTIN_OPEN
            changed = guard.verify()
            if not changed:
                raise AssertionError("후킹 교체 감지가 되지 않았습니다.")
            if builtins.open is not before:
                raise AssertionError("후킹이 재설치되지 않았습니다.")
            if not guard.warnings:
                raise AssertionError("후킹 교체 경고가 기록되지 않았습니다.")

        def check_namespace_and_protocol() -> None:
            resp = run_sandbox("x = 21\nprint(x * 2)")
            if "42" not in (resp.get("stdout") or ""):
                raise AssertionError("네임스페이스 유지/stdout 캡처가 깨졌습니다.")
            resp = run_sandbox("40 + 2")
            if resp.get("result") != "42":
                raise AssertionError(f"마지막 표현식 값 반환이 깨졌습니다: {resp.get('result')!r}")

        record("import 차단 (subprocess/ctypes/importlib/os/sys/socket/pathlib/pickle)", check_import_blocked)
        record("os.system 차단", check_os_system_blocked)
        record("file:// URL 차단", check_file_scheme_blocked)
        record("범위 밖 TCP connect / DNS 터널 차단", check_out_of_scope_connect)
        record("실행 디렉터리 밖 쓰기 / 허용 밖 읽기 차단", check_write_outside_run_dir)
        record("IPv4 축약 표기(127.1 / 2130706433) 정규화 판정", check_ipv4_shorthand)
        record("RPS 제한 동작", check_rps_limit)
        record("자격증명 마스킹", check_credentials_masked)
        record("안전 builtins (exec/compile/input/help 차단, eval 동작)", check_safe_builtins)
        record("후킹 교체 감지 · 재설치", check_hook_reinstall)
        record("네임스페이스 유지 · 프로토콜 유지", check_namespace_and_protocol)
    finally:
        guard.uninstall()
        try:
            for name in os.listdir(run_dir):
                os.remove(os.path.join(run_dir, name))
            os.rmdir(run_dir)
        except Exception:
            pass

    failed = 0
    for name, ok, message in results:
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name}" + (f" — {message}" if message else ""))
        if not ok:
            failed += 1
    print(f"\n{len(results) - failed}/{len(results)} 개 통과")
    return 1 if failed else 0


# ─────────────────────────────────────────────────────────────────────────────
# 진입점
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    scope_path = None
    base_url = None
    run_dir = os.path.abspath(os.getcwd())
    args = sys.argv[1:]
    if "--selftest" in args:
        raise SystemExit(_selftest())
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
        with _BUILTIN_OPEN(scope_path, "r", encoding="utf-8") as fh:
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
