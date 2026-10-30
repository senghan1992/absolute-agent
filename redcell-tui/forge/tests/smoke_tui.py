#!/usr/bin/env python3
"""REDFORGE TUI 스모크 테스트 — tmux 로 실제 화면을 띄워 렌더링을 검증한다.

외부 대상으로는 요청하지 않는다. 인가는 임시 파일(127.0.0.1 만 허용)로 만들고
로컬 루프백 서버만 연다.

사용법:
  python3 tests/smoke_tui.py --output /tmp/forge-screens
"""

from __future__ import annotations

import argparse
import http.server
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(REPO, "target", "debug", "forge")

PAGE = b"""<!doctype html><html><head><title>Forge Smoke</title></head><body>
<a href="/about">about</a>
<form action="/login" method="post"><input name="user"><input name="pass"></form>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = PAGE if self.path.startswith("/") else b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_lab():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.allow_reuse_address = True
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def write_scope(path: str, port: int):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(
            "engagement:\n"
            "  name: \"forge-smoke\"\n"
            "  authorized_from: \"2020-01-01\"\n"
            "  authorized_until: \"2099-12-31\"\n"
            "scope:\n"
            "  allow:\n"
            "    - host: \"127.0.0.1\"\n"
            "ports:\n"
            "  allow_tcp: [%d]\n"
            "limits:\n"
            "  max_requests_per_second: 100\n" % port
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="/tmp/forge-screens")
    args = ap.parse_args()

    if not os.path.exists(BIN):
        print(f"바이너리 없음: {BIN} — cargo build 를 먼저 실행하세요.", file=sys.stderr)
        return 2
    if shutil.which("tmux") is None:
        print("tmux 가 필요합니다.", file=sys.stderr)
        return 2

    os.makedirs(args.output, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="forge-smoke-")
    scope = os.path.join(tmp, "authorization.yaml")
    srv, port = start_lab()
    write_scope(scope, port)

    sock = "forge-smoke-%d" % os.getpid()
    env = dict(os.environ, TMUX_TMPDIR=os.path.join(tmp, "tmux"))
    os.makedirs(env["TMUX_TMPDIR"], mode=0o700, exist_ok=True)

    def tmux(*cmd):
        return subprocess.run(["tmux", "-L", sock, *cmd], capture_output=True, text=True, env=env)

    tmux("kill-server")
    tmux("new-session", "-d", "-x", "120", "-y", "34", "-s", "smoke",
         f"cd {REPO} && {BIN} --scope {scope} --target http://127.0.0.1:{port}/")
    time.sleep(2.5)

    failures = []

    def screen(name: str) -> str:
        out = tmux("capture-pane", "-p", "-t", "smoke").stdout
        with open(os.path.join(args.output, f"{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write(out)
        return out

    def check(name: str, needle: str):
        out = screen(name)
        if needle not in out:
            failures.append(f"{name}: '{needle}' 를 화면에서 찾지 못함")
            print(f"  ✖ {name} — '{needle}' 없음")
        else:
            print(f"  ✔ {name} — '{needle}' 확인")

    check("01-시작", "REDFORGE")
    check("01-시작", "인가 forge-smoke")

    # 명령 팔레트
    tmux("send-keys", "-t", "smoke", "C-p")
    time.sleep(0.6)
    check("02-팔레트", "명령")

    tmux("send-keys", "-t", "smoke", "Escape")
    time.sleep(0.4)

    # /help
    tmux("send-keys", "-t", "smoke", "/help")
    tmux("send-keys", "-t", "smoke", "Enter")
    time.sleep(0.8)
    check("03-도움말", "/autopilot")

    # /scope
    tmux("send-keys", "-t", "smoke", "/scope")
    tmux("send-keys", "-t", "smoke", "Enter")
    time.sleep(0.8)
    check("04-인가", "engagement")

    # /storm — 실제 요청이 나가야 함
    tmux("send-keys", "-t", "smoke", "/storm")
    tmux("send-keys", "-t", "smoke", "Enter")
    time.sleep(6)
    out = screen("05-스톰")
    if "req/s" not in out:
        failures.append("05-스톰: 진행 표시 없음")
        print("  ✖ 05-스톰 — 진행 표시 없음")
    else:
        print("  ✔ 05-스톰 — 진행 표시 확인")

    # 탭 전환 (스톰 → 발견 → 리포트)
    for _ in range(2):
        tmux("send-keys", "-t", "smoke", "Tab")
        time.sleep(0.4)
    check("06-리포트", "리포트")

    tmux("kill-server")
    srv.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\n실패:")
        for f in failures:
            print(" -", f)
        return 1
    print(f"\n스모크 테스트 통과 (화면: {args.output})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
