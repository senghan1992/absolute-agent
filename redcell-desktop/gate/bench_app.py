#!/usr/bin/env python3
"""RedCell 게이트 정답지 앱 — 기지 취약점 내장 (표준 라이브러리만).

bench_run.py 가 기동·채점한다. 각 라우트 주석에 기대 탐지 (카테고리/최소등급)를 명시.
기대값은 탐지기 계약(comments in probes.rs)에서 도출 — 출력 보고 조정 금지.
"""
import base64
import json
import random
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JWT = (
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ."
    "eyJ1c2VyIjoxLCJyb2xlIjoidXNlciJ9."
    "c2lnbmF0dXJlLXBsYWNlaG9sZGVyLWZvci1iZW5jaA"
)  # auth-bypass/medium (JWT 노출) + jwt_risky_claims kid

HOME = """<!DOCTYPE html><html><head><title>BenchShop</title>
<script src="/static/app.js"></script></head>
<body><h1>BenchShop</h1>
<!-- session token for debugging: {jwt} -->
<p>data export: rO0ABQ serial blob v1</p>
<nav>
<a href="/s?q=1">search</a> <a href="/s?id=2">item</a> <a href="/s?name=x">hello</a> <a href="/s?f=1">file</a>
<a href="/api/orders/100">my order</a> <a href="/api/orders/101">recent</a>
<a href="/api/items?id=42">items</a>
<a href="/members">members</a>
<a href="/about" target="_blank">about(new tab)</a>
<a href="/gb">guestbook</a>
</nav>
<form action="/login" method="post">
<input type="text" name="user"><input type="password" name="pw">
<input type="hidden" name="_method" value="PUT">
<input type="submit" value="login"></form>
<form action="/upload" method="post" enctype="multipart/form-data">
<input type="file" name="doc"><input type="submit"></form>
</body></html>""".format(jwt=JWT)

APP_JS = 'var API_KEY="AKIAIOSFODNN7EXAMPLE";\nfetch("/api/u?uid=1");\n'


GB = []  # stored-xss/high 정답지 — POST /gb 저장 후 GET /gb 렌더 (무이스케이프)


def sid():
    return "%08x" % random.randrange(16**8)  # session-entropy/low (16자 미만)


class H(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"  # vuln-component/medium (CVE-2021-23017, 1.20.1 미만)
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=()):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _home(self, qs):
        q = urllib.parse.parse_qs(qs, keep_blank_values=True)
        # Host 헤더 오염 반영 -> host-header/medium
        host = self.headers.get("Host", "") + self.headers.get("X-Forwarded-Host", "")
        host_note = "<p>host:%s</p>" % host if "evil-probe.test" in host else ""
        # q: 무가공 반사 -> xss-reflect/medium + verify-xss/high(브레이크아웃) + hpp/low
        qrefl = " ".join(q.get("q", []))
        # id: SQL 오류 / NoSQL 오류 (Boolean 분화 — 1=2 무행)
        idv = " ".join(q.get("id", []))
        if "1=2" in idv:
            return self._send(200, "no rows")
        if "'" in idv or '"' in idv:
            return self._send(200, "DB failed: You have an error in your SQL syntax near '%s'" % idv[:40])
        nekey = [k for k in q if k.startswith("id[")]
        if nekey:
            return self._send(200, "MongoError: unknown operator: $ne for %s" % nekey[0])
        # name: SSTI 평가
        name = " ".join(q.get("name", []))
        if "{{7919*7331}}" in name:
            return self._send(200, "<p>hello 58054189</p>")
        # url/next/redirect/dest: 오픈 리다이렉트 + SSRF
        for p in ("url", "next", "redirect", "dest"):
            for v in q.get(p, []):
                if "evil" in v and "probe" in v:
                    self.send_response(302)
                    self.send_header("Location", v)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if v.startswith("http://169.254.169.254/"):
                    return self._send(200, "meta: ami-id=i-0abc instance-id=i-0abc local-hostname=bench")
                if v.startswith("http") and "127.0.0.1" in v:
                    # 블라인드 SSRF 시뮬레이션 — 덫 URL만 실제로 가져간다 (정답지 한정).
                    try:
                        with urllib.request.urlopen(v, timeout=3) as r:
                            n = len(r.read(4096))
                        return self._send(200, "<p>fetched %d bytes</p>" % n)
                    except Exception:
                        return self._send(200, "<p>fetch failed</p>")
        # f: CRLF 헤더 주입
        f = " ".join(q.get("f", []))
        extra = [("X-Echo", f)] if f else []
        # Origin: null 반영 -> cors/medium
        if self.headers.get("Origin") == "null":
            extra.append(("Access-Control-Allow-Origin", "null"))
        body = HOME + host_note
        if qrefl:
            body += "<p>results for %s</p>" % qrefl
        if name:
            body += "<p>hello %s</p>" % name
        self._send(200, body, extra=[("Set-Cookie", "sess=%s; Path=/" % sid())] + extra)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        path, qs = url.path.rstrip("/") or "/", url.query
        if path == "/":
            return self._home(qs)
        if path == "/.env":
            return self._send(200, "APP_KEY=base64:abc\nDB_PASSWORD=hunter2-secret\nDEBUG=true\n", "text/plain")
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if path == "/backup.sql":
            return self._send(200, "-- dump\nCREATE TABLE users(id INT);\n", "text/plain")
        if path == "/actuator/env":
            return self._send(200, '{"profiles":["prod"],"db.password":"s3cret"}', "application/json")
        if path == "/admin":
            return self._send(200, "<h1>admin console</h1>")
        if "%2e%2e" in self.path.lower() or "..;/" in self.path or "win.ini" in self.path.lower():
            return self._send(200, "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1\n")
        if path == "/graphql":
            if "__schema" in qs:
                return self._send(200, '{"data":{"__schema":{"queryType":{"name":"Q"},"mutationType":{"name":"M"}}}}', "application/json")
            if "__typename" in qs:
                return self._send(200, '{"data":{"a":{"__typename":"Q"}}}', "application/json")
            return self._send(200, '{"errors":[{"message":"query required"}]}', "application/json")
        if path == "/login":
            return self._send(200, '<form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>')
        if path == "/dashboard":
            return self._send(200, "<h1>welcome admin</h1>")
        if path == "/members":
            if not self.headers.get("Cookie"):
                return self._send(401, "login required")
            uid = " ".join(urllib.parse.parse_qs(qs).get("uid", []))
            body = "<h1>members</h1><a href=\"/members?uid=1\">u1</a><p>backup key: AKIAIOSFODNN7EXAMPLE</p>"
            if uid:
                body += "<p>member %s</p>" % uid
            return self._send(200, body)
        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[-1]
            if oid == "100":
                return self._send(200, '{"id":100,"owner":"me","email":"me100@example.com","note":"padpad"}', "application/json")
            if oid in ("98", "99", "101", "102"):
                return self._send(200, '{"id":%s,"owner":"other","email":"other%s@example.com"}' % (oid, oid), "application/json")
            return self._send(404, "nf")
        if path == "/api/items":
            q = urllib.parse.parse_qs(qs)
            iid = (q.get("id", [""])[0] or "")
            if iid == "42":
                return self._send(200, '{"id":42,"owner":"me","email":"me42@example.com","note":"padpad"}', "application/json")
            if iid in ("40", "41", "43", "44"):
                return self._send(200, '{"id":%s,"owner":"other","email":"o%s@example.com"}' % (iid, iid), "application/json")
            return self._send(404, "nf")
        if path.startswith("/rc7x-probe-"):
            return self._send(200, "rc7x-consented-write-probe-ok")
        if path == "/gb":
            items = "".join("<li>%s</li>" % m for m in GB)
            return self._send(200, '<h1>guestbook</h1><form action="/gb" method="post">'
                                   '<input type="text" name="msg"><input type="submit" value="sign"></form>'
                                   "<ul>%s</ul>" % items)
        if path == "/openapi.json":
            return self._send(200, '{"openapi":"3.0.3","paths":{"/api/echo":{"get":{"parameters":[{"name":"q","in":"query"}]}},"/api/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"}]}},"/api/users":{"post":{}}}}', "application/json")
        if path == "/api/echo":
            # A71 xss-reflect/medium + A72 verify-xss/high (스펙 쿼리 투입).
            qrefl = " ".join(urllib.parse.parse_qs(qs, keep_blank_values=True).get("q", []))
            return self._send(200, "<p>results for %s</p>" % qrefl)
        if path == "/api/users" or path.startswith("/api/users/"):
            return self._send(200, '{"id":1,"name":"bench"}', "application/json")
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path in ("/about", "/contact", "/health", "/s"):
            return self._send(200, "<p>clean page %s</p>" % path)
        return self._send(404, "nf")

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/gb":
            ln = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(ln).decode("utf-8", "replace")
            q = urllib.parse.parse_qs(body)
            msg = (q.get("msg", [""])[0] or "")[:200]
            if msg:
                GB.append(msg)
            items = "".join("<li>%s</li>" % m for m in GB)
            return self._send(200, "<ul>%s</ul>" % items)
        if url.path == "/login":
            ln = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(ln).decode("utf-8", "replace")
            q = urllib.parse.parse_qs(body)
            u = (q.get("user", [""])[0] or "")
            p = (q.get("pw", [""])[0] or "")
            if u == "admin" and p == "admin1234":
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", "sess=adminsession1234567890; Path=/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(200, '<p>Invalid credentials</p><form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>')
        return self._send(404, "nf")

    def do_PUT(self):
        if self.path.startswith("/rc7x-probe-"):
            ln = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(ln)
            return self._send(201, "created")
        return self._send(404, "nf")

    def do_DELETE(self):
        if self.path.startswith("/rc7x-probe-"):
            return self._send(200, "deleted")
        return self._send(404, "nf")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Methods", "PUT, DELETE")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        body = "TRACE / HTTP/1.1\r\nX-RC-Probe: rc7xtrace"
        self._send(200, body, "message/http")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    print("BENCH_PORT=%d" % srv.server_address[1], flush=True)
    srv.serve_forever()
