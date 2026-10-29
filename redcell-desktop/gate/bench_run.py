#!/usr/bin/env python3
"""RedCell 게이트 정답지 채점 — bench_app.py 기동 → sweep → 재현율/정밀도.

기대값은 탐지기 계약에서 도출 (bench_app.py 주석 참조). 결과 해석:
- MISS: 정답지를 못 찾음 (미탐, recall 결함)
- SUSPECT: 기대에 없는 high/critical (오탐 후보, 수동 확인 필요)
- FP-CLEAN: 클린 경로(/about,/contact,/health,/s) 발견 (오탐)
종료 코드: MISS·SUSPECT·FP-CLEAN 중 하나라도 있으면 1.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# (id, category, min_severity, target_substring, title_substring)
SAFE_EXPECTED = [
    ("V01", "paths", "high", "/.env", ""),
    ("V01b", "secret", "high", "/.env", ""),
    ("V02", "paths", "high", "/.git/HEAD", ""),
    ("V03", "paths", "medium", "/backup.sql", ""),
    ("V04", "paths", "high", "/actuator/env", ""),
    ("V05", "paths", "low", "/admin", ""),
    ("V05b", "paths", "low", "/admin/", ""),
    ("V06", "paths", "high", "%2e%2e", ""),
    ("V06b", "paths", "high", "..;/", ""),
    ("V06c", "paths", "high", "win.ini", ""),
    ("V07", "xss-reflect", "medium", "?q=", ""),
    ("V08", "verify-xss", "high", "?q=", ""),
    ("V08b", "verify-xss", "high", "?name=", ""),
    ("V09", "sqli-signal", "high", "?id=", ""),
    ("V09b", "verify-sqli", "high", "?id=", "Boolean"),
    ("V10", "nosql-signal", "high", "id[", ""),
    ("V11", "openredirect", "high", "?url=", ""),
    ("V11b", "openredirect", "high", "?next=", ""),
    ("V11c", "openredirect", "high", "?redirect=", ""),
    ("V12", "verify-redirect", "high", "?url=", ""),
    ("V12b", "verify-redirect", "high", "?next=", ""),
    ("V12c", "verify-redirect", "high", "?redirect=", ""),
    ("V13", "ssti-eval", "high", "?name=", ""),
    ("V14", "hpp-ambiguity", "low", "?q=", ""),
    ("V15", "crlf-inject", "high", "?f=", ""),
    ("V16", "ssrf-signal", "high", "?url=", ""),
    ("V16b", "ssrf-signal", "high", "?dest=", ""),
    ("V16c", "ssrf-signal", "high", "?next=", ""),
    ("V17", "host-header", "medium", "BASE/", ""),
    ("V18", "cors", "medium", "BASE/", "null"),
    ("V19", "cors", "medium", "BASE/", "preflight"),
    ("V20", "graphql-introspect", "medium", "/graphql", ""),
    ("V21", "graphql-mutation", "info", "/graphql", ""),
    ("V22", "graphql-depth", "low", "/graphql", ""),
    ("V23", "methods", "medium", "BASE/", "쓰기"),
    ("V24", "methods", "low", "BASE/", "TRACE"),
    ("V25", "secret", "high", "/static/app.js", ""),
    ("V25b", "secret", "high", "BASE", "JWT"),
    ("V26", "js-hint", "info", "/static/app.js", ""),
    ("V27", "auth-bypass", "medium", "BASE/", "JWT"),
    ("V28", "deserialize-sig", "medium", "BASE/", ""),
    ("V29", "tabnabbing", "low", "BASE/", ""),
    ("V30", "upload-surface", "info", "BASE/", ""),
    ("V31", "method-override", "low", "BASE", ""),
    ("V32", "authform", "low", "BASE/", ""),
    ("V33", "headers", "medium", "BASE/", ""),
    ("V34", "cookies", "medium", "BASE/", ""),
    ("V35", "tls", "low", "BASE/", ""),
    ("V35b", "paths", "info", "/health", ""),
    ("V36", "vuln-component", "medium", "BASE/", ""),
    ("V37", "bola-surface", "info", "/api/orders", ""),
    ("V38", "bola-surface", "info", "?id=", ""),
    ("V39", "session-entropy", "low", "BASE", ""),
    ("V39b", "stored-xss", "info", "/gb", "후보"),
]
DANGER_EXPECTED = [
    ("D40", "danger-creds", "critical", "/login", ""),
    ("D41", "danger-idor", "high", "/api/orders/98", ""),
    ("D42", "danger-bola", "high", "id=40", ""),
    ("D43", "danger-write", "high", "rc7x-probe-", ""),
    ("D44", "auth-bypass", "high", "/admin", ""),
    ("D45", "auth-bypass", "high", "/dashboard", ""),
    ("D46", "stored-xss", "high", "/gb", ""),
    ("D47", "danger-write", "info", "/gb", "폼 제출"),
]
CLEAN_PATHS = ("/about", "/contact")
OOB_EXPECTED = [
    ("O60", "ssrf-signal", "high", "?url=", "블라인드 콜백"),
    ("O61", "ssrf-signal", "high", "?next=", "블라인드 콜백"),
    ("O62", "ssrf-signal", "high", "?dest=", "블라인드 콜백"),
]
CRAWL_EXPECTED = [
    ("C50", "secret", "high", "/members", ""),
    ("C51", "xss-reflect", "medium", "/members/", "'uid'"),
    ("C52", "verify-xss", "high", "/members/", "'uid'"),
]
OPENAPI_EXPECTED = [
    ("A70", "api-surface", "info", "/api/echo", ""),
    ("A71", "xss-reflect", "medium", "/api/echo", ""),
    ("A72", "verify-xss", "high", "/api/echo", ""),
]
OPENAPI_YAML = """openapi: 3.0.3
paths:
  /api/echo:
    get:
      parameters:
        - name: q
          in: query
  /api/users/{id}:
    get:
      parameters:
        - name: id
          in: path
  /api/users:
    post:
      responses:
        '200':
          description: ok
"""
OPENAPI_YAML_EXPECTED = [
    ("A73", "api-surface", "info", "/api/echo", ""),
]


def start_app():
    p = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "bench_app.py")],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    line = p.stdout.readline()
    if "BENCH_PORT=" not in line:
        p.terminate()
        raise RuntimeError("bench app起動 실패: " + line)
    return p, int(line.split("=")[1])


def run_sweep(sweep_bin, port, extra):
    cmd = [sweep_bin, "127.0.0.1", "--port", str(port), "--timeout", "120", "--json"] + extra
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    rep = json.loads(r.stdout)
    return rep, r.returncode


def match(hits, cat, minsev, tsub, title):
    return [h for h in hits
            if h["category"] == cat and tsub in h["target"] and title in h["title"]
            and SEV_RANK.get(h["severity"], -1) >= SEV_RANK[minsev]]


def score(rep, expected, hostport):
    hits = rep.get("hits", [])
    rows = []
    for vid, cat, minsev, tsub, title in expected:
        found = match(hits, cat, minsev, tsub.replace("BASE", hostport), title)
        rows.append((vid, cat, minsev, bool(found),
                     found[0]["id"] if found else "-",
                     found[0]["severity"] if found else "-"))
    return rows


def main():
    sweep_bin = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        HERE, "..", "src-tauri", "target", "debug", "sweep")
    sweep_bin = os.path.abspath(sweep_bin)
    app, port = start_app()
    hostport = "127.0.0.1:%d" % port
    fails = []
    try:
        print("== 정답지 앱 포트 %d ==" % port)
        rep, _ = run_sweep(sweep_bin, port, [])
        print("safe: probes=%d hits=%d" % (rep.get("probes_run", 0), len(rep.get("hits", []))))
        rows = score(rep, SAFE_EXPECTED, hostport)
        for vid, cat, ms, ok, pid, sev in rows:
            print("  [%s] %-18s %-6s %s %s(%s)" % ("OK" if ok else "MISS", cat, ms, vid, pid, sev))
        fails += ["MISS %s/%s" % (m[0], m[1]) for m in rows if not m[3]]

        repd, _ = run_sweep(sweep_bin, port, ["--danger", "--cookie", "SESS=bench"])
        print("danger: probes=%d hits=%d" % (repd.get("probes_run", 0), len(repd.get("hits", []))))
        drows = score(repd, DANGER_EXPECTED, hostport)
        for vid, cat, ms, ok, pid, sev in drows:
            print("  [%s] %-18s %-6s %s %s(%s)" % ("OK" if ok else "MISS", cat, ms, vid, pid, sev))
        fails += ["MISS %s/%s" % (m[0], m[1]) for m in drows if not m[3]]

        repc, _ = run_sweep(sweep_bin, port, ["--login-user", "admin", "--login-pass", "admin1234",
                                                          "--crawl", "15"])
        print("crawl: probes=%d hits=%d auth=%s" % (repc.get("probes_run", 0), len(repc.get("hits", [])),
                                                   repc.get("authenticated")))
        if not repc.get("authenticated"):
            fails.append("CRAWL-AUTH 로그인 실패")
        crows = score(repc, CRAWL_EXPECTED, hostport)
        for vid, cat, ms, ok, pid, sev in crows:
            print("  [%s] %-18s %-6s %s %s(%s)" % ("OK" if ok else "MISS", cat, ms, vid, pid, sev))
        fails += ["MISS %s/%s" % (m[0], m[1]) for m in crows if not m[3]]

        import socket as _s
        _t = _s.socket()
        _t.bind(("127.0.0.1", 0))
        oob_port = _t.getsockname()[1]
        _t.close()
        repo, _ = run_sweep(sweep_bin, port, ["--oob-bind", "127.0.0.1:%d" % oob_port,
                                              "--oob-base", "http://127.0.0.1:%d/oob/" % oob_port])
        print("oob: probes=%d hits=%d" % (repo.get("probes_run", 0), len(repo.get("hits", []))))
        orows = score(repo, OOB_EXPECTED, hostport)
        for vid, cat, ms, ok, pid, sev in orows:
            print("  [%s] %-18s %-6s %s %s(%s)" % ("OK" if ok else "MISS", cat, ms, vid, pid, sev))
        fails += ["MISS %s/%s" % (m[0], m[1]) for m in orows if not m[3]]

        repa, _ = run_sweep(sweep_bin, port, ["--openapi", "http://127.0.0.1:%d/openapi.json" % port])
        print("openapi: probes=%d hits=%d" % (repa.get("probes_run", 0), len(repa.get("hits", []))))
        arows = score(repa, OPENAPI_EXPECTED, hostport)
        for vid, cat, ms, ok, pid, sev in arows:
            print("  [%s] %-18s %-6s %s %s(%s)" % ("OK" if ok else "MISS", cat, ms, vid, pid, sev))
        fails += ["MISS %s/%s" % (m[0], m[1]) for m in arows if not m[3]]

        import tempfile as _tf
        with _tf.NamedTemporaryFile("w", suffix=".yaml", delete=False) as _f:
            _f.write(OPENAPI_YAML)
            _yamlspec = _f.name
        repay, _ = run_sweep(sweep_bin, port, ["--openapi", _yamlspec])
        print("openapi-yaml: probes=%d hits=%d" % (repay.get("probes_run", 0), len(repay.get("hits", []))))
        yrows = score(repay, OPENAPI_YAML_EXPECTED, hostport)
        for vid, cat, ms, ok, pid, sev in yrows:
            print("  [%s] %-18s %-6s %s %s(%s)" % ("OK" if ok else "MISS", cat, ms, vid, pid, sev))
        fails += ["MISS %s/%s" % (m[0], m[1]) for m in yrows if not m[3]]

        # 정밀도: 클린 경로 발견 + 기대外 high/critical.
        exp_all = SAFE_EXPECTED + DANGER_EXPECTED + CRAWL_EXPECTED + OOB_EXPECTED + OPENAPI_EXPECTED + OPENAPI_YAML_EXPECTED
        for rep_, tag in ((rep, "safe"), (repd, "danger"), (repc, "crawl"), (repo, "oob"), (repa, "openapi"), (repay, "openapi-yaml")):
            for h in rep_.get("hits", []):
                if any(cp in h["target"] for cp in CLEAN_PATHS):
                    fails.append("FP-CLEAN %s %s %s" % (tag, h["category"], h["target"]))
                if SEV_RANK.get(h["severity"], 0) >= 3 and not any(
                        h["category"] == c and t.replace("BASE", hostport) in h["target"]
                        and ti in h["title"] for _, c, _, t, ti in exp_all):
                    fails.append("SUSPECT %s [%s] %s %s" % (tag, h["severity"], h["category"], h["target"]))

        # 게이트 모드: 정답지는 high 다수 → exit 1 + SARIF 유효성.
        sarif = "/tmp/bench.sarif"
        cmd = [sweep_bin, "127.0.0.1", "--port", str(port), "--timeout", "120",
               "--gate", "--sarif", sarif]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        print("gate exit=%d (기대 1)" % r.returncode)
        if r.returncode != 1:
            fails.append("GATE-EXIT 기대 1, 실제 %d" % r.returncode)
        with open(sarif) as f:
            s = json.load(f)
        assert s["version"] == "2.1.0", "SARIF 버전"
        assert len(s["runs"][0]["results"]) == len(rep.get("hits", [])), "SARIF 결과 수"
        print("sarif: rules=%d results=%d OK"
              % (len(s["runs"][0]["tool"]["driver"]["rules"]), len(s["runs"][0]["results"])))
    finally:
        app.terminate()
    print("== %s ==" % ("FAIL" if fails else "PASS"))
    for f in fails:
        print("  " + f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
