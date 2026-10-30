#!/usr/bin/env python3
"""외부 독립 타겟 벤치 — sweep 바이너리 + manifest 기반 recall/오탐/결정성 채점.

정답지(bench_app)와 달리 외부 타겟에는 완전한 ground truth가 없으므로,
기대 항목(recall)과 오탐 상한을 분리 채점하고, 기대外 high/critical은
수동 트리아지 대상(REVIEW)으로 보고한다 (자동 실패 아님).

사용법:
  python3 extbench.py [sweep 바이너리] [manifest ...] [--twice] [--out DIR]
  manifest 생략 시 manifests/*.json 전체. --twice는 결정성 비교용 2회 실행.

manifest 형식은 manifests/README.md 참조.
"""
import glob
import json
import os
import subprocess
import sys
import time

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def run_sweep(sweep_bin, target, args, timeout):
    cmd = [sweep_bin, target, "--json"] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode not in (0,):
        raise RuntimeError("sweep exit=%d: %s" % (r.returncode, r.stderr[-500:]))
    return json.loads(r.stdout)


def match_hit(hit, exp):
    if hit["category"] != exp["category"]:
        return False
    if exp.get("target_contains") and exp["target_contains"] not in hit["target"]:
        return False
    if exp.get("title_contains") and exp["title_contains"] not in hit["title"]:
        return False
    if SEV_RANK.get(hit["severity"], 0) < SEV_RANK.get(exp.get("min_severity", "info"), 0):
        return False
    return True


def score_manifest(manifest, rep):
    """(found, missed, review) — review는 기대外 high/critical."""
    hits = rep.get("hits", [])
    found, missed = [], []
    for exp in manifest.get("expected", []):
        ok = [h for h in hits if match_hit(h, exp)]
        (found if ok else missed).append(exp["id"])
    exp_ids = set()
    for exp in manifest.get("expected", []):
        for h in hits:
            if match_hit(h, exp):
                exp_ids.add(h.get("fingerprint") or h.get("id"))
    review = []
    for h in hits:
        key = h.get("fingerprint") or h.get("id")
        if SEV_RANK.get(h["severity"], 0) >= 3 and key not in exp_ids:
            review.append(h)
    fps = []
    for h in hits:
        if manifest.get("clean") and SEV_RANK.get(h["severity"], 0) >= 3:
            fps.append(h)
    # 부재 단언 — 과거 오탐 회귀 방지 (일치하면 실패).
    violated = []
    for rule in manifest.get("absent", []):
        bad = [h for h in hits if match_hit(h, rule)]
        if bad:
            violated.append((rule["id"], bad))
    return found, missed, review, fps, violated


def coverage_line(rep):
    from collections import Counter
    c = Counter(u["disposition"] for u in rep.get("coverage", []))
    return " ".join("%s=%d" % (k, c.get(k, 0))
                    for k in ("covered", "finding", "deferred", "out_of_scope", "blocked"))


def main():
    args = sys.argv[1:]
    twice = "--twice" in args
    args = [a for a in args if a != "--twice"]
    outdir = None
    if "--out" in args:
        i = args.index("--out")
        outdir = args[i + 1]
        del args[i:i + 2]
    sweep_bin = args[0] if args and not args[0].endswith(".json") else \
        "../src-tauri/target/debug/sweep"
    rest = args[1:] if args and not args[0].endswith(".json") else args
    here = os.path.dirname(os.path.abspath(__file__))
    manifests = rest or sorted(glob.glob(os.path.join(here, "manifests", "*.json")))
    if not manifests:
        print("manifest 없음: redcell-desktop/gate/manifests/*.json")
        return 2
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    overall_fail = []
    report = ["# 외부 독립 벤치 결과 (%s)" % stamp, ""]
    for mp in manifests:
        with open(mp) as f:
            m = json.load(f)
        print("== %s (%s) ==" % (m["id"], m["target"]))
        report.append("## %s (%s)" % (m["id"], m["target"]))
        report.append("")
        report.append("- 승인 근거: %s" % m.get("authorized", "(미기재)"))
        timeout = int(m.get("timeout", 420))
        try:
            rep = run_sweep(sweep_bin, m["target"], m.get("sweep_args", []), timeout)
        except Exception as e:  # noqa: BLE001
            print("  실행 실패: %s" % e)
            report.append("- 실행 실패: %s" % e)
            overall_fail.append(m["id"] + ": 실행 실패")
            continue
        if outdir:
            with open(os.path.join(outdir, "%s-%s.json" % (m["id"], stamp)), "w") as f:
                json.dump(rep, f, ensure_ascii=False, indent=1)
        found, missed, review, fps, violated = score_manifest(m, rep)
        exp = m.get("expected", [])
        print("  probes=%d hits=%d recall=%d/%d review=%d fp=%d absent-viol=%d" % (
            rep.get("probes_run"), len(rep.get("hits", [])),
            len(found), len(exp), len(review), len(fps), len(violated)))
        print("  coverage: %s" % coverage_line(rep))
        for eid in missed:
            print("  MISS %s" % eid)
        for h in review:
            print("  REVIEW [%s] %s %s — %s" % (
                h["severity"], h["category"], h["target"][:90], h["title"][:60]))
        for h in fps:
            print("  FP-CLEAN [%s] %s %s" % (h["severity"], h["category"], h["target"][:90]))
        for rid, bad in violated:
            print("  ABSENT-VIOLATED %s: %d건 (예: [%s] %s %s)" % (
                rid, len(bad), bad[0]["severity"], bad[0]["category"], bad[0]["target"][:80]))
        if twice:
            rep2 = run_sweep(sweep_bin, m["target"], m.get("sweep_args", []), timeout)
            f1 = sorted(h.get("fingerprint", "") for h in rep.get("hits", []))
            f2 = sorted(h.get("fingerprint", "") for h in rep2.get("hits", []))
            same = f1 == f2
            print("  determinism: %s (%d vs %d)" % ("SAME" if same else "DIFF", len(f1), len(f2)))
            if not same:
                only1 = [x for x in f1 if x not in f2][:5]
                only2 = [x for x in f2 if x not in f1][:5]
                print("    only1: %s" % only1)
                print("    only2: %s" % only2)
        for km in m.get("known_misses", []):
            print("  KNOWN-MISS %s: %s" % (km["id"], km["reason"][:80]))
        report.append("- probes=%d hits=%d recall=%d/%d review=%d fp=%d absent-viol=%d" % (
            rep.get("probes_run"), len(rep.get("hits", [])),
            len(found), len(exp), len(review), len(fps), len(violated)))
        report.append("- coverage: %s" % coverage_line(rep))
        if missed:
            report.append("- MISS: %s" % ", ".join(missed))
        for h in review:
            report.append("- REVIEW [%s] %s %s — %s" % (
                h["severity"], h["category"], h["target"][:100], h["title"][:70]))
        for km in m.get("known_misses", []):
            report.append("- KNOWN-MISS %s: %s" % (km["id"], km["reason"]))
        report.append("")
        if missed or fps or violated:
            overall_fail.append("%s: miss=%d fp=%d absent-viol=%d" % (
                m["id"], len(missed), len(fps), len(violated)))
    print("== %s ==" % ("FAIL" if overall_fail else "PASS"))
    for f in overall_fail:
        print("  " + f)
    if outdir:
        with open(os.path.join(outdir, "report-%s.md" % stamp), "w") as f:
            f.write("\n".join(report) + "\n")
        print("report: %s/report-%s.md" % (outdir, stamp))
    return 1 if overall_fail else 0


if __name__ == "__main__":
    sys.exit(main())
