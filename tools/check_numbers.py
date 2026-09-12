#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recompute every headline figure from the data, and flag stale ones in the docs.

Numbers in this project live in four places that drift apart: README.md,
RESULTS.md, the console's VEX Decision Logic page (via src/vex_decision.CORPUS)
and the result JSON itself. This recomputes them from the results and diffs
against CORPUS, so a stale claim is a failing check rather than something a
reader has to catch.

  python tools/check_numbers.py           report
  python tools/check_numbers.py --write   update src/vex_decision.CORPUS in place
"""
import argparse
import collections
import csv
import io
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))


def _j(*p, default=None):
    path = os.path.join(BASE, *p)
    if not os.path.exists(path):
        return default
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def compute():
    n = {}
    snapdir = os.path.join(BASE, "data", "source_snapshots")
    n["snapshots"] = len(os.listdir(snapdir)) if os.path.isdir(snapdir) else 0

    camp = os.path.join(BASE, "results", "verify_full_summary.csv")
    if os.path.exists(camp):
        rows = list(csv.DictReader(open(camp, encoding="utf-8")))
        n["campaign_attempted"] = len({r["cve"] for r in rows if r.get("cve")})
        n["campaign_outcomes"] = dict(collections.Counter(r.get("outcome") for r in rows))

    tgt = _j("data", "vuln_targets.json", default={})
    n["targets_located"] = sum(1 for v in tgt.values() if v.get("targets"))
    n["targets_by_source"] = dict(collections.Counter(
        v["source"] for v in tgt.values() if v.get("targets")))

    q2 = _j("results", "callgraph_reach.json", default=[])
    c2 = collections.Counter(r.get("verdict", r.get("status")) for r in q2)
    n["q2_rows"], n["q2"] = len(q2), dict(c2)
    n["q2_reachable"], n["q2_unreachable"] = c2.get("reachable", 0), c2.get("unreachable", 0)

    q3 = _j("results", "taint_reach.json", default=[])
    c3 = collections.Counter(r.get("verdict", r.get("status")) for r in q3)
    n["q3_rows"], n["q3"] = len(q3), dict(c3)
    n["q3_controllable"] = c3.get("controllable", 0)
    n["q3_not_controllable"] = c3.get("not-controllable", 0)

    q4 = _j("results", "mitigation_scan.json", default=[])
    n["q4_rows"] = len(q4)
    n["q4_mitigation_cleared"] = sum(1 for r in q4 if r.get("vex") == "not_affected")

    # A clearance is a `not_affected` outcome, not a raw verdict: Q3's gates
    # (target source, graph completeness, entry-model roots) can hold a
    # not-controllable verdict at under_investigation - Spring4Shell is one.
    n["q3_cleared"] = sum(1 for r in q3 if r.get("vex") == "not_affected")
    n["clearances_from_source_analysis"] = (n["q2_unreachable"] + n["q3_cleared"]
                                            + n["q4_mitigation_cleared"])

    rank = _j("results", "codebert_rank.json", default={})
    if rank:
        n["codebert_eval_n"] = rank.get("n")
        n["codebert_top20_recall"] = rank.get("top20_recall")

    rem = _j("data", "remediations.json", default={})
    n["remediation_cves"] = len(rem)
    n["remediation_triage"] = dict(collections.Counter(
        r.get("likelihood") for r in rem.values()))

    summ = _j("results", "vex_batch_summary.json", default={})
    if summ:
        n["statements"] = summ.get("total_findings")
        n["by_vex"] = summ.get("by_vex")
        n["by_likelihood"] = summ.get("by_likelihood")

    vm = _j("results", "version_match.json", default={})
    if vm:
        n["version_match"] = {k: vm.get(k) for k in
                              ("universe_n", "affected_precision_pct", "recall_pct", "macro_f1")}
    return n


# The same Q2/Q3 phrase appears in both documents and in the QUESTIONS prose the
# console renders; covering all three here means --write leaves nothing to fix
# by hand (the prose used to print "must be edited by hand" and drifted).
DOC_FILES = ("README.md", "RESULTS.md", os.path.join("src", "vex_decision.py"))
_DOC_ROWS = {
    "Q2": (re.compile(r"reachable \d+, target-not-found \d+, no-source \d+"),
           lambda n: "reachable %d, target-not-found %d, no-source %d" % (
               n["q2"].get("reachable", 0), n["q2"].get("target-not-found", 0),
               n["q2"].get("no-source", 0))),
    "Q3": (re.compile(r"controllable \d+, target-not-found \d+, no-source \d+"),
           lambda n: "controllable %d, target-not-found %d, no-source %d" % (
               n["q3"].get("controllable", 0), n["q3"].get("target-not-found", 0),
               n["q3"].get("no-source", 0))),
}


def check_docs(n, write):
    """Stale Q2/Q3 phrases in the docs -> [(file, question, found, wanted)]."""
    stale = []
    for f in DOC_FILES:
        p = os.path.join(BASE, f)
        if not os.path.exists(p):
            continue
        text = io.open(p, encoding="utf-8").read()
        new = text
        for q, (pat, want_of) in _DOC_ROWS.items():
            want = want_of(n)
            for m in pat.finditer(text):
                if m.group(0) != want:
                    stale.append((f, q, m.group(0), want))
            if write:
                new = pat.sub(want, new)
        if write and new != text:
            io.open(p, "w", encoding="utf-8", newline="\n").write(new)
    return stale


CORPUS_KEYS = ["snapshots", "targets_located", "q2_reachable", "q2_unreachable",
               "q3_controllable", "q3_not_controllable", "q4_mitigation_cleared",
               "clearances_from_source_analysis"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="rewrite src/vex_decision.CORPUS with the computed values")
    a = ap.parse_args()

    n = compute()
    print("== recomputed from results ==")
    for k, v in n.items():
        print("  %-34s %s" % (k, v))

    import vex_decision as VD
    print("\n== CORPUS in src/vex_decision.py ==")
    stale = []
    for k in CORPUS_KEYS:
        want, have = n.get(k), VD.CORPUS.get(k)
        flag = "OK " if want == have else "STALE"
        if want != have:
            stale.append((k, have, want))
        print("  %-5s %-34s doc=%-6s data=%s" % (flag, k, have, want))

    # CORPUS is not the only place a number lives: QUESTIONS[].result carries the
    # same counts as prose, and it is what the console page prints. A checker
    # that only reads CORPUS lets those drift (it did - "reachable 62" survived a
    # CORPUS fix), so verify them too.
    print("\n== QUESTIONS[].result prose ==")
    prose = {
        "Q2": "reachable %d, target-not-found %d, no-source %d" % (
            n["q2"].get("reachable", 0), n["q2"].get("target-not-found", 0),
            n["q2"].get("no-source", 0)),
        "Q3": "controllable %d, target-not-found %d, no-source %d" % (
            n["q3"].get("controllable", 0), n["q3"].get("target-not-found", 0),
            n["q3"].get("no-source", 0)),
    }
    for q in VD.QUESTIONS:
        want = prose.get(q["id"])
        if not want:
            continue
        ok = want in q["result"]
        if not ok:
            stale.append((q["id"] + "_prose", q["result"][:40], want))
        print("  %-5s %-6s expects %r" % ("OK " if ok else "STALE", q["id"], want))

    print("\n== README.md / RESULTS.md / src/vex_decision.py Q2-Q3 phrases ==")
    doc_stale = check_docs(n, a.write)
    if not doc_stale:
        print("  OK    every copy matches the data")
    for f, q, found, want in doc_stale:
        print("  %s %-10s %s  found %r  data %r"
              % ("FIXED" if a.write else "STALE", f, q, found, want))
    if doc_stale and not a.write:
        stale.append(("docs", len(doc_stale), 0))

    if stale and a.write:
        p = os.path.join(BASE, "src", "vex_decision.py")
        s = io.open(p, encoding="utf-8").read()
        for k, _old, new in stale:
            if k.endswith("_prose"):
                print("  !! %s must be edited by hand (prose)" % k)
                continue
            s2 = re.sub(r'("%s":\s*)(\d+)' % re.escape(k), r"\g<1>%d" % new, s, count=1)
            if s2 == s:
                print("  !! could not rewrite %s" % k)
            s = s2
        io.open(p, "w", encoding="utf-8", newline="\n").write(s)
        print("\nrewrote %d CORPUS values" % len(stale))
    elif stale:
        print("\n%d stale value(s); re-run with --write to fix" % len(stale))
    else:
        print("\nCORPUS matches the data")
    return 1 if stale and not a.write else 0


if __name__ == "__main__":
    sys.exit(main())
