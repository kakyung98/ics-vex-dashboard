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

    # Targets, Q3 and Q4 now come from the VEX-v2 caches, not the retired engines.
    # callgraph_reach.json / taint_reach.json / vuln_targets.json were the old
    # execution-verification campaign and are gone; reading them left every figure
    # here at 0 while the docs (correctly) showed the live numbers. src/vex_decision
    # already derives these from the same caches, so this reads straight from it to
    # keep the checker and the page on one source.
    loc = _j("data", "source_locations.json", default={})
    n["targets_located"] = sum(1 for v in loc.values()
                               if (v or {}).get("any_function_found"))

    reach = _j("data", "reachability.json", default={})
    c2 = collections.Counter((v or {}).get("verdict") for v in reach.values())
    n["q3_rows"], n["q3"] = len(reach), dict(c2)
    n["q3_reachable"] = c2.get("reachable", 0)
    n["q3_unreachable"] = c2.get("not-reachable", 0)       # VEX-v2 spells it with a hyphen

    ctrl = _j("data", "controllability.json", default={})
    c3 = collections.Counter((v or {}).get("verdict") for v in ctrl.values())
    n["q4_rows"], n["q4"] = len(ctrl), dict(c3)
    n["q4_controllable"] = c3.get("controllable", 0)
    n["q4_not_controllable"] = c3.get("not-controllable", 0)
    n["q4_environment_dependent"] = c3.get("environment-dependent", 0)

    # A clearance is an actual `not_affected` final verdict, not a raw refutation.
    # The old formula added q3_unreachable, because the retired engine let a
    # not-reachable verdict clear a CVE. VEX-v2 does NOT: Q3/Q4 are optional and
    # never refute, so a not-reachable verdict only weakens the tier. The count is
    # therefore the not_affected finals in vex_v2.json alone - 0 here - which is how
    # src/vex_decision.CORPUS derives it, so the two agree.
    v2 = _j("data", "vex_v2.json", default={})
    v2rows = v2 if isinstance(v2, list) else list(v2.values())
    n["q4_cleared"] = sum(1 for r in v2rows if isinstance(r, dict)
                          and r.get("final_vex") == "not_affected")
    n["clearances_from_source_analysis"] = n["q4_cleared"]

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


# The same Q3/Q4 phrase appears in both documents and in the QUESTIONS prose the
# console renders; covering all three here means --write leaves nothing to fix
# by hand (the prose used to print "must be edited by hand" and drifted).
DOC_FILES = ("README.md", "RESULTS.md", os.path.join("src", "vex_decision.py"))
# The VEX-v2 vocabulary: `reachable N, not-reachable N, unknown N` for Q3 and
# `controllable N, not-controllable N, environment-dependent N` for Q4. These are
# the phrases the docs and the console prose actually use now; the retired
# `target-not-found / no-source` format is gone.
_DOC_ROWS = {
    "Q3": (re.compile(r"reachable \d+, not-reachable \d+, unknown \d+"),
           lambda n: "reachable %d, not-reachable %d, unknown %d" % (
               n["q3"].get("reachable", 0), n["q3"].get("not-reachable", 0),
               n["q3"].get("unknown", 0))),
    "Q4": (re.compile(r"controllable \d+, not-controllable \d+, environment-dependent \d+"),
           lambda n: "controllable %d, not-controllable %d, environment-dependent %d" % (
               n["q4"].get("controllable", 0), n["q4"].get("not-controllable", 0),
               n["q4"].get("environment-dependent", 0))),
}


def check_docs(n, write):
    """Stale Q3/Q4 phrases in the docs -> [(file, question, found, wanted)]."""
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


CORPUS_KEYS = ["snapshots", "targets_located", "q3_reachable", "q3_unreachable",
               "q4_controllable", "q4_not_controllable",
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
        "Q3": "reachable %d, not-reachable %d, unknown %d" % (
            n["q3"].get("reachable", 0), n["q3"].get("not-reachable", 0),
            n["q3"].get("unknown", 0)),
        "Q4": "controllable %d, not-controllable %d, environment-dependent %d" % (
            n["q4"].get("controllable", 0), n["q4"].get("not-controllable", 0),
            n["q4"].get("environment-dependent", 0)),
    }
    for q in VD.QUESTIONS:
        want = prose.get(q["id"])
        if not want:
            continue
        ok = want in q["result"]
        if not ok:
            stale.append((q["id"] + "_prose", q["result"][:40], want))
        print("  %-5s %-6s expects %r" % ("OK " if ok else "STALE", q["id"], want))

    print("\n== README.md / RESULTS.md / src/vex_decision.py Q3-Q4 phrases ==")
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
