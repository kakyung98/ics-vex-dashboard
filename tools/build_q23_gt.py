#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ground truth for Q2 (reachability) and Q3 (controllability), from authorities
the solvers do not read.

Item #4 scores the `affected` verdict, which vex_judge_v2 decides at Q1. Q2 and Q3
only set the evidence tier, and the tier is scored against nothing - so Joern and
Z3 contribute exactly 0 to every published figure. This builds the answer key that
lets them be scored, and the whole point is that its labels come from somewhere
else:

  Q2 reachability   the component's own PUBLIC API SURFACE. A vulnerable function
                    declared in a shipped header is externally callable, so for a
                    library consumer it IS an entry point - reachable by
                    construction, with no call-graph walk involved. The converse
                    label comes from the build: a function that only exists under
                    test/, fuzz/ or examples/ is not in the shipped artifact, so a
                    consumer cannot reach it at all.

  Q3 controllability NVD's CVSS v3 vector. `UI:N` asserts that no second party has
                    to act, and AV:N/A/L that the input arrives over a channel the
                    attacker speaks; together they are an authority's statement
                    that the attacker supplies the triggering input.

Both are one-sided on purpose, and that limit is published rather than papered
over. A header gives no evidence that an INTERNAL function is unreachable (it is
called by the public ones), and CVSS `UI:R` does not mean the triggering value is
not attacker-chosen - a malicious file is fully attacker-written, the user merely
opens it. So those cases are HELD OUT with a reason instead of being labelled, the
same discipline tools/build_vex_gt.py applies to single-authority not_affected.

Out: data/vex_q23_gt.jsonl  +  data/vex_q23_gt_manifest.json
"""
import collections
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
LOC = os.path.join(BASE, "data", "source_locations.json")
CVSS = os.path.join(BASE, "data", "nvd_cvss.json")
OUT = os.path.join(BASE, "data", "vex_q23_gt.jsonl")
MANIFEST = os.path.join(BASE, "data", "vex_q23_gt_manifest.json")

HDR_EXT = (".h", ".hpp", ".hh", ".hxx")
BS = chr(92)

# Directories whose contents are not part of the installed artifact. A vulnerable
# function found only here is unreachable for a consumer of the component - the
# code is simply not in what ships.
NONSHIP = re.compile(
    r"(^|/)(test|tests|testing|fuzz|fuzzing|oss-fuzz|demos?|examples?|sample|samples"
    r"|doc|docs|contrib|benchmarks?|bench|perf)(/|$)", re.I)

# A header under one of these is an internal interface, not the public surface.
# `_locl.h` is OpenSSL's own convention for exactly that (`ssl/ssl_locl.h` declares
# `tls1_process_heartbeat`, which is not API any consumer calls), and leaving it in
# produced 5 labels whose stated justification was simply wrong.
PRIVATE_HDR = re.compile(
    r"(^|/)(internal|priv|private)(/|$)|_(int|local|locl|lcl|priv)\.h$", re.I)


def _rel(path, root):
    return os.path.relpath(path, root).replace(BS, "/")


def _header_order(root, func_dir):
    """(headers to search, how many were deliberately left out).

    A component's PUBLIC interface lives in one of three places: an include/
    directory, beside the implementation, or at the project root. Everything deeper
    is an interior header, and searching it would not answer the question anyway -
    a declaration buried in `drivers/net/.../foo.h` is not the surface a consumer
    compiles against.

    This is also what makes the scan finishable. A first cut searched the whole tree
    and, on a miss, read every header in it; for the linux and glibc snapshots that
    is tens of thousands of files, and the build did not complete in twelve minutes.
    The count of skipped headers is returned so a held-out case can say the search
    was bounded rather than exhaustive."""
    # keep[0] include/ · keep[1] the implementation directory · keep[2] project root
    keep, skipped = [[], [], []], 0
    for r, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", ".svn")]
        for f in files:
            if not f.endswith(HDR_EXT):
                continue
            rp = _rel(os.path.join(r, f), root)
            if NONSHIP.search(rp) or PRIVATE_HDR.search(rp):
                continue
            seg = rp.split("/")
            if "include" in [s.lower() for s in seg[:-1]]:
                keep[0].append(os.path.join(r, f))
            elif func_dir and rp.rsplit("/", 1)[0] == func_dir:
                keep[1].append(os.path.join(r, f))
            elif len(seg) == 1:
                # Project ROOT only. `len(seg) <= 2` also matched `src/foo.h`, which
                # sent SQLite's internal `src/sqliteInt.h` into the root bucket and
                # kept it out of reach of the implementation-directory rule below.
                keep[2].append(os.path.join(r, f))
            else:
                skipped += 1
    # A project with NO include/ directory stages nothing for installation, so a
    # header sitting in the implementation directory is internal by construction -
    # SQLite's `src/sqliteInt.h` and dnsmasq's `src/dnsmasq.h` are both that, and
    # both produced labels claiming a public surface that does not exist. Where an
    # include/ tree DOES exist, implementation-directory headers are kept: pre-1.1.0
    # OpenSSL really does keep its public `ssl/ssl.h` and `ssl/dtls1.h` beside the
    # sources and links them into include/openssl at configure time, so dropping
    # them wholesale would discard correct labels.
    if not keep[0]:
        return keep[0] + keep[2], skipped + len(keep[1])
    return keep[0] + keep[1] + keep[2], skipped


def _declared_in_header(root, names, func_dir):
    """((name, header), searched, skipped) - the first located name declared in a
    shipped public header, or None for the first element.

    A declaration is the name followed by `(`; a definition in a header counts too,
    since an `inline` in a public header is still part of the compiled-against
    surface."""
    pat = re.compile(r"\b(%s)\s*\(" % "|".join(re.escape(n) for n in names))
    hdrs, skipped = _header_order(root, func_dir)
    for n, hp in enumerate(hdrs, 1):
        try:
            with open(hp, encoding="utf-8", errors="replace") as f:
                t = f.read()
        except OSError:
            continue
        m = pat.search(t)
        if m:
            return (m.group(1), _rel(hp, root)), n, skipped
    return None, len(hdrs), skipped


def _cvss_parts(vector):
    """Metric -> value. A v3 vector opens with `CVSS:3.1`; a v2 vector has no prefix
    at all, so skipping the first segment unconditionally swallowed v2's AV and made
    19 records read as unparseable rather than as what they are - v2 records, which
    carry no User Interaction metric and therefore cannot answer this question."""
    segs = [x for x in (vector or "").split("/") if ":" in x]
    if segs and segs[0].upper().startswith("CVSS:"):
        segs = segs[1:]
    return dict(x.split(":", 1) for x in segs)


def reachability_label(cve, loc):
    """(expected, evidence_type, reference, detail) or (None, ..., reason)."""
    sn = (loc or {}).get("snapshot")
    root = os.path.join(SNAP, cve, sn) if sn else None
    fns = [f for f in (loc or {}).get("functions", [])
           if f.get("found") and f.get("file")]
    if not fns:
        return None, None, None, "q1_located_nothing: Q1 located no function, so "                                  "there is nothing to reach"
    if not root or not os.path.isdir(root):
        return None, None, None, "snapshot_missing: not in data/source_snapshots"

    for f in fns:
        rp = (f.get("file") or "").replace(BS, "/")
        if NONSHIP.search(rp):
            return ("not-reachable", "not_shipped",
                    rp, "the vulnerable function exists only under a path that is "
                        "not part of the installed artifact (%s), so a consumer of "
                        "the component cannot call it" % rp)

    # A leading double underscore is a RESERVED identifier in C: glibc's
    # `__vsyslog_internal` and the kernel's `__tcp_retransmit_skb` are declared in
    # an installed header, but they are not names a consumer is meant to call, so
    # "it is on the public surface" would be a false justification. Whether a public
    # function calls them is the call-graph question again, so they are held out.
    names = [f["name"] for f in fns if not f["name"].startswith("__")]
    if not names:
        return (None, None, None,
                "reserved_identifier: every located function is a reserved `__` name, "
                "which an installed header may declare but no consumer calls; "
                "reaching it is a call-graph question - no independent label")
    # source_locations records the file WITH the snapshot directory in front
    # (`sqlite-version-3.8.5/src/sqlite3.c`) while the header paths are relative to
    # that directory, so comparing them directly never matched and the
    # implementation-directory bucket stayed empty for every component.
    fpath = (fns[0].get("file") or "").replace(BS, "/")
    if sn and fpath.startswith(sn + "/"):
        fpath = fpath[len(sn) + 1:]
    func_dir = fpath.rsplit("/", 1)[0] if "/" in fpath else None
    hit, searched, skipped = _declared_in_header(root, names, func_dir)
    if hit:
        return ("reachable", "public_api",
                "%s declared in %s" % hit,
                "the vulnerable function is declared in a shipped public header, so "
                "it is itself an entry point for a consumer of the component")
    return (None, None, None,
            "not_on_public_surface: whether a public function CALLS an interior "
            "function is a call-graph question, which is the SUT's own method, so "
            "there is no independent label (%d public headers searched, %d interior "
            "headers out of scope)" % (searched, skipped))


def controllability_label(cve, cvss):
    e = cvss.get(cve)
    if not e:
        return None, None, None, "no_cvss: no CVSS vector in the NVD cache"
    p = _cvss_parts(e.get("vector"))
    av, ui = p.get("AV"), p.get("UI")
    if av and not ui:
        # CVSS v2 has no User Interaction metric at all, so the authority simply
        # cannot say whether a second party must act. Held out as a v2 record
        # rather than reported as a malformed vector.
        return (None, None, None,
                "cvss_v2_no_ui: CVSS v2 has no User Interaction metric, so the "
                "vector cannot assert that the attacker alone supplies the trigger "
                "(%s)" % e.get("vector"))
    if not av or not ui:
        return None, None, None, ("cvss_unparsed: vector carries no AV (%s)"
                                  % e.get("vector"))
    if ui == "N" and av in ("N", "A", "L"):
        return ("controllable", "cvss_vector", e.get("vector"),
                "NVD asserts the attack needs no second party (UI:N) over a channel "
                "the attacker speaks (AV:%s), i.e. the attacker supplies the "
                "triggering input" % av)
    return (None, None, None,
            "cvss_needs_second_party: CVSS says a second party must act or the "
            "attacker must be physically "
            "present (AV:%s/UI:%s). That does not settle whether the triggering "
            "VALUE is attacker-chosen - a malicious file is attacker-written and the "
            "user only opens it" % (av, ui))


def build():
    loc = json.load(open(LOC, encoding="utf-8"))
    cvss = json.load(open(CVSS, encoding="utf-8"))
    rows = []
    stat = collections.Counter()
    held = collections.Counter()

    for i, cve in enumerate(sorted(loc), 1):
        rv, ret, rref, rdet = reachability_label(cve, loc.get(cve))
        if rv:
            rows.append({"test_case_id": "%s/q2" % cve, "cve_id": cve,
                         "question": "Q2", "expected_verdict": rv,
                         "evidence_type": ret, "evidence_reference": rref,
                         "review_status": "authority", "_detail": rdet})
            stat["Q2 %s (%s)" % (rv, ret)] += 1
        else:
            held["Q2 %s" % rdet.split(":", 1)[0]] += 1

        cv, cet, cref, cdet = controllability_label(cve, cvss)
        if cv:
            rows.append({"test_case_id": "%s/q3" % cve, "cve_id": cve,
                         "question": "Q3", "expected_verdict": cv,
                         "evidence_type": cet, "evidence_reference": cref,
                         "review_status": "authority", "_detail": cdet})
            stat["Q3 %s (%s)" % (cv, cet)] += 1
        else:
            held["Q3 %s" % cdet.split(":", 1)[0]] += 1
        if i % 25 == 0:
            print("  [%3d/%3d] labels so far: %d" % (i, len(loc), len(rows)), flush=True)

    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    manifest = {
        "population": len(loc),
        "labels": len(rows),
        "by_label": dict(stat),
        "held_out": dict(held),
        "authorities": {
            "Q2 public_api": "a shipped public header of the component declares the "
                             "vulnerable function, so it is externally callable "
                             "without any call-graph reasoning",
            "Q2 not_shipped": "the vulnerable function exists only under test/, "
                              "fuzz/, examples/ or docs/, which are not installed",
            "Q3 cvss_vector": "NVD CVSS v3 AV/UI: UI:N with AV in {N,A,L}",
        },
        "one_sided_by_construction": (
            "Neither authority can produce the opposite label. A public header says "
            "nothing about whether an INTERNAL function is unreachable, because the "
            "public functions call it; and CVSS UI:R does not mean the triggering "
            "value is not attacker-chosen. So Q2 has a negative class only from the "
            "build layout (not_shipped) and Q3 has none at all: a Q3 refutation is "
            "unmeasurable against any public authority, which is also why "
            "vex_judge_v2 must never let Q3 refute."),
    }
    json.dump(manifest, open(MANIFEST, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    print()
    print("population %d -> %d labels" % (len(loc), len(rows)))
    for k, v in sorted(stat.items()):
        print("  %-42s %d" % (k, v))
    print("  -- held out")
    for k, v in held.most_common():
        print("  %-78s %d" % (k, v))
    print("-> %s" % OUT)
    print("-> %s" % MANIFEST)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    build()
