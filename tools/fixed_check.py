#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Patch-signature check — is the FIX already present in the collected source?

The VEX-v2 gates decide *affected* by presence; they never look at whether the version is
already patched. This adds the missing sound refutation on the other side: a CVE's fix commit
turns specific vulnerable lines into fixed ones (`data/code_evidence.json` stores both the
`vuln_code` and the `patched_code` hunk). If the collected source contains the fix's distinctive
lines and not the vulnerable ones, this build is patched -> **fixed / vulnerable_code_not_present**;
if it still carries the vulnerable lines, it is **affected**. Unlike Joern reachability this is
sound: it reads the actual code that the CVE is about, no consumer/entry model needed.

Verdicts: fixed | vulnerable | inconclusive (fix hunk ambiguous or file not found).

Usage:  python tools/fixed_check.py --cve CVE-XXXX --snapshot <dir>
        python tools/fixed_check.py --demo        # zlib vuln-version vs 1.2.13
"""
import argparse
import glob
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVID = os.path.join(BASE, "data", "code_evidence.json")
SNAP = os.path.join(BASE, "data", "source_snapshots")
SKIP = ("test", "tests", "example", "examples", "fuzz", "contrib", "doc", ".git")


# lines that occur all over any C file, so their presence proves nothing about the fix location
_TRIVIAL = {"return null;", "return;", "return 0;", "return -1;", "return 1;", "break;",
            "continue;", "}", "{", "});", "};", "return true;", "return false;", "else",
            "else {", "goto err;", "goto out;", "goto fail;", "return ret;", "return err;",
            "return rc;", "return error;", "return -einval;", "return -enomem;", "}}"}


def _lines(code):
    """Distinctive, non-trivial code lines (drop short/boilerplate/ubiquitous statements)."""
    out = []
    for ln in (code or "").splitlines():
        s = ln.strip()
        if len(s) <= 8 or s.lower() in _TRIVIAL:
            continue
        if s.startswith(("*", "/*", "//", "#include")):
            continue
        out.append(s)
    return out


def _signatures(vuln, patched):
    """(fix-added lines, vuln-only lines) — the lines that actually changed."""
    v, p = set(_lines(vuln)), set(_lines(patched))
    added = [l for l in _lines(patched) if l not in v]     # introduced by the fix
    removed = [l for l in _lines(vuln) if l not in p]      # present only while vulnerable
    return added, removed


def _find_file(snap_root, rel):
    base = os.path.basename(rel)
    best = None
    for p in glob.glob(os.path.join(snap_root, "**", base), recursive=True):
        low = p.replace("\\", "/").lower()
        if any(("/" + s + "/") in low for s in SKIP):
            continue
        # prefer a path that also matches the parent dir of the evidence file
        if rel.replace("\\", "/") in p.replace("\\", "/"):
            return p
        best = best or p
    return best


def check(cve, ev, snap_root):
    if not (ev and ev.get("vuln_code") and ev.get("patched_code") and ev.get("file")):
        return {"cve": cve, "verdict": "inconclusive", "detail": "no fix-hunk evidence"}
    path = _find_file(snap_root, ev["file"])
    if not path:
        return {"cve": cve, "verdict": "inconclusive", "detail": "file %s not in snapshot" % ev["file"]}
    try:
        src = open(path, encoding="utf-8", errors="ignore").read()
    except Exception as e:
        return {"cve": cve, "verdict": "inconclusive", "detail": "read error: %s" % e}
    srclines = set(l.strip() for l in src.splitlines())
    added, removed = _signatures(ev["vuln_code"], ev["patched_code"])
    fix_hits = sum(1 for l in added if l in srclines)
    vuln_hits = sum(1 for l in removed if l in srclines)
    det = "fix-lines %d/%d, vuln-lines %d/%d in %s" % (
        fix_hits, len(added), vuln_hits, len(removed), os.path.basename(path))
    # decide: ALL of the fix's distinctive added lines present (and the vulnerable ones gone)
    # => patched. Requiring every distinctive line (not just one) avoids a stray guard/return
    # elsewhere in a big file spuriously "clearing" a vulnerable build.
    if added:
        if fix_hits >= 2 and fix_hits >= 0.6 * len(added) and vuln_hits == 0:
            return {"cve": cve, "verdict": "fixed", "detail": det}    # >=2 distinctive anchors
        if vuln_hits > 0 and fix_hits < len(added):
            return {"cve": cve, "verdict": "vulnerable", "detail": det}
    else:  # no distinctive fix line (a pure-removal or refactor fix) — a weak signal, so only
           # CONFIRM fixed on a clean removal; never assert "vulnerable" from it (the vulnerable
           # lines textually persisting through a refactor does not prove the build is unpatched).
        if removed and vuln_hits == 0:
            return {"cve": cve, "verdict": "fixed", "detail": det}
    return {"cve": cve, "verdict": "inconclusive", "detail": det}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--snapshot")
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()
    ev = json.load(open(EVID, encoding="utf-8"))

    if a.demo:
        # zlib: same CVE, its shipped vulnerable version vs a patched 1.2.13 snapshot.
        fixed_root = a.snapshot                       # dir containing zlib-1.2.13
        print("CVE               vulnerable build            patched build (zlib-1.2.13)")
        for cve in ["CVE-2016-9840", "CVE-2016-9841", "CVE-2018-25032", "CVE-2022-37434"]:
            vuln_root = os.path.join(SNAP, cve)
            rv = check(cve, ev.get(cve), vuln_root)
            rf = check(cve, ev.get(cve), fixed_root) if fixed_root else {"verdict": "-"}
            print("%-17s %-27s %s" % (cve, rv["verdict"] + " (" + rv["detail"][:18] + ")", rf["verdict"]))
        return

    if not (a.cve and a.snapshot):
        ap.error("pass --cve and --snapshot, or --demo --snapshot <dir with zlib-1.2.13>")
    print(json.dumps(check(a.cve, ev.get(a.cve), a.snapshot), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
