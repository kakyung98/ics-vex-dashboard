#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 2 — source search: is the vulnerable component + function present?

Given the CTI extraction (step 1), decide whether the vulnerable code is actually
in the collected source snapshot. This is Q2 - the presence gate.

Function names come from the CTI extraction when it named any; NVD descriptions
often name none, so it falls back to the patch-localised targets
(data/vuln_targets.json, from the fix commit). Presence is checked against the
per-snapshot function index (data/func_index/<CVE>.json: functions -> [file,lines]).

  no function found  -> Q2 fails: not_affected / vulnerable_code_not_present
  function(s) found  -> the targets the reachability + controllability engines judge

Out: data/source_locations.json  { <CVE>: {...} }

Usage:  python tools/source_locate.py --cve CVE-2018-25032
        python tools/source_locate.py --all
"""
import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_func_index import roots as _build_roots  # noqa: E402  (one path table)

TARG = os.path.join(BASE, "data", "vuln_targets.json")
CTI = os.path.join(BASE, "data", "cti_extractions.json")
OUT = os.path.join(BASE, "data", "source_locations.json")
# Q2 is asked of a BUILD, not of a CVE. The vulnerable tree and the vendor's
# remediated release are two different answers to "is the vulnerable code here",
# so each build gets its own snapshot root, function index and cache file; the
# caller picks with `--build`.
SNAP, FUNC = _build_roots("vulnerable")


def _snapshot_dir(cve):
    """The component-version directory inside the snapshot, or None."""
    d = os.path.join(SNAP, cve)
    if not os.path.isdir(d):
        return None
    subs = [s for s in sorted(os.listdir(d)) if os.path.isdir(os.path.join(d, s))]
    return subs[0] if subs else None


def _func_index(cve):
    p = os.path.join(FUNC, cve + ".json")
    if not os.path.exists(p):
        return {}
    try:
        return json.load(open(p, encoding="utf-8")).get("functions", {})
    except Exception:
        return {}


BUILD = "vulnerable"


def locate(cve, extraction, targets):
    comp = (extraction or {}).get("vulnerable_component") or ""
    snap = _snapshot_dir(cve)
    # function candidates: CTI first, patch-localised fallback
    funcs = list((extraction or {}).get("vulnerable_functions") or [])
    src = "cti"
    if not funcs:
        funcs = list((targets.get(cve) or {}).get("targets") or [])
        src = "patch" if funcs else "none"
    fidx = _func_index(cve)
    found = []
    for fn in funcs:
        locs = fidx.get(fn) or fidx.get(fn.lstrip("_")) or []
        found.append({"name": fn, "found": bool(locs),
                      "file": locs[0][0] if locs else None,
                      "lines": locs[0][1:] if locs else None})
    any_found = any(f["found"] for f in found)
    # Q2 verdict
    if any_found:
        q2 = "present"                       # -> reachability/controllability judge it
    elif snap is not None:
        q2 = "component_only"                # component in tree, no named vuln func found
    else:
        q2 = "absent"                        # -> not_affected / vulnerable_code_not_present
    return {"cve": cve, "component": comp, "component_present": snap is not None,
            "snapshot": snap, "build": BUILD, "localization_source": src,
            "functions": found, "any_function_found": any_found, "q2": q2}


def main():
    global SNAP, FUNC, OUT, BUILD
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--build", choices=["vulnerable", "patched"], default="vulnerable",
                    help="'patched' asks Q2 of data/fixed_releases/<CVE> instead, and "
                         "caches to data/source_locations_patched.json. Kept apart "
                         "because a patched build still DEFINES the vulnerable "
                         "function, so one shared cache would answer for the wrong tree")
    a = ap.parse_args()

    BUILD = a.build
    SNAP, FUNC = _build_roots(a.build)
    if a.build != "vulnerable":
        OUT = os.path.join(BASE, "data", "source_locations_%s.json" % a.build)
    if not os.path.isdir(SNAP):
        ap.error("no snapshot root for build %r: %s" % (a.build, SNAP))

    cti = json.load(open(CTI, encoding="utf-8")) if os.path.exists(CTI) else {}
    targets = json.load(open(TARG, encoding="utf-8")) if os.path.exists(TARG) else {}
    if a.cve:
        cves = [a.cve]
    elif a.all:
        cves = sorted(c for c in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, c)))
    else:
        ap.error("pass --cve CVE-XXXX or --all")

    out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    for cve in cves:
        r = locate(cve, cti.get(cve), targets)
        out[cve] = r
        nf = sum(1 for f in r["functions"] if f["found"])
        if a.cve:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        else:
            print("  %-18s comp=%-14s q2=%-13s funcs %d/%d (%s)"
                  % (cve, r["component"][:14], r["q2"], nf, len(r["functions"]),
                     r["localization_source"]))
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("-> %s (%d)" % (OUT, len(out)))


if __name__ == "__main__":
    main()
