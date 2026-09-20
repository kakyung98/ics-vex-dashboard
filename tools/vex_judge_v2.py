#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 5 — orchestrator: combine the engines into a final VEX.

Three gates, in order, each mapped to the CISA justification it settles. A gate is
only ever cleared by positive evidence; "unknown" stops at under_investigation and
never clears (the project's "not found != not there" rule).

  1 present?       source_locate (step 2)   absent  -> not_affected / vulnerable_code_not_present
  2 reachable?     joern (step 4)            no      -> not_affected / vulnerable_code_not_in_execute_path
  3 controllable?  z3 (step 3)               no      -> not_affected / vulnerable_code_cannot_be_controlled_by_adversary
  1&2&3 all yes                              -> affected
  any gate unknown before a hard no          -> under_investigation

Reads the step 1-4 caches (run those first, or `--run` to run them here). The vuln
function is located from the CTI extraction, falling back to the patch (step 2).

Out: data/vex_v2.json  { <CVE>: {...} }
"""
import argparse
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(BASE, "tools")
F = {k: os.path.join(BASE, "data", v) for k, v in {
    "cti": "cti_extractions.json", "loc": "source_locations.json",
    "reach": "reachability.json", "ctrl": "controllability.json"}.items()}
OUT = os.path.join(BASE, "data", "vex_v2.json")

AFFECTED, NOT_AFF, UNDER = "affected", "not_affected", "under_investigation"


def judge(cve, loc, reach, ctrl):
    ev = {"q1": (loc or {}).get("q1"),
          "reachability": (reach or {}).get("verdict"),
          "controllability": (ctrl or {}).get("verdict")}
    # gate 1 — presence
    if loc is None or ev["q1"] == "absent":
        return _v(cve, NOT_AFF, "vulnerable_code_not_present",
                  "the vulnerable function is not defined in the collected source", ev)
    if ev["q1"] == "component_only":
        return _v(cve, UNDER, None,
                  "component present but the vulnerable function could not be located", ev)
    # gate 2 — reachability (Joern)
    if ev["reachability"] == "not-reachable":
        return _v(cve, NOT_AFF, "vulnerable_code_not_in_execute_path",
                  "no located function is reachable from an entry point (joern)", ev)
    if ev["reachability"] != "reachable":
        return _v(cve, UNDER, None,
                  "reachability undecided (%s)" % (ev["reachability"] or "not run"), ev)
    # gate 3 — controllability (Z3)
    if ev["controllability"] == "not-controllable":
        return _v(cve, NOT_AFF, "vulnerable_code_cannot_be_controlled_by_adversary",
                  "the trigger needs an environment value the attacker cannot set (z3)", ev)
    if ev["controllability"] != "controllable":
        return _v(cve, UNDER, None,
                  "controllability undecided (%s)" % (ev["controllability"] or "not run"), ev)
    # all three cleared
    return _v(cve, AFFECTED, None,
              "vulnerable code present, reachable (joern) and adversary-controllable (z3)", ev)


def _v(cve, vex, just, basis, ev):
    return {"cve": cve, "final_vex": vex, "justification": just,
            "basis": basis, "evidence": ev}


def _run_chain(cves):
    """Run steps 1-4 for the given CVEs so the caches exist."""
    scripts = [("cti_extract.py", "1 CTI"), ("source_locate.py", "2 source"),
               ("z3_controllability.py", "3 z3"), ("joern_reachability.py", "4 joern")]
    for cve in cves:
        for sc, label in scripts:
            print("  run step %s for %s" % (label, cve))
            subprocess.run([sys.executable, os.path.join(TOOLS, sc), "--cve", cve],
                           cwd=BASE, check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--run", action="store_true", help="run steps 1-4 first")
    a = ap.parse_args()

    if a.run and a.cve:
        _run_chain([a.cve])
    data = {k: (json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {})
            for k, p in F.items()}
    cves = [a.cve] if a.cve else sorted(data["loc"]) if a.all else None
    if not cves:
        ap.error("pass --cve CVE-XXXX or --all")

    out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    tally = {}
    for cve in cves:
        r = judge(cve, data["loc"].get(cve), data["reach"].get(cve), data["ctrl"].get(cve))
        out[cve] = r
        tally[r["final_vex"]] = tally.get(r["final_vex"], 0) + 1
        print("  %-18s %-20s %s" % (cve, r["final_vex"], r["justification"] or r["basis"]))
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("tally:", tally, "->", OUT)


if __name__ == "__main__":
    main()
