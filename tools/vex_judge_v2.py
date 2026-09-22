#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 5 — orchestrator: combine the engines into a final VEX.

All 104 CVEs have the product source collected, so the analysis is COMPLETE for each one
and none may rest in `under_investigation` (which the VEX spec reserves for "not yet
analysed"). VEX puts the burden of proof on not_affected: vulnerable code present in the
product is `affected` by default; not_affected must be positively EARNED. So the solvers
only ever DOWNGRADE on positive refutation - they are evidence, not required upgrade gates.

  present?      source_locate   absent          -> not_affected / vulnerable_code_not_present
  reachable?    joern           REFUTES (no path)-> not_affected / vulnerable_code_not_in_execute_path
  controllable? z3              strengthens only  (never refutes - unreliable labelling)
  otherwise (present, not refuted)               -> affected

Only two refutations clear a CVE, both grounded in artifacts: source-absence and a real CPG
showing no path to the function. Joern being unavailable, or Z3's "not-controllable", never
un-affects anything (the affected basis just records weaker/stronger evidence in `ev`).

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
    # These 104 all have the product source collected, so the analysis is COMPLETE for every
    # one - none may rest in under_investigation (a VEX status the spec reserves for "not yet
    # analysed"). VEX puts the burden of proof on not_affected: vulnerable code present in the
    # product is `affected` by default, and not_affected must be positively EARNED. So the
    # solvers only ever DOWNGRADE on positive refutation; when they cannot refute, the verdict
    # stays affected, and `ev` records how strong the evidence is.

    # gate 1 — presence: the one place we can prove not_present (function absent from source).
    if loc is None or ev["q1"] == "absent":
        return _v(cve, NOT_AFF, "vulnerable_code_not_present",
                  "the vulnerable function is not defined in the collected source", ev)
    # gate 2 — reachability (Joern) can REFUTE: a real CPG showing the located function on no
    # path from any entry point. (Joern being unavailable/no-entry does NOT un-affect anything.)
    if ev["reachability"] == "not-reachable":
        return _v(cve, NOT_AFF, "vulnerable_code_not_in_execute_path",
                  "no located function is reachable from an entry point (joern)", ev)
    # gate 3 — controllability (Z3) does NOT refute: its "not-controllable" rests on the LLM's
    # attacker-vs-environment labelling, which is unreliable and solver-indistinguishable from a
    # genuine environment gate, so it can only STRENGTHEN an affected verdict, never clear it.

    # affected — the vulnerable code is present and not refuted. The basis states the tier:
    if ev["reachability"] == "reachable" and ev["controllability"] == "controllable":
        basis = "present, reachable (joern) and adversary-controllable (z3)"    # strongest
    elif ev["reachability"] == "reachable":
        basis = "present and reachable (joern); adversary control not confirmed"
    elif ev["q1"] == "component_only":
        basis = "vulnerable component present; specific function not localised in source"
    else:
        basis = "vulnerable code present; not refuted (reachability not analysable - no CPG/entry)"
    return _v(cve, AFFECTED, None, basis, ev)


def _v(cve, vex, just, basis, ev):
    return {"cve": cve, "final_vex": vex, "justification": just,
            "basis": basis, "evidence": ev}


def _run_chain(cves):
    """Run the steps for the given CVEs so the caches exist. VEX flow order:
    reachability (Joern) is the earlier gate, so it runs before controllability (Z3)."""
    scripts = [("cti_extract.py", "1 CTI"), ("source_locate.py", "2 source"),
               ("joern_reachability.py", "3 joern"), ("z3_controllability.py", "4 z3")]
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
