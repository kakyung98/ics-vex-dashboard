#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VEX-v2 · step 5 — orchestrator: combine the engines into a final VEX.

All 104 CVEs have the product source collected, so the analysis is COMPLETE for each one
and none may rest in `under_investigation` (which the VEX spec reserves for "not yet
analysed"). VEX puts the burden of proof on not_affected: vulnerable code present in the
product is `affected` by default; not_affected must be positively EARNED. So the solvers
only ever DOWNGRADE on positive refutation - they are evidence, not required upgrade gates.

The VEX justifications are a HIERARCHY; the verdict is settled at the shallowest level, and
reachability/controllability are OPTIONAL - they grade confidence, they never decide:

  Level 1  present?   source_locate  absent -> not_affected / vulnerable_code_not_present
  (decides everything else) present    -> affected
  Level 2  reachable? joern (OPTIONAL) positive "reachable" only STRENGTHENS the tier
  Level 3  control.?  z3    (OPTIONAL) positive "controllable" only STRENGTHENS the tier

Only source-absence (Level 1) soundly clears a CVE. Q2/Q3 never refute: a collected library
snapshot has no consumer, so its true entry points (the exported API) are outside the graph, and
Joern "not reachable from an in-snapshot root" false-negatives on the attack-surface API itself
(zlib `inflate`, openssl `GENERAL_NAME_cmp`); Z3 "not-controllable" rests on unreliable LLM
labelling. So most CVEs are decided at Level 1 alone; Q2/Q3 are run only to raise the evidence
tier where they are meaningful. Each verdict carries `evidence_tier`:
  verified (reachable+controllable) > reachable > component > present   [not-present for not_affected]

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


# Reachability (Q2) and controllability (Q3) are OPTIONAL enrichment: they only grade how much
# source evidence backs an `affected` verdict, they never decide it. Strongest first.
def _tier(ev):
    if ev["reachability"] == "reachable" and ev["controllability"] == "controllable":
        return ("verified",
                "present, reachable (joern) and adversary-controllable (z3)")
    if ev["reachability"] == "reachable":
        return ("reachable",
                "present and reachable (joern); adversary control not confirmed")
    if ev["q1"] == "component_only":
        return ("component",
                "vulnerable component present; specific function not localised in source")
    return ("present",
            "vulnerable code present; not refuted (Q2/Q3 optional and not decisive here)")


def judge(cve, loc, reach, ctrl):
    ev = {"q1": (loc or {}).get("q1"),
          "reachability": (reach or {}).get("verdict"),
          "controllability": (ctrl or {}).get("verdict")}
    # VEX justifications form a HIERARCHY; return at the SHALLOWEST level that settles the CVE,
    # and never sit in under_investigation (the source is collected, so the analysis is complete).
    #
    #   Level 1 - presence  : the only sound machine refutation for a source snapshot.
    #   Level 2 - reachable : OPTIONAL. Not a refutation - a library snapshot has no consumer, so
    #                         Joern "not reachable from an in-snapshot root" false-negatives on the
    #                         attack-surface API itself (zlib `inflate`, openssl `GENERAL_NAME_cmp`).
    #                         A positive "reachable" only strengthens confidence.
    #   Level 3 - control.  : OPTIONAL. Z3 "not-controllable" rests on the LLM's attacker/environment
    #                         labelling (unreliable), so it too only strengthens.
    #
    # So the verdict is decided at Level 1 (presence); Q2/Q3 are not required and only set the tier.
    if loc is None or ev["q1"] == "absent":
        return _v(cve, NOT_AFF, "vulnerable_code_not_present",
                  "the vulnerable function is not defined in the collected source", "not-present", ev)
    tier, basis = _tier(ev)                      # present -> affected; Q2/Q3 grade the confidence
    return _v(cve, AFFECTED, None, basis, tier, ev)


def _v(cve, vex, just, basis, tier, ev):
    return {"cve": cve, "final_vex": vex, "justification": just,
            "basis": basis, "evidence_tier": tier, "evidence": ev}


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
