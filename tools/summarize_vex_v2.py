#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Roll the VEX-v2 pipeline outputs (gitignored, regenerable) up into a single
committed summary: results/vex_v2_summary.json.

Aggregates the final verdict distribution, the CISA justifications, the three
Stage-3 gates, and a per-CVE row with its evidence trail. Run after the pipeline
(cti_extract -> source_locate -> joern_reachability -> z3_controllability ->
vex_judge_v2) has been run over the corpus.
"""
import collections
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "results", "vex_v2_summary.json")


def _load(name):
    p = os.path.join(BASE, "data", name + ".json")
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}


def main():
    loc, reach, ctrl, v2 = (_load("source_locations"), _load("reachability"),
                            _load("controllability"), _load("vex_v2"))
    if not v2:
        print("no data/vex_v2.json - run the pipeline first")
        return
    rows = []
    for cve in sorted(v2):
        x = v2[cve]
        rows.append({"cve": cve, "final_vex": x["final_vex"],
                     "justification": x.get("justification"),
                     "basis": x.get("basis"),      # the per-CVE reason (evidence tier)
                     "evidence_tier": x.get("evidence_tier"),
                     "component": (loc.get(cve) or {}).get("component"),
                     "evidence": {"q1": (loc.get(cve) or {}).get("q1"),
                                  "reachability": (reach.get(cve) or {}).get("verdict"),
                                  "controllability": (ctrl.get(cve) or {}).get("verdict")}})
    summary = {
        "generated": "2026-09-27",
        "test": "VEX-v2 judgment over source-collectable CVEs",
        "method": "CTI(LLM agent) -> source locate (presence, decides) -> optional Joern "
                  "reachability + Z3 controllability (evidence tier only)",
        "population": len(v2),
        "final_vex": dict(collections.Counter(x["final_vex"] for x in v2.values())),
        "evidence_tier": dict(collections.Counter(
            x.get("evidence_tier") for x in v2.values())),
        "justifications": dict(collections.Counter(
            x["justification"] for x in v2.values() if x.get("justification"))),
        "gates": {
            "q1_present": dict(collections.Counter(x["q1"] for x in loc.values())),
            "q2_reachable_joern": dict(collections.Counter(x["verdict"] for x in reach.values())),
            "q3_controllable_z3": dict(collections.Counter(x["verdict"] for x in ctrl.values())),
        },
        "note": "VEX justifications are a hierarchy: presence (Q1) decides (present -> affected, "
                "absent -> not_affected). Reachability (Joern) and controllability (Z3) are "
                "OPTIONAL - they only raise the evidence_tier, they never refute (a library "
                "snapshot has no consumer, so not-reachable false-negatives on the API itself).",
        "cves": rows,
    }
    json.dump(summary, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("wrote %s: %d CVEs | %s" % (OUT, len(rows), summary["final_vex"]))


if __name__ == "__main__":
    main()
