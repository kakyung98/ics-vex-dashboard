#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static -> CVE-Genie bridge: pick which CVEs go to execution reproduction.

The static sweep (src/vex_batch.py) triages all 13,005 findings. Only a small
subset can ever be *execution-verified* by CVE-Genie: those whose OSS source is
obtainable. This bridge reads the static batch + code evidence and emits a
prioritized reproduction worklist for CVE-Genie, so the expensive execution
runs are spent only where they can grow the execution-verified ground truth.

Selection (source_class from vex_batch):
  ready       code-available  -> vuln/patched pair already collected (repo+commit)
  needs-code  oss-attributed  -> OSS (tier A/C) but code not yet collected
  (vendor-proprietary is never eligible and is dropped)

Ranking: ready-before-needs-code, then KEV, reachability (yes>conditional),
severity, EPSS. One row per CVE (findings deduped, worst-case aggregated).

Outputs:
  results/genie_candidates.json   ordered worklist (CVE id, repo, commit, why)

Run:
  python src/vex_batch.py                 # produce results/vex_batch.jsonl first
  python tools/export_genie_candidates.py
  python tools/export_genie_candidates.py --ready-only --top 25
"""
import os, sys, json, argparse
from collections import defaultdict

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
BATCH = os.path.join(BASE, "results", "vex_batch.jsonl")
CODE_EV = os.path.join(BASE, "data", "code_evidence.json")
OUT = os.path.join(BASE, "results", "genie_candidates.json")

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
REACH_RANK = {"yes": 3, "conditional": 2, "unknown": 1, "no": 0}
VEX_RANK = {"LIKELY_AFFECTED": 3, "UNDER_INVESTIGATION": 2, "LIKELY_NOT_AFFECTED": 1}


def load_code_pairs():
    if not os.path.exists(CODE_EV):
        return {}
    d = json.load(open(CODE_EV, encoding="utf-8"))
    return {k: v for k, v in d.items()
            if isinstance(v, dict) and v.get("vuln_code") and v.get("patched_code")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ready-only", action="store_true",
                    help="only CVEs whose code pair is already collected")
    ap.add_argument("--top", type=int, default=None, help="keep only the top N")
    a = ap.parse_args()

    if not os.path.exists(BATCH):
        sys.exit("run src/vex_batch.py first (missing results/vex_batch.jsonl)")
    pairs = load_code_pairs()

    # aggregate findings -> per-CVE worst case
    agg = {}
    for line in open(BATCH, encoding="utf-8"):
        r = json.loads(line)
        cls = r.get("source_class")
        if cls == "vendor-proprietary":
            continue  # never reproducible
        cve = r["cve"]
        cur = agg.get(cve)
        if cur is None:
            cur = agg[cve] = {
                "cve": cve, "component": r.get("product") or r.get("component"),
                "source_class": cls, "kev": bool(r.get("kev")),
                "sev": r.get("sev", ""), "av": r.get("av", ""),
                "epss": r.get("epss"), "reachability": r.get("reachability", "unknown"),
                "static_vex": r.get("final_vex"), "n_findings": 0,
                "devices": set(),
            }
        cur["n_findings"] += 1
        cur["kev"] = cur["kev"] or bool(r.get("kev"))
        if SEV_RANK.get(r.get("sev", ""), 0) > SEV_RANK.get(cur["sev"], 0):
            cur["sev"] = r.get("sev", "")
        if REACH_RANK.get(r.get("reachability"), 0) > REACH_RANK.get(cur["reachability"], 0):
            cur["reachability"] = r.get("reachability")
        if VEX_RANK.get(r.get("final_vex"), 0) > VEX_RANK.get(cur["static_vex"], 0):
            cur["static_vex"] = r.get("final_vex")
        if r.get("device"):
            cur["devices"].add(r["device"])
        if (r.get("epss") or 0) > (cur["epss"] or 0):
            cur["epss"] = r.get("epss")

    cands = []
    for cve, c in agg.items():
        ev = pairs.get(cve) or {}
        ready = bool(ev.get("repo") and ev.get("commit"))
        if a.ready_only and not ready:
            continue
        repo = ev.get("repo")
        c_out = {
            "cve": cve,
            "status": "ready" if ready else "needs-code",
            "source_class": c["source_class"],
            "component": c["component"],
            "repo_url": (f"https://github.com/{repo}" if repo and "/" in repo
                         else ev.get("repo")),
            "commit": ev.get("commit"),
            "file": ev.get("file"),
            "kev": c["kev"], "severity": c["sev"], "av": c["av"],
            "epss": c["epss"], "reachability": c["reachability"],
            "static_vex": c["static_vex"],
            "asset_count": len(c["devices"]), "finding_count": c["n_findings"],
            "why": _why(c, ready),
        }
        c_out["_score"] = (
            (1 if ready else 0) * 1000
            + (1 if c["kev"] else 0) * 100
            + REACH_RANK.get(c["reachability"], 0) * 20
            + SEV_RANK.get(c["sev"], 0) * 4
            + (c["epss"] or 0)
        )
        cands.append(c_out)

    cands.sort(key=lambda x: -x["_score"])
    if a.top:
        cands = cands[: a.top]
    for c in cands:
        c.pop("_score", None)

    ready_n = sum(1 for c in cands if c["status"] == "ready")
    out = {
        "generated_from": "results/vex_batch.jsonl",
        "note": ("Static triage selects execution-reproduction targets. 'ready' has "
                 "a collected vuln/patched pair (repo+commit) and can go straight to "
                 "CVE-Genie; 'needs-code' is OSS-attributed but needs code collection "
                 "first. vendor-proprietary findings are excluded (not reproducible)."),
        "total_candidates": len(cands),
        "ready": ready_n,
        "needs_code": len(cands) - ready_n,
        "candidates": cands,
    }
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("== CVE-Genie reproduction candidates ==")
    print("ready (code collected) :", ready_n)
    print("needs-code (OSS)       :", len(cands) - ready_n)
    print("wrote:", os.path.relpath(OUT, BASE))
    print("\ntop ready targets:")
    for c in [x for x in cands if x["status"] == "ready"][:12]:
        print("  %-18s %-10s KEV=%-5s reach=%-11s %s" % (
            c["cve"], c["severity"], c["kev"], c["reachability"], c["repo_url"] or ""))


def _why(c, ready):
    bits = []
    if ready:
        bits.append("code pair collected")
    if c["kev"]:
        bits.append("KEV (exploited in the wild)")
    bits.append("reachability=%s" % c["reachability"])
    if c["sev"]:
        bits.append("%s severity" % c["sev"])
    return "; ".join(bits)


if __name__ == "__main__":
    main()
