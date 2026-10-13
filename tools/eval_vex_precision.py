#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test item #4 - precision of the VEX affected judgment.

    precision = TP / (TP + FP)              (acceptance: >= 0.85)

      positive class : affected
      TP: SUT = affected  AND  ground truth = affected
      FP: SUT = affected  AND  ground truth = not_affected

SUT is tools/vex_judge_v2 as cached in data/vex_v2.json. Ground truth is
data/vex_gt_104.jsonl (tools/build_vex_gt.py), labelled from execution pairs and
fix-commit patch signatures only.

A GT label is about a BUILD, not a CVE, and the SUT's caches are keyed by CVE alone,
so one verdict file answers for exactly one build. Both are now produced -
`vex_judge_v2 --build vulnerable` and `--build patched` - and this scorer takes one
file per build (`--sut`, `--sut-patched`) and picks by the case's `_build`. Scoring a
patched case against the vulnerable tree's verdict would be measuring nothing, so a
build with no verdict file supplied is held out and counted, never folded in.

What `--build all` costs in independence: a patched build can only be judged with the
patch gate LIVE (Q2 asks whether the vulnerable function is DEFINED, and a fix edits
that function rather than deleting it - Q2 reads `present` on 10 of the 12 collected
patched trees). So the patched half is unavailable pre-gate, and 7 of its 9 cases are
`patch_verified`, i.e. share the gate's oracle. `--independent` is therefore the only
non-circular way to quote the full population; the pre-gate vulnerable-build figure
remains the non-circular way to quote the largest one.

Usage:
  python tools/eval_vex_precision.py [--build vulnerable|patched|all]
  python tools/eval_vex_precision.py --build all --sut-patched data/vex_v2_patched.json
"""
import argparse
import collections
import json
import os
import sys

# This tool prints Korean headings and an em-dash; a Windows console defaults to
# cp949, which cannot encode either, and the traceback used to land AFTER the
# measurement was computed but BEFORE it was written out - losing the run.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(BASE, "data", "vex_gt_104.jsonl")
SUT = os.path.join(BASE, "data", "vex_v2.json")
OUT = os.path.join(BASE, "results", "vex_precision.json")
TARGET = 0.85


def score(gt_path=GT, sut_path=SUT, sut_patched=None, build="vulnerable",
          independent=False):
    """Measure test item #4 and return the result record.

    Split out of main() for the same reason as item #3's: the web app scores
    through this function, so the page cannot show a number the CLI would not.
    """
    gt = [json.loads(l) for l in open(gt_path, encoding="utf-8") if l.strip()]
    sut = json.load(open(sut_path, encoding="utf-8"))
    by_build = {"vulnerable": sut}
    if sut_patched:
        by_build["patched"] = json.load(open(sut_patched, encoding="utf-8"))

    SHARED_ORACLE = {"patch_verified"}
    gate_live = any("patch_gate" in (v or {}) or (v or {}).get("final_vex") == "fixed"
                    for m in by_build.values() for v in m.values())

    tp = fp = tn = fn = 0
    not_in_sut = 0
    other_build = 0
    shared_oracle_cases = 0
    no_sut_for_build = collections.Counter()
    fp_rows, fn_rows = [], []
    per_build = collections.defaultdict(collections.Counter)

    for r in gt:
        if build != "all" and r["_build"] != build:
            other_build += 1
            continue
        if independent and r["evidence_type"] in SHARED_ORACLE:
            shared_oracle_cases += 1
            continue
        if r["evidence_type"] in SHARED_ORACLE:
            shared_oracle_cases += 1
        bmap = by_build.get(r["_build"])
        if bmap is None:
            no_sut_for_build[r["_build"]] += 1
            continue
        verdict = (bmap.get(r["cve_id"]) or {}).get("final_vex")
        if verdict is None:
            not_in_sut += 1
            continue
        gold = r["expected_status"]
        # The positive class is `affected`, so every other status is one negative
        # class here, `fixed` included. CSAF distinguishes them - `fixed` means the
        # code was there and was remediated, `known_not_affected` that it never
        # applied - but neither is a claim of impact, and precision only asks which
        # cases the SUT asserted impact for.
        if verdict == "affected":
            if gold == "affected":
                tp += 1
                per_build[r["_build"]]["TP"] += 1
            else:
                fp += 1
                per_build[r["_build"]]["FP"] += 1
                fp_rows.append({"cve": r["cve_id"], "build": r["_build"],
                                "evidence_type": r["evidence_type"],
                                "gt_detail": r.get("_detail"),
                                "sut_basis": (bmap.get(r["cve_id"]) or {}).get("basis")})
        else:
            if gold == "affected":
                fn += 1
                per_build[r["_build"]]["FN"] += 1
                fn_rows.append({"cve": r["cve_id"], "build": r["_build"],
                                "sut": verdict})
            else:
                tn += 1
                per_build[r["_build"]]["TN"] += 1

    scored = tp + fp
    prec = tp / scored if scored else 0.0
    recall = tp / (tp + fn) if (tp + fn) else None

    return {
        "test": "VEX affected-judgment precision (test item #4)",
        "sut": "tools/vex_judge_v2 (cached: %s)" % ", ".join(
            "%s=%s" % (b, os.path.relpath(
                sut_path if b == "vulnerable" else sut_patched, BASE))
            for b in sorted(by_build)),
        "ground_truth": os.path.relpath(gt_path, BASE),
        "gt_evidence_types": ["execution_verified", "patch_verified"],
        "build_scored": build,
        "scope": "independent evidence only" if independent else "all evidence types",
        "patch_gate_live": gate_live,
        "shared_oracle_cases": shared_oracle_cases,
        "gt_cases_total": len(gt),
        "gt_cases_other_build": other_build,
        "gt_cases_not_in_sut": not_in_sut,
        "gt_cases_no_sut_for_build": dict(no_sut_for_build) or None,
        "per_build": {b: dict(c) for b, c in sorted(per_build.items())},
        "positive_class": "affected",
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "classified_affected": scored,
        "precision": round(prec, 4),
        "recall": round(recall, 4) if recall is not None else None,
        "acceptance_criterion": "precision >= %.2f" % TARGET,
        "pass": prec >= TARGET,
        "fp_cases": fp_rows,
        "fn_cases": fn_rows,
        "circularity_warning": (
            "patch gate is LIVE and %d of the scored cases are patch_verified, whose "
            "labels come from the same fix-signature + NVD authorities the gate reads. "
            "Agreement on them is structural. Quote --independent, or quote the "
            "pre-gate figure (vex_judge_v2 --no-patch-gate)." % shared_oracle_cases)
            if (gate_live and not independent and shared_oracle_cases) else None,
        "patched_build_note": (
            "patched-build cases are judged from data/fixed_releases/<CVE> by "
            "vex_judge_v2 --build patched. They require the patch gate: Q2 reads "
            "'present' on 10 of the 12 collected patched trees, because a fix edits "
            "the vulnerable function rather than deleting it. So there is no pre-gate "
            "patched figure to quote, and 7 of the 9 patched GT cases are "
            "patch_verified; --independent is what removes the shared oracle."),
        "unscored_note": (
            "GT cases with no verdict for their build: %s"
            % (dict(no_sut_for_build) or "none")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="vulnerable",
                    choices=["vulnerable", "patched", "all"])
    ap.add_argument("--gt", default=GT)
    ap.add_argument("--sut", default=SUT,
                    help="verdicts for the vulnerable build")
    ap.add_argument("--sut-patched",
                    help="verdicts for the patched build (data/vex_v2_patched.json). "
                         "Required to score --build patched/all; without it those "
                         "cases are held out as having no comparable verdict")
    ap.add_argument("--out", help="write elsewhere than results/vex_precision.json; "
                                  "pass it when scoring a non-default --gt/--sut")
    ap.add_argument("--independent", action="store_true",
                    help="score only GT cases whose evidence the patch gate does not "
                         "read (execution_verified), so the SUT and the GT do not "
                         "share an oracle")
    a = ap.parse_args()

    for p in (a.gt, a.sut):
        if not os.path.isfile(p):
            print("missing: %s" % p)
            return
    if a.sut_patched and not os.path.isfile(a.sut_patched):
        print("missing: %s" % a.sut_patched)
        return

    res = score(a.gt, a.sut, a.sut_patched, build=a.build,
                independent=a.independent)
    gt = [json.loads(l) for l in open(a.gt, encoding="utf-8") if l.strip()]
    tp, fp, tn, fn = res["TP"], res["FP"], res["TN"], res["FN"]
    prec, recall = res["precision"], res["recall"]
    other_build = res["gt_cases_other_build"]
    not_in_sut = res["gt_cases_not_in_sut"]
    no_sut_for_build = res["gt_cases_no_sut_for_build"] or {}
    per_build, fp_rows = res["per_build"], res["fp_cases"]

    print("=== test item #4 - VEX affected-judgment precision ===")
    print("  SUT            : %s" % res["sut"])
    print("  GT             : %s  (%d cases)" % (res["ground_truth"], len(gt)))
    print("  build scored   : %s" % a.build)
    print("  held out       : other build=%d, CVE not in SUT=%d, no SUT for build=%s"
          % (other_build, not_in_sut, dict(no_sut_for_build) or "-"))
    if len(per_build) > 1:
        for b, c in sorted(per_build.items()):
            print("    %-11s TP=%d FP=%d TN=%d FN=%d"
                  % (b, c.get("TP", 0), c.get("FP", 0),
                     c.get("TN", 0), c.get("FN", 0)))
    print("  TP=%d  FP=%d  TN=%d  FN=%d" % (tp, fp, tn, fn))
    print("  PRECISION      = %.4f   (acceptance >= %.2f)  ->  %s"
          % (prec, TARGET, "PASS" if res["pass"] else "FAIL"))
    if recall is not None:
        print("  (recall        = %.4f — not tested, shown for context)" % recall)
    if res["circularity_warning"]:
        print("\n  !! CIRCULAR: %s" % res["circularity_warning"])
    if fp_rows:
        print("\n  FP (SUT=affected, GT=not_affected):")
        for x in fp_rows:
            print("    %-16s %-16s %s" % (x["cve"], x["evidence_type"],
                                          (x["gt_detail"] or "")[:52]))
    out_path = a.out or OUT
    json.dump(res, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", out_path)


if __name__ == "__main__":
    main()
