#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""시험항목 #4 — VEX 기반 식별된 취약점 영향 판단 정밀도.

    precision = TP / (TP + FP)              (acceptance: >= 0.85)

      positive class : affected
      TP: SUT = affected  AND  ground truth = affected
      FP: SUT = affected  AND  ground truth = not_affected

SUT is tools/vex_judge_v2 as cached in data/vex_v2.json. Ground truth is
data/vex_gt_104.jsonl (tools/build_vex_gt.py), labelled from execution pairs and
fix-commit patch signatures only.

A GT label is about a BUILD, not a CVE, and that bounds what can be scored here.
vex_judge_v2 analysed the collected (vulnerable) snapshot, so only the
`_build == "vulnerable"` cases are comparable to its cached verdicts. The patched-
build cases describe source the SUT never ran against; scoring them against a
verdict produced from a different tree would be measuring nothing. They are counted
and reported as pending a SUT re-run, not quietly folded into the result.

Usage:
  python tools/eval_vex_precision.py [--build vulnerable|patched|all]
"""
import argparse
import collections
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(BASE, "data", "vex_gt_104.jsonl")
SUT = os.path.join(BASE, "data", "vex_v2.json")
OUT = os.path.join(BASE, "results", "vex_precision.json")
TARGET = 0.85


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", default="vulnerable",
                    choices=["vulnerable", "patched", "all"])
    ap.add_argument("--gt", default=GT)
    ap.add_argument("--sut", default=SUT)
    ap.add_argument("--out", help="write elsewhere than results/vex_precision.json; "
                                  "pass it when scoring a non-default --gt/--sut")
    ap.add_argument("--independent", action="store_true",
                    help="score only GT cases whose evidence the patch gate does not "
                         "read (execution_verified), so the SUT and the GT do not "
                         "share an oracle")
    a = ap.parse_args()

    for p in (a.gt, a.sut):
        if not os.path.isfile(p):
            print("없음: %s" % p)
            return

    gt = [json.loads(l) for l in open(a.gt, encoding="utf-8") if l.strip()]
    sut = json.load(open(a.sut, encoding="utf-8"))

    # the patch gate (src/patch_gate) decides from the fix signature plus the NVD
    # range — the same two authorities the GT's patch_verified labels come from. Once
    # the gate is live those cases are no longer an independent test: agreement is
    # structural, not earned. SHARED_ORACLE names them so the result can say so.
    SHARED_ORACLE = {"patch_verified"}
    gate_live = any("patch_gate" in (v or {}) or
                    (v or {}).get("final_vex") == "fixed" for v in sut.values())

    tp = fp = tn = fn = 0
    not_in_sut = 0
    other_build = 0
    shared_oracle_cases = 0
    fp_rows, fn_rows = [], []

    for r in gt:
        if a.build != "all" and r["_build"] != a.build:
            other_build += 1
            continue
        if a.independent and r["evidence_type"] in SHARED_ORACLE:
            shared_oracle_cases += 1
            continue
        if r["evidence_type"] in SHARED_ORACLE:
            shared_oracle_cases += 1
        verdict = (sut.get(r["cve_id"]) or {}).get("final_vex")
        if verdict is None:
            not_in_sut += 1
            continue
        gold = r["expected_status"]
        if verdict == "affected":
            if gold == "affected":
                tp += 1
            else:
                fp += 1
                fp_rows.append({"cve": r["cve_id"], "build": r["_build"],
                                "evidence_type": r["evidence_type"],
                                "gt_detail": r.get("_detail"),
                                "sut_basis": (sut.get(r["cve_id"]) or {}).get("basis")})
        else:
            if gold == "affected":
                fn += 1
                fn_rows.append({"cve": r["cve_id"], "sut": verdict})
            else:
                tn += 1

    scored = tp + fp
    prec = tp / scored if scored else 0.0
    # recall is not the tested metric, but it says what the precision cost
    recall = tp / (tp + fn) if (tp + fn) else None

    res = {
        "test": "VEX affected-judgment precision (시험항목 #4)",
        "sut": "tools/vex_judge_v2 (cached: %s)" % os.path.relpath(a.sut, BASE),
        "ground_truth": os.path.relpath(a.gt, BASE),
        "gt_evidence_types": ["execution_verified", "patch_verified"],
        "build_scored": a.build,
        "scope": "independent evidence only" if a.independent else "all evidence types",
        "patch_gate_live": gate_live,
        "shared_oracle_cases": shared_oracle_cases,
        "gt_cases_total": len(gt),
        "gt_cases_other_build": other_build,
        "gt_cases_not_in_sut": not_in_sut,
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
            if (gate_live and not a.independent and shared_oracle_cases) else None,
        "unscored_note": "patched-build GT cases need vex_judge_v2 re-run against "
                         "data/fixed_releases/<CVE>; its caches are keyed by CVE, not "
                         "by snapshot path, so the cached verdicts cannot stand in",
    }

    print("=== 시험항목 #4 · VEX 영향 판단 정밀도 ===")
    print("  SUT            : %s" % res["sut"])
    print("  GT             : %s  (%d cases)" % (res["ground_truth"], len(gt)))
    print("  build scored   : %s" % a.build)
    print("  held out       : other build=%d, CVE not in SUT=%d"
          % (other_build, not_in_sut))
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
