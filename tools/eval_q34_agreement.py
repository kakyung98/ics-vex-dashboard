#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Score Q3 (Joern) and Q4 (Z3) against the authority labels in data/vex_q34_gt.jsonl.

This exists because the two solvers contributed nothing measurable to any published
figure. vex_judge_v2 decides `affected` at Q2; Q3/Q4 only set the evidence tier, and
no answer key carried a tier - so item #4's 0.9718 is a measurement of Q1+Q2 alone,
however much Joern and Z3 ran. This is a SUPPLEMENTARY disclosure, not a
certification item: no acceptance criterion is claimed for it.

The two questions get different metrics, because their answer keys are shaped
differently and pretending otherwise would manufacture a number:

  Q3  precision AND recall. The key has both classes - a shipped public header
      declares the function (reachable), or the function only exists under test/ or
      fuzz/ (not-reachable, it is not in the installed artifact).

  Q4  recall ONLY, and precision is reported as null with the reason. CVSS can
      assert that the attacker supplies the triggering input, but nothing public
      asserts the opposite: `UI:R` means a second party must act, not that the
      value is not attacker-chosen. With no negative class a precision would come
      out 1.0000 by construction - it would measure the key's shape, not the
      solver. What IS measurable is the converse: of the CVEs NVD says are
      attacker-triggerable, how many does Z3 actually confirm?

Abstentions (`unknown`, `environment-dependent`) never score. They are reported,
because a solver that answers less looks better on precision alone.
"""
import argparse
import collections
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(BASE, "data", "vex_q34_gt.jsonl")
REACH = os.path.join(BASE, "data", "reachability.json")
CTRL = os.path.join(BASE, "data", "controllability.json")
OUT = os.path.join(BASE, "results", "q34_agreement.json")

# A verdict that asserts the positive answer. Everything else is either the
# negative assertion or an abstention - see _bucket.
POSITIVE = {"Q3": "reachable", "Q4": "controllable"}
NEGATIVE = {"Q3": "not-reachable", "Q4": "not-controllable"}


def _bucket(question, verdict):
    """'positive' / 'negative' / 'abstain' for a SUT verdict."""
    if verdict == POSITIVE[question]:
        return "positive"
    if verdict == NEGATIVE[question]:
        return "negative"
    return "abstain"


def load_gt(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                rows.append(json.loads(ln))
    return rows


def score(gt_path=GT, reach_path=REACH, ctrl_path=CTRL):
    gt = load_gt(gt_path)
    sut = {
        "Q3": json.load(open(reach_path, encoding="utf-8")),
        "Q4": json.load(open(ctrl_path, encoding="utf-8")),
    }

    per = {}
    for q in ("Q3", "Q4"):
        c = collections.Counter()
        misses, wrong, absent = [], [], []
        for r in [x for x in gt if x.get("question") == q]:
            cve = r["cve_id"]
            rec = sut[q].get(cve)
            if not rec:
                c["no_sut_verdict"] += 1
                absent.append({"cve": cve, "expected": r["expected_verdict"]})
                continue
            v = rec.get("verdict")
            b = _bucket(q, v)
            exp = r["expected_verdict"]
            if b == "abstain":
                c["abstained"] += 1
                misses.append({"cve": cve, "expected": exp, "sut": v,
                               "sut_detail": rec.get("detail"),
                               "authority": r.get("evidence_reference")})
            elif exp == POSITIVE[q]:
                c["TP" if b == "positive" else "FN"] += 1
                if b != "positive":
                    wrong.append({"cve": cve, "expected": exp, "sut": v,
                                  "sut_detail": rec.get("detail"),
                                  "authority": r.get("evidence_reference"),
                                  "why_label": r.get("_detail")})
            else:                                   # expected the negative class
                c["FP" if b == "positive" else "TN"] += 1
                if b == "positive":
                    wrong.append({"cve": cve, "expected": exp, "sut": v,
                                  "sut_detail": rec.get("detail"),
                                  "authority": r.get("evidence_reference"),
                                  "why_label": r.get("_detail")})

        tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
        answered = tp + fp + fn + tn
        labelled = answered + c["abstained"] + c["no_sut_verdict"]
        has_neg = (fp + tn) > 0
        per[q] = {
            "labels": labelled,
            "answered": answered,
            "abstained": c["abstained"],
            "no_sut_verdict": c["no_sut_verdict"],
            "abstention_pct": (round(100.0 * c["abstained"] / labelled, 1)
                               if labelled else None),
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": (round(tp / (tp + fp), 4) if has_neg and (tp + fp) else None),
            "precision_null_reason": None if has_neg else (
                "the answer key has no negative class for this question, so a "
                "precision would be 1.0000 by construction and would describe the "
                "key rather than the solver"),
            "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
            # The criterion is on CONTRADICTIONS, not on recall or precision.
            # Neither of those can carry one here: precision has no negative class
            # to fail against, and a recall threshold is passed outright by a
            # system that answers "yes" to everything without analysing anything.
            #
            # What this pipeline can actually be harmed by is one-directional. An
            # over-positive solver is safe - it clears nothing, it only leaves the
            # tier weaker. An over-REFUTING solver produces false clearances, which
            # is the failure that matters. So the bar is that the solver must never
            # assert the negative where an outside authority asserts the positive.
            # A trivial yes-to-everything solver passes this, and should: it is not
            # the dangerous one.
            "contradictions": fn,
            "contradiction_cases": [w["cve"] for w in wrong
                                    if w["expected"] == POSITIVE[q]],
            "acceptance_criterion": "contradictions == 0 (no refutation against an "
                                    "authority-confirmed positive)",
            "pass": fn == 0,
            "misses": misses[:40],
            "disagreements": wrong[:40],
            "no_verdict_cases": absent[:20],
        }

    return {
        "test": "Q3 reachability / Q4 controllability agreement with external authorities",
        "status": "supplementary disclosure - not a certification test item; the "
                  "criterion below is this repository's own, not the scheme's",
        # The axis passes only if BOTH questions do. Reporting a per-question pass
        # and then quoting the better one is how a two-part result turns into a
        # one-part claim.
        "pass": all(per[q]["pass"] for q in ("Q3", "Q4")),
        "acceptance_criterion": "contradictions == 0 for both questions",
        "ground_truth": os.path.relpath(gt_path, BASE),
        "sut": {"Q3": "tools/joern_reachability (Joern CPG call graph)",
                "Q4": "tools/z3_controllability (Z3 over an LLM constraint model)"},
        "authorities": {"Q3": "the component's shipped public headers; and the build "
                              "layout for the negative class",
                        "Q4": "NVD CVSS v3 AV/UI"},
        "per_question": per,
        "why_this_exists": (
            "item #4 scores the `affected` verdict, which vex_judge_v2 decides at Q2. "
            "Q3/Q4 only grade the evidence tier and no answer key carried a tier, so "
            "Joern and Z3 contributed 0 to every published figure. This is the axis "
            "on which they are measurable."),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=GT)
    ap.add_argument("--reach", default=REACH)
    ap.add_argument("--ctrl", default=CTRL)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    for p in (a.gt, a.reach, a.ctrl):
        if not os.path.isfile(p):
            print("없음: %s" % p)
            return
    r = score(a.gt, a.reach, a.ctrl)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(r, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    for q in ("Q3", "Q4"):
        d = r["per_question"][q]
        print("%s  labels %-4d answered %-4d abstained %-4d (%.1f%%)"
              % (q, d["labels"], d["answered"], d["abstained"],
                 d["abstention_pct"] or 0))
        print("    TP %-4d FP %-4d FN %-4d TN %-4d" % (d["TP"], d["FP"], d["FN"], d["TN"]))
        print("    precision %s   recall %s"
              % (d["precision"] if d["precision"] is not None else "n/a (no negative class)",
                 d["recall"]))
        print("    contradictions %-3d  -> %s  (%s)"
              % (d["contradictions"], "PASS" if d["pass"] else "FAIL",
                 d["acceptance_criterion"]))
        if d["disagreements"]:
            print("    -- disagreements")
            for w in d["disagreements"][:6]:
                print("       %-18s authority=%-10s sut=%s"
                      % (w["cve"], w["expected"], w["sut"]))
        print()
    print("-> %s" % a.out)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
