#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pick the retrieval thresholds from the ground truth instead of guessing them.

src/cpe_match_ai accepts a retrieved product only when the top score clears
MIN_SIM *and* beats the runner-up by MIN_MARGIN — the same shape of rule the string
path uses, because a similarity is a ranking and the margin is what turns it into a
decision. The defaults were placeholders written before the encoder was trained, and
the trained encoder's score distribution is nothing like the untrained one's (mean
pairwise cosine went 0.9238 -> 0.0212), so they have to be re-derived.

Retrieval runs once per component and the thresholds are swept over the cached
results, which is the difference between one pass and one pass per grid point.

Scored exactly as tools/eval_cpe_match_precision does, so a number here means the
same thing it will mean there:
  TP  the retrieved product matches an authoritative product for the component
  FP  it does not, and the component's own name does not support it either
  held out  the name does support it (the two authorities disagree about filing)

Only components the string cascade abstains on are considered: the AI path never
sees the others, so including them would dilute the curve with cases it cannot
affect.

Out: results/cpe_ai_threshold_sweep.json
"""
import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
sys.path.insert(0, os.path.join(BASE, "tools"))

import cpe_match_ai as AI
from cpe_match_l0l3 import identify_product as string_identify
from eval_cpe_match_precision import load_gt, same_product, name_supports

OUT = os.path.join(BASE, "results", "cpe_ai_threshold_sweep.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(BASE, "data", "cpe_match_eval.jsonl"))
    ap.add_argument("--limit", type=int, default=0,
                    help="cap the abstained components considered (quick pass)")
    ap.add_argument("--topk", type=int, default=5)
    a = ap.parse_args()

    gt, cases, conflicts, unreachable = load_gt(a.data)
    todo = []
    for case in cases:
        comp = {"name": case["name"], "version": case["version"] or ""}
        if case.get("cpe"):
            comp["cpe"] = case["cpe"]
        product, _how = string_identify(comp)
        if product:
            continue                 # the string path handles it; AI never runs
        todo.append(case)
    if a.limit:
        todo = todo[:a.limit]
    print("string cascade abstains on %d of %d scorable components"
          % (len(todo), len(cases)))

    # retrieve once
    cached = []
    for i, case in enumerate(todo, 1):
        hits = AI.retrieve(case["name"], k=a.topk)
        if not hits:
            continue
        best, score = hits[0]
        runner = hits[1][1] if len(hits) > 1 else 0.0
        ok = any(same_product(best, p) for p in case["correct_products"])
        supported = name_supports(best, case["name"])
        cached.append({"score": score, "margin": score - runner,
                       "ok": ok, "supported": supported})
        if i % 500 == 0:
            print("  retrieved %d/%d" % (i, len(todo)), flush=True)

    rows = []
    for min_sim in [0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
        for min_margin in [0.00, 0.02, 0.05, 0.10, 0.20]:
            tp = fp = held = 0
            for c in cached:
                if c["score"] < min_sim or c["margin"] < min_margin:
                    continue          # abstain, exactly as the matcher would
                if c["ok"]:
                    tp += 1
                elif c["supported"]:
                    held += 1
                else:
                    fp += 1
            scored = tp + fp
            rows.append({"min_sim": min_sim, "min_margin": min_margin,
                         "tp": tp, "fp": fp, "scored": scored, "held_out": held,
                         "precision": round(tp / scored, 4) if scored else None,
                         "recovered": tp + fp + held})

    json.dump({"note": "swept over components the string cascade abstains on; "
                       "scored with the same rules as eval_cpe_match_precision",
               "abstained_considered": len(todo), "retrieved": len(cached),
               "grid": rows},
              open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    print()
    print("min_sim  margin     TP     FP   scored  precision   recovered")
    for r in rows:
        if r["scored"] == 0:
            continue
        print("  %.2f    %.2f   %5d  %5d   %6d     %.4f      %6d"
              % (r["min_sim"], r["min_margin"], r["tp"], r["fp"], r["scored"],
                 r["precision"], r["recovered"]))
    print()
    print("->", os.path.relpath(OUT, BASE))


if __name__ == "__main__":
    main()
