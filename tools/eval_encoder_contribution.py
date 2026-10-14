#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""What does the trained encoder actually contribute to test item #3?

Item #3's SUT is a string cascade with an embedding retrieval stage behind it, and the
published 0.9490 is the pair. That phrasing lets the figure be read as "the encoder
identifies ICS products at 0.9490", which is not what happens: run the cascade alone
and it scores 0.9499. The encoder moves the fourth decimal place.

This tool states the contribution as a subtraction rather than an adjective, and puts
the encoder's own training and retrieval metrics beside it, because those were
measured already (four result files) and never surfaced anywhere a reader would find
them. They are not flattering, and that is the point: they are what justifies running
the retrieval behind a recall-safe gate instead of in front of the cascade.

    python tools/eval_encoder_contribution.py
"""
import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(BASE, "results")
OUT = os.path.join(RESULTS, "encoder_contribution.json")

# The two item #3 runs that differ only in whether the retrieval stage is enabled.
CASCADE = "cpe_match_precision_model.json"   # string cascade alone (the ablation)
FULL = "cpe_match_precision_ai.json"         # cascade + retrieval (the default SUT)

# Already-measured encoder metrics, with what each one is actually evidence FOR. The
# second field matters: DAPT's perplexity drop is the only good number here, and it
# measures language-model adaptation, not retrieval - quoting it as evidence that the
# encoder identifies products would be the exact overstatement this tool exists to
# prevent.
COMPONENT_METRICS = [
    ("dapt_metrics.json", "SecureBERT domain-adaptive pretraining",
     ["perplexity_before", "perplexity_after", "perplexity_drop_pct"],
     "masked-LM adaptation to security text. NOT a retrieval metric - a model can "
     "adapt its language modelling and still rank products badly, which is what "
     "happened."),
    ("codebert_rank.json", "CodeBERT ranking recall",
     ["n", "top1_recall", "top5_recall", "top20_recall"],
     "how often the correct product is ranked first / in the top k. This is the "
     "retrieval metric, and it is poor."),
    ("codebert_finetune_metrics.json", "CodeBERT fine-tuning",
     ["n_pairs", "vuln_patch_match_frozen", "vuln_patch_match_finetuned"],
     "fine-tuning made the vuln/patch matching WORSE than the frozen encoder "
     "(0.500 -> 0.426) over 34 pairs - too small to conclude from, too clear to omit."),
]


def _load(name):
    p = os.path.join(RESULTS, name)
    return json.load(open(p, encoding="utf-8")) if os.path.isfile(p) else None


def score():
    full, casc = _load(FULL), _load(CASCADE)
    res = {
        "test": "Encoder contribution to test item #3 (supplementary disclosure)",
        "status": "not a certification test item - it decomposes one",
        "question": "how much of item #3's 0.9490 is the trained encoder?",
    }
    if not full or not casc:
        res["error"] = ("need both %s and %s in results/ - run "
                        "eval_cpe_match_precision.py for each SUT variant"
                        % (FULL, CASCADE))
        return res

    d_tp = full["TP"] - casc["TP"]
    d_fp = full["FP"] - casc["FP"]
    recovered = casc["sut_abstained"] - full["sut_abstained"]
    res["variants"] = {
        "cascade_only": {"sut": casc.get("sut"), "TP": casc["TP"], "FP": casc["FP"],
                         "abstained": casc["sut_abstained"],
                         "precision": casc["precision"]},
        "cascade_plus_retrieval": {"sut": full.get("sut"), "TP": full["TP"],
                                   "FP": full["FP"],
                                   "abstained": full["sut_abstained"],
                                   "precision": full["precision"]},
    }
    res["retrieval_marginal"] = {
        "TP_added": d_tp, "FP_added": d_fp,
        "components_recovered_from_abstention": recovered,
        "precision_on_what_it_recovered": (round(d_tp / (d_tp + d_fp), 4)
                                           if (d_tp + d_fp) else None),
        "share_of_cascade_abstentions_touched": (
            round(recovered / casc["sut_abstained"], 4)
            if casc.get("sut_abstained") else None),
        "headline_delta": round(full["precision"] - casc["precision"], 4),
    }
    res["reading"] = (
        "The encoder answers %d of the %d components the cascade abstains on (%.1f%%) "
        "and is right on %.1f%% of them. It moves the headline by %+.4f. So item #3's "
        "figure is the string cascade's; the encoder adds recall at the margin without "
        "costing precision."
        % (recovered, casc["sut_abstained"],
           100.0 * recovered / casc["sut_abstained"],
           100.0 * d_tp / (d_tp + d_fp) if (d_tp + d_fp) else 0.0,
           full["precision"] - casc["precision"]))

    # The sweep is why the gate is set where it is: ungated, the same retrieval scores
    # 0.26-0.52 over the components the cascade declines.
    sweep = _load("cpe_ai_threshold_sweep.json")
    if sweep and sweep.get("grid"):
        precs = [g["precision"] for g in sweep["grid"] if g.get("precision") is not None]
        best = max(sweep["grid"], key=lambda g: g.get("precision") or 0)
        res["ungated_sweep"] = {
            "considered": sweep.get("abstained_considered"),
            "precision_range": [min(precs), max(precs)],
            "best_cell": {k: best.get(k) for k in
                          ("min_sim", "min_margin", "precision", "recovered")},
            "note": ("the same retrieval across gate settings, over the components the "
                     "cascade abstains on. Trusted openly (min_sim 0.5, no margin) it "
                     "scores 0.2636 - three wrong answers for every right one. The "
                     "sweep's precision-optimal cell is min_sim 0.95 / margin 0.05 at "
                     "0.9463, recovering 392, and that recovery count is exactly what "
                     "the shipped SUT recovers: this sweep is HOW the recall-safe gate "
                     "was chosen, not an alternative to it. The gate's price is "
                     "visible here - it declines 94% of the components it could have "
                     "answered in order to hold precision."),
        }

    res["component_metrics"] = []
    for fname, label, keys, what in COMPONENT_METRICS:
        doc = _load(fname)
        if not doc:
            continue
        res["component_metrics"].append({
            "source": "results/" + fname, "measures": label,
            "values": {k: doc.get(k) for k in keys if k in doc},
            "evidence_for": what,
        })
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    res = score()

    def say(msg):
        e = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(str(msg).encode(e, "replace").decode(e, "replace"))

    say("=== encoder contribution to test item #3 ===")
    if res.get("error"):
        say("  " + res["error"])
        return 1
    v = res["variants"]
    say("  %-24s %-8s %-7s %-9s %s" % ("variant", "TP", "FP", "abstain", "precision"))
    for key, label in (("cascade_only", "cascade only"),
                       ("cascade_plus_retrieval", "cascade + retrieval")):
        d = v[key]
        say("  %-24s %-8s %-7s %-9s %s"
            % (label, d["TP"], d["FP"], d["abstained"], d["precision"]))
    m = res["retrieval_marginal"]
    say("  %-24s %-8s %-7s %-9s %s"
        % ("-> retrieval marginal", "+%d" % m["TP_added"], "+%d" % m["FP_added"],
           "-%d" % m["components_recovered_from_abstention"],
           m["precision_on_what_it_recovered"]))
    say("\n  " + res["reading"])
    if res.get("ungated_sweep"):
        s = res["ungated_sweep"]
        say("\n  gate sweep over the same %s components: precision %.4f - %.4f"
            % (s["considered"], s["precision_range"][0], s["precision_range"][1]))
        say("    best cell min_sim=%s margin=%s -> %.4f over %d recovered "
            "(== the shipped gate)"
            % (s["best_cell"]["min_sim"], s["best_cell"]["min_margin"],
               s["best_cell"]["precision"], s["best_cell"]["recovered"]))
    say("\n  encoder's own metrics, as already measured:")
    for c in res["component_metrics"]:
        say("    %-38s %s" % (c["measures"], c["values"]))
        say("      ^ %s" % c["evidence_for"])
    json.dump(res, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    say("\n-> %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
