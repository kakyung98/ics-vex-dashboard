#!/usr/bin/env python3
"""Derive not_affected INDEPENDENTLY at the model-variant level and compare against the
CISA labels.

What is input and what is the answer are kept strictly apart:

  INPUT (what we are allowed to look at)
    - product_tree                     the model list the advisory enumerates
    - product_status.known_affected    the models the advisory calls affected
    - the asset's own model identity (the SBOM)
    All three are what any asset owner reads straight off the advisory.

  ANSWER (never used as input)
    - product_status.known_not_affected
    - vulnerabilities[].flags[].label      <- CISA's justification

  Derivation rule (the inference an asset owner actually makes)
    my model is not in this CVE's known_affected list  ->  not_affected
    the grounds being that the model lacks the vulnerable part
                                                      ->  component_not_present

It is not circular, because known_not_affected is never read. But it also cannot tell
"a model that was not enumerated" from "a model explicitly declared unaffected", and
that limit is reported alongside the score.
"""
import argparse
import collections
import glob
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def variants_of(csaf):
    names = {}

    def walk(bs, pref):
        for b in bs or []:
            nm = pref + [b.get("name", "")]
            if "product" in b and b["product"].get("product_id"):
                names[b["product"]["product_id"]] = " ".join(n for n in nm if n).strip()
            walk(b.get("branches"), nm)

    walk((csaf.get("product_tree") or {}).get("branches"), [])
    for fp in (csaf.get("product_tree") or {}).get("full_product_names") or []:
        if fp.get("product_id"):
            names.setdefault(fp["product_id"], fp.get("name", ""))
    # Synthetic product_ids that appear only in relationships also belong to the model
    # population
    for rel in (csaf.get("product_tree") or {}).get("relationships") or []:
        fpn = rel.get("full_product_name") or {}
        if fpn.get("product_id"):
            names.setdefault(fpn["product_id"], fpn.get("name", ""))
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=os.path.join(BASE, "data", "gt_icsa"))
    a = ap.parse_args()

    man = json.load(open(os.path.join(a.gt, "manifest.json"), encoding="utf-8"))
    tp = fp = fn = 0
    just_ok = 0
    per = []
    unenumerated = 0

    for rec in man["tier1"]:
        aid = rec["advisory_id"]
        p = os.path.join(a.gt, "tier1_justification", "cisa_csaf", aid + ".json")
        csaf = json.load(open(p, encoding="utf-8"))
        models = variants_of(csaf)
        for v in csaf.get("vulnerabilities") or []:
            cve = v.get("cve")
            if cve not in rec["flags"]:
                continue
            ps = v.get("product_status") or {}
            affected = set(ps.get("known_affected") or [])
            truth_not = set(ps.get("known_not_affected") or [])     # the answer
            truth_lab = rec["flags"][cve][0]                        # the answer

            # --- derivation: a model absent from known_affected is not_affected ---
            derived_not = {m for m in models if m not in affected}
            derived_lab = "component_not_present"

            t = len(derived_not & truth_not)
            f = len(derived_not - truth_not)
            n = len(truth_not - derived_not)
            tp += t; fp += f; fn += n
            unenumerated += len(derived_not - truth_not - affected)
            ok = (derived_lab == truth_lab)
            just_ok += bool(ok and t)
            per.append((aid, cve, len(models), len(affected), len(truth_not),
                        len(derived_not), t, f, n, truth_lab, ok))

    print("Independent per-model not_affected derivation vs the CISA labels\n")
    print("%-18s %-16s %5s %5s %5s %5s %4s %4s %4s  %s"
          % ("ICSA", "CVE", "models", "aff", "truth", "derived", "TP", "FP", "FN",
             "label match"))
    for r in per:
        print("%-18s %-16s %5d %5d %5d %5d %4d %4d %4d  %s"
              % (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8],
                 "O" if r[10] else "X (%s)" % r[9]))

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec_ = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec_ / (prec + rec_) if (prec + rec_) else 0.0
    print("\nPer model (product_id)")
    print("  TP %d / FP %d / FN %d" % (tp, fp, fn))
    print("  precision %.3f | recall %.3f | F1 %.3f" % (prec, rec_, f1))
    print("\nPer (ICSA, CVE) pair")
    print("  pairs matching the justification too: %d/%d" % (just_ok, len(per)))
    print("\nLimit: %d of the %d false positives are models CISA never enumerated."
          % (fp, unenumerated))
    print("      known_not_affected was not used as input, so 'not affected' and")
    print("      'not mentioned' cannot be told apart - the ceiling of public data.")


if __name__ == "__main__":
    main()
