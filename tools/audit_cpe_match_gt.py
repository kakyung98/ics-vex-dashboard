#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit of the item-#3 ground truth, per the review memo (problems 1-16).

It changes NOTHING. It re-derives the anchored-CPE sets the way
tools/build_cpe_match_gt.anchored_cpes does, and measures - on the real data -
how often the GT's product identity rests on more than vendor agreement, plus the
Layer-A/B and provenance facts the memo asks to quantify.

Output: results/audit_cpe_match_gt.json (+ a printed summary).

The guiding distinction the memo insists on: separate a confirmed code/data defect
from a hypothesis that still needs checking. Each finding below says which it is.
"""
import collections
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "tools"))
import build_cpe_match_gt as G   # reuse its norm()/anchored_cpes() exactly

RSBOM = os.path.join(BASE, "reverse_sbom")
DETAIL = os.path.join(BASE, "data", "nvd_cpe_detail.json")
GT = os.path.join(BASE, "data", "cpe_match_eval.jsonl")
GT_B = os.path.join(BASE, "data", "cpe_match_eval_layerB.jsonl")
OUT = os.path.join(BASE, "results", "audit_cpe_match_gt.json")


def _load_gt(path):
    rows = []
    if os.path.isfile(path):
        for ln in open(path, encoding="utf-8"):
            ln = ln.strip()
            if ln:
                rows.append(json.loads(ln))
    return rows


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    detail = json.load(open(DETAIL, encoding="utf-8"))

    # Re-walk every SBOM exactly as the GT builder does, but keep the FULL anchored
    # set per (asset, component, CVE) so we can count distinct products.
    per_record = []          # one per Layer-A pair
    files = sorted(f for f in os.listdir(RSBOM) if f.endswith(".json"))
    for fn in files:
        try:
            sbom = json.load(open(os.path.join(RSBOM, fn), encoding="utf-8"))
        except Exception:
            continue
        comps = {}
        for c in sbom.get("components") or []:
            ref = c.get("bom-ref")
            if ref:
                comps[ref] = c
        for vuln in sbom.get("vulnerabilities") or []:
            cve = vuln.get("id")
            nvd = detail.get(cve)
            if not nvd:
                continue
            for aff in vuln.get("affects") or []:
                comp = comps.get(aff.get("ref"))
                if not comp:
                    continue
                entries = G.anchored_cpes(comp.get("publisher"), nvd)
                if not entries:
                    continue                      # Layer B, handled separately
                prods = {(e.get("vendor"), e.get("product")) for e in entries}
                per_record.append({
                    "cve": cve, "publisher": comp.get("publisher"),
                    "name": comp.get("name"),
                    "n_entries": len(entries),
                    "n_distinct_products": len(prods),
                    "chosen": (entries[0].get("vendor"), entries[0].get("product")),
                    "all_products": sorted("%s:%s" % p for p in prods)[:8],
                })

    # --- Finding 1: how often is the product identity more than vendor agreement ---
    n = len(per_record)
    multi = [r for r in per_record if r["n_distinct_products"] > 1]
    dist = collections.Counter(r["n_distinct_products"] for r in per_record)
    # the version_match gate can still separate products that differ by range, but
    # product IDENTITY (vendor:product string) is what entries[0] fixes blindly.
    finding1 = {
        "status": "CONFIRMED code/data defect, impact measured",
        "what": "to_gt() sets product_match=True from entries[0] after anchored_cpes "
                "matched on VENDOR substring only; product is never compared.",
        "layer_a_pairs_rebuilt": n,
        "single_product_anchored": n - len(multi),
        "multi_product_anchored": len(multi),
        "multi_product_pct": round(100.0 * len(multi) / n, 2) if n else 0,
        "distinct_product_histogram": {str(k): v for k, v in sorted(dist.items())},
        "reading": ("Where the anchored set has ONE product (%.1f%%), entries[0] is "
                    "unambiguous and product_match=True is effectively correct. The "
                    "%d pairs (%.1f%%) with >1 product are where the GT product is an "
                    "unverified pick among same-vendor products."
                    % (100.0 * (n - len(multi)) / n if n else 0,
                       len(multi), 100.0 * len(multi) / n if n else 0)),
        "samples_multi": [r for r in multi[:15]],
    }

    # --- Finding (Layer A/B + circular) provenance facts -----------------------
    gt_a = _load_gt(GT)
    gt_b = _load_gt(GT_B)
    rev = collections.Counter(r.get("review_status") for r in gt_a if r.get("applicable"))
    layers = collections.Counter(r.get("_layer") for r in gt_a)
    facts = {
        "gt_a_records": len(gt_a),
        "gt_b_records": len(gt_b),
        "gt_a_review_status": dict(rev),
        "gt_a_by_layer": dict(layers),
    }

    out = {"finding1_product_identity": finding1, "corpus_facts": facts,
           "note": "re-derived with tools/build_cpe_match_gt.anchored_cpes; nothing changed"}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    print("== Finding 1: GT product identity (problem 1) ==")
    f = finding1
    print("  Layer-A pairs re-derived      : %d" % f["layer_a_pairs_rebuilt"])
    print("  anchored set has 1 product    : %d (%.1f%%)"
          % (f["single_product_anchored"],
             100.0 * f["single_product_anchored"] / n if n else 0))
    print("  anchored set has >1 product   : %d (%.1f%%)  <- entries[0] is a guess here"
          % (f["multi_product_anchored"], f["multi_product_pct"]))
    print("  distinct-product histogram    : %s" % f["distinct_product_histogram"])
    print()
    print("  sample multi-product anchored sets:")
    for r in f["samples_multi"][:8]:
        print("    %-16s pub=%-22s chose %s of %s"
              % (r["cve"], (r["publisher"] or "")[:22], "%s:%s" % r["chosen"],
                 r["all_products"]))
    print()
    print("== corpus facts ==")
    print("  GT-A records %d | GT-B records %d" % (facts["gt_a_records"], facts["gt_b_records"]))
    print("  review_status: %s" % facts["gt_a_review_status"])
    print("-> %s" % OUT)


if __name__ == "__main__":
    main()
