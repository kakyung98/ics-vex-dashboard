#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""시험항목 #3 — SBOM 기반 공개 취약점 정보 식별 정밀도.

    precision = TP / (TP + FP)              (acceptance: >= 0.80)

      TP: the SUT identified (component -> vendor:product@version, CVE) and the
          ground truth marks that exact mapping applicable.
      FP: the SUT identified a mapping the ground truth marks NOT applicable —
          a wrong product/vendor mapping, or a version outside the affected range.

SUT is the current matcher, src/cpe_match_l0l3.cves_for (L0 full NVD CPE product
index + L3 vendor confidence), which resolves identity identifiers-first and only
falls back to an unambiguous name match. The previous version of this script drove
api_server.vex_compare_sbom at Ratcliff-Obershelp 0.7 — the matcher that scores
`openssl` against `openssh` at 0.857 — and targeted 95%; both are replaced here.

Ground truth is data/cpe_match_eval.jsonl (tools/build_cpe_match_gt.py), built from
CISA CSAF product_tree assertions cross-checked against NVD applicability. It is a
PARTIAL oracle: it labels the mappings those two authorities cover, not every
mapping the SUT can emit. So a prediction with no GT record is counted `unlabelled`
and kept out of TP/FP rather than guessed at, and the unlabelled share is printed —
a precision computed over a small labelled slice of a large prediction set is not
representative, and hiding that would overstate the result.

Per the test spec's 전제 조건, 'affected' is not considered: only whether an
identified CVE maps exactly onto the component.

Usage:
  python tools/eval_cpe_match_precision.py [--strict] [--data ...]
"""
import argparse
import collections
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
import cpe_match_l0l3 as M
from cpe_match_l0l3 import identify_product

DATA = os.path.join(BASE, "data", "cpe_match_eval.jsonl")
OUT = os.path.join(BASE, "results", "cpe_match_precision.json")
TARGET = 0.80


def _np(s):
    """Product-name normalization. Separators must go: NVD spells the same product
    both `scada_web_server` and `scada_webserver`, and M._norm only lowercases and
    strips a `lib` prefix, so comparing through it called those two different."""
    return re.sub(r"[^a-z0-9]", "", M._norm(s))


def same_product(predicted, correct):
    """Is the SUT's product the authoritative one?

    Exact equality over-penalizes: NVD carries both `scalance_x414-3e` and
    `scalance_x414-3e_firmware` for one device, and either is a correct
    identification. Containment after normalization accepts those and still
    rejects an unrelated product.
    """
    p, c = _np(predicted), _np(correct)
    if not p or not c:
        return False
    return p == c or p in c or c in p


def name_supports(product, component_name):
    """Does the component's own name contain the product the SUT resolved to?

    This separates a wrong-product mapping from a case the GT simply cannot
    adjudicate. "Siemens JT2Go" resolving to `jt2go` is a correct identification
    of the named component, yet the GT's vendor-anchored CPE for that CVE is
    `siemens:drawings_software_development_kit` — the embedded Open Design Alliance
    SDK. The authority disagrees with the matcher about WHICH product the CVE is
    filed against, not about what the component is, so it is not scorable either way.
    """
    p, n = _np(product), _np(component_name)
    return bool(p) and bool(n) and p in n


def load_gt(path):
    """Index the GT two ways.

    `applicable` tells which (component, product, version, CVE) mappings are right;
    `correct_product` is the per-component authoritative product identity, which is
    what makes a wrong-product FP detectable at all.

    Pre-built negatives are read, but note which family can actually fire:
      version  — the SUT's own range filter (_entry_decides) already refuses these,
                 so they rarely become predictions. Their value is confirming the
                 filter, not generating FPs.
      vendor   — NOT reachable for this SUT. It reports identity as (product,
                 vendor-of-that-product-entry), so for product `zlib` every entry
                 carries vendor `zlib`; it can never emit `fedoraproject:fedora`
                 for a Siemens component. Counted and reported, never scored.
    The product axis is therefore scored by a closed-world rule instead of by
    pre-enumerated records: for a component whose authoritative product is known,
    any CVE emitted under a different product is a wrong-product mapping.
    """
    gt, cases, conflicts = {}, {}, 0
    unreachable = collections.Counter()
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("review_status") == "conflict":
            conflicts += 1          # CISA and NVD disagree — not a usable label
            continue
        c = r["component"]
        fam = r.get("_negative_family")
        if fam == "vendor":
            unreachable["vendor"] += 1
            continue
        gt[(r["component_id"], c["product"], c["version"], r["cve_id"])] = r
        si = r["_sut_input"]
        ck = (r["component_id"], c["version"])
        case = cases.setdefault(ck, {
            "component_id": r["component_id"], "name": si["name"],
            "version": c["version"], "publisher": si.get("publisher") or "",
            "correct_products": set(), "asserted_cves": set(),
        })
        if r["applicable"]:
            case["correct_products"].add(c["product"])
            case["asserted_cves"].add(r["cve_id"])
        elif fam == "version":
            # identity is right here, only the version is past the fix
            case["correct_products"].add(c["product"])
    return gt, [c for c in cases.values() if c["correct_products"]], conflicts, unreachable


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--strict", action="store_true",
                    help="SUT precision mode: drop co-listed-vendor CVEs")
    a = ap.parse_args()

    if not os.path.isfile(a.data):
        print("GT 없음: %s\n  python tools/build_cpe_match_gt.py 로 먼저 생성" % a.data)
        return

    gt, cases, conflicts, unreachable = load_gt(a.data)
    tp = fp = unlabelled = abstained = unadjudicable = 0
    fp_axis = collections.Counter()
    fp_rows = []

    for case in cases:
        comp = {"name": case["name"], "version": case["version"] or ""}
        product, _how = identify_product(comp)
        if not product:
            abstained += 1              # identified nothing: no prediction to score
            continue
        product_ok = any(same_product(product, p) for p in case["correct_products"])
        # not the GT product, but the component's own name carries it: the two
        # authorities disagree about which product the CVE is filed against, so the
        # GT cannot adjudicate and the prediction is held out rather than charged
        indeterminate = not product_ok and name_supports(product, case["name"])
        for pred in M.cves_for(comp, sbom_vendor=case["publisher"], strict=a.strict):
            if indeterminate:
                unadjudicable += 1
                continue
            if not product_ok:
                # wrong-product mapping: the authoritative identity is known and the
                # component's own name does not support the SUT's product either
                fp += 1
                fp_axis["product"] += 1
                if len(fp_rows) < 40:
                    fp_rows.append({"component": case["name"][:70],
                                    "sut_product": product,
                                    "correct_products": sorted(case["correct_products"]),
                                    "cve": pred["cve"], "axis": "product"})
                continue
            label = gt.get((case["component_id"], product, case["version"], pred["cve"]))
            if label is None:
                # GT lists only the CVEs CISA asserted for this component; a CVE
                # outside that set is unjudged, not wrong
                unlabelled += 1
            elif label["applicable"]:
                tp += 1
            else:
                fp += 1
                fp_axis[label.get("_negative_family") or "?"] += 1
                if len(fp_rows) < 40:
                    fp_rows.append({"component": case["name"][:70],
                                    "sut_product": product,
                                    "version": case["version"], "cve": pred["cve"],
                                    "axis": label.get("_negative_family")})

    scored = tp + fp
    prec = tp / scored if scored else 0.0
    res = {
        "test": "SBOM CVE-identification precision (시험항목 #3)",
        "sut": "src/cpe_match_l0l3.cves_for (L0 NVD CPE index + L3 vendor guard)",
        "sut_mode": "strict (co-listed dropped)" if a.strict else "recall-safe (default)",
        "ground_truth": os.path.relpath(a.data, BASE),
        "gt_labels": len(gt), "gt_conflicts_held_out": conflicts,
        "gt_unreachable_for_this_sut": dict(unreachable),
        "unreachable_reason": "co-listed-vendor negatives name a foreign vendor's OWN "
                              "product; the SUT reports (product, vendor-of-that-"
                              "product) so it can never emit them. The product axis "
                              "is scored by closed-world rule instead.",
        "sut_runs": len(cases), "sut_abstained": abstained,
        "TP": tp, "FP": fp, "scored": scored,
        "unlabelled_predictions": unlabelled,
        "unadjudicable_predictions": unadjudicable,
        "unadjudicable_reason": "SUT resolved the product the component name itself "
                                "carries, but the GT's vendor-anchored CPE names a "
                                "different (usually embedded) product for that CVE; "
                                "the authorities disagree on filing, not on identity",
        "labelled_share_pct": round(100.0 * scored / (scored + unlabelled + unadjudicable), 2)
                              if (scored + unlabelled + unadjudicable) else 0.0,
        "fp_by_axis": dict(fp_axis),
        "precision": round(prec, 4),
        "acceptance_criterion": "precision >= %.2f" % TARGET,
        "pass": prec >= TARGET,
        "fp_examples": fp_rows,
    }

    print("=== 시험항목 #3 · SBOM 기반 공개 취약점 식별 정밀도 ===")
    print("  SUT            : %s" % res["sut"])
    print("  mode           : %s" % res["sut_mode"])
    print("  GT labels      : %d  (conflict held out: %d)" % (len(gt), conflicts))
    print("  SUT runs       : %d components  (abstained: %d)" % (len(cases), abstained))
    if unreachable:
        print("  GT unreachable : %s  (see unreachable_reason)" % dict(unreachable))
    print("  TP=%d  FP=%d  scored=%d" % (tp, fp, scored))
    if fp_axis:
        print("  FP by axis     : %s" % dict(fp_axis))
    print("  unlabelled     : %d predictions  (labelled share %.2f%%)"
          % (unlabelled, res["labelled_share_pct"]))
    print("  unadjudicable  : %d predictions  (authority disagreement on filing)"
          % unadjudicable)
    print("  PRECISION      = %.4f   (acceptance >= %.2f)  ->  %s"
          % (prec, TARGET, "PASS" if res["pass"] else "FAIL"))
    if res["labelled_share_pct"] < 50 and unlabelled:
        print("  NOTE: under half the predictions carry a GT label; the figure "
              "describes the labelled slice only.")
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", OUT)


if __name__ == "__main__":
    main()
