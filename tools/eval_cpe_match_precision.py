#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test item #3 - precision of SBOM-based public vulnerability identification.

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

Per the test spec's preconditions, 'affected' is not considered: only whether an
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

def _matcher(which):
    """The matcher module for this run. Both expose the same contract, so the
    choice is just which module `score` calls.

    This used to rebind the module-level `M` and `identify_product`. That is
    process-wide and permanent, so once an `ai` run had happened, every later
    `string` run in the same process silently used the retrieval matcher and
    reported its numbers under the other label - which is exactly what the web
    app does, since it serves both variants from one process. Returning the
    module instead keeps the selection inside the call that made it.
    """
    if which == "ai":
        import cpe_match_ai as AI
        return AI
    return M

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
            # CSAF's product_identification_helper, present on ~2% of components.
            # `purl` is deliberately NOT passed: every purl in this corpus is
            # pkg:generic/<slugified name>, synthesised by the SBOM builder from the
            # very name the matcher is being asked to resolve. Feeding it back would
            # dress name matching up as identifier matching.
            "cpe": si.get("cpe"),
            "correct_products": set(), "asserted_cves": set(),
        })
        if r["applicable"]:
            case["correct_products"].add(c["product"])
            case["asserted_cves"].add(r["cve_id"])
        elif fam == "version":
            # identity is right here, only the version is past the fix
            case["correct_products"].add(c["product"])
        # CVE-level label, independent of which product key the matcher routed
        # through. The spec defines TP as "the identified CVE maps onto the
        # component", not "the matcher produced the CPE product key NVD happens to
        # use", and an identifier path can reach the right CVE without a product key.
        #
        # OR, not overwrite. 7,993 (component, CVE) pairs carry both labels, because
        # the label hangs off the product key: CVE-2018-25032 on a SIMATIC S7-1500 is
        # applicable under siemens:scalance_sc622-2c_firmware and not applicable under
        # netapp:h300s_firmware, the co-listed vendor. Taking the last record seen let
        # a co-listing negative erase a real positive and charged the identifier path
        # for CVEs the ground truth actually asserts.
        lab = case.setdefault("cve_label", {})
        lab[r["cve_id"]] = bool(lab.get(r["cve_id"])) or bool(r["applicable"])
    return gt, [c for c in cases.values() if c["correct_products"]], conflicts, unreachable


def score(data=DATA, matcher="string", strict=False, progress=None):
    """Measure test item #3 and return the result record.

    Split out of main() so the web app scores through exactly this function rather
    than reimplementing the rules. A second implementation is a second set of
    numbers, and the whole point of the certification page is that the figure it
    shows is the figure that was measured.

    progress: optional callable(done, total, note) for a long run - the full corpus
    is ~14k components and takes minutes, so the caller needs to be able to report
    where it is without this function knowing anything about HTTP.
    """
    MM = _matcher(matcher)
    identify = MM.identify_product
    gt, cases, conflicts, unreachable = load_gt(data)
    tp = fp = unlabelled = abstained = unadjudicable = 0
    fp_axis = collections.Counter()
    by_path = collections.Counter()
    fp_rows = []
    # Per-vendor, because the corpus is not uniform and the single figure hides
    # that: Siemens alone is 47.6% of the components, and the matcher abstains on
    # 43.9% inside the ten largest vendors against 55.5% outside them. Reporting
    # the breakdown is the alternative to SCOPING to those vendors - scoping
    # would raise the number by removing the harder half, which is the same trap
    # the retired per-vendor cap fell into (0.9870 -> 0.9499 when it was lifted).
    vend = collections.defaultdict(collections.Counter)

    for i, case in enumerate(cases):
        if progress and i % 200 == 0:
            progress(i, len(cases), "scoring components")
        comp = {"name": case["name"], "version": case["version"] or ""}
        if case.get("cpe"):
            comp["cpe"] = case["cpe"]
        _v = (case.get("publisher") or "?").strip() or "?"
        vend[_v]["components"] += 1
        product, _how = identify(comp)
        if not product:
            abstained += 1              # identified nothing: no prediction to score
            vend[_v]["abstained"] += 1
            continue
        if _how == "model-number":
            labels = case.get("cve_label") or {}
            for pred in MM.cves_for(comp, sbom_vendor=case["publisher"], strict=strict):
                lab = labels.get(pred["cve"])
                if lab is None:
                    unlabelled += 1
                elif lab:
                    tp += 1
                    by_path["model-number"] += 1
                    vend[_v]["TP"] += 1
                else:
                    fp += 1
                    fp_axis["identifier"] += 1
                    vend[_v]["FP"] += 1
            continue
        product_ok = any(same_product(product, p) for p in case["correct_products"])
        indeterminate = not product_ok and name_supports(product, case["name"])
        for pred in MM.cves_for(comp, sbom_vendor=case["publisher"], strict=strict):
            if indeterminate:
                unadjudicable += 1
                continue
            if not product_ok:
                fp += 1
                fp_axis["product"] += 1
                vend[_v]["FP"] += 1
                if len(fp_rows) < 40:
                    fp_rows.append({"component": case["name"][:70],
                                    "sut_product": product,
                                    "correct_products": sorted(case["correct_products"]),
                                    "cve": pred["cve"], "axis": "product"})
                continue
            label = gt.get((case["component_id"], product, case["version"], pred["cve"]))
            if label is None:
                unlabelled += 1
            elif label["applicable"]:
                tp += 1
                vend[_v]["TP"] += 1
            else:
                fp += 1
                fp_axis[label.get("_negative_family") or "?"] += 1
                vend[_v]["FP"] += 1
                if len(fp_rows) < 40:
                    fp_rows.append({"component": case["name"][:70],
                                    "sut_product": product,
                                    "version": case["version"], "cve": pred["cve"],
                                    "axis": label.get("_negative_family")})
    if progress:
        progress(len(cases), len(cases), "done")

    scored = tp + fp
    prec = tp / scored if scored else 0.0
    return {
        "test": "SBOM CVE-identification precision (test item #3)",
        "sut": ("src/cpe_match_ai (retrieval behind the cascade)" if matcher == "ai"
                else "src/cpe_match_l0l3.cves_for (L0 NVD CPE index + L3 vendor guard)"),
        "sut_mode": "strict (co-listed dropped)" if strict else "recall-safe (default)",
        "ground_truth": os.path.relpath(data, BASE),
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
        "tp_by_path": dict(by_path),
        # Ordered by how much of the corpus each vendor is, not by how well it
        # scores - a table sorted by precision invites reading the top of it as
        # the result.
        "by_vendor": [
            {"vendor": v,
             "components": c["components"],
             "abstained": c["abstained"],
             "abstention_pct": round(100.0 * c["abstained"] / c["components"], 1)
             if c["components"] else None,
             "TP": c["TP"], "FP": c["FP"],
             "scored": c["TP"] + c["FP"],
             "precision": round(c["TP"] / (c["TP"] + c["FP"]), 4)
             if (c["TP"] + c["FP"]) else None}
            for v, c in sorted(vend.items(),
                               key=lambda kv: -kv[1]["components"])],
        "precision": round(prec, 4),
        "acceptance_criterion": "precision >= %.2f" % TARGET,
        "pass": prec >= TARGET,
        "fp_examples": fp_rows,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--out", help="write elsewhere than results/cpe_match_precision.json. "
                                  "Pass it when scoring a non-default --data: the fixed "
                                  "output path silently overwrote the whole-corpus result "
                                  "with a 104-scoped one once already")
    ap.add_argument("--matcher", choices=["string", "ai"], default="ai",
                    help="'ai' (default) adds semantic retrieval behind the string "
                         "cascade; 'string' is the cascade alone. The retrieval "
                         "stage degrades to the cascade when the encoder is not "
                         "installed, so 'ai' is safe on a fresh checkout")
    ap.add_argument("--strict", action="store_true",
                    help="SUT precision mode: drop co-listed-vendor CVEs")
    a = ap.parse_args()

    if not os.path.isfile(a.data):
        print("no ground truth: %s\n  build it first with python tools/build_cpe_match_gt.py" % a.data)
        return

    res = score(a.data, matcher=a.matcher, strict=a.strict)
    tp, fp, scored = res["TP"], res["FP"], res["scored"]
    prec, conflicts = res["precision"], res["gt_conflicts_held_out"]
    gt_labels, abstained = res["gt_labels"], res["sut_abstained"]
    unlabelled = res["unlabelled_predictions"]
    unadjudicable = res["unadjudicable_predictions"]
    unreachable, fp_axis = res["gt_unreachable_for_this_sut"], res["fp_by_axis"]
    by_path = res["tp_by_path"]

    print("=== test item #3 - SBOM-based public vulnerability identification precision ===")
    print("  SUT            : %s" % res["sut"])
    print("  mode           : %s" % res["sut_mode"])
    print("  GT labels      : %d  (conflict held out: %d)" % (gt_labels, conflicts))
    print("  SUT runs       : %d components  (abstained: %d)"
          % (res["sut_runs"], abstained))
    if unreachable:
        print("  GT unreachable : %s  (see unreachable_reason)" % dict(unreachable))
    print("  TP=%d  FP=%d  scored=%d" % (tp, fp, scored))
    if fp_axis:
        print("  FP by axis     : %s" % dict(fp_axis))
    if by_path:
        print("  TP by path     : %s" % dict(by_path))
    print("  unlabelled     : %d predictions  (labelled share %.2f%%)"
          % (unlabelled, res["labelled_share_pct"]))
    print("  unadjudicable  : %d predictions  (authority disagreement on filing)"
          % unadjudicable)
    print("  PRECISION      = %.4f   (acceptance >= %.2f)  ->  %s"
          % (prec, TARGET, "PASS" if res["pass"] else "FAIL"))
    bv = [r for r in res["by_vendor"] if r["scored"]][:10]
    if bv:
        print("  by vendor (top %d by corpus share):" % len(bv))
        print("    %-26s %7s %7s %6s %6s  %s"
              % ("vendor", "comps", "abstain", "TP", "FP", "precision"))
        for r in bv:
            print("    %-26s %7d %6.1f%% %6d %6d  %s"
                  % (r["vendor"][:26], r["components"], r["abstention_pct"] or 0,
                     r["TP"], r["FP"],
                     "%.4f" % r["precision"] if r["precision"] is not None else "-"))
    if res["labelled_share_pct"] < 50 and unlabelled:
        print("  NOTE: under half the predictions carry a GT label; the figure "
              "describes the labelled slice only.")
    out_path = a.out or OUT
    json.dump(res, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", out_path)


if __name__ == "__main__":
    main()
