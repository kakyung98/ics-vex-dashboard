#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Measure the L0 + L3 delta over the old 42-entry OSS knowledge base.

L0 (recall): identity coverage - how many products the matcher can even name.
L3 (precision): how many product->CVE matches the vendor guard removes as
co-listing / non-canonical-vendor artefacts (guard off vs on, corpus-wide),
plus a few hand-labelled adversarial cases where the guard's verdict is checkable.

No fabricated ground truth: L0 coverage is definitional (product counts), the
guard effect is a direct off/on difference on real NVD entries, and the
adversarial cases assert only facts (openssl and openssh share no CVEs).

Output: results/l0l3_delta.json
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
import cpe_match_l0l3 as M            # loads data/cpe_index.json
from generate_ics_sbom import OSS    # the old 42-entry OSS catalog (baseline)

OUT = os.path.join(BASE, "results", "l0l3_delta.json")


def baseline_products():
    """product tokens the old 42-KB recognises (cpe_product + catalog name)."""
    s = set()
    for _k, spec in OSS.items():
        for t in (spec.get("cpe_product"), spec.get("name")):
            if t:
                s.add(M._norm(t))
    return s


def main():
    if not M.BY_PRODUCT:
        print("data/cpe_index.json not built - run tools/build_cpe_index.py first")
        return

    base = baseline_products()

    # --- L0: identity coverage -------------------------------------------------
    l0_products = len(M.BY_PRODUCT)
    base_in_index = sum(1 for p in M.BY_PRODUCT if M._norm(p) in base)

    # --- L3: vendor-confidence distribution corpus-wide (sbom_vendor unknown) ---
    # Nothing is dropped by default; this shows what strict mode WOULD drop and how
    # rare that is - the honest measure of the guard's reach and cost.
    conf = {"anchored": 0, "canonical": 0, "co-listed": 0}
    tot = multi = 0
    for prod, entries in M.BY_PRODUCT.items():
        if len({e["vendor"] for e in entries}) > 1:
            multi += 1
        for e in entries:
            tot += 1
            conf[M.vendor_confidence(e["vendor"], prod, "")] += 1
    strict_drop = conf["co-listed"]                 # what strict mode removes

    # --- adversarial precision cases (facts, not fabricated labels) ------------
    def n(name, ver="", vendor="", strict=False):
        return len(M.cves_for({"name": name, "version": ver}, sbom_vendor=vendor, strict=strict))
    cases = [
        # openssl and openssh share zero CVEs; a matcher must not bleed one into the other
        {"case": "openssl 1.1.1k", "cves": n("openssl", "1.1.1k")},
        {"case": "openssh 8.0", "cves": n("openssh", "8.0")},
        # version filtering: a newer release sits past most fixed ranges
        {"case": "zlib 1.2.11 (old)", "cves": n("zlib", "1.2.11")},
        {"case": "zlib 1.3.1 (new)", "cves": n("zlib", "1.3.1")},
        # embedded-layer recall: 'linux' is multi-vendor; strict mode drops the
        # non-dominant (redhat/windriver) entries a device legitimately runs
        {"case": "linux (default)", "cves": n("linux")},
        {"case": "linux (strict)", "cves": n("linux", strict=True)},
    ]

    res = {
        "l0": {"baseline_products_42kb": len(base),
               "l0_products": l0_products,
               "expansion_x": round(l0_products / max(len(base), 1), 1),
               "baseline_products_present_in_index": base_in_index},
        "l3_confidence": {"total_product_cve_entries": tot,
                          "by_confidence": conf,
                          "strict_would_drop": strict_drop,
                          "strict_drop_pct": round(100 * strict_drop / max(tot, 1), 2),
                          "multi_vendor_products": multi,
                          "multi_vendor_pct": round(100 * multi / max(l0_products, 1), 2)},
        "adversarial": cases,
    }
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    print("=== L0+L3 delta vs 42-entry OSS KB ===")
    print("L0 recall   : products %d -> %d  (%.0fx),  42-KB products in index: %d/%d"
          % (len(base), l0_products, res["l0"]["expansion_x"], base_in_index, len(base)))
    print("L3 grading  : anchored %d / canonical %d / co-listed %d  of %d entries"
          % (conf["anchored"], conf["canonical"], conf["co-listed"], tot))
    print("            : strict mode would drop %d (%.1f%%); multi-vendor products %d (%.1f%%)"
          % (strict_drop, res["l3_confidence"]["strict_drop_pct"], multi, res["l3_confidence"]["multi_vendor_pct"]))
    print("cases:")
    for c in cases:
        print("   %-22s CVEs=%d" % (c["case"], c["cves"]))
    print("->", OUT)


if __name__ == "__main__":
    main()
