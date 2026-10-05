#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Measure the L0 + L3 delta over the old 42-entry OSS knowledge base.

L0 (recall): identity coverage - how many products the matcher can even name.
L3 (precision): how many product->CVE matches the vendor guard removes as
co-listing / non-canonical-vendor artefacts (guard off vs on, corpus-wide),
plus a few hand-labelled adversarial cases where the guard's verdict is checkable.

L0 resolution: the rate at which real corpus names actually resolve to a product
token, per resolution path (exact / normalized / fuzzy) and per layer. Product
counts alone say what the matcher *could* name; this says what it *does* name on
the reverse_sbom corpus, which is the number the README quotes.

No fabricated ground truth: L0 coverage is definitional (product counts), the
guard effect is a direct off/on difference on real NVD entries, and the
adversarial cases assert only facts (openssl and openssh share no CVEs).

Output: results/l0l3_delta.json
"""
import glob
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
import cpe_match_l0l3 as M            # loads data/cpe_index.json
from generate_ics_sbom import OSS    # the old 42-entry OSS catalog (baseline)

import component_resolve as R    # Stage 1 layering, so the rate is per layer

OUT = os.path.join(BASE, "results", "l0l3_delta.json")
CORPUS = os.path.join(BASE, "reverse_sbom")

# Resolution paths, strongest identity first. Identifier paths (purl/cpe) are
# lookups; name paths are inferences and are reported separately for that reason.
_PATHS = ["purl", "cpe", "name-exact", "name-normalized", "name-fuzzy", "unresolved"]


def baseline_products():
    """product tokens the old 42-KB recognises (cpe_product + catalog name)."""
    s = set()
    for _k, spec in OSS.items():
        for t in (spec.get("cpe_product"), spec.get("name")):
            if t:
                s.add(M._norm(t))
    return s


# --- L0 resolution on the real corpus ----------------------------------------
def corpus_rows():
    """[(name, layer, component)] for every named component in reverse_sbom.

    Both layers are collected. `metadata.component` is the ICS product the
    advisory is about (a vendor display name - the hard case); `components[]`
    holds its injected model variants and its embedded software (the case that
    carries purl/cpe identifiers). They resolve at very different rates, so the
    layer is kept alongside every name instead of being averaged away."""
    rows = []
    for f in sorted(glob.glob(os.path.join(CORPUS, "*.json"))):
        try:
            sbom = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        r = R.resolve(sbom)
        for e in [r["product"]] + r["variants"] + r["embedded"]:
            if e.get("name"):
                rows.append((e["name"], e["layer"],
                             {"name": e["name"], "purl": e["purl"], "cpe": e["cpe"]}))
    return rows


def measure_resolution(rows):
    """Resolution counts per layer, both unique-name and occurrence weighted.

    identify_product() is memoized on the identity triple, so the occurrence
    weighting costs nothing beyond the unique-name work (the fuzzy path is ~0.1s
    per unseen name and dominates the runtime)."""
    cache, by_layer = {}, {}
    for name, layer, comp in rows:
        key = (comp["name"], comp["purl"], comp["cpe"])
        if key not in cache:
            prod, how = M.identify_product(comp)
            cache[key] = how if prod else "unresolved"
        path = cache[key]
        d = by_layer.setdefault(layer, {"unique": {}, "occurrence": {}, "_seen": set()})
        d["occurrence"][path] = d["occurrence"].get(path, 0) + 1
        if key not in d["_seen"]:
            d["_seen"].add(key)
            d["unique"][path] = d["unique"].get(path, 0) + 1

    def pack(c):
        n = sum(c.values())
        named = sum(c.get(p, 0) for p in ("name-exact", "name-normalized"))
        ident = sum(c.get(p, 0) for p in ("purl", "cpe"))
        return {"n": n,
                "paths": {p: c.get(p, 0) for p in _PATHS},
                "resolved_pct": round(100 * (n - c.get("unresolved", 0)) / max(n, 1), 1),
                "exact_normalized_pct": round(100 * named / max(n, 1), 1),
                "identifier_pct": round(100 * ident / max(n, 1), 1)}

    out = {"by_layer": {}, "all": {}}
    for layer, d in sorted(by_layer.items()):
        out["by_layer"][layer] = {w: pack(d[w]) for w in ("unique", "occurrence")}
    for w in ("unique", "occurrence"):
        tot = {}
        for d in by_layer.values():
            for k, v in d[w].items():
                tot[k] = tot.get(k, 0) + v
        out["all"][w] = pack(tot)
    out["corpus_files"] = len(glob.glob(os.path.join(CORPUS, "*.json")))
    out["headline"] = headline(out)
    return out


def headline(res):
    """The single (n, pct, label) the README quotes for Stage 2 resolution.

    TODO(human): pick the cell and return
        {"n": <int>, "pct": <float>, "label": "<what the number means>"}

    The cells available in `res` are, for each layer in res["by_layer"] and for
    res["all"], under "unique" (distinct names) or "occurrence" (every listing):
        n                     - denominator
        resolved_pct          - any path, identifiers included
        exact_normalized_pct  - exact + normalized name paths only
        identifier_pct        - purl + cpe only

    The trade-off is what the number is allowed to claim. `all`/`occurrence`
    /`resolved_pct` is the biggest and the least informative - 1,937 injected
    variant files repeat the same product names, so occurrence weighting lets one
    well-covered vendor inflate the corpus rate. `unique` removes that bias but
    then under-counts what a real scan sees. And `resolved_pct` folds in the
    purl/cpe lookups, which measure how well the *corpus* is identified rather
    than how well the *matcher* reads ICS display names - the stated claim was
    about exact+normalized specifically. Layer matters too: `ics-product` is the
    noisy-display-name case the normalizer was built for, `embedded-component`
    is where the identifiers live, so an `all` figure averages two different
    problems into one number."""
    return None


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

    # --- L0 resolution on the real corpus -------------------------------------
    rows = corpus_rows()
    resolution = measure_resolution(rows)

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
        "l0_resolution": resolution,
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
    a = resolution["all"]
    print("L0 resolution: corpus %d files, %d unique names / %d listings"
          % (resolution["corpus_files"], a["unique"]["n"], a["occurrence"]["n"]))
    for layer, d in sorted(resolution["by_layer"].items()):
        u, o = d["unique"], d["occurrence"]
        print("   %-19s unique n=%-6d resolved %5.1f%%  exact+norm %5.1f%%  ident %5.1f%%"
              % (layer, u["n"], u["resolved_pct"], u["exact_normalized_pct"], u["identifier_pct"]))
        print("   %-19s occur  n=%-6d resolved %5.1f%%  exact+norm %5.1f%%  ident %5.1f%%"
              % ("", o["n"], o["resolved_pct"], o["exact_normalized_pct"], o["identifier_pct"]))
    print("   %-19s unique n=%-6d resolved %5.1f%%  exact+norm %5.1f%%  ident %5.1f%%"
          % ("ALL", a["unique"]["n"], a["unique"]["resolved_pct"],
             a["unique"]["exact_normalized_pct"], a["unique"]["identifier_pct"]))
    print("   headline    :", resolution["headline"])
    print("cases:")
    for c in cases:
        print("   %-22s CVEs=%d" % (c["case"], c["cves"]))
    print("->", OUT)


if __name__ == "__main__":
    main()
