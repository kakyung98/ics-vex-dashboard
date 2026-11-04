#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tag every item #3 ground-truth pair with the problem layer(s) it exercises.

The deck sets L2 (component-name ambiguity), L3 (version representation) and L4
(identifier inconsistency) as the problems this research solves. A single headline
precision over 41,868 pairs cannot show that, because it mixes a pair whose answer
turns on a near-identical sibling name with one whose answer turns on a version
bound. This script adds `_problem_layers` to each pair so the scorer can report a
precision PER LAYER, and writes the per-layer composition.

The tags are read off the authorities already in the record - nothing new is judged:

  L2  the advisory vendor anchors >1 distinct NVD product for this CVE
      (`_ambiguous_product`), so the component NAME is what has to separate them.
      sub-tag L2-exposed: the component carries no CPE either, so the name is the
      only route left.
  L3  the version axis is what decides this pair:
      - a negative whose family is `version` (same product, version out of range)
      - a positive whose version_match is True/False (a bound actually applied)
      - version_match None -> L3-undecidable: CISA published only an upper bound,
        so no version can be confirmed affected; tagged apart because a matcher
        cannot be scored on it.
      - sub-tag L3-notation: the CISA range string carries no ordered version
        (vendor notation like `6.1|SP1`, or free text)
  L4  the identifier axis is what decides this pair:
      - a negative whose family is `vendor` (a co-listed foreign vendor's own
        product on a shared-code CVE)
      - vendor_match False
      - sub-tag L4-absence: the component carries neither CPE nor purl, so there
        is no identifier to compare in the first place

A pair can carry several tags. That is the point: the layers overlap, and the
overlap is what a single headline hides.

Input : data/cpe_match_eval_ambig.jsonl  (the ambiguity-aware GT; the base
        cpe_match_eval.jsonl asserts product identity from vendor anchoring alone
        and so carries no L2 signal)
Output: data/cpe_match_eval_layered.jsonl, results/gt_problem_layers.json
"""
import collections
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "data", "cpe_match_eval_ambig.jsonl")
OUT = os.path.join(BASE, "data", "cpe_match_eval_layered.jsonl")
REPORT = os.path.join(BASE, "results", "gt_problem_layers.json")


def _ordered_version(s):
    """True when the CISA range string contains a version a machine can order."""
    t = (s or "").strip().lower()
    if not t:
        return False
    if re.search(r"(sp|hf|upd|update|cpr|build)[0-9_]", t):
        return False                      # vendor notation: no defined ordering
    return bool(re.search(r"[0-9]+\.[0-9]", t) or re.fullmatch(r"v?[0-9]+", t))


def _range_text(rec):
    r = rec.get("_cisa_range")
    if isinstance(r, dict):
        return " ".join(str(v) for v in r.values() if v)
    return str(r or rec["_sut_input"].get("version") or "")


def layers_for(rec):
    tags = set()
    ev = rec["evidence"]
    fam = rec.get("_negative_family")
    sut = rec.get("_sut_input") or {}

    # --- L2 -----------------------------------------------------------------
    if rec.get("_ambiguous_product"):
        tags.add("L2")
        if not sut.get("cpe"):
            tags.add("L2-exposed")

    # --- L3 -----------------------------------------------------------------
    if fam == "version":
        tags.add("L3")
    if ev.get("version_match") is True or ev.get("version_match") is False:
        tags.add("L3")
    if ev.get("version_match") is None:
        tags.add("L3-undecidable")
    if not _ordered_version(_range_text(rec)):
        tags.add("L3-notation")

    # --- L4 -----------------------------------------------------------------
    if fam == "vendor":
        tags.add("L4")
    if ev.get("vendor_match") is False:
        tags.add("L4")
    if not sut.get("cpe") and not sut.get("purl"):
        tags.add("L4-absence")
    return sorted(tags)


def main():
    comp = collections.Counter()
    combo = collections.Counter()
    by_pol = collections.defaultdict(collections.Counter)
    n = 0
    with open(OUT, "w", encoding="utf-8") as out:
        for ln in open(SRC, encoding="utf-8"):
            rec = json.loads(ln)
            tags = layers_for(rec)
            rec["_problem_layers"] = tags
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
            for t in tags:
                comp[t] += 1
                by_pol["positive" if rec["applicable"] else "negative"][t] += 1
            core = tuple(t for t in ("L2", "L3", "L4") if t in tags)
            combo[core or ("none",)] += 1

    res = {
        "source": os.path.relpath(SRC, BASE).replace("\\", "/"),
        "pairs": n,
        "per_layer": dict(comp),
        "per_layer_pct": {k: round(100.0 * v / n, 1) for k, v in comp.items()},
        "positives": dict(by_pol["positive"]),
        "negatives": dict(by_pol["negative"]),
        "core_combination": {"+".join(k): v for k, v in sorted(combo.items())},
        "note": "layers overlap by design; per_layer sums to more than `pairs`",
    }
    json.dump(res, open(REPORT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
