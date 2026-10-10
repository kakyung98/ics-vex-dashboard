#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Training pairs for the CPE product verifier — no hand labelling.

NVD's CPE dictionary publishes, for every product it knows, a human display name
beside the machine key:

    "Siemens SIMATIC S7-1500"  <->  cpe:2.3:o:siemens:simatic_s7-1500_firmware

That pairing is exactly the transform test item #3 is scored on, and the dictionary
has hundreds of thousands of examples of it. Positives are read off directly;
negatives are built by swapping one field of a real entry.

NEGATIVES ARE SWAPS, NEVER ABSENCES. "This string resolves to nothing in the
dictionary" is not evidence of a mismatch — NVD's coverage of ICS vendor firmware is
thin (2% of this corpus's components carry a CPE at all), so training on unmatched
real-world strings would teach the model NVD's gaps instead of real mismatches. Every
negative here starts from an entry that exists, changes vendor or product, and is
kept only after confirming the changed triple is absent.

LEAKAGE. The evaluation ground truth (data/cpe_match_eval.jsonl) draws its component
strings from CISA advisories and the dictionary draws titles from NVD, so the two are
normally disjoint — but 22 names coincide, covering 36 of the 5,373 positive records
(0.7%). Any title whose normalised form appears as a component name in the evaluation
set is dropped wholesale, by NAME rather than by (name, product) pair: a name that
shows up in the test must not reach training under any label.

NOISE AUGMENTATION. NVD titles are clean ("Siemens SIMATIC S7-1500"); CISA writes
"Siemens SIMATIC S7-1500 CPU 1518F-4 PN/DP MFP (6ES7518-4FX00-1AC0) <V5.2.6". Training
on clean titles alone would fit a distribution the matcher never sees at inference, so
positives are duplicated with order codes, version ranges and corporate suffixes mixed
in, modelled on the real strings in the corpus.

Out: data/cpe_match_pairs.jsonl   {text, product, label, kind}
     data/cpe_match_pairs_manifest.json
"""
import argparse
import collections
import json
import os
import random
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DICT = os.path.join(BASE, "data", "cpe_dictionary.jsonl")
EVAL_GT = os.path.join(BASE, "data", "cpe_match_eval.jsonl")
OUT = os.path.join(BASE, "data", "cpe_match_pairs.jsonl")
MANIFEST = os.path.join(BASE, "data", "cpe_match_pairs_manifest.json")

ORDER_CODES = ["(6ES7518-4FX00-1AC0)", "(6GK5206-1BC00-2AF2)", "(6AV2124-0GC01-0AX0)",
               "(1756-L71)", "(NSD570)", "(RTU560)"]
VERSION_TAILS = ["<V5.2.6", "<= 2021.1", ">=2.0|<3.4", "vers:intdot/<4.3.4",
                 "V8.2 Upd12", "< 7.1_2013.05.30"]
SUFFIXES = ["Inc.", "GmbH", "Corporation", "Co., Ltd.", "AG", "(Update A)"]


def nz(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def eval_names():
    """Normalised component strings that appear in the evaluation set."""
    names = set()
    if not os.path.isfile(EVAL_GT):
        return names
    for line in open(EVAL_GT, encoding="utf-8"):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        si = r.get("_sut_input") or {}
        if si.get("name"):
            names.add(nz(si["name"]))
    return names


def load_dictionary():
    """(vendor, product) -> title, plus the vendor/product sets used for swaps."""
    titles, by_vendor, products, known = {}, collections.defaultdict(set), set(), set()
    if not os.path.isfile(DICT):
        return titles, by_vendor, products, known
    for line in open(DICT, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        v, p, t = r.get("vendor"), r.get("product"), r.get("title")
        if not v or not p:
            continue
        known.add((v, p))
        products.add(p)
        by_vendor[v].add(p)
        if t and (v, p) not in titles:
            titles[(v, p)] = t
    return titles, by_vendor, products, known


def augment(title, rnd):
    """Dirty a clean NVD title the way a CISA advisory would."""
    out = []
    out.append("%s %s" % (title, rnd.choice(ORDER_CODES)))
    out.append("%s %s" % (title, rnd.choice(VERSION_TAILS)))
    out.append("%s %s %s" % (rnd.choice(SUFFIXES), title, rnd.choice(VERSION_TAILS)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261010)
    ap.add_argument("--neg-per-pos", type=float, default=1.0)
    ap.add_argument("--augment", type=int, default=2,
                    help="noisy variants per clean positive (0 disables)")
    a = ap.parse_args()
    rnd = random.Random(a.seed)

    held = eval_names()
    titles, by_vendor, products, known = load_dictionary()
    if not titles:
        print("사전 없음 또는 비어 있음: %s" % os.path.relpath(DICT, BASE))
        print("  python tools/fetch_cpe_dictionary.py --vendors  로 먼저 수집하십시오.")
        return

    rows = []
    dropped = 0
    product_list = sorted(products)
    vendor_list = sorted(by_vendor)

    for (vendor, product), title in sorted(titles.items()):
        if nz(title) in held:
            dropped += 1          # appears in the evaluation set: never train on it
            continue
        rows.append({"text": title, "product": product, "label": 1, "kind": "title"})
        for extra in augment(title, rnd)[:a.augment]:
            rows.append({"text": extra, "product": product, "label": 1,
                         "kind": "title-noised"})

    positives = len(rows)
    want_neg = int(positives * a.neg_per_pos)
    seen = set()
    guard = 0
    while len(rows) - positives < want_neg and guard < want_neg * 40:
        guard += 1
        vendor, product = rnd.choice(sorted(known))
        title = titles.get((vendor, product))
        if not title or nz(title) in held:
            continue
        if rnd.random() < 0.5:
            # vendor swap: a product this vendor does not ship
            other = rnd.choice(vendor_list)
            if other == vendor or (other, product) in known:
                continue
            wrong, kind = product, "vendor-swap"
            text = title.replace(vendor, other) if vendor in title else "%s %s" % (other, title)
            # the label is on the PAIR: this text does not denote `wrong` under `other`
            key = (text, wrong)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"text": text, "product": wrong, "label": 0, "kind": kind,
                         "swapped_vendor": other})
        else:
            # product swap: same text, a different product that exists elsewhere
            other = rnd.choice(product_list)
            if other == product or (vendor, other) in known:
                continue
            key = (title, other)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"text": title, "product": other, "label": 0,
                         "kind": "product-swap"})

    rnd.shuffle(rows)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    kinds = collections.Counter(r["kind"] for r in rows)
    manifest = {
        "source": "data/cpe_dictionary.jsonl (NVD CPE dictionary, ICS vendors)",
        "seed": a.seed,
        "counts": {"total": len(rows), "positive": positives,
                   "negative": len(rows) - positives, "by_kind": dict(kinds)},
        "held_out_titles": dropped,
        "held_out_rule": "a title whose normalised form appears as a component name in "
                         "data/cpe_match_eval.jsonl is dropped by NAME, not by pair — a "
                         "string that shows up in the test must not reach training under "
                         "any label",
        "negative_rule": "swap a field of an existing entry and confirm the result is "
                         "absent; never label an unmatched real-world string as negative, "
                         "which would train on NVD's ICS coverage gaps",
        "augmentation": "order codes, version-range tails and corporate suffixes, so the "
                        "training distribution resembles CISA advisory strings rather "
                        "than NVD's clean titles",
    }
    json.dump(manifest, open(MANIFEST, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    print("pairs      : %d  (positive %d / negative %d)"
          % (len(rows), positives, len(rows) - positives))
    print("by kind    : %s" % dict(kinds))
    print("held out   : %d titles present in the evaluation set" % dropped)
    print("->", OUT)
    print("->", MANIFEST)


if __name__ == "__main__":
    main()
