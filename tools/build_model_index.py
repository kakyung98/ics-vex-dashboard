#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Index ICS model numbers to the CVEs their advisory declares them affected by.

Why this exists: an ICS SBOM names a vendor product, not an OSS library, and
fuzzy-matching that name against an OSS knowledge base is a category error - it
returned RO 0.30-0.37 against unrelated components and zero CVEs. CPE cannot
rescue it either: only 0.2% of CISA's OT products carry one.

What CISA does publish is a model number on 28.1% of OT products - a Siemens
MLFB order code like `6GK7342-5DA02-0XE0`, which is an exact string an asset
owner reads off the device. And the advisory that carries it already states
which CVEs that product_id is affected by, so no inference is needed at all:
the mapping is a lookup, and a lookup cannot mis-fire the way a similarity
score can.

Output: data/model_cve_index.json
  {model_number: {"products": [...], "cves": [...], "advisories": [...]}}
"""
import argparse
import collections
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "model_cve_index.json")


def products_of(csaf):
    """{product_id: (name, [model numbers], cpe)} from every product_tree location."""
    out = {}

    def take(p):
        pid = p.get("product_id")
        if not pid:
            return
        h = p.get("product_identification_helper") or {}
        out[pid] = (p.get("name", ""), list(h.get("model_numbers") or []), h.get("cpe"))

    def walk(bs):
        for b in bs or []:
            if "product" in b:
                take(b["product"])
            walk(b.get("branches"))

    pt = csaf.get("product_tree") or {}
    walk(pt.get("branches"))
    for fp in pt.get("full_product_names") or []:
        take(fp)
    for r in pt.get("relationships") or []:
        if r.get("full_product_name"):
            take(r["full_product_name"])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf-repo", required=True)
    a = ap.parse_args()

    idx = collections.defaultdict(lambda: {"products": set(), "cves": set(),
                                           "advisories": set()})
    ndoc = nmodel = 0
    for dp, _dn, fns in os.walk(a.csaf_repo):
        if ".git" in dp.replace("\\", "/").split("/"):
            continue
        for fn in fns:
            if not fn.endswith(".json"):
                continue
            try:
                d = json.load(open(os.path.join(dp, fn), encoding="utf-8"))
            except Exception:
                continue
            prods = products_of(d)
            if not prods:
                continue
            ndoc += 1
            aid = ((d.get("document") or {}).get("tracking") or {}).get("id") or fn
            # only `known_affected` - the advisory asserting this product IS
            # affected. Other statuses are not a finding.
            for v in d.get("vulnerabilities") or []:
                cve = v.get("cve")
                if not cve:
                    continue
                for pid in (v.get("product_status") or {}).get("known_affected") or []:
                    name, models, _cpe = prods.get(pid, ("", [], None))
                    for m in models:
                        e = idx[m]
                        e["products"].add(name)
                        e["cves"].add(cve)
                        e["advisories"].add(aid)
                        nmodel += 1

    out = {m: {"products": sorted(v["products"])[:6],
               "cves": sorted(v["cves"]),
               "advisories": sorted(v["advisories"])}
           for m, v in idx.items()}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    ncve = len({c for v in out.values() for c in v["cves"]})
    multi = sum(1 for v in out.values() if len(v["advisories"]) > 1)
    print("== model -> CVE index ==")
    print("   documents scanned      %d" % ndoc)
    print("   distinct model numbers %d" % len(out))
    print("   distinct CVEs          %d" % ncve)
    print("   models in >1 advisory  %d" % multi)
    print("   CVEs per model: median %d, max %d"
          % (sorted(len(v["cves"]) for v in out.values())[len(out) // 2] if out else 0,
             max((len(v["cves"]) for v in out.values()), default=0)))
    print("->", OUT)


if __name__ == "__main__":
    main()
