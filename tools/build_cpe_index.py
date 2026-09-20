#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L0 — build a product -> CVE identity index from NVD, keeping the CPE detail
the census threw away.

survey_cpe_all.py scans the whole of NVD with the bulk endpoint (2000/page,
~145 calls) and keeps only {cpe count, ranged count, vendors[:4]} per ICSA CVE.
That is enough to *count* CPE coverage but not to *identify* CVEs from an SBOM
component: identification needs the PRODUCT token and its version bound, which
summarize() discards.

This tool reuses the same bulk scan but keeps, per vulnerable cpeMatch, the full
(vendor, product, version, bounds). It inverts to product -> [CVE entries], the
expanded knowledge base the analyzer matches against (L0), and it carries the
vendor on every entry so the L3 co-listing / vendor-anchoring guards have the
evidence they need.

Output: data/cpe_index.json
  { "generated_products": N, "generated_cves": M,
    "by_product": { "<product>": [ {cve, vendor, version, startIncl, startExcl,
                                     endIncl, endExcl}, ... ], ... },
    "cve_vendors": { "<CVE>": ["vendor", ...] } }      # full vendor set per CVE

Run:  python tools/build_cpe_index.py            # 6.5s/page anonymous (~13 min)
      NVD_API_KEY=... python tools/build_cpe_index.py   # 0.7s/page (~2 min)
"""
import collections
import json
import os
import time
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "cpe_index.json")
RAW = os.path.join(BASE, "data", "nvd_cpe_detail.json")   # per-CVE detail cache (resumable)
EP = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=%d"
UA = {"User-Agent": "ics-vex-research/1.0"}

_UNPINNED = {"*", "-", "", None}


def fetch(url, key, tries=5):
    h = dict(UA)
    if key:
        h["apiKey"] = key
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h),
                                        timeout=120) as r:
                return json.load(r)
        except Exception as e:
            wait = 8 * (i + 1)
            print("   retry (%s) sleep %ds" % (type(e).__name__, wait), flush=True)
            time.sleep(wait)
    return None


def detail(cve):
    """[{vendor, product, version, startIncl, startExcl, endIncl, endExcl}] for
    every vulnerable cpeMatch. version is the exact pinned version or None (*)."""
    out = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                p = (m.get("criteria") or "").split(":")
                if len(p) < 6:
                    continue
                ver = p[5]
                out.append({
                    "vendor": p[3], "product": p[4],
                    "version": None if ver in _UNPINNED else ver,
                    "startIncl": m.get("versionStartIncluding"),
                    "startExcl": m.get("versionStartExcluding"),
                    "endIncl": m.get("versionEndIncluding"),
                    "endExcl": m.get("versionEndExcluding"),
                })
    return out


def main():
    key = os.environ.get("NVD_API_KEY")
    delay = 0.7 if key else 6.5

    adv = json.load(open(os.path.join(BASE, "data", "cisa_advisories.json"), encoding="utf-8"))
    ours = {c for x in adv.values() for c in (x.get("cves") or [])}
    print("ICSA CVE population: %d | api key: %s" % (len(ours), bool(key)), flush=True)

    # resumable per-CVE detail cache
    got = json.load(open(RAW, encoding="utf-8")) if os.path.exists(RAW) else {}
    print("detail cache: %d CVEs already fetched" % len(got), flush=True)

    idx, total = 0, None
    while total is None or idx < total:
        d = fetch(EP % idx, key)
        if d is None:
            print("giving up at startIndex=%d" % idx, flush=True)
            break
        total = d.get("totalResults", 0)
        items = d.get("vulnerabilities") or []
        for it in items:
            c = it.get("cve") or {}
            cid = c.get("id")
            if cid in ours:
                got[cid] = detail(c)
        idx += len(items) or 2000
        print("  %6d / %6d   matched %d" % (idx, total, len(got)), flush=True)
        json.dump(got, open(RAW, "w", encoding="utf-8"), ensure_ascii=False)
        time.sleep(delay)

    # invert to product -> [CVE entries]; collect full vendor set per CVE
    by_product = collections.defaultdict(list)
    cve_vendors = {}
    for cve, entries in got.items():
        vs = set()
        for e in entries:
            vs.add(e["vendor"])
            by_product[e["product"]].append(dict(e, cve=cve))
        cve_vendors[cve] = sorted(vs)

    out = {"generated_products": len(by_product), "generated_cves": len(got),
           "by_product": by_product, "cve_vendors": cve_vendors}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    print("\nwrote %s: %d products, %d CVEs" % (OUT, len(by_product), len(got)), flush=True)


if __name__ == "__main__":
    main()
