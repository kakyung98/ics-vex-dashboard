#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full census of NVD CPE coverage over every ICSA CVE.

The sampled version answered "roughly how many", but the number decides whether
CPE normalization is viable at all for this corpus, so it is worth the exact
figure. Per-CVE queries would take ~19 h at the anonymous rate limit; the bulk
endpoint returns 2,000 records per request, so the whole of NVD is ~145 calls.
Everything is filtered locally afterwards.

Two distinct things get counted, because they are different claims:
  has_cpe    NVD attaches at least one vulnerable cpeMatch to this CVE
  has_range  at least one of those carries a version bound, which is what makes
             a match decidable rather than "this product, some version"

Output: results/cpe_census.json
"""
import argparse
import collections
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "results", "cpe_census.json")
CACHE = os.path.join(BASE, "data", "nvd_cpe_raw.json")
EP = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=%d"
UA = {"User-Agent": "ics-vex-research/1.0"}


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


def summarize(cve):
    n = ranged = 0
    vendors = set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                n += 1
                p = (m.get("criteria") or "").split(":")
                if len(p) > 3:
                    vendors.add(p[3])
                if any(m.get(k) for k in ("versionStartIncluding", "versionStartExcluding",
                                          "versionEndIncluding", "versionEndExcluding")):
                    ranged += 1
    return n, ranged, sorted(vendors)[:4]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=6.5,
                    help="6.5 anonymous, 0.7 with NVD_API_KEY")
    a = ap.parse_args()
    key = os.environ.get("NVD_API_KEY")
    delay = 0.7 if key else a.delay

    adv = json.load(open(os.path.join(BASE, "data", "cisa_advisories.json"), encoding="utf-8"))
    ours = {c for x in adv.values() for c in (x.get("cves") or [])}
    print("ICSA CVE population: %d | api key: %s" % (len(ours), bool(key)))

    got = json.load(open(CACHE, encoding="utf-8")) if os.path.exists(CACHE) else {}
    print("cache: %d CVEs already summarised" % len(got))

    idx, total = 0, None
    while total is None or idx < total:
        d = fetch(EP % idx, key)
        if d is None:
            print("giving up at startIndex=%d" % idx)
            break
        total = d.get("totalResults", 0)
        items = d.get("vulnerabilities") or []
        for it in items:
            c = it.get("cve") or {}
            cid = c.get("id")
            if cid in ours:
                n, ranged, v = summarize(c)
                got[cid] = {"cpe": n, "ranged": ranged, "vendors": v}
        idx += len(items) or 2000
        print("  %6d / %6d   matched so far %d" % (idx, total, len(got)), flush=True)
        json.dump(got, open(CACHE, "w", encoding="utf-8"), ensure_ascii=False)
        time.sleep(delay)

    seen = set(got)
    withcpe = [c for c in seen if got[c]["cpe"] > 0]
    withrange = [c for c in seen if got[c]["ranged"] > 0]
    vend = collections.Counter(v for c in seen for v in got[c]["vendors"])
    res = {"population": len(ours), "found_in_nvd": len(seen),
           "missing_from_nvd": len(ours - seen),
           "with_any_cpe": len(withcpe), "with_version_range": len(withrange),
           "pct_with_cpe": round(100 * len(withcpe) / max(len(seen), 1), 2),
           "pct_with_range": round(100 * len(withrange) / max(len(seen), 1), 2),
           "top_vendors": vend.most_common(25)}
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("\n== NVD CPE census over ICSA CVEs ==")
    for k in ("population", "found_in_nvd", "missing_from_nvd", "with_any_cpe",
              "with_version_range", "pct_with_cpe", "pct_with_range"):
        print("   %-22s %s" % (k, res[k]))
    print("   top vendors: %s" % vend.most_common(8))
    print("->", OUT)


if __name__ == "__main__":
    main()
