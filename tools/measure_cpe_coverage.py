#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""How many of our ICSA CVEs actually carry a CPE in NVD?

The CSAF side is already measured: 47 of 28,631 OT products (0.2%) carry a CPE.
But that is the ADVISORY's own identification. NVD separately publishes a
`configurations` block per CVE, and that is what a CPE-normalizing matcher would
consult. The two are not the same question, and the second one decides whether
CPE normalization is viable at all for this corpus.

Sampled rather than exhaustive: NVD allows 5 requests / 30s without a key, so
11,336 CVEs would take ~19 hours. A random sample with a fixed seed answers the
question to within a few points.

Output: results/cpe_coverage.json
"""
import argparse
import collections
import json
import os
import random
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "results", "cpe_coverage.json")
API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
UA = {"User-Agent": "ics-vex-research/1.0"}
DELAY = 6.5
SEED = 20260910


def cpes_of(cve):
    """(n_cpe_criteria, n_with_version_range, vendors) from NVD configurations."""
    n = ranged = 0
    vendors = set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                n += 1
                parts = (m.get("criteria") or "").split(":")
                if len(parts) > 4:
                    vendors.add(parts[3])
                if any(m.get(k) for k in ("versionStartIncluding", "versionStartExcluding",
                                          "versionEndIncluding", "versionEndExcluding")):
                    ranged += 1
    return n, ranged, vendors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=60)
    a = ap.parse_args()

    adv = json.load(open(os.path.join(BASE, "data", "cisa_advisories.json"), encoding="utf-8"))
    ours = sorted({c for x in adv.values() for c in (x.get("cves") or [])})
    random.seed(SEED)
    pick = random.sample(ours, min(a.sample, len(ours)))
    print("ICSA CVE population: %d | sampling %d" % (len(ours), len(pick)))

    rows, vend = [], collections.Counter()
    for cve in pick:
        try:
            with urllib.request.urlopen(urllib.request.Request(API % cve, headers=UA),
                                        timeout=45) as r:
                items = json.load(r).get("vulnerabilities") or []
        except Exception as e:
            print("  %-18s !! %s" % (cve, type(e).__name__))
            time.sleep(DELAY)
            continue
        time.sleep(DELAY)
        if not items:
            rows.append({"cve": cve, "cpe": 0, "ranged": 0, "status": "not-in-nvd"})
            print("  %-18s not in NVD" % cve)
            continue
        n, ranged, vs = cpes_of(items[0]["cve"])
        vend.update(vs)
        rows.append({"cve": cve, "cpe": n, "ranged": ranged, "status": "ok"})
        print("  %-18s cpe=%-4d ranged=%-4d %s" % (cve, n, ranged, sorted(vs)[:2]), flush=True)

    ok = [r for r in rows if r["status"] == "ok"]
    withcpe = [r for r in ok if r["cpe"] > 0]
    withrange = [r for r in ok if r["ranged"] > 0]
    res = {"population": len(ours), "sampled": len(rows), "resolved": len(ok),
           "with_any_cpe": len(withcpe), "with_version_range": len(withrange),
           "pct_with_cpe": round(100 * len(withcpe) / max(len(ok), 1), 1),
           "pct_with_range": round(100 * len(withrange) / max(len(ok), 1), 1),
           "top_vendors": vend.most_common(12), "seed": SEED, "rows": rows}
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("\n== NVD CPE coverage over ICSA CVEs (sample n=%d) ==" % len(ok))
    print("   with at least one CPE   %d  (%.1f%%)" % (len(withcpe), res["pct_with_cpe"]))
    print("   with a version range    %d  (%.1f%%)" % (len(withrange), res["pct_with_range"]))
    print("   top CPE vendors         %s" % vend.most_common(6))
    print("->", OUT)


if __name__ == "__main__":
    main()
