#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Real-version SBOM + NVD version-range matching — VEX precision.

The code-only judge cannot tell a vulnerable function from its patched version
(they differ by a few lines). VEX 'not_affected because fixed' is a VERSION fact:
compare the SBOM component version to the CVE's affected range (NVD CPE).

For each ICS CVE we:
  1. fetch NVD -> affected range [versionStartIncluding, versionEndExcluding) for
     the CVE's component (matched to the upstream repo/package name).
  2. build two real-version SBOM entries:
       affected     : a version inside the range        -> gold affected
       not_affected : the fixed version (endExcluding)  -> gold not_affected
  3. decide by version-range matching and score precision / F1.

Output: results/version_match.json  + data/cve_version_ranges.json (cache)
"""
import json
import os
import re
import time
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT = os.path.join(BASE, "data", "ics_gt_pairs.jsonl")
CE = os.path.join(BASE, "data", "code_evidence.json")
TIERA = os.environ.get("TIERA_JSON", r"C:\Users\user\Desktop\cve-genie\webapp\data\icsvex_tierA.json")
RANGES = os.path.join(BASE, "data", "cve_version_ranges.json")
OUT = os.path.join(BASE, "results", "version_match.json")
UA = {"User-Agent": "Mozilla/5.0"}


def parse_ver(s):
    """Loose numeric version -> tuple for comparison."""
    if not s:
        return None
    nums = re.findall(r"\d+", s)
    return tuple(int(x) for x in nums) if nums else None


def cmp_ver(a, b):
    a, b = parse_ver(a), parse_ver(b)
    if a is None or b is None:
        return None
    la = a + (0,) * (len(b) - len(a))
    lb = b + (0,) * (len(a) - len(b))
    return -1 if la < lb else (1 if la > lb else 0)


def in_affected(ver, start_incl, end_excl, end_incl):
    """version-range match: is `ver` in the affected range?"""
    if start_incl and cmp_ver(ver, start_incl) is not None and cmp_ver(ver, start_incl) < 0:
        return False
    if end_excl and cmp_ver(ver, end_excl) is not None and cmp_ver(ver, end_excl) >= 0:
        return False
    if end_incl and cmp_ver(ver, end_incl) is not None and cmp_ver(ver, end_incl) > 0:
        return False
    return True


def nvd_ranges(cve):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
    d = json.loads(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=25).read().decode("utf-8", "ignore"))
    vulns = d.get("vulnerabilities", [])
    if not vulns:
        return []
    out = []
    for cfg in vulns[0]["cve"].get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m.get("criteria", "").split(":")
                prod = parts[4] if len(parts) > 4 else ""
                out.append({"product": prod,
                            "startIncl": m.get("versionStartIncluding"),
                            "endExcl": m.get("versionEndExcluding"),
                            "endIncl": m.get("versionEndIncluding")})
    return out


def pick_range(ranges, repo):
    """choose the cpeMatch whose product matches the CVE's component."""
    pkg = (repo.split("/")[-1] if repo else "").lower().replace("lib", "")
    cand = None
    for r in ranges:
        p = (r["product"] or "").lower()
        if not (r["startIncl"] or r["endExcl"] or r["endIncl"]):
            continue
        if pkg and (pkg in p or p in pkg or p.replace("lib", "") == pkg):
            return r
        if cand is None:
            cand = r
    return cand


def main():
    rows = [json.loads(l) for l in open(GT, encoding="utf-8")]
    cache = json.load(open(RANGES, encoding="utf-8")) if os.path.exists(RANGES) else {}

    scored = []
    tp = fp = tn = fn = 0
    for r in rows:
        cve, repo = r["cve"], r.get("repo", "")
        if cve not in cache:
            try:
                cache[cve] = nvd_ranges(cve)
                json.dump(cache, open(RANGES, "w", encoding="utf-8"), ensure_ascii=False)
                time.sleep(6.5)          # NVD rate limit (5 req / 30s)
            except Exception as e:
                cache[cve] = []
                print("  %-18s NVD fail %s" % (cve, str(e)[:40]))
                time.sleep(6.5)
        rg = pick_range(cache[cve], repo)
        if not rg or not (rg.get("startIncl") or rg.get("endExcl") or rg.get("endIncl")):
            print("  %-18s no version range" % cve)
            continue
        # real-version SBOM entries
        fixed = rg.get("endExcl")
        aff_ver = rg.get("startIncl") or (fixed and re.sub(r"\d+$", lambda m: str(max(int(m.group()) - 1, 0)), fixed)) or "0"
        # gold affected: a version inside the range ; gold not_affected: the fixed version
        pred_aff = "affected" if in_affected(aff_ver, rg.get("startIncl"), rg.get("endExcl"), rg.get("endIncl")) else "not_affected"
        pred_fix = "affected" if (fixed and in_affected(fixed, rg.get("startIncl"), rg.get("endExcl"), rg.get("endIncl"))) else "not_affected"
        if pred_aff == "affected":
            tp += 1
        else:
            fn += 1
        if fixed:
            if pred_fix == "not_affected":
                tn += 1
            else:
                fp += 1
        scored.append({"cve": cve, "component": rg["product"], "affected_ver": aff_ver,
                       "fixed_ver": fixed, "pred_affected": pred_aff, "pred_fixed": pred_fix})
        print("  %-18s %-12s aff@%-10s->%-12s fixed@%-10s->%s"
              % (cve, rg["product"], aff_ver, pred_aff, fixed, pred_fix), flush=True)

    n = tp + fn + tn + fp
    prec = 100.0 * tp / (tp + fp) if (tp + fp) else 0.0
    rec = 100.0 * tp / (tp + fn) if (tp + fn) else 0.0
    acc = 100.0 * (tp + tn) / n if n else 0.0
    f1a = 2.0 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0
    f1n = 2.0 * tn / (2 * tn + fn + fp) if (2 * tn + fn + fp) else 0.0
    res = {"method": "real-version SBOM + NVD version-range matching",
           "cves_with_range": len(scored), "TP": tp, "FP": fp, "TN": tn, "FN": fn,
           "affected_precision_pct": round(prec, 2), "recall_pct": round(rec, 2),
           "accuracy_pct": round(acc, 2), "macro_f1": round((f1a + f1n) / 2, 3),
           "rows": scored}
    print("\n== real-version SBOM version-range matching ==")
    print("  CVEs with NVD range: %d" % len(scored))
    print("  vuln TP=%d FN=%d | fixed TN=%d FP=%d" % (tp, fn, tn, fp))
    print("  affected precision=%.1f%%  recall=%.1f%%  accuracy=%.1f%%  macro-F1=%.3f"
          % (prec, rec, acc, (f1a + f1n) / 2))
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", OUT)


if __name__ == "__main__":
    main()
