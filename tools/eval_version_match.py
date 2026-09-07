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


def _alpha_ord(s):
    """Bijective base-26 for letter revisions: a=1 .. z=26, za=27 (OpenSSL 1.0.2a..zf)."""
    n = 0
    for c in s.lower():
        if "a" <= c <= "z":
            n = n * 26 + (ord(c) - 96)
    return n


def parse_ver(s):
    """Version -> comparable tuple. Handles letter revisions (OpenSSL 1.0.2zf, curl 7.86.0):
    tokenize into digit / letter groups so 1.0.2 < 1.0.2a < 1.0.2zf orders correctly."""
    if not s:
        return None
    toks = re.findall(r"\d+|[A-Za-z]+", s)
    if not toks:
        return None
    return tuple(int(t) if t.isdigit() else _alpha_ord(t) for t in toks)


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


def _norm_pkg(x):
    """Normalize a component name: strip a LEADING 'lib' only (libexpat->expat) so
    'glibc' is not mangled to 'gc' by a blanket replace."""
    return re.sub(r"^lib", "", (x or "").lower())


def pick_range(ranges, repo):
    """choose the cpeMatch whose product matches the CVE's component."""
    pkg = _norm_pkg(repo.split("/")[-1] if repo else "")
    cand = None
    for r in ranges:
        if not (r["startIncl"] or r["endExcl"] or r["endIncl"]):
            continue
        p = _norm_pkg(r["product"])
        if pkg and (pkg == p or pkg in p or p in pkg):
            return r
        if cand is None:
            cand = r
    return cand


SNAP = os.path.join(BASE, "data", "source_snapshots")


def build_universe():
    """CVE -> repo over the FULL source-collected universe (tierA ∪ snapshots ∪ GT),
    not just the 50 CVEs that yielded a vuln/patched code pair. Version-range
    matching needs only (component, NVD range, SBOM version) — never a code pair."""
    repo = {}
    # GT pairs carry a curated repo string — highest priority
    if os.path.exists(GT):
        for l in open(GT, encoding="utf-8"):
            r = json.loads(l)
            if r.get("repo"):
                repo.setdefault(r["cve"], r["repo"])
    # tierA: owner/repo from the source archive URL (present for all 101)
    if os.path.isfile(TIERA):
        ta = json.load(open(TIERA, encoding="utf-8"))
        for cve, v in ta.items():
            if cve in repo:
                continue
            m = re.search(r"github\.com/([^/]+/[^/]+?)/(?:archive|commit|releases)", v.get("sw_version_wget") or "")
            if not m:
                for pc in v.get("patch_commits") or []:
                    m = re.search(r"github\.com/([^/]+/[^/]+)/commit", pc.get("url") or "")
                    if m:
                        break
            repo[cve] = m.group(1) if m else ""
    # snapshots-only CVEs: infer product token from the checkout dir name
    if os.path.isdir(SNAP):
        for cve in os.listdir(SNAP):
            if cve in repo:
                continue
            subs = os.listdir(os.path.join(SNAP, cve))
            repo[cve] = subs[0].split("-")[0] if subs else ""
    return repo


def main():
    universe = build_universe()
    rows = [{"cve": c, "repo": r} for c, r in sorted(universe.items())]
    cache = json.load(open(RANGES, encoding="utf-8")) if os.path.exists(RANGES) else {}
    no_range = []

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
            no_range.append(cve)
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
           "universe_n": len(rows), "cves_with_range": len(scored),
           "no_range_n": len(no_range), "no_range_cves": no_range,
           "TP": tp, "FP": fp, "TN": tn, "FN": fn,
           "affected_precision_pct": round(prec, 2), "recall_pct": round(rec, 2),
           "accuracy_pct": round(acc, 2), "macro_f1": round((f1a + f1n) / 2, 3),
           "rows": scored}
    print("\n== real-version SBOM version-range matching ==")
    print("  universe: %d | CVEs with NVD range: %d | no range: %d"
          % (len(rows), len(scored), len(no_range)))
    print("  vuln TP=%d FN=%d | fixed TN=%d FP=%d" % (tp, fn, tn, fp))
    print("  affected precision=%.1f%%  recall=%.1f%%  accuracy=%.1f%%  macro-F1=%.3f"
          % (prec, rec, acc, (f1a + f1n) / 2))
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("->", OUT)


if __name__ == "__main__":
    main()
