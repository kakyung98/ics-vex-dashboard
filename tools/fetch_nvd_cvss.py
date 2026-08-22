#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch CVSS base scores from the NVD API 2.0 for corpus CVEs that lack one.

Pulls per-CVE CVSS (v3.1 -> v3.0 -> v2 fallback) and severity/vector from NVD and
caches them in data/nvd_cvss.json  { CVE: {score, severity, vector, ver} }.
Resumable (skips CVEs already cached). API key from env NVD_API_KEY (never stored).

Run:
  NVD_API_KEY=<key> python tools/fetch_nvd_cvss.py            # only CVEs missing a score
  NVD_API_KEY=<key> python tools/fetch_nvd_cvss.py --all      # refresh every corpus CVE
"""
import os, sys, csv, json, time, argparse, urllib.request, urllib.error

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(BASE, "data")
OUT = os.path.join(DATA, "nvd_cvss.json")
API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
KEY = os.environ.get("NVD_API_KEY", "").strip()


def corpus_cves():
    cves = []
    seen = set()
    fp = os.path.join(DATA, "findings.csv")
    for r in csv.DictReader(open(fp, encoding="utf-8-sig")):
        c = (r.get("cve") or "").strip()
        if c and c not in seen:
            seen.add(c); cves.append(c)
    return cves


def already_scored():
    have = set()
    nvd = os.path.join(DATA, "nvd_cache.json")
    if os.path.exists(nvd):
        for c, e in json.load(open(nvd, encoding="utf-8")).items():
            if isinstance(e, dict) and (e.get("metric") or {}).get("score") is not None:
                have.add(c)
    adv = os.path.join(DATA, "cisa_advisories.json")
    if os.path.exists(adv):
        for a in json.load(open(adv, encoding="utf-8")).values():
            for vu in (a.get("vulns") or []):
                if vu.get("cvss_v3_score") is not None or vu.get("cvss_v4_score") is not None:
                    have.add(vu.get("cve"))
    for r in csv.DictReader(open(os.path.join(DATA, "findings.csv"), encoding="utf-8-sig")):
        if r.get("cvss_v3_score"):
            have.add(r["cve"])
    return have


def parse_metrics(cve_obj):
    m = cve_obj.get("metrics", {}) or {}
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        arr = m.get(key)
        if arr:
            dd = arr[0].get("cvssData", {})
            return dd.get("baseScore"), (dd.get("baseSeverity") or "").lower(), dd.get("vectorString", ""), ver
    arr = m.get("cvssMetricV2")
    if arr:
        dd = arr[0].get("cvssData", {})
        return dd.get("baseScore"), (arr[0].get("baseSeverity") or "").lower(), dd.get("vectorString", ""), "2.0"
    return None, "", "", ""


def fetch(cve, tries=4):
    req = urllib.request.Request(API + cve, headers={"apiKey": KEY, "User-Agent": "ics-vex/1.0"} if KEY else {"User-Agent": "ics-vex/1.0"})
    for a in range(tries):
        try:
            r = urllib.request.urlopen(req, timeout=30)
            d = json.loads(r.read().decode("utf-8"))
            vs = d.get("vulnerabilities") or []
            if not vs:
                return {"score": None, "severity": "", "vector": "", "ver": "", "nf": True}
            sc, sev, vec, ver = parse_metrics(vs[0].get("cve", {}))
            return {"score": sc, "severity": sev, "vector": vec, "ver": ver}
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                time.sleep(6 * (a + 1)); continue
            if e.code == 404:
                return {"score": None, "severity": "", "vector": "", "ver": "", "nf": True}
            time.sleep(2 * (a + 1))
        except Exception:
            time.sleep(2 * (a + 1))
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    if not KEY:
        print("WARNING: NVD_API_KEY not set — public rate limit (5/30s) applies", flush=True)
    cache = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    allc = corpus_cves()
    skip = set() if a.all else already_scored()
    todo = [c for c in allc if c not in cache and c not in skip]
    if a.limit:
        todo = todo[:a.limit]
    print("corpus %d | already-scored %d | cached %d | TODO %d" % (len(allc), len(skip), len(cache), len(todo)), flush=True)
    delay = 0.65 if KEY else 6.5
    got = 0
    for i, cve in enumerate(todo, 1):
        res = fetch(cve)
        if res is not None:
            cache[cve] = res
            if res.get("score") is not None:
                got += 1
        if i % 50 == 0 or i == len(todo):
            json.dump(cache, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
            print("[%d/%d] cached=%d with_score=%d" % (i, len(todo), len(cache), got), flush=True)
        time.sleep(delay)
    json.dump(cache, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    print("DONE. cache=%d new_scores=%d -> %s" % (len(cache), got, os.path.relpath(OUT, BASE)), flush=True)


if __name__ == "__main__":
    main()
