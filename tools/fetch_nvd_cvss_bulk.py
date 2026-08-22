#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bulk-fetch CVSS from NVD API 2.0 by paging the full feed (2000/request) and
keeping only our corpus CVEs. Far fewer requests than per-CVE (≈125 vs ≈9000).

Merges into data/nvd_cvss.json { CVE: {score, severity, vector, ver} }.
API key from env NVD_API_KEY (never stored). Resumable via startIndex checkpoint
in data/nvd_cvss.json under key "__cursor__".

Run:  NVD_API_KEY=<key> python tools/fetch_nvd_cvss_bulk.py
"""
import os, sys, csv, json, time, urllib.request, urllib.error

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(BASE, "data")
OUT = os.path.join(DATA, "nvd_cvss.json")
KEY = os.environ.get("NVD_API_KEY", "").strip()
EP = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=%d"


def corpus():
    s = set()
    for r in csv.DictReader(open(os.path.join(DATA, "findings.csv"), encoding="utf-8-sig")):
        c = (r.get("cve") or "").strip()
        if c:
            s.add(c)
    return s


def metrics(cve_obj):
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


def get(idx, tries=5):
    req = urllib.request.Request(EP % idx,
        headers={"apiKey": KEY, "User-Agent": "ics-vex/1.0"} if KEY else {"User-Agent": "ics-vex/1.0"})
    for a in range(tries):
        try:
            return json.loads(urllib.request.urlopen(req, timeout=60).read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                time.sleep(8 * (a + 1)); continue
            time.sleep(3 * (a + 1))
        except Exception:
            time.sleep(3 * (a + 1))
    return None


def main():
    if not KEY:
        print("WARNING: NVD_API_KEY not set — very slow public limit", flush=True)
    corp = corpus()
    cache = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    idx = int(cache.pop("__cursor__", 0))
    total = None
    hits = sum(1 for k, v in cache.items() if isinstance(v, dict) and v.get("score") is not None)
    delay = 0.65 if KEY else 6.5
    while True:
        d = get(idx)
        if d is None:
            print("stop: request failed at idx", idx, flush=True); break
        if total is None:
            total = d.get("totalResults", 0)
            print("NVD totalResults=%d | corpus=%d | resuming idx=%d" % (total, len(corp), idx), flush=True)
        for v in d.get("vulnerabilities", []):
            co = v.get("cve", {})
            cid = co.get("id")
            if cid in corp and cid not in cache:
                sc, sev, vec, ver = metrics(co)
                cache[cid] = {"score": sc, "severity": sev, "vector": vec, "ver": ver}
                if sc is not None:
                    hits += 1
        idx += 2000
        cache["__cursor__"] = idx
        json.dump(cache, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
        got = len([k for k in cache if k != "__cursor__"])
        print("idx=%d/%d | corpus cached=%d with_score=%d" % (idx, total, got, hits), flush=True)
        if idx >= total:
            break
        time.sleep(delay)
    cache.pop("__cursor__", None)
    json.dump(cache, open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    got = len(cache)
    print("DONE. corpus CVEs cached=%d with_score=%d" % (got, hits), flush=True)


if __name__ == "__main__":
    main()
