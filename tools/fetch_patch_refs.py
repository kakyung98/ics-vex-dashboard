#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Find each CVE's fix commit from its NVD references.

Why this exists: tools/fetch_nvd.py keeps only the FIRST SIX references per CVE
(`references[:6]`), and NVD does not order them usefully - the commit link is
usually further down. Of 104 snapshot CVEs only 4 had a commit URL in that
cache, which is what capped target localization, not the forge a project uses
(nearly all of these projects are on GitHub).

Here the full reference list is fetched and every commit-shaped URL kept, with
NVD's own "Patch" tag recorded when present. Handles the forges this corpus
actually uses: GitHub, GitLab, cgit/gitweb (git.kernel.org, sourceware,
busybox), and Fossil (sqlite).

Output: data/patch_refs.json  {CVE: [{"url", "tags", "kind"}]}
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
TARGETS = os.path.join(BASE, "data", "vuln_targets.json")
OUT = os.path.join(BASE, "data", "patch_refs.json")
API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
UA = {"User-Agent": "ics-vex-research/1.0"}
DELAY = 6.5          # NVD allows 5 requests / 30s without an API key
MAX_RETRY = 4

COMMIT_PATTERNS = [
    ("github", re.compile(r"github\.com/[^/\s]+/[^/\s]+/commit/[0-9a-f]{7,40}")),
    ("gitlab", re.compile(r"gitlab\.[^/\s]+/[^\s]+/-/commit/[0-9a-f]{7,40}")),
    ("cgit", re.compile(r"(?:cgit|git)\.[^/\s]+/[^\s]*commit/?\?id=[0-9a-f]{7,40}")),
    ("gitweb", re.compile(r"[^\s]*gitweb[^\s]*[?;]a=commit[^\s]*h=[0-9a-f]{7,40}")),
    ("fossil", re.compile(r"sqlite\.org/src/info/[0-9a-f]{8,40}")),
    ("github_pr", re.compile(r"github\.com/[^/\s]+/[^/\s]+/pull/\d+")),
]


def commit_kind(url):
    for kind, pat in COMMIT_PATTERNS:
        if pat.search(url or ""):
            return kind
    return None


def fetch(cve_id):
    req = urllib.request.Request(API % cve_id, headers=UA)
    for attempt in range(MAX_RETRY):
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                payload = json.load(resp)
            items = payload.get("vulnerabilities", [])
            if not items:
                return None
            return items[0]["cve"].get("references", [])
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                wait = DELAY * (attempt + 2)
                print("  rate %s (%s) sleep %.0fs" % (cve_id, e.code, wait), flush=True)
                time.sleep(wait)
                continue
            print("  %s http-%d" % (cve_id, e.code), flush=True)
            return None
        except Exception as e:
            wait = DELAY * (attempt + 2)
            print("  retry %s (%s) sleep %.0fs" % (cve_id, type(e).__name__, wait), flush=True)
            time.sleep(wait)
    return None


def main():
    only_missing = "--all" not in sys.argv
    known = json.load(open(TARGETS, encoding="utf-8")) if os.path.exists(TARGETS) else {}
    out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}

    cves = sorted(d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, d)))
    if only_missing:
        cves = [c for c in cves if not (known.get(c) or {}).get("targets")]
    todo = [c for c in cves if c not in out]
    print("== %d CVEs to query (%d already cached) ==" % (len(todo), len(cves) - len(todo)))

    for cve in todo:
        refs = fetch(cve)
        time.sleep(DELAY)
        if refs is None:
            continue
        hits = []
        for r in refs:
            url = r.get("url") or ""
            kind = commit_kind(url)
            if kind:
                hits.append({"url": url, "tags": r.get("tags") or [], "kind": kind})
        out[cve] = hits
        json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("%-18s refs=%-3d commit-links=%d %s" %
              (cve, len(refs), len(hits),
               sorted({h["kind"] for h in hits}) if hits else ""), flush=True)

    got = sum(1 for c in cves if out.get(c))
    print("\n== %d / %d CVEs have at least one commit-shaped reference ==" % (got, len(cves)))
    print("->", OUT)


if __name__ == "__main__":
    main()
