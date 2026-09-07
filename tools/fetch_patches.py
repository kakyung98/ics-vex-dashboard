#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch the full fix-commit diffs for the source-snapshot CVEs.

The cached patch blobs in the tier-A dataset are truncated at 6000 chars, which
drops the actual source hunks (only the alphabetically-first build/doc files
survive). extract_vuln_funcs.py needs the real diff to find the vulnerable
function, so pull each commit's .patch once and cache it in the repo.

Output: data/patches/<CVE>/<sha>.diff
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
OUTD = os.path.join(BASE, "data", "patches")
TIERA = os.environ.get("TIERA_JSON",
                       r"C:\Users\user\Desktop\cve-genie\webapp\data\icsvex_tierA.json")
UA = {"User-Agent": "Mozilla/5.0 (ICS-VEX patch fetcher)"}
COMMIT_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-f]{7,40})")


def patch_urls(v):
    """(sha, .patch URL) for every GitHub fix commit referenced by a tier-A row."""
    out = []
    for pc in v.get("patch_commits") or []:
        m = COMMIT_RE.search(pc.get("url") or "")
        if m:
            owner, repo, sha = m.groups()
            out.append((sha, "https://github.com/%s/%s/commit/%s.patch" % (owner, repo, sha)))
    return out


def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def main():
    tier = json.load(open(TIERA, encoding="utf-8"))
    snaps = {d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, d))}
    ok = miss = err = cached = 0
    for cve in sorted(snaps):
        urls = patch_urls(tier.get(cve, {}))
        if not urls:
            print("%-18s -- no commit URL" % cve)
            miss += 1
            continue
        d = os.path.join(OUTD, cve)
        os.makedirs(d, exist_ok=True)
        got = 0
        for sha, url in urls:
            dst = os.path.join(d, sha + ".diff")
            if os.path.exists(dst) and os.path.getsize(dst) > 0:
                cached += 1
                got += 1
                continue
            try:
                txt = fetch(url)
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                print("%-18s !! %s %s" % (cve, sha[:10], str(e)[:60]))
                err += 1
                continue
            open(dst, "w", encoding="utf-8", newline="\n").write(txt)
            got += 1
            print("%-18s -> %s  %d bytes" % (cve, sha[:10], len(txt)))
            time.sleep(0.7)  # be polite to github.com
        if got:
            ok += 1
    print("\n== %d CVEs with a cached diff (%d files already present, %d no URL, %d errors) =="
          % (ok, cached, miss, err))
    print("->", OUTD)


if __name__ == "__main__":
    sys.exit(main())
