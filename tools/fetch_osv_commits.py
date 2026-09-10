#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recover fix commits from OSV.dev for CVEs whose NVD references have none.

36 of the unlocated CVEs cite only distro advisories and mailing lists in NVD,
so the obvious next step looked like a parser per project (curl's vuln.json,
OpenSSL's advisories, ...). It is not needed: curl publishes in OSV format, and
OSV.dev aggregates the same data for the other projects here. An OSV record's
GIT range carries the `fixed` commit SHA directly, which is exactly the evidence
path A wants — one API, no per-project scraping.

NEGATIVE RESULT - this does not work, and the tool is kept only to document why.
OSV's GIT `fixed` event marks the *version boundary* at which a range stops being
vulnerable, not the commit that fixed it. In practice that is the release commit:
curl CVE-2022-32221 resolves to cd95ee9f7713 ("RELEASE: synced, the 7.86.0
release") and OpenSSL's resolve to commits touching only CHANGES/NEWS/VERSION.dat.
None of the 24 CVEs this recovered a link for gained a target.

The `references[type=FIX]` field is no better - OSV tags Oracle advisory pages
FIX. So OSV cannot supply path-A evidence for this corpus; the remaining CVEs
need a per-project source that publishes CVE -> commit directly.
"""
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
TARGETS = os.path.join(BASE, "data", "vuln_targets.json")
REFS = os.path.join(BASE, "data", "patch_refs.json")
API = "https://api.osv.dev/v1/vulns/%s"
UA = {"User-Agent": "ics-vex-research/1.0"}
SHA_MIN = 7


def osv(cve):
    try:
        with urllib.request.urlopen(urllib.request.Request(API % cve, headers=UA),
                                    timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"_err": "http-%d" % e.code}
    except Exception as e:
        return {"_err": type(e).__name__}


def fix_commits(rec):
    """(repo, sha) for every GIT range end point OSV marks as the fix."""
    out = []
    for a in rec.get("affected", []):
        for r in a.get("ranges", []):
            if r.get("type") != "GIT":
                continue
            repo = (r.get("repo") or "").rstrip("/").removesuffix(".git")
            for ev in r.get("events", []):
                sha = ev.get("fixed")
                if sha and len(sha) >= SHA_MIN and repo:
                    out.append((repo, sha))
    return out


def main():
    known = json.load(open(TARGETS, encoding="utf-8")) if os.path.exists(TARGETS) else {}
    refs = json.load(open(REFS, encoding="utf-8")) if os.path.exists(REFS) else {}
    cves = sorted(d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, d)))
    todo = [c for c in cves if not (known.get(c) or {}).get("targets")]
    print("== %d CVEs without a target ==" % len(todo))

    gained = 0
    for cve in todo:
        rec = osv(cve)
        time.sleep(0.4)
        if rec.get("_err"):
            print("%-18s -- %s" % (cve, rec["_err"]))
            continue
        commits = fix_commits(rec)
        if not commits:
            print("%-18s -- no GIT fix range" % cve)
            continue
        have = {h["url"] for h in refs.get(cve) or []}
        added = 0
        for repo, sha in commits:
            url = "%s/commit/%s" % (repo, sha)
            if url in have:
                continue
            refs.setdefault(cve, []).append(
                {"url": url, "tags": ["Patch", "OSV"], "kind": "github"})
            added += 1
        if added:
            gained += 1
        print("%-18s -> %d fix commit(s), %d new  %s"
              % (cve, len(commits), added, commits[0][0].split("/")[-1]))

    json.dump(refs, open(REFS, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n== %d CVEs gained a commit link from OSV ==" % gained)
    print("->", REFS)


if __name__ == "__main__":
    main()
