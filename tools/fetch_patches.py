#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch the full fix-commit diffs for the source-snapshot CVEs.

Two sources, because neither alone covers the corpus:

  tier-A patch_commits   cached blobs truncated at 6000 chars, which drops the
                         actual source hunks (only the alphabetically-first
                         build/doc files survive) - so the commit is refetched
  data/patch_refs.json   commit URLs recovered from the FULL NVD reference list
                         (tools/fetch_patch_refs.py); the old NVD cache kept only
                         references[:6] and lost nearly every patch link

Every forge this corpus actually uses is handled - GitHub, GitLab, cgit/gitweb
(git.kernel.org, sourceware, busybox, dnsmasq) and Fossil (sqlite) - since each
exposes a raw-diff endpoint at a different URL shape.

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
REFS = os.path.join(BASE, "data", "patch_refs.json")

# Each forge serves a raw unified diff at its own URL shape, and some serve it
# unreliably - so a commit maps to a LIST of candidates, tried in order until one
# actually returns a diff.
_GH = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-f]{7,40})")
_GL = re.compile(r"(gitlab\.[^/\s]+/[^\s]+/-/commit/([0-9a-f]{7,40}))")
_CGIT = re.compile(r"((?:cgit|git)\.[^/\s]+/[^\s]*?)commit/?\?id=([0-9a-f]{7,40})")
# NOTE: gitweb uses a=commitdiff as often as a=commit, and matching the shorter
# verb first rewrote "a=commitdiff" into the nonexistent "a=patchdiff".
_GITWEB = re.compile(r"([^\s]*gitweb[^\s]*?)[?;]a=commit(?:diff)?([^\s]*?)h=([0-9a-f]{7,40})")
_FOSSIL = re.compile(r"(?:www\.)?sqlite\.org/src/info/([0-9a-f]{8,40})")
# A PR is not a commit, but GitHub serves the whole series as one patch, which is
# exactly what the extractor consumes. NVD cites PRs far more often than commits
# (44 vs 20 links here), so ignoring them wastes most of the recovered evidence.
_GHPR = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/pull/(\d+)")


def diff_urls(url):
    """(candidate raw-diff URLs, sha) for a commit URL on any supported forge."""
    url = url or ""
    m = _GH.search(url)
    if m:
        return ["https://github.com/%s/%s/commit/%s.patch" % m.groups()], m.group(3)
    m = _GL.search(url)
    if m:
        return ["https://%s.patch" % m.group(1)], m.group(2)
    m = _CGIT.search(url)
    if m:
        host, sha = m.group(1), m.group(2)
        cands = ["https://%spatch/?id=%s" % (host, sha)]
        # kernel.org's per-subsystem trees answer /patch/ with a 500 often enough
        # that the GitHub mirror is worth trying: a merged commit keeps its sha.
        if "kernel.org" in host:
            cands.append("https://github.com/torvalds/linux/commit/%s.patch" % sha)
        return cands, sha
    m = _GITWEB.search(url)
    if m:
        # rewrite the verb in place; rebuilding the URL kept losing the ";"
        # separators and produced "?p=openssl.git?a=patch;;h=..."
        hit = url[m.start():m.end()]
        sha = m.group(3)
        cands = []
        for verb in ("a=commitdiff", "a=commit"):
            if verb in hit:
                cands.append(hit.replace(verb, "a=patch"))
                break
        # git.openssl.org no longer answers; GitHub mirrors the same hashes
        if "openssl.org" in hit:
            cands.append("https://github.com/openssl/openssl/commit/%s.patch" % sha)
        return cands, sha
    m = _GHPR.search(url)
    if m:
        owner, repo, num = m.groups()
        return (["https://github.com/%s/%s/pull/%s.patch" % (owner, repo, num)],
                "pr%s" % num)
    m = _FOSSIL.search(url)
    if m:
        # Fossil exposes no raw-diff endpoint addressable by a single check-in id
        # (/vpatch needs both endpoints of the range), and its git mirror rewrites
        # hashes, so this commit cannot be fetched as a diff.
        return [], m.group(1)
    return [], None


def diff_url(url):
    """First candidate only - kept for callers that want a single URL."""
    cands, sha = diff_urls(url)
    return (cands[0] if cands else None), sha


def patch_urls(v, ref_hits=()):
    """(sha, raw-diff URL) for every fix commit known for this CVE.

    tier-A commits first (they were curated), then anything the NVD references
    turned up; NVD's own "Patch"-tagged links are preferred within that."""
    out, seen = [], set()

    def add(url):
        cands, sha = diff_urls(url)
        if cands and sha not in seen:
            seen.add(sha)
            out.append((sha, cands))

    for pc in v.get("patch_commits") or []:
        add(pc.get("url") or "")
    for h in sorted(ref_hits, key=lambda x: "Patch" not in (x.get("tags") or [])):
        add(h.get("url") or "")
    return out


def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def main():
    tier = json.load(open(TIERA, encoding="utf-8")) if os.path.isfile(TIERA) else {}
    refs = json.load(open(REFS, encoding="utf-8")) if os.path.exists(REFS) else {}
    snaps = {d for d in os.listdir(SNAP) if os.path.isdir(os.path.join(SNAP, d))}
    ok = miss = err = cached = 0
    for cve in sorted(snaps):
        urls = patch_urls(tier.get(cve, {}), refs.get(cve) or [])
        if not urls:
            print("%-18s -- no commit URL" % cve)
            miss += 1
            continue
        d = os.path.join(OUTD, cve)
        os.makedirs(d, exist_ok=True)
        got = 0
        for sha, cands in urls:
            dst = os.path.join(d, sha + ".diff")
            if os.path.exists(dst) and os.path.getsize(dst) > 0:
                cached += 1
                got += 1
                continue
            txt, why = None, "no candidate URL"
            for url in cands:
                try:
                    body = fetch(url)
                except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                    why = "%s: %s" % (url.split("/")[2], str(e)[:40])
                    continue
                finally:
                    time.sleep(0.7)   # be polite to every forge
                if "@@ -" in body:
                    txt = body
                    break
                why = "no diff at %s" % url[:60]
            if txt is None:
                print("%-18s !! %s %s" % (cve, sha[:10], why))
                err += 1
                continue
            open(dst, "w", encoding="utf-8", newline="\n").write(txt)
            got += 1
            print("%-18s -> %s  %d bytes" % (cve, sha[:10], len(txt)))
        if got:
            ok += 1
    print("\n== %d CVEs with a cached diff (%d files already present, %d no URL, %d errors) =="
          % (ok, cached, miss, err))
    print("->", OUTD)


if __name__ == "__main__":
    sys.exit(main())
