#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pull upstream fix-commit links out of the Debian security tracker.

Debian's security team reads the upstream fix for a CVE before deciding whether
to backport it, and records what they found as NOTE lines on the CVE's entry:

    CVE-2016-9318 (libxml2 2.9.4 and earlier does not offer a flag ...)
        - libxml2 2.9.4+dfsg1-2.2
        [jessie] - libxml2 <no-dsa> (Minor issue)
        NOTE: https://bugzilla.gnome.org/show_bug.cgi?id=772726
        NOTE: Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/2304078...

That is a CVE -> commit mapping maintained by hand, for exactly the CVEs whose
NVD entry has none: NVD carries distro advisories and mailing-list archives for
these, while the tracker carries the commit. It is one flat file for every CVE
Debian has ever triaged, so this is a single download rather than an API walk.

The tracker is a secondary source and is treated as one. Nothing here decides a
verdict: every URL found is written beside the CVE's NVD references and goes
through the same key extraction and the same downstream checks in
tools/git_grep_fix_commits, where a found commit is a candidate whose diff must
still agree with the snapshot.

Out: data/debian_refs.json  {CVE: [{"url", "tags": ["debian-security-tracker"]}]}
"""
import argparse
import json
import os
import re
import subprocess

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
OUT = os.path.join(BASE, "data", "debian_refs.json")
CACHE = os.path.join(BASE, "data", "_debian_cve_list.txt")
# salsa's raw endpoint truncates this file: it answered 753 KB (4,626 CVEs,
# nothing before 2013) and cut off mid-line inside an nvidia entry. A truncated
# answer is worse than a failed one here, because the parse still "succeeds"
# and simply finds nothing for the older CVEs - which is most of this corpus.
# So the file comes from a shallow clone of the tracker instead, where git
# verifies what it received, and a short file is refused rather than parsed.
REPO = ("https://salsa.debian.org/security-tracker-team/security-tracker.git")
MIRROR = os.path.join(
    os.environ.get("GIT_MIRRORS", os.path.join(
        os.path.expanduser("~"), "Desktop", "gitmirrors")),
    "debian-security-tracker")
LIST_IN_REPO = "data/CVE/list"
# A full record set reaches back to the 1990s. Far short of this means a
# partial file, which must fail loudly rather than parse to zero.
MIN_RECORDS = 100_000

_CVE_LINE = re.compile(r"^(CVE-\d{4}-\d{4,})")
_URL = re.compile(r"https?://[^\s,;)\]]+")


def download(force=False):
    """The tracker's CVE list, via a shallow clone, cached on disk (~50 MB)."""
    if os.path.isfile(CACHE) and not force:
        text = open(CACHE, encoding="utf-8", errors="replace").read()
        if text.count("\nCVE-") >= MIN_RECORDS:
            return text

    os.makedirs(os.path.dirname(MIRROR), exist_ok=True)
    if os.path.isdir(os.path.join(MIRROR, ".git")):
        for args in (["fetch", "--depth", "1", "origin", "master"],
                     ["reset", "--hard", "FETCH_HEAD"]):
            subprocess.run(["git", "-C", MIRROR] + args, check=False,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["git", "clone", "--depth", "1",
                        "--filter=blob:none", "--sparse", REPO, MIRROR],
                       check=True)
        # sparse-checkout takes directories, not files: pointing it at
        # data/CVE/list fails with "is not a directory". data/CVE holds the
        # list plus a handful of small siblings, which is close enough.
        subprocess.run(["git", "-C", MIRROR, "sparse-checkout", "set",
                        os.path.dirname(LIST_IN_REPO)], check=True)

    src = os.path.join(MIRROR, *LIST_IN_REPO.split("/"))
    if not os.path.isfile(src):
        raise SystemExit("tracker list not found at %s" % src)
    text = open(src, encoding="utf-8", errors="replace").read()
    n = text.count("\nCVE-")
    if n < MIN_RECORDS:
        raise SystemExit(
            "tracker list looks partial: %d records, expected >= %d"
            % (n, MIN_RECORDS))
    open(CACHE, "w", encoding="utf-8", newline="\n").write(text)
    return text


def parse(text, wanted=None):
    """{CVE: [urls]} from the NOTE lines under each CVE record.

    A record starts at column 0 with the CVE id; everything indented below it
    belongs to that record until the next one.
    """
    out, cur = {}, None
    for line in text.splitlines():
        m = _CVE_LINE.match(line)
        if m:
            cur = m.group(1)
            continue
        if cur is None or not line.startswith((" ", "\t")):
            continue
        if wanted is not None and cur not in wanted:
            continue
        s = line.strip()
        if not s.startswith("NOTE:"):
            continue
        for u in _URL.findall(s):
            out.setdefault(cur, [])
            if u not in out[cur]:
                out[cur].append(u)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true",
                    help="re-download the tracker list instead of using the cache")
    ap.add_argument("--all-cves", action="store_true",
                    help="keep every CVE, not just the ones with a snapshot")
    a = ap.parse_args()

    wanted = None
    if not a.all_cves:
        wanted = {d for d in os.listdir(SNAP)
                  if os.path.isdir(os.path.join(SNAP, d))}
    text = download(a.refresh)
    found = parse(text, wanted)

    out = {c: [{"url": u, "tags": ["debian-security-tracker"]} for u in urls]
           for c, urls in sorted(found.items())}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    commitish = sum(1 for urls in found.values()
                    for u in urls if "commit" in u or "/-/commit/" in u
                    or "h=" in u or "id=" in u)
    print("tracker list      : %d lines" % text.count("\n"))
    print("CVEs in scope     : %s" % (len(wanted) if wanted is not None else "all"))
    print("CVEs with NOTEs   : %d" % len(out))
    print("NOTE urls         : %d  (commit-shaped: %d)"
          % (sum(len(v) for v in found.values()), commitish))
    print("->", OUT)


if __name__ == "__main__":
    main()
