#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect source snapshots for CVEs the hand catalog never covered.

The 107 existing snapshots all came through `tools/generate_ics_sbom.py:OSS`, a
42-entry hand catalog that carries `(version, [cves])` pairs — the collector read
the version straight out of it, so a CVE outside the catalog had no version to
fetch and could not be collected at all. That, not repository availability, is why
collection stopped at 107.

This takes the version from NVD's applicability range instead (the exact `version`
of a matching cpeMatch entry, else its `versionStartIncluding`), which is the same
source `tools/eval_version_match.py` already uses to decide affectedness. Repo and
tag templates come from `tools/oss_repos.py`.

WHAT THE VERSION MEANS. A version picked from an NVD range is "a release the CVE
applies to", NOT "the release this ICS device ships" — CISA publishes no component
versions, so that is unknowable from this corpus. Every snapshot is written with
`version_basis: nvd-range-lower-bound` in the index so a downstream VEX verdict
cannot silently present an assumed version as an observed one.

linux_kernel is skipped by default: it is 218 of the 424 targets, each archive is
hundreds of MB, and locating a vulnerable function inside the whole kernel tree is
a different problem from doing it inside a single library. Pass --include-kernel
to attempt it anyway.

Usage:
  python tools/collect_snapshots_nvd.py --targets data/collect_targets_424.json
  python tools/collect_snapshots_nvd.py --limit 20 --dry-run
"""
import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "tools"))
from oss_repos import OSS_REPOS

SNAP = os.path.join(BASE, "data", "source_snapshots")
INDEX = os.path.join(BASE, "data", "snapshot_index.json")
UA = {"User-Agent": "Mozilla/5.0 (ICS-VEX snapshot collector)"}
SKIP_BY_DEFAULT = {"linux_kernel", "linux-kernel"}


def variants(version):
    """Dotted and underscore spellings a tag template may want."""
    v = str(version).strip()
    return {"v": v, "u": v.replace(".", "_")}


def tag_exists(repo, tag):
    url = "https://api.github.com/repos/%s/git/ref/tags/%s" % (repo, tag)
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status == 200
    except urllib.error.HTTPError:
        return False
    except Exception:
        return False


def resolve_tag(spec, version):
    """First template whose tag actually exists upstream.

    Verified rather than assumed: a guessed tag yields a 404 zip that would land as
    an empty snapshot directory and read downstream as "source collected".
    """
    f = variants(version)
    for tmpl in spec.get("tags") or []:
        tag = tmpl.format(**f)
        if tag_exists(spec["gh"], tag):
            return tag
    return None


def fetch_zip(repo, tag, dest):
    url = "https://github.com/%s/archive/refs/tags/%s.zip" % (repo, tag)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=180) as r:
        blob = r.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        z.extractall(dest)
    return len(blob)


def fetch_tarball(spec, version, dest):
    import tarfile
    url = spec["tarball"].format(**variants(version))
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=180) as r:
        blob = r.read()
    with tarfile.open(fileobj=io.BytesIO(blob)) as t:
        t.extractall(dest)
    return len(blob)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default=os.path.join(BASE, "data",
                                                      "collect_targets_424.json"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--include-kernel", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    targets = json.load(open(a.targets, encoding="utf-8"))
    if not a.include_kernel:
        targets = [t for t in targets if t["oss"] not in SKIP_BY_DEFAULT]
    if a.limit:
        targets = targets[:a.limit]
    print("대상 %d건 (kernel %s)" % (len(targets),
                                    "포함" if a.include_kernel else "제외"))

    index = json.load(open(INDEX, encoding="utf-8")) if os.path.isfile(INDEX) else {}
    ok = skip = fail = 0
    reasons = {}
    for i, t in enumerate(targets, 1):
        cve, oss, ver = t["cve"], t["oss"], t["version"]
        dest = os.path.join(SNAP, cve)
        if os.path.isdir(dest) and os.listdir(dest):
            skip += 1
            continue
        spec = OSS_REPOS.get(oss) or OSS_REPOS.get(oss.replace("_", "-"))
        if not spec or spec.get("closed"):
            fail += 1
            reasons[cve] = "no repo map"
            continue
        if a.dry_run:
            print("  [%d/%d] %s %s@%s" % (i, len(targets), cve, oss, ver))
            continue
        try:
            if spec.get("gh"):
                tag = resolve_tag(spec, ver)
                if tag:
                    os.makedirs(dest, exist_ok=True)
                    n = fetch_zip(spec["gh"], tag, dest)
                    index[cve] = {"component": oss, "version": ver, "tag": tag,
                                  "source": "github:%s" % spec["gh"], "bytes": n,
                                  "version_basis": t.get("version_basis")}
                    ok += 1
                    print("  [%d/%d] %s %s@%s tag=%s %.1fMB"
                          % (i, len(targets), cve, oss, ver, tag, n / 1e6), flush=True)
                    continue
            if spec.get("tarball"):
                os.makedirs(dest, exist_ok=True)
                n = fetch_tarball(spec, ver, dest)
                index[cve] = {"component": oss, "version": ver, "tag": None,
                              "source": spec["tarball"], "bytes": n,
                              "version_basis": t.get("version_basis")}
                ok += 1
                print("  [%d/%d] %s %s@%s tarball %.1fMB"
                      % (i, len(targets), cve, oss, ver, n / 1e6), flush=True)
                continue
            fail += 1
            reasons[cve] = "no tag resolved for %s" % ver
            if os.path.isdir(dest) and not os.listdir(dest):
                os.rmdir(dest)
        except Exception as e:
            fail += 1
            reasons[cve] = "%s: %s" % (type(e).__name__, str(e)[:60])
            if os.path.isdir(dest) and not os.listdir(dest):
                os.rmdir(dest)
        time.sleep(0.4)          # upstream courtesy

    if not a.dry_run:
        json.dump(index, open(INDEX, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
    print("\n수집 성공 %d  이미보유 %d  실패 %d" % (ok, skip, fail))
    if reasons:
        import collections
        kinds = collections.Counter(v.split(":")[0] for v in reasons.values())
        print("실패 사유:", dict(kinds))
    print("->", SNAP, "|", INDEX)


if __name__ == "__main__":
    main()
