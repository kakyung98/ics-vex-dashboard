#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Locate the vulnerable function by diffing the fixed release against the snapshot.

Paths A and B both need something published about the CVE - a fix commit, or a
function named in the NVD text. 44 of the 104 snapshots have neither, and for 20
of them NVD carries no commit link at all.

This path needs neither. NVD does say which version fixed the CVE, and we
already hold the vulnerable source, so:

    snapshot (vulnerable release)  ─┐
                                    ├─ tree-sitter both, compare function bodies
    fixed release (downloaded)     ─┘   -> functions that changed between them

The vulnerable function is necessarily in that set. It is a superset - a release
carries unrelated changes too - so this evidence is weaker than a fix commit and
is recorded as its own source (`release-diff`), which bounds what it may
conclude downstream.

The fixed version must come from a range belonging to THIS product. NVD lists
ranges for every product a CVE touches, and taking the first one resolved
CVE-2018-25032 to nokogiri < 1.13.4 instead of zlib < 1.2.12.

NEGATIVE RESULT - measured, not adopted. The assumption was that knowing the
fixed version substitutes for knowing the fix commit. It does not, because a
snapshot is not the last release before the fix: curl's snapshot is 7.79.1 and
the fix landed in 7.83.0, four minor releases later, so the diff changes 549
functions. Of 12 CVEs that produced a diff at all, exactly one passed a usable
gate (the fixed version must post-date the snapshot, and the changed set must be
small enough to be evidence): zlib 1.2.11 -> 1.2.12, 36 changed. Three had a
"fixed" version older than the snapshot, which is how a wrong product range
survives even after the product filter.

Kept to document why the shortcut fails: a release diff needs the immediately
preceding release, which is nearly as precise a requirement as the commit
itself.

Output: data/release_diff.json {CVE: {"fixed": v, "repo": r, "funcs": [...]}}
"""
import argparse
import io
import json
import os
import re
import sys
import tarfile
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
FIXED = os.path.join(BASE, "data", "fixed_releases")
OUT = os.path.join(BASE, "data", "release_diff.json")
UA = {"User-Agent": "ics-vex-research/1.0"}

sys.path.insert(0, os.path.join(BASE, "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbom_match as M                                    # noqa: E402
from extract_vuln_funcs import TIERA, _funcname, _parser  # noqa: E402
from build_func_index import index_snapshot               # noqa: E402

_GH_ARCHIVE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+?)/archive")


def fixed_version(cve, component, ranges):
    pkg = M._norm_pkg(component)
    for r in ranges.get(cve) or []:
        if not r.get("endExcl"):
            continue
        p = M._norm_pkg(r.get("product"))
        if pkg and (pkg == p or pkg in p or p in pkg):
            return r["endExcl"]
    return None


def tag_candidates(repo, version):
    """Tag spellings the ecosystems in this corpus actually use."""
    v = version
    u = v.replace(".", "_")
    name = repo.split("/")[-1]
    return [v, "v" + v, "V" + v, u, "v" + u,
            "%s-%s" % (name, v), "%s-%s" % (name, u),
            "%s_%s" % (name.upper(), u), "OpenSSL_" + u,
            "V_%s_P1" % u, "rel_%s" % u, "%s-release" % v]


def download_release(repo, version, dst):
    """Fetch a GitHub source archive for `version`, trying known tag spellings."""
    if os.path.isdir(dst) and os.listdir(dst):
        return True, "cached"
    for tag in tag_candidates(repo, version):
        url = "https://codeload.github.com/%s/tar.gz/refs/tags/%s" % (repo, tag)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                        timeout=120) as r:
                blob = r.read()
        except Exception:
            continue
        try:
            os.makedirs(dst, exist_ok=True)
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
                t.extractall(dst)
            return True, tag
        except Exception:
            continue
    return False, "no tag matched"


def _bodies(root):
    """{function name: normalised body} over a source tree."""
    funcs, _n = index_snapshot(root)
    out = {}
    for name, locs in funcs.items():
        f, s, e = locs[0]
        p = os.path.join(root, f.replace("/", os.sep))
        try:
            lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            continue
        body = "\n".join(lines[s:e + 1])
        out[name] = re.sub(r"\s+", " ", body).strip()
    return out


def changed_functions(vuln_root, fixed_root, cap=40):
    a, b = _bodies(vuln_root), _bodies(fixed_root)
    changed = [n for n in a if n in b and a[n] != b[n]]
    removed = [n for n in a if n not in b]
    # a function the fix deleted outright is as much a candidate as a changed one
    out = sorted(set(changed) | set(removed))
    return out[:cap], len(changed), len(removed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    tgt = json.load(open(os.path.join(BASE, "data", "vuln_targets.json"), encoding="utf-8"))
    ranges = json.load(open(os.path.join(BASE, "data", "cve_version_ranges.json"),
                            encoding="utf-8"))
    tier = json.load(open(TIERA, encoding="utf-8")) if os.path.isfile(TIERA) else {}
    rows = {}
    p = os.path.join(BASE, "data", "tier_a_cve_dataset.jsonl")
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            r = json.loads(line)
            rows[r["cve"]] = r

    out = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    todo = [c for c in sorted(os.listdir(SNAP))
            if not (tgt.get(c) or {}).get("targets") and c not in out]
    if a.limit:
        todo = todo[:a.limit]
    print("candidates: %d" % len(todo))

    for cve in todo:
        comp = (rows.get(cve, {}).get("component") or "")
        fv = fixed_version(cve, comp, ranges)
        m = _GH_ARCHIVE.search((tier.get(cve) or {}).get("sw_version_wget") or "")
        if not fv or not m:
            print("  %-18s -- %s" % (cve, "no fixed version" if not fv else "no repo"))
            continue
        repo = "%s/%s" % m.groups()
        dst = os.path.join(FIXED, cve)
        ok, tag = download_release(repo, fv, dst)
        if not ok:
            print("  %-18s !! %s %s (%s)" % (cve, repo, fv, tag))
            continue
        sub = [os.path.join(dst, d) for d in os.listdir(dst)]
        froot = next((s for s in sub if os.path.isdir(s)), dst)
        vroot = os.path.join(SNAP, cve)
        vsub = [os.path.join(vroot, d) for d in os.listdir(vroot)]
        vroot = next((s for s in vsub if os.path.isdir(s)), vroot)
        try:
            funcs, nch, nrm = changed_functions(vroot, froot)
        except Exception as e:
            print("  %-18s !! diff failed %s" % (cve, str(e)[:50]))
            continue
        out[cve] = {"fixed": fv, "repo": repo, "tag": tag, "funcs": funcs,
                    "changed": nch, "removed": nrm}
        json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("  %-18s -> %-22s %s  %d changed, %d removed -> %d candidates"
              % (cve, repo, fv, nch, nrm, len(funcs)), flush=True)

    print("\n== %d CVEs given release-diff candidates ==" % len(out))
    print("->", OUT)


if __name__ == "__main__":
    main()
