#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Patch-signature gate — is the collected source ALREADY patched?

The VEX-v2 gates decide `affected` from presence: the vulnerable function is defined
in the snapshot, therefore the product is affected. They never ask whether the version
in hand already carries the fix, so a snapshot taken at dnsmasq 2.78 — the release
that fixed CVE-2017-14491 — is still reported affected. Measuring that against
ground truth put it at 4 of 51 judged cases (results/vex_precision.json).

This module is the missing refutation, and it is held to the standard VEX puts on
`not_affected`: it must be positively EARNED, never inferred from absence. Two
independent authorities have to agree before the gate clears a CVE:

  1. code     the fix commit's distinctive added lines are present in the source and
              its removed lines are gone (tools/fixed_check), with at least one fix
              line actually found — "no vulnerable lines matched" alone is worthless,
              because a failed file/line match produces it just as readily as a
              patched build, and a pure-addition fix has no vulnerable lines at all.
  2. version  NVD's affected range for THIS product no longer covers the snapshot
              version. The product filter is essential: a shared-code CVE lists every
              co-listed product, so CVE-2024-6387 carries NetApp bounds (10.0.0,
              11.70.2) beside OpenSSH's, and comparing against those clears an
              openssh 9.6p1 snapshot that sits squarely inside openssh 8.6-9.8.

Either authority alone mislabels. Requiring both is what makes the gate sound in the
direction that matters: it may fail to clear a patched build (costing recall), but it
does not clear a vulnerable one (which would cost precision on `affected`).

NOTE ON CIRCULARITY: data/vex_gt_104.jsonl derives its `not_affected` labels from
these same two authorities. Once this gate is live, those cases are no longer an
independent test of the judgment — the SUT and the ground truth share an oracle, so
precision over them approaches 1.0 by construction rather than by merit. A figure
quoted for the gated system has to come from evidence the gate does not read
(execution_verified), or be quoted for the pre-gate system. See the README.
"""
import glob
import json
import os
import re
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "tools"))
sys.path.insert(0, os.path.join(BASE, "src"))
from fixed_check import check as _signature_check
from sbom_match import cmp_ver

SNAP = os.path.join(BASE, "data", "source_snapshots")
PATCHES = os.path.join(BASE, "data", "patches")
RANGES = os.path.join(BASE, "data", "cve_version_ranges.json")
LOCS = os.path.join(BASE, "data", "source_locations.json")

C_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")
_DETAIL_RE = re.compile(r"fix-lines (\d+)/(\d+), vuln-lines (\d+)/(\d+)")
_IMPL = (".c", ".cc", ".cpp", ".cxx")


def _nz(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _load(path):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return {}


def diff_hunks(diff_text):
    """Per-file (path, vuln_code, patched_code) from a unified git diff.

    Kept per file because the signature check locates the file inside the snapshot;
    merging every C file in the commit into one blob would lose the path.
    """
    out, path, before, after = [], None, [], []

    def flush():
        if path and (before or after):
            out.append((path, "\n".join(before).strip(), "\n".join(after).strip()))

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            flush()
            m = re.search(r" b/(\S+)", line)
            path = m.group(1) if m and m.group(1).lower().endswith(C_EXT) else None
            before, after = [], []
            continue
        if path is None:
            continue
        if line.startswith(("+++", "---", "@@", "index ", "new file", "deleted file",
                            "similarity index", "rename ")):
            continue
        if line.startswith("-"):
            before.append(line[1:])
        elif line.startswith("+"):
            after.append(line[1:])
        elif line.startswith(" "):
            before.append(line[1:])
            after.append(line[1:])
    flush()
    return out


def hunks_for(cve):
    """Fix hunks from every downloaded fix-commit diff for this CVE."""
    evs = []
    for dp in sorted(glob.glob(os.path.join(PATCHES, cve, "*.diff"))):
        try:
            text = open(dp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for path, vuln, patched in diff_hunks(text):
            if vuln and patched:
                evs.append({"file": path, "vuln_code": vuln, "patched_code": patched,
                            "commit": os.path.basename(dp)})
    return evs


def vulnerable_files(cve, locs=None):
    """Basenames of the files the vulnerable function was located in.

    A fix commit touches more than the vulnerability — zlib's CVE-2016-9840 commit
    also bumps the version string in `zlib.h` — so the hunk from the vulnerability's
    own file has to be consulted first or the verdict comes from an unrelated file.
    """
    locs = locs if locs is not None else _load(LOCS)
    names = set()
    for fn in (locs.get(cve) or {}).get("functions") or []:
        if fn.get("file"):
            names.add(os.path.basename(fn["file"]).lower())
    return names


def rank_hunks(evs, vuln_names):
    """Vulnerability's own file, then implementation files, then headers."""
    def rank(ev):
        base = os.path.basename(ev["file"]).lower()
        if vuln_names and base in vuln_names:
            return 0
        return 1 if base.endswith(_IMPL) else 2
    return sorted(evs, key=rank)


def hunk_basis(ev, vuln_names):
    base = os.path.basename(ev["file"]).lower()
    if vuln_names and base in vuln_names:
        return "vuln-located file"
    return "implementation file" if base.endswith(_IMPL) else "header/other"


def has_positive_fix_evidence(detail):
    """Were fix lines actually found? `fix-lines 0/0` means the commit had no
    distinctive added line here, so a `fixed` verdict would rest only on the
    vulnerable lines being missing."""
    m = _DETAIL_RE.search(detail or "")
    return bool(m) and int(m.group(1)) >= 1


def snapshot_version(dirname):
    """Version out of a snapshot directory name: `curl-curl-7_64_0` -> 7.64.0,
    `openssh-portable-V_9_6_P1` -> 9.6p1, `busybox-1_30_1` -> 1.30.1."""
    s = re.sub(r"^[A-Za-z][A-Za-z0-9+._-]*?[-_](?=[Vv]?[0-9_.])", "", dirname, count=1)
    s = re.sub(r"^[Vv](?=[0-9])", "", s).replace("_", ".")
    s = re.sub(r"\.?[Pp](\d)", r"p\1", s)
    m = re.search(r"\d[\d.]*[a-z]?\d*", s)
    return m.group(0) if m else None


def version_of(root):
    """Version of the tree at `root` (its single inner project directory)."""
    if not os.path.isdir(root):
        return None
    inner = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
    return snapshot_version(inner[0]) if inner else None


def nvd_still_affected(cve, version, ranges=None, locs=None):
    """True / False / None(no product-matched range) — does NVD still cover it?"""
    if not version:
        return None
    ranges = ranges if ranges is not None else _load(RANGES)
    locs = locs if locs is not None else _load(LOCS)
    comp = _nz((locs.get(cve) or {}).get("component"))
    entries = []
    for e in ranges.get(cve) or []:
        p = _nz(e.get("product"))
        if comp and p and (p in comp or comp in p):
            entries.append(e)
    if not entries:
        return None
    for e in entries:
        inside = True
        for bound, violates in ((e.get("startIncl"), lambda c: c < 0),
                                (e.get("endExcl"), lambda c: c >= 0),
                                (e.get("endIncl"), lambda c: c > 0)):
            if bound:
                c = cmp_ver(version, bound)
                if c is not None and violates(c):
                    inside = False
                    break
        if inside:
            return True        # an entry (an all-null one means every version) covers it
    return False


def signature_verdict(cve, root, vuln_names=None):
    """(verdict, detail, hunk) for the build at `root`: vulnerable / fixed / None.

    The first hunk to reach a definite verdict decides, in rank order, so the
    vulnerability's own file is read before a version-bump header.
    """
    evs = hunks_for(cve)
    if not evs or not os.path.isdir(root):
        return None, "no fix-commit hunk" if not evs else "build not present", None
    names = vuln_names if vuln_names is not None else vulnerable_files(cve)
    for ev in rank_hunks(evs, names):
        v = _signature_check(cve, ev, root)
        if v["verdict"] in ("vulnerable", "fixed"):
            return v["verdict"], v.get("detail"), ev
    return None, "signature inconclusive in %d hunk(s)" % len(evs), None


def decide(cve, root=None, ranges=None, locs=None):
    """Does the collected source already carry the fix?

    Returns {cleared, verdict, version, detail, corroboration, reason}. `cleared` is
    True only when the code signature and NVD's range agree, which is what keeps the
    gate from clearing a build that is merely hard to match.
    """
    root = root or os.path.join(SNAP, cve)
    version = version_of(root)
    verdict, detail, ev = signature_verdict(cve, root, vulnerable_files(cve, locs))
    out = {"cleared": False, "verdict": verdict, "version": version,
           "detail": detail, "corroboration": None, "reason": None,
           "file": (ev or {}).get("file")}

    if verdict != "fixed":
        out["reason"] = "code signature does not show the fix (%s)" % (verdict or detail)
        return out
    if not has_positive_fix_evidence(detail):
        out["reason"] = "fixed verdict without positive fix evidence (%s)" % detail
        return out
    still = nvd_still_affected(cve, version, ranges, locs)
    if still is True:
        out["reason"] = ("NVD range still covers %s, so the code signature is not "
                         "corroborated" % version)
        return out
    if still is None:
        out["reason"] = ("no product-matched NVD range for %s; a single authority may "
                         "not clear a CVE" % version)
        return out
    out.update({"cleared": True, "corroboration": "patch+nvd"})
    return out
