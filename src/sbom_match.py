#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identify SBOM components and their CVEs precisely.

Two defects in the previous matching cost most of the precision:

1. Name similarity decided identity. Ratcliff-Obershelp scores `openssl` against
   `openssh` at 0.857 - above any usable threshold - and they share no CVEs at
   all. Structured identifiers (purl, CPE) are checked first here, and a name is
   only consulted when no identifier exists. A fuzzy match must additionally be
   UNAMBIGUOUS: a clear winner, or the component is reported unidentified rather
   than guessed.

2. A version that was not an exact key in the KB fell back to the union of every
   CVE that component ever had - so `zlib 1.2.13` returned all of zlib's CVEs.
   Here the version is tested against the NVD affected RANGE
   (data/cve_version_ranges.json). That method is measured:
   tools/eval_version_match.py scores precision 100.0% / recall 98.3% /
   macro-F1 0.99 over 125 CVEs.

When the version cannot be decided (absent, NOASSERTION, no cached range), the
CVE is still returned but flagged `version_decided=False`, so a caller can tell
"this version is affected" from "we could not check the version".
"""
import json
import os
import re

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
RANGES_PATH = os.path.join(BASE, "data", "cve_version_ranges.json")

# a fuzzy name match must beat this, and beat the runner-up by this margin
RO_MIN = 0.90
RO_MARGIN = 0.05
UNPINNED = {"", "noassertion", "unknown", "none", "n/a", "*"}


def _load_ranges():
    try:
        return json.load(open(RANGES_PATH, encoding="utf-8"))
    except Exception:
        return {}


RANGES = _load_ranges()


def _alpha_ord(s):
    n = 0
    for c in s.lower():
        if "a" <= c <= "z":
            n = n * 26 + (ord(c) - 96)
    return n


def parse_ver(s):
    """Version -> comparable tuple, letter revisions included (1.0.2 < 1.0.2a)."""
    if not s:
        return None
    toks = re.findall(r"\d+|[A-Za-z]+", s)
    if not toks:
        return None
    return tuple(int(t) if t.isdigit() else _alpha_ord(t) for t in toks)


def cmp_ver(a, b):
    ta, tb = parse_ver(a), parse_ver(b)
    if ta is None or tb is None:
        return None
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _norm_pkg(x):
    return re.sub(r"^lib", "", (x or "").lower())


def in_affected_range(cve, product, version):
    """Is `version` inside this CVE's NVD affected range for `product`?

    Returns True / False / None, where None means undecidable - no cached range,
    an unparseable version, or a range with no bounds. None must never be read as
    False: not knowing is not the same as not affected."""
    if not version or version.strip().lower() in UNPINNED:
        return None
    rs = RANGES.get(cve)
    if not rs:
        return None
    pkg = _norm_pkg(product)
    cand = None
    for r in rs:
        if not (r.get("startIncl") or r.get("endExcl") or r.get("endIncl")):
            continue
        p = _norm_pkg(r.get("product"))
        if pkg and (pkg == p or pkg in p or p in pkg):
            cand = r
            break
        if cand is None:
            cand = r
    if not cand:
        return None
    lo, hi_ex, hi_in = cand.get("startIncl"), cand.get("endExcl"), cand.get("endIncl")
    if lo:
        c = cmp_ver(version, lo)
        if c is None:
            return None
        if c < 0:
            return False
    if hi_ex:
        c = cmp_ver(version, hi_ex)
        if c is None:
            return None
        if c >= 0:
            return False
    if hi_in:
        c = cmp_ver(version, hi_in)
        if c is None:
            return None
        if c > 0:
            return False
    return True


def identify(component, kb_idx, kb_match, ro_best):
    """(kb component, how, detail) for one SBOM component.

    `how` is one of: purl, cpe, name-exact, name-fuzzy, unidentified.
    Identifiers win; a name is a last resort and must be unambiguous."""
    name = (component.get("name") or "").strip()
    purl = (component.get("purl") or "").strip().lower()
    cpe = (component.get("cpe") or "").strip().lower()

    if purl:
        # pkg:generic/zlib@1.2.11  ->  zlib
        m = re.match(r"pkg:[^/]+/(?:[^/@]+/)?([^@?#]+)", purl)
        if m:
            hit = kb_idx.get(m.group(1).lower())
            if hit:
                return hit, "purl", purl
    if cpe:
        # cpe:2.3:a:openssl:openssl:1.0.2k:*:*  ->  vendor=openssl product=openssl
        parts = cpe.split(":")
        if len(parts) >= 5:
            hit = kb_idx.get(parts[4])
            if hit:
                return hit, "cpe", cpe
    if name:
        hit = kb_idx.get(name.lower())
        if hit:
            return hit, "name-exact", name
        comp, ratio, matched, runner_up = ro_best(name)
        if comp and ratio >= RO_MIN and (ratio - runner_up) >= RO_MARGIN:
            return comp, "name-fuzzy", "%s (RO %.3f, next %.3f)" % (matched, ratio, runner_up)
        # Ambiguous or weak: report it, do not guess. This is the openssl/openssh
        # case - guessing here invents a whole CVE set.
        return None, "unidentified", ("closest %s RO %.3f" % (matched, ratio)
                                      if comp else "no candidate")
    return None, "unidentified", "component has no name, purl or cpe"


def cves_for(comp, version):
    """[(cve_record, version_decided)] for a KB component at `version`.

    Every CVE the component carries is tested against its NVD range. A CVE the
    range excludes is dropped; one that cannot be decided is kept and flagged."""
    out, seen = [], set()
    for lst in (comp.get("versions") or {}).values():
        for cv in lst:
            if cv["id"] in seen:
                continue
            seen.add(cv["id"])
            verdict = in_affected_range(cv["id"], comp.get("cpe_product") or comp.get("key"),
                                        version)
            if verdict is False:
                continue                      # version is outside the affected range
            out.append((cv, verdict is True))
    return out
