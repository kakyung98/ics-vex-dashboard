#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L0 + L3 — expanded CPE identity index with precision guards.

L0  Match SBOM components against the full NVD CPE product index
    (data/cpe_index.json, built by tools/build_cpe_index.py), not just the
    42-entry OSS knowledge base. This lifts recall: thousands of products
    instead of 42.

L3  The guards that keep that wider net from turning shared-code CPEs into false
    positives. A CPE is `cpe:2.3:a:VENDOR:PRODUCT:VERSION`; when vulnerable code
    lives in shared OSS, NVD attaches one CPE per vendor that ships it, so a
    single CVE carries zlib:zlib AND netapp:ontap AND oracle:db AND apple:macos.
    Matching on PRODUCT while ignoring VENDOR turns the co-listed IT vendors into
    false positives. `vendor_ok()` is the predicate that decides which vendor an
    entry may be trusted through (co-listing + vendor anchoring).

Identity discipline is inherited from sbom_match: identifiers first, a name only
when exact or fuzzy-AND-unambiguous. Version is decided per cpeMatch entry as
True / False / None, where None (undecidable) is never read as False.
"""
import difflib
import json
import os
import re

# reuse the identity + version primitives so the two matchers cannot drift
from sbom_match import parse_ver, cmp_ver, _norm_pkg, RO_MIN, RO_MARGIN, UNPINNED  # noqa: F401

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
INDEX_PATH = os.path.join(BASE, "data", "cpe_index.json")


def _load_index():
    try:
        d = json.load(open(INDEX_PATH, encoding="utf-8"))
        return d.get("by_product", {}), d.get("cve_vendors", {})
    except Exception:
        return {}, {}


BY_PRODUCT, CVE_VENDORS = _load_index()


# --- version decision on a single cpeMatch entry -----------------------------
def _entry_decides(entry, version):
    """True / False / None for one NVD cpeMatch entry.

    None = undecidable (unpinned/unparseable version, or a product named with no
    version bound at all - NVD limit 4). Never read None as False."""
    if not version or str(version).strip().lower() in UNPINNED:
        return None
    ev = entry.get("version")
    if ev:                                   # the CPE pins an exact version
        c = cmp_ver(version, ev)
        return None if c is None else c == 0
    lo_i, lo_x = entry.get("startIncl"), entry.get("startExcl")
    hi_i, hi_x = entry.get("endIncl"), entry.get("endExcl")
    if not (lo_i or lo_x or hi_i or hi_x):
        return None                          # product, some version -> undecidable
    for bound, is_out in ((lo_i, lambda c: c < 0), (lo_x, lambda c: c <= 0),
                          (hi_i, lambda c: c > 0), (hi_x, lambda c: c >= 0)):
        if bound is None:
            continue
        c = cmp_ver(version, bound)
        if c is None:
            return None
        if is_out(c):
            return False
    return True


# --- identity: component -> product key in the expanded index -----------------
def _ro_best(name):
    """(product, ratio, runner_up) - closest product key by Ratcliff-Obershelp.

    The runner-up is what makes ambiguity detectable: without it `openssl` wins
    over `openssh` at 0.857 and silently drags in a whole wrong CVE set.

    Blocking: difflib over all 13.7k products is the L0 bottleneck (the 42-KB was
    cheap only because it was tiny). A candidate that shares no 3-char prefix with
    any name token cannot reach a useful ratio, so it is skipped before the
    expensive SequenceMatcher - this is a speed filter, not a correctness change."""
    n = _norm_pkg(name)
    pref = {t[:3] for t in re.split(r"[^a-z0-9]+", name.lower()) if len(t) >= 3}
    best, br, second = None, 0.0, 0.0
    for prod in BY_PRODUCT:
        pn = _norm_pkg(prod)
        if pref and not any(p in pn for p in pref):
            continue
        r = difflib.SequenceMatcher(None, n, pn).ratio()
        if r > br:
            second, br, best = br, r, prod
        elif r > second:
            second = r
    return best, round(br, 3), round(second, 3)


# ICS display names carry vendor prefixes, version suffixes and boilerplate that
# sink the similarity score ("Sielco Sistemi Winlog Lite <2.07.09" scores 0.54
# against the CPE product `winlog_lite`). Normalising to tokens and testing the
# contiguous n-grams as exact index keys recovers the product inside the noise.
_STOP = {"the", "a", "an", "and", "of", "for", "vendor", "firmware", "application",
         "app", "software", "system", "systems", "series", "update", "inc", "corp",
         "corporation", "ltd", "gmbh", "ag", "co", "llc", "sa", "plc", "automation"}


def _clean_tokens(name):
    """Lowercased word tokens with version fragments, parentheticals and corporate
    boilerplate removed. A token starting with a digit is treated as a version."""
    s = re.sub(r"\([^)]*\)", " ", str(name or "").lower())     # (Update A)
    out = []
    for t in re.split(r"[^a-z0-9]+", s):
        if not t or t[0].isdigit() or t in _STOP:              # version frag / filler
            continue
        out.append(t)
    return out


def _ngrams(toks):
    """(candidate, size) for every contiguous run, longest first, joined by '_'
    and by '' (NVD writes both winlog_lite and, elsewhere, winccflexible)."""
    n = len(toks)
    out = []
    for size in range(n, 0, -1):
        for i in range(n - size + 1):
            g = toks[i:i + size]
            out.append(("_".join(g), size))
            if size > 1:
                out.append(("".join(g), size))
    return out


def _normalized_match(name):
    """A product key recovered from a noisy ICS display name, or None.

    Longest n-gram wins (winlog_lite over lite); a 1-token match must be >=5 chars
    so 'pro'/'lite'/'os' cannot hijack a match."""
    for cand, size in _ngrams(_clean_tokens(name)):
        if cand in BY_PRODUCT and (size >= 2 or len(cand) >= 5):
            return cand
    return None


def identify_product(component):
    """(product, how) for one SBOM component, or (None, reason).

    `how` is one of purl / cpe / name-exact / name-normalized / name-fuzzy.
    Identifiers win; a name is a last resort and must be unambiguous."""
    purl = str(component.get("purl") or "").strip().lower()
    if purl:
        m = re.match(r"pkg:[^/]+/(?:[^/@]+/)?([^@?#]+)", purl)
        if m and m.group(1) in BY_PRODUCT:
            return m.group(1), "purl"
    cpe = str(component.get("cpe") or "").strip().lower()
    if cpe:
        parts = cpe.split(":")
        if len(parts) >= 5 and parts[4] in BY_PRODUCT:
            return parts[4], "cpe"
    name = str(component.get("name") or "").strip()
    if not name:
        return None, "no name/purl/cpe"
    if name.lower() in BY_PRODUCT:
        return name.lower(), "name-exact"
    norm = _normalized_match(name)
    if norm:
        return norm, "name-normalized"
    prod, ratio, runner = _ro_best(name)
    if prod and ratio >= RO_MIN and (ratio - runner) >= RO_MARGIN:
        return prod, "name-fuzzy"
    return None, ("ambiguous (%s %.3f/next %.3f)" % (prod, ratio, runner) if prod else "no candidate")


# --- L3 GUARD ----------------------------------------------------------------
# Product-token allowlist normaliser: an OSS project's own vendor token often
# equals or embeds the product ("openssl:openssl", "gnu:glibc" via _norm_pkg).
def _norm(s):
    return _norm_pkg(str(s or "").lower())


_DOMINANT = {}


def _dominant_vendor(product):
    """The vendor that owns most of this product token's cpeMatch entries.

    For real OSS a product token has essentially one vendor (curl->haxx,
    glibc->gnu, zlib->zlib), so the dominant vendor IS the canonical library.
    Generic tokens ("gateway", "commander") are shared across vendors, and there
    the dominant one is still the safest single anchor. Memoized."""
    if product not in _DOMINANT:
        c = {}
        for e in BY_PRODUCT.get(product, []):
            c[e["vendor"]] = c.get(e["vendor"], 0) + 1
        _DOMINANT[product] = max(c, key=c.get) if c else None
    return _DOMINANT[product]


def vendor_confidence(entry_vendor, product, sbom_vendor):
    """Grade an entry's vendor evidence: 'anchored' | 'canonical' | 'co-listed'.

    This started as a hard accept/reject guard, but measuring it exposed that a
    hard filter is unsafe here (see cves_for): the index is keyed by PRODUCT, so
    real co-listing scatters across *different* product tokens (only 0.8% of
    products carry >1 vendor), and where a token does (e.g. `linux` ->
    codesys/oracle/redhat/windriver) a 'canonical vendor' guess mis-anchors it and
    the whole embedded-component layer (a Schneider device runs windriver linux;
    windriver != schneider). So vendor evidence GRADES a match, it does not drop it.

      anchored  : entry vendor matches the SBOM's declared vendor (strongest)
      canonical : entry vendor is the dominant vendor of this product token
      co-listed : neither - a co-listed / downstream vendor (weakest; still kept)"""
    ev = _norm(entry_vendor)
    sv = _norm(sbom_vendor)
    if sv and ev and (sv == ev or sv in ev or ev in sv):
        return "anchored"
    dom = _dominant_vendor(product)
    if dom is not None and ev == _norm(dom):
        return "canonical"
    return "co-listed"


# --- match one component -> CVEs ---------------------------------------------
def cves_for(component, sbom_vendor="", strict=False):
    """[{cve, vendor, version_decided, how, confidence}] for one component.

    Recall-safe by default: a CVE the version excludes is dropped, but vendor
    evidence only GRADES a match (confidence: anchored/canonical/co-listed), it
    does not drop it - dropping 'co-listed' loses the embedded-component layer
    (windriver/redhat linux under a non-matching device vendor). strict=True is the
    opt-in precision mode that does drop 'co-listed' entries, for callers that want
    fewer false positives at the cost of embedded-layer recall."""
    product, how = identify_product(component)
    if not product:
        return []
    version = str(component.get("version") or "").strip()
    out, seen = [], set()
    for entry in BY_PRODUCT.get(product, []):
        cve = entry["cve"]
        conf = vendor_confidence(entry["vendor"], product, sbom_vendor)
        if strict and conf == "co-listed":
            continue                                   # opt-in precision mode
        decided = _entry_decides(entry, version)
        if decided is False:
            continue                                   # version outside the range
        if cve in seen:
            continue
        seen.add(cve)
        out.append({"cve": cve, "vendor": entry["vendor"], "confidence": conf,
                    "version_decided": decided is True, "how": how})
    return out
