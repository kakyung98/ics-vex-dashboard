#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attach each CVE to the OSS component the SBOM already declares for it.

CISA publishes `product_status` as a list of product ids, so the reverse SBOM hangs
every CVE on the device variants and nothing else. When the same SBOM also declares
the library the CVE is actually filed against, the answer is already in the file and
simply never connected:

    icsa-14-128-01 (Digi International)
      components:   pkg:oss:openssl                     <- declared
                    variant:digi-...-connectport-lts
      dependencies: device:icsa-14-128-01 -> pkg:oss:openssl
      CVE-2014-0160 affects -> variant:...connectport-lts   <- device only
                    (NVD files CVE-2014-0160 under openssl:openssl)

4,893 such pairs sit in the corpus, and every one of them is currently counted as
"the ICS name is absent from NVD, so no matcher can reach it". This adds the missing
`affects` edge so the CVE also points at the library.

CIRCULARITY. A declared OSS component has one of two origins, recorded in
`component:source-availability`:

  C / E  the advisory text named the library; the CVE played no part in creating the
         component, so linking it is sound evidence either way.
  A      build_reverse_sbom attached the library *because* a hand-curated catalog maps
         that CVE to it. Linking the CVE back to a component the CVE itself produced is
         circular: a matcher would be credited for finding what the data was built from.

Both are linked — the SBOM should say what the product contains regardless of how it
was learned — but tier A links are listed in `link:circular-cves` on the component so
the ground-truth builder can hold them out of scoring. The catalog is consulted
directly (build_reverse_sbom.build_oss_index) rather than guessed at, and every CVE it
attributes to the component is held out, not only the one that happened to create it.

Usage:
  python tools/link_oss_components.py [--dry-run]
"""
import argparse
import collections
import glob
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
import build_reverse_sbom as B

SBOM = os.path.join(BASE, "reverse_sbom")
NVD_DETAIL = os.path.join(BASE, "data", "nvd_cpe_detail.json")


def nz(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def tier_of(comp):
    for p in comp.get("properties") or []:
        if p.get("name") == "component:source-availability":
            return p.get("value")
    return None


def set_prop(comp, name, value):
    props = [p for p in (comp.get("properties") or []) if p.get("name") != name]
    if value:
        props.append({"name": name, "value": value})
    comp["properties"] = props


def link(sbom, detail, oss_by_cve):
    """Returns (links added, circular links) for one SBOM, mutating it in place."""
    comps = sbom.get("components") or []
    oss = [c for c in comps if str(c.get("bom-ref", "")).startswith("pkg:oss:")]
    if not oss:
        return 0, 0

    # the product names NVD uses, per declared library
    by_norm = {}
    for c in oss:
        by_norm.setdefault(nz(c.get("name")), []).append(c)
        by_norm.setdefault(nz(str(c.get("bom-ref", "")).split(":")[-1]), []).append(c)

    added = circular = 0
    newly = collections.defaultdict(list)
    circ = collections.defaultdict(list)
    for vuln in sbom.get("vulnerabilities") or []:
        cve = vuln.get("id")
        entries = detail.get(cve) or []
        if not entries:
            continue
        affects = vuln.setdefault("affects", [])
        have = {a.get("ref") for a in affects}
        for e in entries:
            prod = nz(e.get("product"))
            if not prod:
                continue
            # a declared library counts as the target when NVD's product name is the
            # library's own name; substring either way catches libcurl/curl and the
            # "GNU C Library"/glibc spellings without opening the door to a fuzzy match
            hits = by_norm.get(prod) or [c for k, cs in by_norm.items()
                                         if k and (k in prod or prod in k) for c in cs]
            for c in hits:
                ref = c["bom-ref"]
                if ref in have:
                    continue
                affects.append({"ref": ref})
                have.add(ref)
                added += 1
                newly[ref].append(cve)
                if oss_by_cve.get(cve) == str(ref).split(":")[-1].replace("-", "_"):
                    circ[ref].append(cve)
                    circular += 1

    for c in oss:
        ref = c["bom-ref"]
        if newly.get(ref):
            set_prop(c, "link:added-cves", ",".join(sorted(set(newly[ref]))))
        # hold-out list: every CVE the catalog attributes to this library, not just the
        # one that created it — any of them could have been the origin
        key = str(ref).split(":")[-1].replace("-", "_")
        cat = sorted({cve for cve, k in oss_by_cve.items() if k == key})
        if cat and tier_of(c) == "A":
            set_prop(c, "link:circular-cves", ",".join(cat))
    return added, circular


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    detail = json.load(open(NVD_DETAIL, encoding="utf-8"))
    oss_by_cve, _names, _rx = B.build_oss_index()
    print("NVD CPE detail: %d CVE  |  OSS catalog: %d CVE-attributions"
          % (len(detail), len(oss_by_cve)))

    files = sorted(glob.glob(os.path.join(SBOM, "*.json")))
    n_sbom = n_add = n_circ = 0
    by_tier = collections.Counter()
    for fp in files:
        try:
            sbom = json.load(open(fp, encoding="utf-8"))
        except Exception:
            continue
        added, circ = link(sbom, detail, oss_by_cve)
        if not added:
            continue
        for c in sbom.get("components") or []:
            if str(c.get("bom-ref", "")).startswith("pkg:oss:"):
                for p in c.get("properties") or []:
                    if p.get("name") == "link:added-cves":
                        by_tier[tier_of(c)] += len(p["value"].split(","))
        n_sbom += 1
        n_add += added
        n_circ += circ
        if not a.dry_run:
            json.dump(sbom, open(fp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    print("연결한 SBOM        : %d / %d" % (n_sbom, len(files)))
    print("추가된 affects 간선 : %d" % n_add)
    print("  tier별           : %s" % dict(by_tier))
    print("  순환(tier A)      : %d  -> link:circular-cves 로 표시, 채점에서 제외" % n_circ)
    if a.dry_run:
        print("(dry-run — 파일을 쓰지 않았다)")


if __name__ == "__main__":
    main()
