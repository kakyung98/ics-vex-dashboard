#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L2 / L3 / L4 incidence over the WHOLE target CVE population.

tools/measure_sbom_cpe_limits.py answers "what is wrong with an ICS SBOM's CPEs".
This answers the narrower question the deck asks: of every CVE this system has to
identify, what share is blocked by L2 (component-name ambiguity), L3 (version
applicability) and L4 (identifier inconsistency)?

Population: every CVE named by a CISA ICS-CERT advisory in data/cisa_advisories.json.

Per-CVE axis definitions (independent, NOT mutually exclusive - a CVE can be hit
by two or three at once; the overlap table at the end reports that):

  L2  the advisory vendor anchors >1 distinct NVD product for this CVE, so the
      component name alone cannot say WHICH product the CVE is filed against.
      This is the same `_ambiguous_product` rule the GT builder uses to hold a
      pair out of scoring (tools/build_cpe_match_gt.py).
  L3  the CVE has >=1 CPE but not one of its cpeMatch entries carries a version
      or a version bound, so no SBOM version can be decided against it.
  L4  the CVE has >=1 CPE but no CPE vendor matches the advisory vendor, so the
      SBOM's publisher string does not reach the CVE's identifier. Split into
      `alias` (same company under another vendor id - a true identifier
      inconsistency) and `third_party` (the CVE really is filed against someone
      else's embedded component).

  L1  reported alongside for context: no CPE at all, or not in NVD.

Output: results/l2l3l4_incidence.json
"""
import collections
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "results", "l2l3l4_incidence.json")

# Same-company vendor ids. Each entry is a measured case, not a guess: see
# docs/L2_L3_L4_CASES.md section L4 for the advisory that proves it.
ALIAS = {
    "deltaelectronics": {"deltaww"},
    "abb": {"hitachienergy"},
    "hitachienergy": {"hitachi"},
    "aveva": {"schneiderelectric", "schneider-electric"},
    "mitsubishielectric": {"mitsubishi", "mitsubishi_electric"},
    "schneiderelectric": {"schneider-electric", "schneider_electric", "se"},
    "generalelectric": {"ge"},
    "lselectric": {"ls-electric", "lsis"},
    "rockwellautomation": {"rockwell", "rockwellautomation"},
    "wecon": {"we-con"},
    "sierrawireless": {"sierra_wireless"},
    "hanwhavision": {"hanwha-security", "hanwhasecurity"},
    "cambiumnetworks": {"cambium_networks"},
    "3ssoftware": {"3s-software"},
    "digitalalertsystems": {"digital_alert_systems"},
    "festodidacticse": {"festo"},
}


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _adv_vendors(s):
    """Vendor tokens an advisory's vendor string stands for, aliases expanded."""
    out = set()
    for part in re.split(r",|/| and |&", s or ""):
        n = _norm(part)
        if n:
            out.add(n)
            out |= ALIAS.get(n, set())
            out |= {_norm(x) for x in ALIAS.get(n, set())}
    return out


def _adv_vendors_plain(_cve, s):
    """The advisory vendor string as written, with no ALIAS expansion."""
    return {_norm(p) for p in re.split(r",|/| and |&", s or "") if _norm(p)}


def _same(a, x):
    return bool(a and x and (a == x or a.startswith(x) or x.startswith(a)))


def main():
    adv = json.load(open(os.path.join(BASE, "data", "cisa_advisories.json"), encoding="utf-8"))
    raw = json.load(open(os.path.join(BASE, "data", "nvd_cpe_raw.json"), encoding="utf-8"))
    idx = json.load(open(os.path.join(BASE, "data", "cpe_index.json"), encoding="utf-8"))

    entries = collections.defaultdict(list)
    for prod, rows in idx["by_product"].items():
        for r in rows:
            entries[r["cve"]].append(r)

    av = collections.defaultdict(set)
    adv_vendor = {}
    population = set()
    for a in adv.values():
        for c in a.get("cves") or []:
            population.add(c)
            av[c] |= _adv_vendors(a.get("vendor"))
            adv_vendor.setdefault(c, a.get("vendor") or "")

    hit = collections.defaultdict(set)      # axis -> CVEs
    l4_kind = collections.Counter()
    l2_products = []                        # (cve, n_anchored) for the tail
    rescued = collections.Counter()         # CVEs the ALIAS table rescues from L4
    for c in sorted(population):
        v = raw.get(c)
        if v is None:
            hit["L1_not_in_nvd"].add(c)
            continue
        if v["cpe"] == 0:
            hit["L1_no_cpe"].add(c)
            continue
        hit["with_cpe"].add(c)
        rows = entries.get(c) or []
        vendors = {_norm(r["vendor"]) for r in rows} or {_norm(x) for x in v["vendors"]}

        # --- L4: does the advisory vendor reach any CPE vendor at all? --------
        # `plain` uses the advisory string as written; `anchored` also accepts the
        # ALIAS table. A CVE only `plain` misses is an identifier inconsistency we
        # have already catalogued - counted as `rescued_by_alias`, still L4 in kind
        # but no longer blocking, because the alias is known.
        plain = [r for r in rows if any(_same(_norm(a), _norm(r["vendor"]))
                                       for a in _adv_vendors_plain(c, adv_vendor[c]))]
        anchored = [r for r in rows if any(_same(a, _norm(r["vendor"])) for a in av[c])]
        if not anchored:
            hit["L4"].add(c)
            l4_kind["third_party"] += 1
        elif not plain:
            hit["L4_alias"].add(c)
            rescued[adv_vendor[c]] += 1

        # --- L2: >1 product anchored by the advisory vendor -------------------
        prods_anchored = {r["product"] for r in anchored if r.get("product")}
        if len(prods_anchored) > 1:
            hit["L2"].add(c)
            l2_products.append((c, len(prods_anchored)))
        # with no anchor at all the product axis cannot be judged by the vendor;
        # the ambiguity over the CVE's own product list is still real, reported apart
        if not anchored and len({r["product"] for r in rows if r.get("product")}) > 1:
            hit["L2_unanchored"].add(c)

        # --- L3: any version or bound anywhere on this CVE? -------------------
        def bounded(r):
            return bool(r.get("startIncl") or r.get("startExcl")
                        or r.get("endIncl") or r.get("endExcl"))
        if rows and not any(bounded(r) or r.get("version") for r in rows):
            hit["L3"].add(c)                     # nothing decides a version at all
        if rows and not any(bounded(r) for r in rows):
            hit["L3_no_range"].add(c)            # exact versions enumerated, no range

    n = len(population)
    pct = lambda s: round(100.0 * len(s) / n, 1)  # noqa: E731
    L2, L3, L4 = hit["L2"] | hit["L2_unanchored"], hit["L3"], hit["L4"] | hit["L4_alias"]
    res = {
        "population": n,
        "not_in_nvd": len(hit["L1_not_in_nvd"]),
        "no_cpe": len(hit["L1_no_cpe"]),
        "with_cpe": len(hit["with_cpe"]),
        "axes": {
            "L1_no_identifier": {"cves": len(hit["L1_not_in_nvd"]) + len(hit["L1_no_cpe"]),
                                 "pct": round(100.0 * (len(hit["L1_not_in_nvd"])
                                                       + len(hit["L1_no_cpe"])) / n, 1)},
            "L2_name_ambiguity": {
                "cves": len(L2), "pct": pct(L2),
                "vendor_anchored": len(hit["L2"]),
                "vendor_anchored_pct": pct(hit["L2"]),
                "unanchored_only": len(hit["L2_unanchored"] - hit["L2"]),
            },
            "L3_version_applicability": {
                "cves": len(L3), "pct": pct(L3),
                "no_range_but_enumerated": len(hit["L3_no_range"] - L3),
                "no_range_total": len(hit["L3_no_range"]),
                "no_range_total_pct": pct(hit["L3_no_range"]),
            },
            "L4_identifier_inconsistency": {
                "cves": len(L4), "pct": pct(L4),
                "third_party": len(hit["L4"]), "third_party_pct": pct(hit["L4"]),
                "rescued_by_alias": len(hit["L4_alias"]),
                "rescued_by_alias_pct": pct(hit["L4_alias"]),
                "rescued_by_vendor": rescued.most_common(10),
            },
        },
        "clean": {"cves": n - len(L2 | L3 | L4 | hit["L1_no_cpe"] | hit["L1_not_in_nvd"])},
        "overlap": {
            "L2_only": len(L2 - L3 - L4), "L3_only": len(L3 - L2 - L4),
            "L4_only": len(L4 - L2 - L3), "L2_L3": len(L2 & L3 - L4),
            "L2_L4": len(L2 & L4 - L3), "L3_L4": len(L3 & L4 - L2),
            "L2_L3_L4": len(L2 & L3 & L4),
            "any": len(L2 | L3 | L4),
        },
        "l2_worst": sorted(l2_products, key=lambda t: -t[1])[:10],
    }
    res["overlap"]["any_pct"] = round(100.0 * res["overlap"]["any"] / n, 1)
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
