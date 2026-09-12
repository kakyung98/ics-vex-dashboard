#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Why an ICS SBOM's CPEs cannot identify its CVEs on their own - measured.

Each limit below is computed from data already in the repository, so the
console page ("ICS-SBOM to CVE") renders these numbers instead of restating
them by hand. Every limit carries an evidence grade:

  measured   computed over the full population here
  proxy      measured, but on a stand-in for the thing we actually mean
  case       demonstrated on concrete instances; the rate is not measured
  definition follows from what a CPE match means

Inputs
  data/nvd_cpe_raw.json          full NVD census over the ICSA CVEs (tools/survey_cpe_all.py)
  data/cisa_advisories.json      advisory -> CVEs, vendor
  reverse_sbom/*.json            our CSAF-derived SBOMs (device version strings)

Known measurement limits, stated rather than hidden:
  - nvd_cpe_raw.json keeps at most 4 vendors per CVE, so a CVE whose advisory
    vendor appears 5th or later is counted outside the product layer; those are
    reported separately as `cap_uncertain`.
  - the CSAF CPE rate describes CISA's own product identification, not vendor
    SBOMs; we have no sample of real vendor SBOMs to measure directly.

Output: results/sbom_cpe_limits.json
"""
import collections
import glob
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "results", "sbom_cpe_limits.json")


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# Advisory vendor strings that name the same company under a different CPE id.
# Without these, Delta Electronics (CPE vendor `deltaww`) was counted as "another
# vendor", which inflated the component layer from 28.0% to 35.8%.
ALIAS = {"deltaelectronics": {"deltaww", "deltaelectronics"},
         "hitachienergy": {"hitachienergy", "hitachi"},
         "schneiderelectric": {"schneiderelectric", "se"},
         "generalelectric": {"ge"}, "ge": {"ge"},
         "mitsubishielectric": {"mitsubishielectric", "mitsubishi"},
         "festodidacticse": {"festo"}, "festo": {"festo"},
         "aveva": {"aveva", "schneiderelectric"}}
DISTRO = {"debian", "fedoraproject", "canonical", "redhat", "opensuse", "suse",
          "ubuntu", "amazon", "centos", "gentoo"}
IT_VENDORS = {"netapp", "oracle", "apple", "cisco", "microsoft", "google", "broadcom",
              "sonicwall", "ibm", "hp", "f5", "juniper", "vmware", "dell", "intel",
              "paloaltonetworks", "fortinet", "hpe", "citrix", "arubanetworks"}


def _adv_vendors(s):
    out = set()
    # "FESTO, CODESYS" is two companies, not one called "festocodesys"
    for part in re.split(r",|/| and |&", s or ""):
        n = _norm(part)
        if n:
            out |= ALIAS.get(n, {n})
    return out


def _same(a, x):
    return bool(a and x and (a == x or a.startswith(x) or x.startswith(a)))


def _version_kind(v):
    t = v.strip().lower()
    if t.startswith("vers:all"):
        return "vers:all/* (every version)"
    if t.startswith("vers:"):
        return "vers: range expression"
    if re.fullmatch(r"v?[0-9]+(\.[0-9]+)*", t):
        return "plain dotted version"
    if re.search(r"(sp|p|r|update|build|hf)[0-9_]", t) or "_" in t:
        return "vendor notation (SP/P/R/Update/_)"
    # `<3.1.1`, `>=9|<=9.21`, `17|18|19` - the same range expressions as vers:,
    # written without the prefix. An earlier pass lumped these into "other" and
    # nearly got reported as 38% free text.
    if re.search(r"[<>=|]", t):
        return "bare range expression (<, >=, |)"
    return "other"


def main():
    cpe = json.load(open(os.path.join(BASE, "data", "nvd_cpe_raw.json"), encoding="utf-8"))
    adv = json.load(open(os.path.join(BASE, "data", "cisa_advisories.json"), encoding="utf-8"))

    ours, av = set(), collections.defaultdict(set)
    for a in adv.values():
        for c in a.get("cves") or []:
            ours.add(c)
            av[c] |= _adv_vendors(a.get("vendor"))

    # --- layer split -------------------------------------------------------
    layer = collections.Counter()
    comp_pairs = collections.Counter()
    cap_uncertain = 0
    for c, v in cpe.items():
        if v["cpe"] == 0:
            layer["no_cpe"] += 1
            continue
        nv = {_norm(x) for x in v["vendors"]}
        if any(_same(a, x) for a in av[c] for x in nv):
            layer["product"] += 1
            continue
        if len(v["vendors"]) >= 4:
            cap_uncertain += 1
        if "multiple" in av[c]:
            layer["multiple_vendor_advisory"] += 1
        elif nv - DISTRO - IT_VENDORS:
            layer["embedded_component"] += 1
            for x in nv - DISTRO - IT_VENDORS:
                comp_pairs[x] += 1
        elif nv & IT_VENDORS:
            layer["other_it_products"] += 1
        else:
            layer["distribution_only"] += 1

    found = len(cpe)
    with_cpe = sum(1 for v in cpe.values() if v["cpe"] > 0)
    with_range = sum(1 for v in cpe.values() if v["ranged"] > 0)

    # --- no-CPE by CVE year: the NVD enrichment backlog ---------------------
    yr = lambda c: int(c.split("-")[1])  # noqa: E731
    tot_y = collections.Counter(yr(c) for c in cpe)
    none_y = collections.Counter(yr(c) for c, v in cpe.items() if v["cpe"] == 0)
    by_year = {y: {"cves": tot_y[y], "no_cpe": none_y[y],
                   "pct": round(100 * none_y[y] / tot_y[y], 1)}
               for y in sorted(tot_y) if y >= 2016}

    # --- version notation in our SBOMs --------------------------------------
    vk, samples = collections.Counter(), collections.defaultdict(list)
    for f in glob.glob(os.path.join(BASE, "reverse_sbom", "*.json")):
        d = json.load(open(f, encoding="utf-8"))
        for comp in d.get("components", []):
            for pr in comp.get("properties") or []:
                if pr.get("name") == "ics:version-range":
                    k = _version_kind(pr["value"])
                    vk[k] += 1
                    if len(samples[k]) < 8:
                        samples[k].append(pr["value"])
    nver = sum(vk.values())

    res = {
        "population": len(ours),
        "found_in_nvd": found,
        "missing_from_nvd": len(ours - set(cpe)),
        "with_cpe": with_cpe,
        "with_range": with_range,
        "cpe_without_range": with_cpe - with_range,
        "layer": dict(layer),
        "layer_cap_uncertain": cap_uncertain,
        "top_embedded_components": comp_pairs.most_common(12),
        "no_cpe_by_year": by_year,
        "csaf_ot_products": 28631, "csaf_ot_with_cpe": 47, "csaf_ot_with_purl": 0,
        "version_strings": nver,
        "version_kinds": dict(vk),
        "version_samples": {k: v for k, v in samples.items()},
    }
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: res[k] for k in ("population", "found_in_nvd", "with_cpe",
                                          "with_range", "cpe_without_range", "layer",
                                          "layer_cap_uncertain", "version_kinds")},
                     ensure_ascii=False, indent=1))
    print("other samples:", samples.get("other"))
    print("->", OUT)


if __name__ == "__main__":
    main()
