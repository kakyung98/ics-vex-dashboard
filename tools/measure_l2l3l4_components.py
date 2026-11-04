#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L2 / L3 / L4 incidence measured ON THE UNIT THE DEFINITIONS ACTUALLY NAME.

tools/measure_l2l3l4.py counted CVEs. Re-reading the deck's own wording, that is
the wrong unit: every one of L2/L3/L4 is defined as a failure of the mapping from
an S/HBOM component to the CVE database, so the unit is the COMPONENT (L2, L4) or
the (component, CVE) pair (L3) - not the CVE.

  L2 "동일·유사 명칭의 제품 및 컴포넌트명 모호성"
     -> a component whose NAME cannot be resolved to one CPE product because the
        candidates are near-indistinguishable. Measured as the identification
        cascade abstaining with a live candidate whose lead over the runner-up is
        below the margin. A component with NO candidate at all is not name
        ambiguity - it is absence, counted separately.
  L3 "버전 표현 불일치, CVE 영향 버전 범위와 빌드/패치 조건의 모호성"
     -> split into the two halves the sentence names:
        L3a notation - the SBOM-side version string is not a comparable version
        L3b range    - the CVE side carries no version bound and no exact version
        (build/patch conditions are NOT measured here; stated as out of scope)
  L4 "S/HBOM과 CVE 데이터베이스 간 제조사명, 제품명, CPE/PURL 등 식별자 불일치"
     -> split into the identifier kinds the sentence names:
        L4a cpe/purl  - no usable CPE or purl on the component
        L4b vendor    - publisher does not reach any CPE vendor of its CVEs
        L4c product   - the same product carries >1 NVD product id (case-counted)

Population: every component of every reverse-built SBOM (reverse_sbom/*.json).

Output: results/l2l3l4_components.json
"""

from sbom_paths import public_sbom_directory
import collections
import glob
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "src"))
import cpe_match_l0l3 as M  # noqa: E402

OUT = os.path.join(BASE, "results", "l2l3l4_components.json")

# A purl this corpus mints from the display name carries no identity beyond the
# name it was slugified from, so it cannot resolve an identifier question.
PLACEHOLDER_PURL = re.compile(r"^pkg:generic/")


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _comparable_version(v):
    """True when a machine can order this version expression against a CPE bound.

    A first cut accepted only plain dotted versions and reported 99.9% as
    incomparable - wrong: `vers:intdot/<4.3.4` and the bare `>=9|<=9.21` are both
    mechanically comparable, and `vers:all/*` is trivially decidable (everything is
    in range). What is genuinely incomparable is vendor notation whose order is not
    defined (SP1, CPR9-SR4, Firmware_V4.9) and free text.
    """
    t = (v or "").strip().lower()
    if not t:
        return False
    if t.startswith("vers:"):
        return True
    if re.fullmatch(r"v?[0-9]+(\.[0-9]+)*", t):
        return True
    if re.search(r"(sp|p|r|update|build|hf)[0-9_]", t) or "_" in t:
        return False                      # vendor notation: no defined ordering
    return bool(re.search(r"[<>=|]", t))  # bare range expression


def main():
    idx = json.load(open(os.path.join(BASE, "data", "cpe_index.json"), encoding="utf-8"))
    entries = collections.defaultdict(list)
    for prod, rows in idx["by_product"].items():
        for r in rows:
            entries[r["cve"]].append(r)

    n = 0
    how = collections.Counter()
    axis = collections.Counter()
    l3_pairs = collections.Counter()
    margins = []
    for f in sorted(glob.glob(os.path.join(str(public_sbom_directory()), "*.json"))):
        d = json.load(open(f, encoding="utf-8"))
        cves = [v.get("id") for v in d.get("vulnerabilities") or [] if v.get("id")]
        for c in d.get("components", []):
            n += 1
            pub = _norm(c.get("publisher"))

            # ---- L4a: is there a usable identifier on the component at all? ---
            purl = str(c.get("purl") or "")
            has_cpe = bool(c.get("cpe"))
            usable_purl = bool(purl) and not PLACEHOLDER_PURL.match(purl)
            if not has_cpe and not usable_purl:
                axis["L4a_no_usable_cpe_or_purl"] += 1

            # ---- identification cascade --------------------------------------
            prod, h = M.identify_product(c)
            kind = h.split(" ")[0]
            how[kind] += 1

            # ---- L2: name ambiguity, as opposed to name absence ---------------
            if kind == "ambiguous":
                m = re.search(r"([0-9.]+)/next ([0-9.]+)", h)
                if m:
                    lead, runner = float(m.group(1)), float(m.group(2))
                    margins.append(round(lead - runner, 3))
                    axis["L2_name_ambiguous"] += 1
                else:
                    axis["L2x_no_candidate"] += 1

            # ---- L4b: does the publisher reach any CPE vendor of its CVEs? ----
            if cves:
                vend = {_norm(r["vendor"]) for cv in cves for r in entries.get(cv, [])}
                if vend and pub and not any(pub == v or pub.startswith(v) or v.startswith(pub)
                                            for v in vend):
                    axis["L4b_vendor_mismatch"] += 1

            # ---- L3a: is the component's own version string comparable? ------
            rng = next((p["value"] for p in c.get("properties") or []
                        if p.get("name") == "ics:version-range"), None)
            ver = rng or c.get("version")
            if rng is not None and not _comparable_version(ver):
                axis["L3a_version_not_comparable"] += 1

            # ---- L3b: per (component, CVE) pair, can any entry decide? --------
            for cv in cves:
                rows = entries.get(cv) or []
                l3_pairs["pairs"] += 1
                if not rows:
                    l3_pairs["no_cpe"] += 1
                elif not any(r.get("version") or r.get("startIncl") or r.get("startExcl")
                             or r.get("endIncl") or r.get("endExcl") for r in rows):
                    l3_pairs["L3b_no_decidable_version"] += 1

    pct = lambda k, tot=n: round(100.0 * axis[k] / tot, 1)  # noqa: E731
    res = {
        "unit": "SBOM component (L2, L4a, L4b, L3a) / (component, CVE) pair (L3b)",
        "components": n,
        "identification_path": dict(how),
        "L2_component_name_ambiguity": {
            "components": axis["L2_name_ambiguous"], "pct": pct("L2_name_ambiguous"),
            "definition": "cascade abstained with a live candidate; lead over runner-up below margin",
            "median_margin": sorted(margins)[len(margins) // 2] if margins else None,
            "also_no_candidate_at_all": axis["L2x_no_candidate"],
        },
        "L3_version_applicability": {
            "L3a_notation": {"components": axis["L3a_version_not_comparable"],
                             "pct": pct("L3a_version_not_comparable"),
                             "of_components_with_a_version_range": None},
            "L3b_range": {"pairs": l3_pairs["L3b_no_decidable_version"],
                          "pairs_total": l3_pairs["pairs"],
                          "pct": round(100.0 * l3_pairs["L3b_no_decidable_version"]
                                       / max(l3_pairs["pairs"], 1), 1),
                          "pairs_cve_without_cpe": l3_pairs["no_cpe"]},
            "build_patch_conditions": "not measured - out of scope of this corpus",
        },
        "L4_identifier_inconsistency": {
            "L4a_no_usable_cpe_or_purl": {"components": axis["L4a_no_usable_cpe_or_purl"],
                                          "pct": pct("L4a_no_usable_cpe_or_purl")},
            "L4b_vendor_mismatch": {"components": axis["L4b_vendor_mismatch"],
                                    "pct": pct("L4b_vendor_mismatch")},
            "L4c_product_id_split": "case-counted in docs/L2_L3_L4_CASES.md (GE CIMPLICITY etc.)",
        },
    }
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
