#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The 6W problem taxonomy for SBOM/HBOM -> CVE identification.

Identifying a CVE from a bill of materials is really six separate identity
questions, and they fail for different reasons and with different prospects of
being fixed. Writing them down as one blob ("matching is hard") hides the fact
that two of the six are not hard but IMPOSSIBLE from the SBOM alone, which is
the single most important thing a methodology has to state.

  WHO    whose product is this          supplier / vendor identity
  WHAT   which product is this          component identity
  WHEN   which build, and as of when    version, affected range, corpus freshness
  WHERE  where does it sit              asset placement, embedded layer, operations
  WHY    why is it vulnerable           the vulnerable code and its trigger
  HOW    how do we know                 evidence provenance of the match itself

Every number in PROBLEMS is MEASURED by survey(), not written down, for the same
reason src/vex_decision._corpus() reads its counts from the caches: a figure
typed into a docstring goes stale silently and then gets quoted in a report. Run
`python src/sbom_cve_problems.py` to regenerate.

Verdicts
--------
  SOLVED        a mechanism exists in this repository and its residual error is
                measured
  PARTIAL       a mechanism exists and provably recovers part of the loss; the
                remainder is reported as abstention rather than guessed
  UNSOLVABLE    not decidable from a bill of materials at all. The methodology's
                job here is to turn it into a declared INPUT, or to refuse to
                answer. Guessing is the one option that is off the table.
"""

import sys as _dataset_sys
from pathlib import Path as _DatasetPath
_dataset_sys.path.insert(0,str(_DatasetPath(__file__).resolve().parents[1]))
from src.dataset_paths import public_sbom_directory
import json
import os
import re
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))

SOLVED = "solved"
PARTIAL = "partial"
UNSOLVABLE = "unsolvable"

PROBLEMS = [
    # ---------------- WHO ----------------
    {"id": "W1", "axis": "WHO", "name": "Shared-code CVEs name every vendor that ships them",
     "problem": "NVD attaches one CPE per vendor that ships the vulnerable code, so a "
                "single zlib CVE also carries netapp, oracle and apple. Matching on the "
                "product field while ignoring the vendor field turns every co-listed IT "
                "vendor into a false positive on an ICS asset.",
     "verdict": SOLVED,
     "mechanism": "src/cpe_match_l0l3.vendor_ok() grades each candidate anchored / "
                  "canonical / co-listed instead of hard-filtering, because a hard "
                  "vendor filter drops the embedded OSS layer - exactly the layer that "
                  "carries most real matches.",
     "residual": "A co-listed entry is kept with a confidence tag, so vendor ambiguity "
                 "becomes a declared confidence level rather than a silent error.",
     "measure": "cve_multi_vendor_pct"},
    {"id": "W2", "axis": "WHO", "name": "Vendor naming is not canonical",
     "problem": "The same supplier appears as 'Siemens', 'Siemens AG', 'siemens' and as "
                "an OEM relabeller of someone else's hardware. HBOM makes this worse: a "
                "relabelled module carries the integrator's name, not the manufacturer's.",
     "verdict": PARTIAL,
     "mechanism": "Vendor normalisation in src/sbom_match.ics_identify plus the "
                  "canonical-vendor table derived from the NVD CPE index.",
     "residual": "OEM relabelling cannot be undone without a manufacturer cross-"
                 "reference the SBOM does not carry; those components resolve through "
                 "the model-code path or abstain.",
     "measure": None},

    # ---------------- WHAT ----------------
    {"id": "W3", "axis": "WHAT", "name": "ICS components carry almost no machine identifier",
     "problem": "CPE is the key CVE identification is built on, and ICS SBOMs barely "
                "have it. Without an identifier the matcher is reduced to the display "
                "name, which is prose: 'SIMATIC CP 1543SP-1 (6GK7543-6WX00-0XE0) "
                ">=V2.0_<V2.2.28' is a product, an order code and a version range in "
                "one string.",
     "verdict": PARTIAL,
     "mechanism": "An identifier-first cascade (model order code -> purl -> cpe -> exact "
                  "name -> ICS name normalisation -> bounded fuzzy) over the full NVD CPE "
                  "product index rather than a 42-entry OSS table. The order code is the "
                  "one identifier that cannot be half-right: it is a key in the index or "
                  "it is not.",
     "residual": "Everything the cascade cannot resolve ABSTAINS. Abstention is reported "
                 "as coverage loss, never filled in by similarity.",
     "measure": "component_cpe_pct"},
    {"id": "W4", "axis": "WHAT", "name": "An SBOM cannot prove it is complete",
     "problem": "A component the supplier did not list is indistinguishable from a "
                "component that is not there. Every recall figure over an SBOM is "
                "conditional on the SBOM, and no analysis of the document can detect an "
                "omission in it.",
     "verdict": UNSOLVABLE,
     "mechanism": "None available from the document. The methodology states recall as "
                  "'of the components the SBOM declares' and never as 'of the software "
                  "on the device'. Closing it needs firmware extraction, i.e. evidence "
                  "from outside the SBOM.",
     "residual": "Unbounded and undetectable. This is the reason a VEX built on an SBOM "
                 "is a statement about a declared inventory, not about a device.",
     "measure": None},

    # ---------------- WHEN ----------------
    {"id": "W5", "axis": "WHEN", "name": "The version field is empty in practice",
     "problem": "Version is what decides whether a CVE applies, and in the measured "
                "corpus the component version field is NOASSERTION everywhere. The "
                "affected RANGE is recoverable from the display name about half the time, "
                "but a range is not an installed version: it says which builds are "
                "vulnerable, not which build is installed.",
     "verdict": PARTIAL,
     "mechanism": "src/cpe_match_l0l3.declared_range() parses the VERS / bare bound out "
                  "of the name, and version comparison is three-valued - True / False / "
                  "None - with None (undecidable) never read as False.",
     "residual": "Where the name carries no bound, version is undecidable and the "
                  "candidate is kept rather than dropped, which costs precision instead "
                  "of silently costing recall.",
     "measure": "version_noassertion_pct"},
    {"id": "W6", "axis": "WHEN", "name": "The installed version is not in the document",
     "problem": "No parsing recovers a fact the document does not contain. When the "
                "SBOM says NOASSERTION and the name carries no bound, the installed "
                "build is simply unknown.",
     "verdict": UNSOLVABLE,
     "mechanism": "Declared as a required INPUT: the asset owner supplies the installed "
                  "version, or the device is interrogated. The pipeline marks the "
                  "statement version-undecidable rather than assuming either side.",
     "residual": "Until the input arrives, every CVE for that component stays a "
                 "candidate. This is the largest single source of over-identification "
                 "and it is an input problem, not an algorithm problem.",
     "measure": "name_range_pct"},
    {"id": "W7", "axis": "WHEN", "name": "An SBOM is a snapshot; CVEs keep arriving",
     "problem": "A bill of materials is true as of its timestamp. The CVE set for the "
                "same unchanged asset grows every week, so a one-time analysis is wrong "
                "by construction a month later.",
     "verdict": SOLVED,
     "mechanism": "Identification is re-run against the refreshed NVD/CISA caches; the "
                  "SBOM is the stable input and the CVE set is the recomputed output. "
                  "Each statement records the cache date it was decided against.",
     "residual": "Bounded by refresh cadence, and visible because the date is recorded.",
     "measure": None},

    # ---------------- WHERE ----------------
    {"id": "W8", "axis": "WHERE", "name": "The vulnerable code is one layer below the product",
     "problem": "A CVE's CPE often names the embedded upstream component (OpenSSL, the "
                "Linux kernel, a CODESYS runtime) and not the ICS product the SBOM "
                "lists. An SBOM read as a flat product list cannot reach those CVEs.",
     "verdict": SOLVED,
     "mechanism": "src/component_resolve.py splits each entry into ics-product / "
                  "product-variant / embedded-component and identifies each layer "
                  "separately, so the runtime inside a device resolves on its own.",
     "residual": "Only the layers the SBOM declares can be split - see W4.",
     "measure": "embedded_component_pct"},
    {"id": "W9", "axis": "WHERE", "name": "Operational context is absent from the SBOM",
     "problem": "Whether a CVE matters depends on where the asset sits and what it does - "
                "zone, exposure, whether a human uses it, whether it carries a safety "
                "function. The CycloneDX schema has a place for this (the ICS property "
                "extension) and the measured corpus populates none of it.",
     "verdict": UNSOLVABLE,
     "mechanism": "Declared as a required INPUT of the VEX stage, collected from the "
                  "asset owner through src/ics_context.CONTEXT_FIELDS, pre-filled from "
                  "the SBOM where the properties happen to exist. It is never inferred "
                  "from the vendor, the device name or the advisory.",
     "residual": "With no context supplied, the judge can produce no refutation at all - "
                 "src/vex_context_judge.readiness() reports this rather than letting a "
                 "blank form look like an analysis.",
     "measure": "asset_opcontext_pct"},

    # ---------------- WHY ----------------
    {"id": "W10", "axis": "WHY", "name": "The source code of ICS software cannot be obtained",
     "problem": "The strongest VEX justifications - vulnerable_code_not_present and a "
                "real execute-path analysis - require reading the code. ICS firmware is "
                "closed, and in the measured corpus the overwhelming majority of "
                "components have no obtainable source. Source-based gates therefore "
                "cannot be the primary method; they can only ever be a minority branch.",
     "verdict": UNSOLVABLE,
     "mechanism": "The methodology inverts the default: the primary VEX arm reasons from "
                  "the complete CVSS vector and the asset's operational context "
                  "(src/vex_context_judge.py), and the source arm runs only where source "
                  "exists. The context arm NEVER claims a code-level justification.",
     "residual": "No context reasoning can decide whether a function is compiled into a "
                 "closed binary. Those two justifications stay permanently out of reach "
                 "for closed firmware, and the pipeline is built so it cannot emit them.",
     "measure": "source_closed_pct"},
    {"id": "W11", "axis": "WHY", "name": "A CVE without a CVSS vector states no preconditions",
     "problem": "The context arm reasons from what a vector REQUIRES. A CVE with no "
                "published vector requires nothing stateable, so there is nothing to "
                "test the asset against.",
     "verdict": PARTIAL,
     "mechanism": "CVSS coverage over the corpus is high, so the gap is small and "
                  "measurable. Where a vector is missing, the CTI-derived service "
                  "requirement is tried; where that is missing too, the statement is "
                  "under_investigation with a triage hint, never not_affected.",
     "residual": "Measured as the share of corpus CVEs with no vector.",
     "measure": "cvss_absent_pct"},
    {"id": "W12", "axis": "WHY", "name": "Attacker-side conditions are not asset facts",
     "problem": "AC:H describes a race window, a reconnaissance step or a configuration "
                "the attacker must find. No fact about the asset refutes it.",
     "verdict": UNSOLVABLE,
     "mechanism": "src/ics_context._eval_ac_h returns `unknown` unconditionally and is "
                  "documented as never refutable, so AC:H can never contribute to a "
                  "clearance.",
     "residual": "By design, AC:H is evidence only.",
     "measure": None},

    # ---------------- HOW ----------------
    {"id": "W13", "axis": "HOW", "name": "A match without its provenance cannot be reviewed",
     "problem": "Six matching paths with different reliabilities produce one list of "
                "CVEs. A reviewer who cannot tell an exact order-code hit from a 0.90 "
                "string-similarity hit cannot audit the result, and a single aggregate "
                "precision figure hides which path is carrying the errors.",
     "verdict": SOLVED,
     "mechanism": "Every match records the path that produced it and precision is "
                  "reported per path (`tp_by_path`), so the fuzzy tail is visible "
                  "separately from the identifier hits.",
     "residual": "None in principle; it is a bookkeeping requirement, and the cost is "
                 "that every new matching path must carry its own measurement.",
     "measure": None},
    {"id": "W14", "axis": "HOW", "name": "A context refutation is a human assertion",
     "problem": "'The radio module is not fitted' and 'the maintenance port is potted' "
                "are claims about hardware that no analysis in this pipeline verifies. "
                "They are strong enough to clear a CVE, which makes them exactly the "
                "claims that need an owner.",
     "verdict": PARTIAL,
     "mechanism": "Every context verdict carries `evidence_basis: asset-owner assertion` "
                  "and an attester field; an unattested not_affected is emitted with an "
                  "explicit UNATTESTED note telling the publisher to attach one.",
     "residual": "The assertion itself is unverified. Verification would need physical "
                 "inspection, which is outside a software pipeline - so the honest move "
                 "is to make the dependency visible in the document.",
     "measure": None},
]


# --- the measurements, recomputed from the corpus ---------------------------
def survey(reverse_dir=None, quiet=True):
    """Recompute every `measure` from the corpus. Missing data yields None, which
    shows up as 'not measured' rather than as a stale-but-plausible number."""
    reverse_dir = reverse_dir or str(public_sbom_directory())
    out = {k: None for k in ("component_cpe_pct", "version_noassertion_pct",
                             "name_range_pct", "source_closed_pct",
                             "embedded_component_pct", "asset_opcontext_pct",
                             "cve_multi_vendor_pct", "cvss_absent_pct",
                             "components", "assets", "cves")}
    try:
        from cpe_match_l0l3 import declared_range
    except Exception:
        declared_range = lambda n: {}        # noqa: E731

    if os.path.isdir(reverse_dir):
        comps = cpe = noassert = ranged = closed = src_known = embedded = 0
        assets = opctx = 0
        cves = set()
        opkeys = ("ics:purdue-level", "ics:network-exposure",
                  "ics:safety-integrity-level", "ics:device-class")
        for fn in sorted(os.listdir(reverse_dir)):
            try:
                with open(os.path.join(reverse_dir, fn), encoding="utf-8") as f:
                    d = json.load(f)
            except Exception:
                continue
            assets += 1
            mc = (d.get("metadata") or {}).get("component") or {}
            names = {p.get("name") for p in (mc.get("properties") or [])}
            if names & set(opkeys):
                opctx += 1
            for c in d.get("components") or []:
                comps += 1
                if c.get("cpe"):
                    cpe += 1
                v = str(c.get("version") or "").upper()
                if v in ("", "NOASSERTION", "UNKNOWN", "*", "VERSION_PLACEHOLDER"):
                    noassert += 1
                if declared_range(c.get("name") or ""):
                    ranged += 1
                pr = {p.get("name"): p.get("value") for p in (c.get("properties") or [])}
                tier = pr.get("component:source-availability")
                if tier:
                    src_known += 1
                    if tier == "E":
                        closed += 1
                if c.get("type") == "library" or pr.get("component:origin") == "third-party-open-source":
                    embedded += 1
            for v in d.get("vulnerabilities") or []:
                if v.get("id"):
                    cves.add(v["id"])
        if comps:
            out.update(components=comps, assets=assets, cves=len(cves),
                       component_cpe_pct=round(100.0 * cpe / comps, 2),
                       version_noassertion_pct=round(100.0 * noassert / comps, 2),
                       name_range_pct=round(100.0 * ranged / comps, 2),
                       embedded_component_pct=round(100.0 * embedded / comps, 2))
        if src_known:
            out["source_closed_pct"] = round(100.0 * closed / src_known, 2)
            out["source_known_n"] = src_known
        if assets:
            out["asset_opcontext_pct"] = round(100.0 * opctx / assets, 2)

        # CVSS coverage over exactly the CVEs this corpus identifies.
        cvp = os.path.join(BASE, "data", "nvd_cvss.json")
        if cves and os.path.isfile(cvp):
            try:
                with open(cvp, encoding="utf-8") as f:
                    cv = json.load(f)
                have = sum(1 for c in cves if (cv.get(c) or {}).get("vector"))
                out["cvss_absent_pct"] = round(100.0 * (len(cves) - have) / len(cves), 2)
            except Exception:
                pass

    idx = os.path.join(BASE, "data", "cpe_index.json")
    if os.path.isfile(idx):
        try:
            with open(idx, encoding="utf-8") as f:
                d = json.load(f)
            cv = d.get("cve_vendors") or {}
            if cv:
                multi = sum(1 for v in cv.values() if len(set(v)) > 1)
                out["cve_multi_vendor_pct"] = round(100.0 * multi / len(cv), 2)
                out["cpe_index_products"] = len(d.get("by_product") or {})
        except Exception:
            pass
    return out


MEASURE_LABEL = {
    "component_cpe_pct": "components carrying a CPE",
    "version_noassertion_pct": "components whose version field is NOASSERTION",
    "name_range_pct": "components whose display name carries an affected range",
    "source_closed_pct": "components with a source-availability tier whose source is closed",
    "embedded_component_pct": "components that are an embedded third-party layer",
    "asset_opcontext_pct": "assets carrying any ICS operational property",
    "cve_multi_vendor_pct": "CVEs whose CPE list names more than one vendor",
    "cvss_absent_pct": "identified CVEs with no published CVSS vector",
}


def report(stats=None):
    """The taxonomy with its measurements attached, ready to render or serialise."""
    stats = stats if stats is not None else survey()
    rows = []
    for p in PROBLEMS:
        r = dict(p)
        key = p.get("measure")
        if key:
            r["measured"] = {"key": key, "value": stats.get(key),
                             "label": MEASURE_LABEL.get(key)}
        rows.append(r)
    counts = {v: sum(1 for p in PROBLEMS if p["verdict"] == v)
              for v in (SOLVED, PARTIAL, UNSOLVABLE)}
    return {"problems": rows, "stats": stats, "verdict_counts": counts}


# --- per-component diagnosis -------------------------------------------------
_VERS = re.compile(r"vers:|[<>]=?\s*_?[Vv]?[0-9]")


def diagnose(component):
    """Which of the 6W questions this one component can answer about itself.

    Used to attach an identification-confidence record to each match, so a
    reviewer sees WHY a component resolved weakly instead of only that it did.
    """
    pr = {p.get("name"): p.get("value") for p in (component.get("properties") or [])}
    name = component.get("name") or ""
    ver = str(component.get("version") or "").upper()
    sup = component.get("supplier") or component.get("publisher") or component.get("group")
    out = {
        "WHO": {"ok": bool(sup), "evidence": "supplier/publisher present" if sup
                else "no supplier recorded (W2)"},
        "WHAT": {"ok": bool(component.get("cpe") or component.get("purl")),
                 "evidence": ("cpe" if component.get("cpe") else
                              "purl only - product field must be inferred (W3)"
                              if component.get("purl") else "name only (W3)")},
        "WHEN": {"ok": ver not in ("", "NOASSERTION", "UNKNOWN", "*", "VERSION_PLACEHOLDER"),
                 "evidence": ("concrete version" if ver not in
                              ("", "NOASSERTION", "UNKNOWN", "*", "VERSION_PLACEHOLDER")
                              else "version NOASSERTION; affected range in the name (W5)"
                              if _VERS.search(name) else
                              "version NOASSERTION and no range in the name (W6)")},
        "WHERE": {"ok": bool(pr.get("component:origin")),
                  "evidence": "origin %s" % pr.get("component:origin") if
                  pr.get("component:origin") else "layer not declared (W8)"},
        "WHY": {"ok": pr.get("component:source-availability") in ("A", "C"),
                "evidence": "source tier %s" % pr.get("component:source-availability")
                if pr.get("component:source-availability") else "source availability not declared (W10)"},
    }
    out["answerable"] = sum(1 for k in ("WHO", "WHAT", "WHEN", "WHERE", "WHY") if out[k]["ok"])
    return out


if __name__ == "__main__":
    rep = report()
    s = rep["stats"]
    print("corpus: %s assets, %s components, %s distinct CVEs\n"
          % (s.get("assets"), s.get("components"), s.get("cves")))
    for axis in ("WHO", "WHAT", "WHEN", "WHERE", "WHY", "HOW"):
        print(axis)
        for p in rep["problems"]:
            if p["axis"] != axis:
                continue
            m = p.get("measured")
            num = ("  [%s%% %s]" % (m["value"], m["label"])) if m and m["value"] is not None else ""
            print("  %-4s %-11s %s%s" % (p["id"], p["verdict"].upper(), p["name"], num))
        print()
    print("verdicts:", rep["verdict_counts"])
