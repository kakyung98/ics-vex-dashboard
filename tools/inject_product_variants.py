#!/usr/bin/env python3
"""Inject CISA CSAF's product_tree into the reverse SBOM to create model variants.

Background - the reverse SBOM collapses one ICSA into one device. But CISA and the
vendor split the verdict **per model** within the same ICSA (ICSA-25-191-06: SIPROTEC 5
CP300, 44 affected / CP200, 20 not_affected). Without a model-variant unit that split
cannot even be expressed.

This tool reads the product_tree of the original CISA CSAF and
  - adds a CycloneDX component (type=device) per model,
  - hangs them off the top-level device through dependencies, and
  - points vulnerabilities[].affects **only at the affected models**.

Careful - which models are affected comes from CISA product_status. The injected SBOM
therefore carries "a fact supplied by upstream", and a verdict resting on it is not our
own derivation. When evaluating, always separate it by provenance
(`variant:source=cisa-csaf`).

Usage:
  python tools/inject_product_variants.py                   # the 25 in data/gt_icsa
  python tools/inject_product_variants.py --csaf-repo /path # all of cisagov/CSAF
"""
import argparse
import glob
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBOM = os.path.join(BASE, "reverse_sbom")


def slug(s):
    s = re.sub(r"[^0-9A-Za-z]+", "-", s or "").strip("-").lower()
    return re.sub(r"-{2,}", "-", s)[:80] or "x"


def csaf_sources(repo):
    """ICSA id -> CSAF file path."""
    out = {}
    pats = [os.path.join(BASE, "data", "gt_icsa", "*", "cisa_csaf", "*.json")]
    if repo:
        pats.insert(0, os.path.join(repo, "csaf_files", "OT", "**", "*.json"))
    for pat in pats:
        for f in glob.glob(pat, recursive=True):
            aid = os.path.basename(f)[:-5]
            if aid.startswith("icsa-"):
                out.setdefault(aid, f)
    return out


def variants_of(csaf):
    """product_tree -> {product_id: {name, cpe, models, hashes, skus, version_range}}

    The previous version returned only the flattened name, which threw away every
    structured identifier CISA does publish. Measured over the OT corpus
    (28,631 products): cpe 0.2%, purl 0%, but **model_numbers 28.1%** - Siemens
    MLFB order codes and their equivalents, 1,326 distinct strings. Those are the
    identifiers an ICS asset owner actually holds; CPE barely exists here because
    NVD's dictionary has no entry for most vendor firmware.

    The version range matters too: 84.6% of OT branches are
    `product_version_range`, and folding that expression into the name is what
    produced component names like "AVEVA Enterprise SCADA >=2024|<=2024_SP1_P01"
    that no matcher can do anything with."""
    out = {}

    def walk(bs, pref, vrange):
        for b in bs or []:
            nm = pref + [b.get("name", "")]
            vr = b.get("name") if b.get("category") == "product_version_range" else vrange
            if "product" in b:
                p = b["product"]
                pid = p.get("product_id")
                if pid:
                    h = p.get("product_identification_helper") or {}
                    out[pid] = {
                        "name": " ".join(n for n in nm if n).strip(),
                        "cpe": h.get("cpe"),
                        "models": list(h.get("model_numbers") or []),
                        "skus": list(h.get("skus") or []),
                        "hashes": list(h.get("hashes") or []),
                        "version_range": vr,
                    }
            walk(b.get("branches"), nm, vr)

    walk((csaf.get("product_tree") or {}).get("branches"), [], None)
    for fp in (csaf.get("product_tree") or {}).get("full_product_names") or []:
        pid = fp.get("product_id")
        if pid and pid not in out:
            h = fp.get("product_identification_helper") or {}
            out[pid] = {"name": fp.get("name", ""), "cpe": h.get("cpe"),
                        "models": list(h.get("model_numbers") or []),
                        "skus": list(h.get("skus") or []),
                        "hashes": list(h.get("hashes") or []),
                        "version_range": None}
    for r in (csaf.get("product_tree") or {}).get("relationships") or []:
        fp = r.get("full_product_name") or {}
        pid = fp.get("product_id")
        if pid and pid not in out:
            h = fp.get("product_identification_helper") or {}
            out[pid] = {"name": fp.get("name", ""), "cpe": h.get("cpe"),
                        "models": list(h.get("model_numbers") or []),
                        "skus": list(h.get("skus") or []),
                        "hashes": list(h.get("hashes") or []),
                        "version_range": None}
    return out


def enrich_placeholder(sbom, names, csaf_path):
    """Single-product advisory: fill the `mod:` placeholder from CSAF.

    Half the OT corpus (1,796 advisories) publishes one product and no
    `relationships`, so there is no model variant to enumerate and `inject` used to
    skip the file outright. The placeholder it left behind was named
    "<X> Vendor Firmware/Application" with no version — nothing a matcher can
    identify, which is most of why it abstains on 49% of these components. CSAF does
    carry the real string ("WellinTech KingView: <6.53"), so it is copied in.

    The version range stays in `ics:version-range` and `version` stays NOASSERTION:
    `<6.53` is a bound, not a pinned version, and writing a bound into `version`
    would make every downstream version comparison read it as an installed version —
    the same confusion that once turned a CSAF `<2022.4` fixed-bound into a phantom
    installed version in the ground truth.
    """
    pid, info = next(iter(names.items()))
    nm = (info.get("name") or "").strip()
    if not nm:
        return False
    mod = next((c for c in sbom.get("components") or []
                if str(c.get("bom-ref", "")).startswith("mod:")), None)
    if mod is None:
        return False

    props = [x for x in (mod.get("properties") or [])
             if not str(x.get("name", "")).startswith(("ics:", "variant:"))]
    props += [{"name": "variant:csaf-product-id", "value": pid},
              {"name": "variant:source", "value": "cisa-csaf"}]
    for m in info.get("models") or []:
        props.append({"name": "ics:model-number", "value": m})
    for k in info.get("skus") or []:
        props.append({"name": "ics:sku", "value": k})
    if info.get("version_range"):
        props.append({"name": "ics:version-range", "value": info["version_range"]})

    mod["name"] = nm
    mod["description"] = ("Single product enumerated by the source CSAF "
                          "product_tree; the advisory declares no model variants.")
    mod["purl"] = "pkg:generic/%s@NOASSERTION" % slug(nm)
    mod["properties"] = props
    if info.get("cpe"):
        mod["cpe"] = info["cpe"]
    return True


def inject(sbom_path, csaf_path):
    sbom = json.load(open(sbom_path, encoding="utf-8"))
    csaf = json.load(open(csaf_path, encoding="utf-8"))
    names = variants_of(csaf)
    if len(names) < 2:
        # no model variants to enumerate, but the one product CSAF does name is
        # still better than the placeholder the SBOM builder left
        if len(names) == 1 and enrich_placeholder(sbom, names, csaf_path):
            return sbom, 0, 0, "enriched"
        return None

    top = ((sbom.get("metadata") or {}).get("component") or {})
    top_ref = top.get("bom-ref") or "device:unknown"
    vend = top.get("publisher") or "NOASSERTION"   # a variant inherits the device vendor

    # one component per model
    comps = sbom.setdefault("components", [])
    have = {c.get("bom-ref") for c in comps}
    vrefs = {}
    for pid, info in sorted(names.items()):
        nm = info["name"]
        ref = "variant:%s" % slug(nm or pid)
        vrefs[pid] = ref
        props = [{"name": "variant:csaf-product-id", "value": pid},
                 {"name": "variant:source", "value": "cisa-csaf"}]
        # A model number is an exact string an asset owner can read off the
        # device (Siemens MLFB "6GK7342-5DA02-0XE0"). Matching on it needs no
        # similarity metric at all, so it cannot mis-fire the way a name can.
        for m in info["models"]:
            props.append({"name": "ics:model-number", "value": m})
        for k in info["skus"]:
            props.append({"name": "ics:sku", "value": k})
        if info["version_range"]:
            props.append({"name": "ics:version-range", "value": info["version_range"]})
        comp = {
            # --- the KISA specification's components[] field order ---
            "type": "device", "bom-ref": ref, "name": nm or pid,
            "version": "NOASSERTION",
            "description": "Product variant enumerated by the source CSAF product_tree.",
            "scope": "required",
            "publisher": vend,
            "manufacturer": {"name": vend},   # per spec: name only
            "supplier": {"name": vend},
            "tags": sorted({"ics", "product-variant", slug(vend)}),
            "licenses": [{"license": {"id": "NOASSERTION"}}],
            "copyright": "NOASSERTION",
            "purl": "pkg:generic/%s@NOASSERTION" % slug(nm or pid),
            # --- CycloneDX extensions (model number, version range, ...) ---
            "properties": props,
        }
        if info["cpe"]:
            comp["cpe"] = info["cpe"]          # CycloneDX has a first-class field
        if info["hashes"]:
            hs = []
            for h in info["hashes"]:
                for fh in (h.get("file_hashes") or []):
                    if fh.get("algorithm") and fh.get("value"):
                        hs.append({"alg": fh["algorithm"].upper(), "content": fh["value"]})
            if hs:
                comp["hashes"] = hs
        # Enrich in place when the variant already exists: skipping it is why an
        # earlier run left every device component without its model number.
        prev = next((c for c in comps if c.get("bom-ref") == ref), None)
        if prev is None:
            comps.append(comp)
            have.add(ref)
        else:
            keep = [x for x in (prev.get("properties") or [])
                    if not x.get("name", "").startswith(("ics:", "variant:"))]
            prev["properties"] = keep + props
            if info["cpe"]:
                prev["cpe"] = info["cpe"]
            if comp.get("hashes"):
                prev["hashes"] = comp["hashes"]

    # dependencies: the top-level device contains the models
    deps = sbom.setdefault("dependencies", [])
    dep = next((d for d in deps if d.get("ref") == top_ref), None)
    if dep is None:
        dep = {"ref": top_ref, "dependsOn": []}
        deps.append(dep)
    for r in vrefs.values():
        if r not in dep["dependsOn"]:
            dep["dependsOn"].append(r)

    # Point each CVE only at the affected models
    status = {}
    for v in csaf.get("vulnerabilities") or []:
        cve = v.get("cve")
        if not cve:
            continue
        ps = v.get("product_status") or {}
        status[cve] = {
            "affected": [p for p in (ps.get("known_affected") or []) if p in vrefs],
            "not_affected": [p for p in (ps.get("known_not_affected") or []) if p in vrefs],
        }

    n_scoped = 0
    for v in sbom.get("vulnerabilities") or []:
        st = status.get(v.get("id"))
        if not st or not st["affected"]:
            continue
        v["affects"] = [{"ref": vrefs[p]} for p in st["affected"]]
        # Idempotent on re-runs: strip the previous variant:* and write them again (same
        # as at component level). Without this dedup, variant:affected-count and friends
        # accumulated on every re-injection - observed triplicated in an on-disk sample.
        props = [p for p in (v.get("properties") or [])
                 if not p.get("name", "").startswith("variant:")]
        props.append({"name": "variant:affected-count", "value": str(len(st["affected"]))})
        props.append({"name": "variant:not-affected-count", "value": str(len(st["not_affected"]))})
        props.append({"name": "variant:source", "value": "cisa-csaf"})
        v["properties"] = props
        n_scoped += 1

    return sbom, len(names), n_scoped, "variants"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf-repo", default=None)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    src = csaf_sources(a.csaf_repo)
    print("CSAF originals obtained: %d ICSAs" % len(src))
    n_done = n_var = n_scoped = n_enriched = 0
    for aid, cpath in sorted(src.items()):
        sp = os.path.join(SBOM, "%s_SBOM-CVE.json" % aid)
        if not os.path.exists(sp):
            continue
        r = inject(sp, cpath)
        if not r:
            continue
        sbom, nv, ns, kind = r
        if not a.dry_run:
            json.dump(sbom, open(sp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        if kind == "enriched":
            n_enriched += 1
        else:
            n_done += 1
            n_var += nv
            n_scoped += ns
    print("SBOMs injected          : %d" % n_done)
    print("model variants added    : %d" % n_var)
    print("findings scoped to model: %d" % n_scoped)
    print("single-product names set: %d" % n_enriched)
    if a.dry_run:
        print("(dry run - no files were written)")


if __name__ == "__main__":
    main()
