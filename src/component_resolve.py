#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage 1 — component resolution: split an ICS SBOM into its layers.

An ICS asset SBOM mixes the device itself with the upstream software inside it. To
identify CVEs at both layers (Stage 2), the components must first be separated:

  ics-product        the device / firmware / OS the SBOM is about (metadata.component)
  product-variant    model variants of that product (from the CSAF product_tree)
  embedded-component the OSS/libraries it ships (OpenSSL, the Linux kernel, curl)

This layering is what reaches the 27.8% of CVEs whose NVD CPE names an embedded
upstream component rather than the ICS product - an SBOM matched only at the product
layer can never reach them. Classification is by CycloneDX `type` plus the
identifiers each component carries (CPE vendor/product, purl, model numbers).

Out (per component): {name, type, vendor, product_token, version, cpe, purl,
                      bom_ref, models, layer}

Usage:  python src/component_resolve.py --file reverse_sbom/icsa-12-006-01_SBOM-CVE.json
"""
import argparse
import json
import os

# CycloneDX component types, mapped to a layer.
_PRODUCT_TYPES = {"device", "firmware", "operating-system", "platform", "hardware"}
_EMBEDDED_TYPES = {"library", "application", "framework", "file", "container",
                   "module", "data"}


def _cpe_vendor_product(cpe):
    p = str(cpe or "").split(":")
    return (p[3], p[4]) if len(p) >= 5 else ("", "")


def _facts(c):
    """Identity facts for one component, source-agnostic."""
    cpe = c.get("cpe") or ""
    v_cpe, p_cpe = _cpe_vendor_product(cpe)
    props = {p.get("name"): p.get("value") for p in (c.get("properties") or [])}
    vendor = (v_cpe or c.get("publisher") or (c.get("supplier") or {}).get("name")
              or props.get("ics:vendor") or "")
    models = [p["value"] for p in (c.get("properties") or [])
              if p.get("name") in ("ics:model-number", "ics:sku") and p.get("value")]
    return {"name": c.get("name") or "", "type": (c.get("type") or "").lower(),
            "vendor": vendor, "product_token": p_cpe,
            "version": c.get("version") or "", "cpe": cpe, "purl": c.get("purl") or "",
            "bom_ref": c.get("bom-ref") or "", "models": models}


def _layer_of(c):
    """The layer a components[] entry belongs to."""
    t = (c.get("type") or "").lower()
    if t in _PRODUCT_TYPES:
        return ("product-variant" if str(c.get("bom-ref", "")).startswith("variant:")
                else "product-firmware")
    # libraries/applications and anything unrecognised lean to embedded - the safe
    # direction, since missing an embedded component loses its CVEs.
    return "embedded-component"


def resolve(sbom):
    """Split the SBOM into product / variants / embedded, with the dependency graph."""
    top = (sbom.get("metadata") or {}).get("component") or {}
    product = dict(_facts(top), layer="ics-product")
    variants, embedded = [], []
    for c in sbom.get("components", []):
        if not isinstance(c, dict):
            continue
        f = dict(_facts(c), layer=_layer_of(c))
        (variants if f["layer"].startswith("product") else embedded).append(f)
    rels = [{"ref": d.get("ref"), "dependsOn": d.get("dependsOn") or []}
            for d in (sbom.get("dependencies") or []) if isinstance(d, dict)]
    return {"product": product, "variants": variants, "embedded": embedded,
            "relationships": rels,
            "summary": {"product": product["name"], "vendor": product["vendor"],
                        "embedded": len(embedded), "variants": len(variants)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="a CycloneDX SBOM (e.g. a reverse_sbom)")
    a = ap.parse_args()
    sbom = json.load(open(a.file, encoding="utf-8"))
    r = resolve(sbom)
    print("ICS product : %s  [%s]" % (r["product"]["name"], r["product"]["vendor"] or "vendor?"))
    print("variants    : %d" % len(r["variants"]))
    for v in r["variants"][:8]:
        print("   - %-14s %s %s" % (v["layer"], v["name"][:48],
                                    ("models=%s" % v["models"]) if v["models"] else ""))
    print("embedded    : %d" % len(r["embedded"]))
    for e in r["embedded"][:12]:
        ident = e["product_token"] or (e["purl"].split("/")[-1].split("@")[0] if e["purl"] else e["name"])
        print("   - %-20s vendor=%-14s ident=%s" % (e["name"][:20], e["vendor"][:14], ident))


if __name__ == "__main__":
    main()
