#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a compact index of the synthetic ICS-SBOM dataset for the web console.

Reads sbom/index.csv (asset metadata), sbom/<file> (components) and
sbom-cve/<file> (identified CVEs) and emits a single same-origin JSON that
powers (1) the ICS-SBOM browse page and (2) the Source-data advisory -> related
SBOM cross-reference (advisory CVEs intersected with each asset's CVEs).

Output: sbom_index.json  { "assets": [ {asset_id, file, vendor, product, ...,
                            components:[{name,version,description}],
                            cves:[{id,component,severity,cwe}] } ], "generated": N }
"""
import os, csv, json, glob

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SBOM = os.path.join(BASE, "sbom")
SBOMCVE = os.path.join(BASE, "sbom-cve")
OUT = os.path.join(BASE, "sbom_index.json")


def _sev(v):
    for r in (v.get("ratings") or []):
        s = (r.get("severity") or "").lower()
        if s:
            return s
    return "unrated"


def _score(v):
    for r in (v.get("ratings") or []):
        if r.get("score") is not None:
            return r["score"]
    return None


def _cwe(v):
    for p in (v.get("properties") or []):
        if p.get("name", "").endswith("cwe") or p.get("name") == "vulnerability:cwe":
            return p.get("value")
    return ""


def cve_file_for(sbom_file):
    stem = sbom_file[:-len(".json")] if sbom_file.endswith(".json") else sbom_file
    return os.path.join(SBOMCVE, stem + "-CVE.json")


def main():
    meta = {r["file"]: r for r in csv.DictReader(open(os.path.join(SBOM, "index.csv"), encoding="utf-8-sig"))}
    assets = []
    for f in sorted(glob.glob(os.path.join(SBOM, "*.json"))):
        fname = os.path.basename(f)
        m = meta.get(fname, {})
        sb = json.load(open(f, encoding="utf-8"))
        comps = []
        for c in sb.get("components", []):
            comps.append({"name": c.get("name"), "version": c.get("version"),
                          "description": c.get("description", "")})
        cves = []
        cf = cve_file_for(fname)
        if os.path.exists(cf):
            cd = json.load(open(cf, encoding="utf-8"))
            # bom-ref -> component name
            ref2name = {c.get("bom-ref"): c.get("name") for c in cd.get("components", [])}
            for v in cd.get("vulnerabilities", []):
                aff = v.get("affects") or []
                ref = aff[0].get("ref") if aff else None
                cves.append({"id": v.get("id"), "component": ref2name.get(ref, ref or ""),
                             "severity": _sev(v), "cvss": _score(v), "cwe": _cwe(v)})
        assets.append({
            "asset_id": m.get("asset_id") or fname.split("_")[0],
            "file": fname,
            "vendor": m.get("vendor", ""),
            "product": m.get("product", sb.get("metadata", {}).get("component", {}).get("name", "")),
            "version": m.get("version", ""),
            "device_class": m.get("device_class", ""),
            "cdx_type": m.get("cdx_type", ""),
            "purdue_level": m.get("purdue_level", ""),
            "base_platform": m.get("base_platform", ""),
            "sector": m.get("sector", ""),
            "protocols": (m.get("protocols", "") or "").split(";") if m.get("protocols") else [],
            "component_count": int(m.get("component_count") or len(comps)),
            "components": comps,
            "cves": cves,
        })
    out = {"generated": len(assets), "assets": assets}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    kb = os.path.getsize(OUT) // 1024
    ncve = sum(len(a["cves"]) for a in assets)
    print("wrote sbom_index.json: %d assets, %d CVE refs, %d KB" % (len(assets), ncve, kb))


if __name__ == "__main__":
    main()
