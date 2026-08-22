#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the ICS-SBOM index for the web console from the advisory-grounded SBOMs.

Source = reverse_sbom/ : one SBOM-CVE per ICS device, reverse-built from the CISA
ICS-CERT corpus. Each carries ics:source-advisories (the exact advisory id[s]), so
the web console can link an advisory to *its* device SBOM(s) precisely — no fuzzy
vendor/product matching.

CVSS score/severity are backfilled from data/nvd_cache.json (and data/findings.csv)
because the reverse_sbom ratings are often empty. CWE integers -> "CWE-nnn".

Output: sbom_index.json { "generated": N, "assets": [ {asset_id, file, vendor,
  product, base_platform, advisories:[...], component_count,
  components:[{name,version,description}], cves:[{id,component,severity,cvss,cwe}] } ] }
"""
import os, csv, json, glob

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
RSBOM = os.path.join(BASE, "reverse_sbom")
# fall back to the user's finalized copy if the primary dir was renamed/emptied
import glob as _g
if not _g.glob(os.path.join(RSBOM, "*.json")):
    _alt = os.path.join(BASE, "(최종)reverse_sbom")
    if _g.glob(os.path.join(_alt, "*.json")):
        RSBOM = _alt
DATA = os.path.join(BASE, "data")
OUT = os.path.join(BASE, "sbom_index.json")


def load_scores():
    score, sev = {}, {}
    ncp = os.path.join(DATA, "nvd_cvss.json")
    if os.path.exists(ncp):
        for c, v in json.load(open(ncp, encoding="utf-8")).items():
            if c == "__cursor__" or not isinstance(v, dict):
                continue
            if v.get("score") is not None:
                score[c] = v["score"]
            if v.get("severity"):
                sev[c] = str(v["severity"]).lower()
    nvd_p = os.path.join(DATA, "nvd_cache.json")
    if os.path.exists(nvd_p):
        nvd = json.load(open(nvd_p, encoding="utf-8"))
        for cid, e in (nvd.items() if isinstance(nvd, dict) else []):
            m = (e or {}).get("metric") or {}
            if isinstance(m, dict):
                if m.get("score") is not None:
                    try: score[cid] = float(m["score"])
                    except (TypeError, ValueError): pass
                if m.get("severity"):
                    sev[cid] = str(m["severity"]).lower()
    fp = os.path.join(DATA, "findings.csv")
    if os.path.exists(fp):
        for r in csv.DictReader(open(fp, encoding="utf-8-sig")):
            c = r.get("cve")
            if c and c not in score and r.get("cvss_v3_score"):
                try: score[c] = float(r["cvss_v3_score"])
                except ValueError: pass
            if c and c not in sev and r.get("severity"):
                sev[c] = str(r["severity"]).lower()
    adv_p = os.path.join(DATA, "cisa_advisories.json")
    if os.path.exists(adv_p):
        adv = json.load(open(adv_p, encoding="utf-8"))
        for a in (adv.values() if isinstance(adv, dict) else []):
            for vu in (a.get("vulns") or []):
                c = vu.get("cve")
                if not c:
                    continue
                sc = vu.get("cvss_v3_score")
                if sc is None:
                    sc = vu.get("cvss_v4_score")
                if c not in score and sc is not None:
                    try: score[c] = float(sc)
                    except (TypeError, ValueError): pass
    return score, sev


def cwe_str(v):
    cs = v.get("cwes") or []
    if not cs:
        return ""
    c = cs[0]
    if isinstance(c, int):
        return "CWE-%d" % c
    s = str(c)
    return s if s.upper().startswith("CWE-") else ("CWE-" + s if s.isdigit() else s)


def main():
    score, sev = load_scores()
    assets = []
    for f in sorted(glob.glob(os.path.join(RSBOM, "*.json"))):
        fname = os.path.basename(f)
        d = json.load(open(f, encoding="utf-8"))
        top = d.get("metadata", {}).get("component", {})
        props = {p["name"]: p["value"] for p in top.get("properties", [])}
        advs = [a.strip() for a in str(props.get("ics:source-advisories", "")).split(",") if a.strip()]
        ref2name = {c.get("bom-ref"): c.get("name") for c in d.get("components", [])}
        comps = [{"name": c.get("name"), "version": c.get("version"),
                  "description": c.get("description") or ""} for c in d.get("components", [])]
        cves = []
        for v in d.get("vulnerabilities", []):
            cid = v.get("id")
            aff = v.get("affects") or []
            ref = aff[0].get("ref") if aff else None
            cves.append({"id": cid, "component": ref2name.get(ref, ref or ""),
                         "severity": sev.get(cid, "unrated"), "cvss": score.get(cid),
                         "cwe": cwe_str(v)})
        assets.append({
            "asset_id": fname[:-len("_SBOM-CVE.json")] if fname.endswith("_SBOM-CVE.json") else fname[:-5],
            "file": fname,
            "vendor": props.get("ics:vendor", top.get("publisher", "")),
            "product": props.get("ics:product", top.get("name", "")),
            "base_platform": props.get("ics:base-platform", ""),
            "advisories": advs,
            "component_count": len(comps),
            "components": comps,
            "cves": cves,
        })
    out = {"generated": len(assets), "assets": assets}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    ncve = sum(len(a["cves"]) for a in assets)
    nadv = len({x for a in assets for x in a["advisories"]})
    print("wrote sbom_index.json: %d assets, %d CVE refs, %d advisories, %d KB"
          % (len(assets), ncve, nadv, os.path.getsize(OUT) // 1024))


if __name__ == "__main__":
    main()
