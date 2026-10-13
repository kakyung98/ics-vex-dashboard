#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tier-A CVE dataset builder.

Selects, from the reverse findings, only the CVEs judged to be confirmed OSS
attributions (tier A), and keeps the dynamic-verification candidates as one dataset.

Deduplicated per CVE - one CVE can appear as tier A, C or E across different devices, so
the highest tier wins - and only CVEs whose highest tier is A are included.

For each CVE it merges:
  - component (OSS) and target language
  - CWE / CVSS / severity / KEV / EPSS              (findings.csv)
  - affected vendors and products, source advisory  (findings.csv)
  - ICS device-class tags from product-name keywords (the rules in this script)
  - execution-verification spec state, repository, build method (verify_specs.json)
  - NVD description and publication date            (nvd_cache.json, when present)

Output:
  data/tier_a_cve_dataset.csv     a flattened table, for review
  data/tier_a_cve_dataset.jsonl   one JSON record per line, as pipeline input
"""
import csv
import json
import os
import sys
import collections

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
FIND = os.path.join(BASE, "data", "findings.csv")
VSPEC = os.path.join(BASE, "data", "verify_specs.json")
NVD = os.path.join(BASE, "data", "nvd_cache.json")
OUT_CSV = os.path.join(BASE, "data", "tier_a_cve_dataset.csv")
OUT_JSONL = os.path.join(BASE, "data", "tier_a_cve_dataset.jsonl")

TIER_RANK = {"A": 3, "C": 2, "E": 1}

# component (OSS) -> target language
LANG = {
    "log4j": "Java", "tomcat": "Java", "jackson": "Java", "spring": "Java", "openjdk": "Java",
    "dotnet": "C#/.NET", "sqlserver_express": "SQL/DB", "sqlite": "C (SQL engine)",
}

# ICS device-class rules: lowercase substring match on the product name. Earlier rules
# carry no priority - every matching class is assigned.
DEVICE_RULES = [
    ("PLC/Controller", ["s7-", "simatic s7", "cpu", "plc", "controllogix", "compactlogix",
                        "melsec", "cecc", "control block", "controller", "tm mfp"]),
    ("HMI", ["hmi", "softgot", "operator unit", "wincc", "vision system", "intouch"]),
    ("SCADA", ["scada", "microscada", "sys600", "plant scada", "ecostruxure power operation",
               "scadaconnect", "gms600", "desigo cc", "telecontrol server", "st7 "]),
    ("RTU/Telecontrol", ["rtu", "pcu400", "telecontrol", "tim 1531", "sicam"]),
    ("IED/Protection Relay", ["siprotec", "relion", "sam600", "feeder", "protection", "relay", "7sj"]),
    ("Network", ["scalance", "ruggedcom", "switch", "router", "gateway", "radio", "wlan", "wpa2",
                 "wireless", "n-tron", "tropos", "mds", "sinec", "m2m", "arctic", "aff66", "sinema",
                 "w1750", "w700", "w1700"]),
    ("Drive/Motion", ["drive", "sinamics", "acs880", "power controller"]),
    ("EWS/APM/Software", ["development system", "automation studio", "appportal", "apm",
                          "asset performance", "lumada", "factorytalk activation", "sidis",
                          "system data manager", "enterprise manager", "powermanage",
                          "software center", "cadra", "bfcclient", "connectivity client", "studio"]),
    ("Sensor/Field/RFID/RTLS", ["transmitter", "sensor", "rtls", "mv500", "camera", "instrument",
                                "locating", "merging unit", "rfid", "rf160", "reader"]),
    ("OPC/Connectivity", ["opc", "kepserver"]),
]
# Signals that an advisory is a broad "shared OSS/stack" one rather than about a
# particular device
GENERIC = ["vxworks", "rtos", "tcp/ip", "ipnet", "codesys", "openssl", "glibc", "goahead",
           "net-snmp", "snmp", "industrial products", "third-party", "affected industrial",
           "dnsmasq", "web server"]


def norm_vendor(v):
    return (v or "").replace("​", "").strip()


def classify(products):
    types = set()
    for p in products:
        pl = p.lower()
        for name, kws in DEVICE_RULES:
            if any(k in pl for k in kws):
                types.add(name)
    return sorted(types)


def category(products, types):
    if types:
        return "device-attributed"
    if any(any(g in p.lower() for g in GENERIC) for p in products):
        return "shared-oss-component"
    return "unclassified"


def main():
    sys.stdout.reconfigure(encoding="utf-8")

    rows = list(csv.DictReader(open(FIND, encoding="utf-8-sig")))

    # Decide the CVE's highest tier
    best = {}
    for r in rows:
        c = r["cve"]
        if c not in best or TIER_RANK[r["tier"]] > TIER_RANK[best[c]]:
            best[c] = r["tier"]
    a_cves = {c for c, t in best.items() if t == "A"}

    # Aggregate per CVE, grounded in the tier-A findings only
    comp = {}
    cwe = {}
    cvss = {}
    sev = {}
    kev = collections.defaultdict(bool)
    epss = {}
    vendors = collections.defaultdict(set)
    products = collections.defaultdict(set)
    advs = collections.defaultdict(set)
    for r in rows:
        if r["tier"] != "A":
            continue
        c = r["cve"]
        comp[c] = r["component"].replace("pkg:oss:", "")
        if r.get("cwe"):
            cwe.setdefault(c, r["cwe"])
        if r.get("cvss_v3_score"):
            cvss[c] = r["cvss_v3_score"]
        if r.get("severity"):
            sev[c] = r["severity"]
        if r.get("kev") == "True":
            kev[c] = True
        if r.get("epss") not in (None, "", "NA"):
            epss[c] = r["epss"]
        if norm_vendor(r.get("vendor")):
            vendors[c].add(norm_vendor(r["vendor"]))
        if r.get("product"):
            products[c].add(r["product"])
        if r.get("source_advisory"):
            advs[c].add(r["source_advisory"])

    # Merge in the verify_specs state
    vspec = {}
    if os.path.exists(VSPEC):
        for s in json.load(open(VSPEC, encoding="utf-8")):
            vspec[s["cve"]] = s

    nvd = {}
    if os.path.exists(NVD):
        nvd = json.load(open(NVD, encoding="utf-8"))

    records = []
    for c in sorted(a_cves):
        prods = products[c]
        types = classify(prods)
        cat = category(prods, types)
        key = comp.get(c, "")
        spec = vspec.get(c, {})
        meta = nvd.get(c) or {}
        records.append({
            "cve": c,
            "component": key,
            "language": LANG.get(key, "C/C++"),
            "cwe": cwe.get(c, ""),
            "cvss_v3_score": cvss.get(c, ""),
            "severity": sev.get(c, ""),
            "kev": kev[c],
            "epss": epss.get(c, ""),
            "device_category": cat,
            "device_types": ";".join(types),
            "vendors": ";".join(sorted(vendors[c])),
            "products": ";".join(sorted(prods)),
            "source_advisories": ";".join(sorted(advs[c])),
            "verify_status": spec.get("status", ""),
            "verify_repo": spec.get("repo", ""),
            "verify_build": spec.get("build", ""),
            "has_trigger": bool(spec.get("trigger")),
            "nvd_published": (meta.get("published") or "")[:10],
            "nvd_description": (meta.get("description") or "")[:300],
        })

    # CSV
    fields = ["cve", "component", "language", "cwe", "cvss_v3_score", "severity", "kev", "epss",
              "device_category", "device_types", "vendors", "products", "source_advisories",
              "verify_status", "verify_repo", "verify_build", "has_trigger",
              "nvd_published", "nvd_description"]
    with open(OUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(records)

    # JSONL
    with open(OUT_JSONL, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Summary
    catc = collections.Counter(r["device_category"] for r in records)
    langc = collections.Counter(r["language"] for r in records)
    vst = collections.Counter(r["verify_status"] for r in records)
    print("tier-A CVE dataset : %d records" % len(records))
    print("  category :", dict(catc))
    print("  language :", dict(langc))
    print("  verify   :", dict(vst))
    print("  KEV      :", sum(1 for r in records if r["kev"]))
    print("output:")
    print("  ", OUT_CSV)
    print("  ", OUT_JSONL)


if __name__ == "__main__":
    main()
