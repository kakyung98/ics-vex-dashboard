#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tier-A CVE 데이터셋 생성기.

역방향 findings 중 OSS 확정 귀속(tier A)으로 판정된 CVE만 추려,
동적 검증 후보군을 단일 데이터셋으로 관리한다.

CVE 단위로 중복을 제거하되(한 CVE가 여러 장비에 걸쳐 tier A/C/E 로 나타날 수
있으므로 최상위 tier 를 채택), 최상위 tier 가 A 인 CVE 만 포함한다.

각 CVE 에 대해 다음을 병합한다:
  - 컴포넌트(OSS) / 대상 언어
  - CWE / CVSS / 심각도 / KEV / EPSS            (findings.csv)
  - 영향 벤더·제품 목록, 출처 어드바이저리       (findings.csv)
  - ICS 장비 유형 분류(제품명 키워드 기반)        (본 스크립트 규칙)
  - 실행 검증 스펙 상태 / 저장소 / 빌드 방식      (verify_specs.json)
  - NVD 설명·발행일                              (nvd_cache.json, 있으면)

출력:
  data/tier_a_cve_dataset.csv     평탄화 테이블 (관리·검수용)
  data/tier_a_cve_dataset.jsonl   레코드별 JSON (파이프라인 입력용)
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

# 컴포넌트(OSS) -> 대상 언어
LANG = {
    "log4j": "Java", "tomcat": "Java", "jackson": "Java", "spring": "Java", "openjdk": "Java",
    "dotnet": "C#/.NET", "sqlserver_express": "SQL/DB", "sqlite": "C (SQL engine)",
}

# ICS 장비 유형 분류 규칙 (제품명 소문자 부분일치, 앞 규칙 우선순위 없음: 매칭되는 모든 유형 부여)
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
# 특정 장비가 아닌 "공유 OSS/스택" 광역 권고를 나타내는 신호
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

    # CVE 최상위 tier 결정
    best = {}
    for r in rows:
        c = r["cve"]
        if c not in best or TIER_RANK[r["tier"]] > TIER_RANK[best[c]]:
            best[c] = r["tier"]
    a_cves = {c for c, t in best.items() if t == "A"}

    # CVE 단위 집계 (tier A findings 만 근거로)
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

    # verify_specs 상태 병합
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

    # 요약
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
