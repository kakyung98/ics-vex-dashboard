#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
역방향 SBOM 생성기: CISA ICS 어드바이저리 -> 장비 단위 가상 SBOM.

[진짜]  vendor / product / CVE / CWE / CVSS(v3·v4 벡터) = CISA 어드바이저리 실값
[합성]  장비 주변 컴포넌트 인벤토리(플랫폼·OSS·벤더모듈)

CVE 배치 규칙(A~E 소스등급 라우팅):
  - 알려진 OSS CVE (카탈로그 대조) 또는 어드바이저리가 OSS 명시  -> OSS 컴포넌트  (동적 arm)
  - 그 외                                                        -> 벤더 모듈(tier E) (맥락 arm)

출력:
  reverse_sbom/<device>_SBOM-CVE.json   장비별 CycloneDX(SBOM + vulnerabilities[])
  data/findings.csv                     (device, cve, component, tier, cwe, cvss, AV...) 평탄화 테이블
  data/devices.csv                      장비 인덱스
"""

import csv
import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from generate_ics_sbom import OSS  # noqa: E402  (OSS 카탈로그: 실제 OSS CVE 대조용)

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ADV = os.path.join(BASE, "data", "cisa_advisories.json")
SIG = os.path.join(BASE, "data", "exploit_signals.json")
OUT_SBOM = os.path.join(BASE, "reverse_sbom")
OUT_DATA = os.path.join(BASE, "data")
NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# ---------------------------------------------------------------------------
# 벤더 정규화
# ---------------------------------------------------------------------------
VENDOR_ALIAS = {
    "ge": "GE", "general electric": "GE", "ge vernova": "GE", "ge digital": "GE",
    "rockwell": "Rockwell Automation", "rockwell automation": "Rockwell Automation",
    "schneider": "Schneider Electric", "schneider electric": "Schneider Electric",
    "siemens": "Siemens", "siemens energy": "Siemens",
    "mitsubishi": "Mitsubishi Electric", "mitsubishi electric": "Mitsubishi Electric",
    "hitachi": "Hitachi Energy", "hitachi energy": "Hitachi Energy", "hitachi abb": "Hitachi Energy",
    "abb": "ABB", "wago": "WAGO", "moxa": "Moxa", "advantech": "Advantech",
    "honeywell": "Honeywell", "emerson": "Emerson", "yokogawa": "Yokogawa",
    "omron": "OMRON", "delta": "Delta Electronics", "delta electronics": "Delta Electronics",
    "phoenix": "Phoenix Contact", "phoenix contact": "Phoenix Contact",
    "codesys": "CODESYS", "beckhoff": "Beckhoff", "pilz": "Pilz",
    "ls": "LS ELECTRIC", "ls electric": "LS ELECTRIC", "lsis": "LS ELECTRIC",
}
SUFFIX_RE = re.compile(r"\b(inc|inc\.|corp|corp\.|corporation|ltd|ltd\.|gmbh|ag|co|co\.|llc|s\.a\.|sa|plc|group|automation|electric|electronics|systems|technologies|technology)\b\.?", re.I)


def norm_vendor(raw):
    if not raw:
        return "Unknown"
    v = raw.strip().rstrip(",.")
    key = v.lower()
    if key in VENDOR_ALIAS:
        return VENDOR_ALIAS[key]
    # 첫 1~2 토큰의 별칭 매칭
    toks = key.split()
    for n in (2, 1):
        cand = " ".join(toks[:n])
        if cand in VENDOR_ALIAS:
            return VENDOR_ALIAS[cand]
    return v


def device_identity(adv):
    title = (adv.get("title") or "").strip()
    vend = norm_vendor(adv.get("vendor") or (title.split()[0] if title else ""))
    # 제품명 = 제목에서 벤더 접두 제거
    prod = title
    for pref in (adv.get("vendor") or "", vend):
        if pref and prod.lower().startswith(pref.lower()):
            prod = prod[len(pref):].strip(" -:")
            break
    prod = re.sub(r"\s+", " ", prod).strip() or title or "Unknown Product"
    return vend, prod


# ---------------------------------------------------------------------------
# OSS 귀속 (CVE -> OSS 컴포넌트)
# ---------------------------------------------------------------------------
def build_oss_index():
    by_cve = {}
    for key, spec in OSS.items():
        for _ver, cves in spec["versions"]:
            for c in cves:
                by_cve[c] = key
    # 텍스트 탐지용 이름 -> 카탈로그 키
    name_map = {}
    for key, spec in OSS.items():
        name_map[spec["name"].lower()] = key
    # 흔한 별칭 보강
    extra = {
        "openssl": "openssl", "busybox": "busybox", "zlib": "zlib", "curl": "libcurl",
        "libcurl": "libcurl", "lwip": "lwip", "linux kernel": "linux_kernel",
        "linux": "linux_kernel", "kernel": "linux_kernel", "dropbear": "dropbear",
        "openssh": "openssh", "mbedtls": "mbedtls", "wolfssl": "wolfssl",
        "libxml2": "libxml2", "expat": "expat", "sqlite": "sqlite", "net-snmp": "net_snmp",
        "snmp": "net_snmp", "lighttpd": "lighttpd", "goahead": "goahead", "nginx": "nginx",
        "dnsmasq": "dnsmasq", "wpa_supplicant": "wpa_supplicant", "u-boot": "u_boot",
        "glibc": "glibc", "musl": "musl", "mosquitto": "mosquitto", "open62541": "open62541",
        "libmodbus": "libmodbus", "freertos": "freertos", "zephyr": "zephyr",
        "log4j": "log4j", "apache log4j": "log4j", "tomcat": "tomcat", "openjdk": "openjdk",
        "java": "openjdk", "jackson": "jackson", "spring": "spring", ".net": "dotnet",
        "treck": "treck_tcpip", "ipnet": "ipnet", "interpeak": "ipnet",
        "codesys": "codesys_rt", "libssh2": "libssh2", "openvpn": "openvpn",
        "ntp": "ntp", "libpcap": "libpcap", "gnutls": None, "boa": None,
    }
    name_map.update({k: v for k, v in extra.items() if v})
    # 탐지 정규식 (긴 이름 우선)
    names = sorted(name_map, key=len, reverse=True)
    rx = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in names) + r")(?![A-Za-z0-9])", re.I)
    return by_cve, name_map, rx


def slug(s):
    s = re.sub(r"[^0-9A-Za-z]+", "-", s).strip("-").lower()
    return re.sub(r"-{2,}", "-", s)[:80] or "x"


# ---------------------------------------------------------------------------
# CVSS 벡터 파싱
# ---------------------------------------------------------------------------
def parse_vector(vec):
    d = {}
    for part in (vec or "").split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            d[k] = v
    return d


def main():
    with open(ADV, encoding="utf-8") as f:
        advisories = [v for v in json.load(f).values() if not v.get("error")]
    signals = {}
    if os.path.exists(SIG):
        with open(SIG, encoding="utf-8") as f:
            signals = json.load(f)

    oss_by_cve, oss_names, oss_rx = build_oss_index()
    os.makedirs(OUT_SBOM, exist_ok=True)
    os.makedirs(OUT_DATA, exist_ok=True)

    # 장비별로 어드바이저리 그룹핑
    devices = {}   # (vendor, product) -> {vendor, product, advisories[], vulns{cve:meta}}
    for adv in advisories:
        if not adv.get("cves"):
            continue
        vend, prod = device_identity(adv)
        key = (vend, prod)
        d = devices.setdefault(key, {"vendor": vend, "product": prod,
                                     "advisories": [], "vulns": {}, "oss_hits": set()})
        d["advisories"].append(adv["advisory_id"])
        # OSS 텍스트 탐지 (어드바이저리 단위)
        text = (adv.get("title", "") + " " + adv.get("affected_text", "")).lower()
        adv_oss = set()
        for m in oss_rx.finditer(text):
            k = oss_names.get(m.group(1).lower())
            if k:
                adv_oss.add(k)
        d["oss_hits"].update(adv_oss)
        # 어드바이저리 수준 AV 분포 (per-CVE 벡터 없는 CVE 폴백용)
        adv_avs = re.findall(r"AV:([NALP])", adv.get("affected_text", ""))
        adv_mode_av = ""
        if adv_avs:
            adv_mode_av = max(set(adv_avs), key=adv_avs.count)
        # per-CVE 메타
        vmeta = {v["cve"]: v for v in adv.get("vulns", [])}
        for cve in adv["cves"]:
            meta = vmeta.get(cve, {"cve": cve})
            if cve not in d["vulns"] or (not d["vulns"][cve].get("cvss_v3_vector") and meta.get("cvss_v3_vector")):
                m2 = dict(meta)
                m2["source_advisory"] = adv["advisory_id"]
                m2["adv_oss"] = sorted(adv_oss)
                m2["adv_mode_av"] = adv_mode_av
                d["vulns"][cve] = m2

    findings = []
    dev_rows = []
    n_written = 0
    for (vend, prod), d in sorted(devices.items()):
        dev_slug = slug(vend + "-" + prod)
        dev_ref = "device:%s" % dev_slug

        # 컴포넌트 구성: OSS(귀속) + 벤더모듈(잔여)
        comps = {}          # bom-ref -> component dict
        cve_to_ref = {}
        for cve, meta in d["vulns"].items():
            oss_key = oss_by_cve.get(cve)   # 카탈로그 확정 귀속
            if not oss_key and len(d["oss_hits"]) == 1:
                oss_key = next(iter(d["oss_hits"]))   # 어드바이저리가 단일 OSS 명시
            if oss_key:
                spec = OSS[oss_key]
                ref = "pkg:oss:%s" % oss_key.replace("_", "-")
                tier = "A" if cve in oss_by_cve else "C"
                if ref not in comps:
                    comps[ref] = {
                        "type": "library", "bom-ref": ref, "name": spec["name"],
                        "version": "NOASSERTION", "scope": "required",
                        "publisher": spec["publisher"],
                        "cpe": "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*" % (spec["cpe_vendor"], spec["cpe_product"]),
                        "purl": spec["purl"],
                        "licenses": [{"license": {"id": spec["license"]}}],
                        "properties": [
                            {"name": "component:origin", "value": "third-party-open-source"},
                            {"name": "component:source-availability", "value": tier},
                        ],
                    }
                cve_to_ref[cve] = (ref, tier, "oss")
            else:
                ref = "mod:%s:firmware" % dev_slug
                if ref not in comps:
                    comps[ref] = {
                        "type": "firmware", "bom-ref": ref,
                        "name": "%s Vendor Firmware/Application" % prod[:48],
                        "version": "NOASSERTION", "scope": "required", "publisher": vend,
                        "properties": [
                            {"name": "component:origin", "value": "vendor-proprietary"},
                            {"name": "component:source-availability", "value": "E"},
                        ],
                    }
                cve_to_ref[cve] = (ref, "E", "vendor")

        # 취약점 객체
        vulns = []
        for cve, meta in sorted(d["vulns"].items()):
            ref, tier, arm = cve_to_ref[cve]
            vec = meta.get("cvss_v3_vector") or ""
            pv = parse_vector(vec)
            av_src = "per-cve"
            if not pv.get("AV") and meta.get("adv_mode_av"):
                pv["AV"] = meta["adv_mode_av"]        # 어드바이저리 모드 AV 폴백
                av_src = "advisory-mode"
            sig = signals.get(cve, {})
            score = meta.get("cvss_v3_score")
            sev = None
            if score is not None:
                sev = ("critical" if score >= 9 else "high" if score >= 7 else
                       "medium" if score >= 4 else "low")
            ratings = []
            if score is not None:
                ratings = [{"source": {"name": "CISA"}, "score": score, "severity": sev,
                            "method": "CVSSv31", "vector": vec or "NOASSERTION"}]
            cwe_num = None
            m = re.match(r"CWE-(\d+)", meta.get("cwe", "") or "")
            if m:
                cwe_num = int(m.group(1))
            vulns.append({
                "bom-ref": "vuln:%s:%s" % (dev_slug, cve),
                "id": cve,
                "source": {"name": "CISA ICS-CERT",
                           "url": "https://www.cisa.gov/news-events/ics-advisories/%s" % meta.get("source_advisory", "")},
                "ratings": ratings,
                "cwes": [cwe_num] if cwe_num else [],
                "affects": [{"ref": ref, "versions": [{"version": "NOASSERTION", "status": "affected"}]}],
                "properties": [
                    {"name": "source:advisory", "value": meta.get("source_advisory", "")},
                    {"name": "cisa:cvss-v3-vector", "value": vec or "NOASSERTION"},
                    {"name": "cisa:cvss-v4-vector", "value": meta.get("cvss_v4_vector", "") or "NOASSERTION"},
                    {"name": "component:source-availability", "value": tier},
                    {"name": "vex:arm", "value": "dynamic" if arm == "oss" else "context"},
                    {"name": "signal:kev", "value": str(bool(sig.get("kev"))).lower()},
                    {"name": "signal:epss", "value": str(sig.get("epss")) if sig.get("epss") is not None else "NA"},
                ],
                "analysis": {"state": "in_triage",
                             "detail": "Identified from CISA ICS advisory. VEX adjudication pending."},
            })

            findings.append({
                "device": dev_slug, "vendor": vend, "product": prod,
                "cve": cve, "component": ref, "tier": tier, "arm": arm,
                "cwe": meta.get("cwe", ""), "cvss_v3_score": score if score is not None else "",
                "severity": sev or "", "av": pv.get("AV", ""), "av_source": av_src, "ac": pv.get("AC", ""),
                "pr": pv.get("PR", ""), "ui": pv.get("UI", ""),
                "kev": bool(sig.get("kev")), "epss": sig.get("epss") if sig.get("epss") is not None else "",
                "source_advisory": meta.get("source_advisory", ""),
            })

        # 최상위 device 컴포넌트 + 문서
        base_platform = "linux" if ("linux_kernel" in d["oss_hits"] or "busybox" in d["oss_hits"]) else (
            "vxworks" if "ipnet" in d["oss_hits"] else "vendor-firmware")
        top = {
            "type": "device", "bom-ref": dev_ref, "name": "%s %s" % (vend, prod),
            "version": "NOASSERTION", "publisher": vend,
            "cpe": "cpe:2.3:o:%s:%s:*:*:*:*:*:*:*:*" % (slug(vend), slug(prod)),
            "manufacturer": {"name": vend},
            "properties": [
                {"name": "ics:vendor", "value": vend},
                {"name": "ics:product", "value": prod},
                {"name": "ics:base-platform", "value": base_platform},
                {"name": "ics:source-advisories", "value": ",".join(sorted(set(d["advisories"])))},
                {"name": "dataset:provenance", "value": "cisa-ics-advisory-reverse"},
                {"name": "dataset:synthetic-inventory", "value": "true"},
            ],
        }
        doc = {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "serialNumber": "urn:uuid:%s" % uuid.uuid5(NS, "reverse::" + dev_slug),
            "version": 1,
            "metadata": {
                "timestamp": "2026-04-10T00:00:00Z",
                "lifecycles": [{"phase": "operations"}],
                "component": top,
                "tools": {"components": [{"type": "application",
                          "name": "ICS-VEX Reverse SBOM Builder", "version": "2026.04"}]},
            },
            "components": list(comps.values()),
            "vulnerabilities": vulns,
        }
        with open(os.path.join(OUT_SBOM, "%s_SBOM-CVE.json" % dev_slug), "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        n_written += 1

        dev_rows.append({
            "device": dev_slug, "vendor": vend, "product": prod[:60],
            "base_platform": base_platform, "advisory_count": len(set(d["advisories"])),
            "cve_count": len(d["vulns"]), "oss_cve": sum(1 for c in cve_to_ref.values() if c[2] == "oss"),
            "vendor_cve": sum(1 for c in cve_to_ref.values() if c[2] == "vendor"),
            "oss_components": ",".join(sorted(d["oss_hits"])),
        })

    # findings.csv
    ff = ["device", "vendor", "product", "cve", "component", "tier", "arm", "cwe",
          "cvss_v3_score", "severity", "av", "av_source", "ac", "pr", "ui", "kev", "epss", "source_advisory"]
    with open(os.path.join(OUT_DATA, "findings.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ff)
        w.writeheader()
        w.writerows(findings)
    # devices.csv
    df = ["device", "vendor", "product", "base_platform", "advisory_count",
          "cve_count", "oss_cve", "vendor_cve", "oss_components"]
    with open(os.path.join(OUT_DATA, "devices.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=df)
        w.writeheader()
        w.writerows(dev_rows)

    oss_f = sum(1 for r in findings if r["arm"] == "oss")
    print("devices(SBOMs) : %d" % n_written)
    print("findings       : %d  (oss-arm %d / context-arm %d)" % (len(findings), oss_f, len(findings) - oss_f))
    print("unique CVEs     : %d" % len({r["cve"] for r in findings}))
    kev_f = sum(1 for r in findings if r["kev"])
    print("KEV findings    : %d" % kev_f)
    print("output          : %s , data/findings.csv , data/devices.csv" % OUT_SBOM)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
