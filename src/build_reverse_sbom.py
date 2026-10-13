#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse SBOM generator: a CISA ICS advisory -> a per-device synthetic SBOM.

[real]      vendor / product / CVE / CWE / CVSS (v3 and v4 vectors) - actual advisory values
[synthetic] the component inventory around the device (platform, OSS, vendor modules)

Where a CVE is placed (the A-E source-tier routing):
  - a known OSS CVE (matched against the catalogue), or an advisory naming the OSS
                                                 -> an OSS component   (dynamic arm)
  - everything else                              -> a vendor module (tier E, context arm)

Output:
  reverse_sbom/<device>_SBOM-CVE.json   per-device CycloneDX (SBOM + vulnerabilities[])
  data/findings.csv                     flattened table (device, cve, component, tier,
                                        cwe, cvss, AV, ...)
  data/devices.csv                      the device index
"""

import csv
import json
import os
import hashlib
import re
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from generate_ics_sbom import OSS  # noqa: E402  (the OSS catalogue, for matching real OSS CVEs)
from generate_ics_sbom import org, DOC_ORG, det_sha256  # KISA field-def helpers

# Components that sit in the OSS catalogue but are closed source in reality
# (source unobtainable -> tier E). Corrects a misclassification as tier A (OSS-attributed).
CLOSED_OSS = {"codesys_rt", "ipnet", "treck_tcpip", "sqlserver_express", "dotnet"}

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ADV = os.path.join(BASE, "data", "cisa_advisories.json")
SIG = os.path.join(BASE, "data", "exploit_signals.json")
OUT_SBOM = os.path.join(BASE, "reverse_sbom")
OUT_DATA = os.path.join(BASE, "data")
NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# The date fields defined by KISA's "SBOM data field definition" (CycloneDX 1.7).
#   properties.SBOM_CREATION_DATE / SBOM_MODIFY_DATE  ->  'YYYY-MM-DD HH:MM:SS'
#   metadata.timestamp                                ->  ISO-8601(Z)
# The specification's examples pin the first two to a timestamp (including 00:00:00),
# correcting an earlier version that wrote a bare date. All three are produced in one
# place so they cannot drift apart.
DOC_DATE_TIME = "2026-04-10 00:00:00"
DOC_TIMESTAMP = "2026-04-10T00:00:00Z"

# ---------------------------------------------------------------------------
# Vendor normalisation
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
    # Alias match on the first one or two tokens
    toks = key.split()
    for n in (2, 1):
        cand = " ".join(toks[:n])
        if cand in VENDOR_ALIAS:
            return VENDOR_ALIAS[cand]
    return v


def device_identity(adv):
    title = (adv.get("title") or "").strip()
    vend = norm_vendor(adv.get("vendor") or (title.split()[0] if title else ""))
    # Product name = the title with the vendor prefix removed
    prod = title
    for pref in (adv.get("vendor") or "", vend):
        if pref and prod.lower().startswith(pref.lower()):
            prod = prod[len(pref):].strip(" -:")
            break
    prod = re.sub(r"\s+", " ", prod).strip() or title or "Unknown Product"
    return vend, prod


# Device-key normalisation - stops one product splitting into two devices over spelling.
# For example "SiPass integrated" vs "SiPass Integrated",
#     "SIMATIC WinCC Vulnerabilities (UPDATE A)" vs "... (Update A)",
#     "WebAccess/SCADA" vs "WebAccess SCADA".
# Without it the two are counted as separate devices and then collide on the same
# filename at the slug() step, so one SBOM overwrites the other - 50 devices and their
# CVEs were lost that way.
def device_key(vend, prod):
    k = re.sub(r"[^0-9a-z]+", " ", (prod or "").lower()).strip()
    return (norm_vendor(vend or "").lower(), k)


# ---------------------------------------------------------------------------
# OSS attribution (CVE -> OSS component)
# ---------------------------------------------------------------------------
# CISA/CSAF justification -> the CycloneDX analysis.justification vocabulary
_CDX_JUST = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_configuration",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}


def load_upstream_vex():
    """Read what the original CISA CSAF already adjudicated (data/gt_icsa/manifest.json).

    ICSA -> {cve: [label, ...]}. Holds only the advisories where CISA or the vendor
    stated a justification via `vulnerabilities[].flags[].label` - 12 across the whole
    public OT corpus. These are **upstream assertions**, not verdicts we derived, so the
    provenance is always recorded and they never mix with our own.
    """
    p = os.path.join(BASE, "data", "gt_icsa", "manifest.json")
    if not os.path.exists(p):
        return {}
    try:
        man = json.load(open(p, encoding="utf-8"))
    except Exception:
        return {}
    return {r["advisory_id"]: r.get("flags", {}) for r in man.get("tier1", []) if r.get("flags")}


def build_oss_index():
    by_cve = {}
    for key, spec in OSS.items():
        for _ver, cves in spec["versions"]:
            for c in cves:
                by_cve[c] = key
    # Detection name -> catalogue key
    name_map = {}
    for key, spec in OSS.items():
        name_map[spec["name"].lower()] = key
    # Reinforce the common aliases
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
    # Detection regex, longest name first
    names = sorted(name_map, key=len, reverse=True)
    rx = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in names) + r")(?![A-Za-z0-9])", re.I)
    return by_cve, name_map, rx


def slug(s):
    s = re.sub(r"[^0-9A-Za-z]+", "-", s).strip("-").lower()
    return re.sub(r"-{2,}", "-", s)[:80] or "x"


# ---------------------------------------------------------------------------
# CVSS vector parsing
# ---------------------------------------------------------------------------
def parse_vector(vec):
    d = {}
    for part in (vec or "").split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            d[k] = v
    return d


# ---------------------------------------------------------------------------
# The vendor organisation block of metadata.component (manufacturer / supplier)
# ---------------------------------------------------------------------------
# The KISA specification defines metadata.component.manufacturer/supplier as
# name + address (country/region/locality) + contact (name/email/phone). But a CISA
# advisory gives us only the vendor's NAME; the real address and contact of thousands of
# third-party vendors are unknown to us. The document author (DOC_ORG) is ourselves and
# so has a complete block; a third-party vendor does not. Note: the already-imported
# org(name, country=None, region=None, contact_name) helper returns a block filled out
# with address and contact once a country is given.
def org_full(vendor):
    """Build the third-party ICS vendor organisation block for metadata.component.

    Policy (a): assert the name only. The vendor name is the one value actually measured
    from the advisory, and the address and contact are unknown, so the specification's
    address/contact structures are left out rather than filled with NOASSERTION - which
    is this repository's 'data honesty' rule: assert only what was measured. Both are
    optional in CycloneDX, so the result is still valid."""
    return org(vendor)   # org(name) -> {"name": name}


def main():
    # authoritative CVSS from NVD (tools/fetch_nvd_cvss_bulk.py) to fill advisory gaps
    _NVD_CVSS = {}
    _ncp = os.path.join(BASE, "data", "nvd_cvss.json")
    if os.path.exists(_ncp):
        try:
            _NVD_CVSS = {k: v for k, v in json.load(open(_ncp, encoding="utf-8")).items()
                         if isinstance(v, dict)}
        except Exception:
            _NVD_CVSS = {}
    with open(ADV, encoding="utf-8") as f:
        advisories = [v for v in json.load(f).values() if not v.get("error")]
    signals = {}
    if os.path.exists(SIG):
        with open(SIG, encoding="utf-8") as f:
            signals = json.load(f)

    oss_by_cve, oss_names, oss_rx = build_oss_index()
    upstream = load_upstream_vex()
    if upstream:
        print("upstream VEX (CISA CSAF flags): %d advisories / %d CVEs"
              % (len(upstream), sum(len(v) for v in upstream.values())))
    os.makedirs(OUT_SBOM, exist_ok=True)
    os.makedirs(OUT_DATA, exist_ok=True)

    # --- the axis: the ICSA advisory ---
    # CISA publishes one CSAF document per ICSA. Using the same axis for our output makes
    # a 1:1 comparison with the original CISA CSAF possible per advisory
    # (csaf_files/OT/white/<year>/<icsa-id>.json in cisagov/CSAF).
    # As a side effect advisory_id is a natural unique key, so filename collisions become
    # impossible by construction.
    devices = {}   # advisory_id -> {advisory_id, vendor, product, advisories[], vulns{cve:meta}}
    for adv in advisories:
        # Advisories with no CVE (Stuxnet mitigation guidance, vendor account warnings and
        # the like) still get an SBOM. Only by holding the axis to EVERY ICSA does the
        # output correspond file-for-file with the CISA CSAF. Such an SBOM has an empty
        # vulnerabilities[] and produces zero statements.
        vend, prod = device_identity(adv)
        key = adv["advisory_id"]
        d = devices.setdefault(key, {"advisory_id": key, "vendor": vend, "product": prod,
                                     "advisories": [], "vulns": {}, "oss_hits": set()})
        d["advisories"].append(adv["advisory_id"])
        # OSS text detection, per advisory
        text = (adv.get("title", "") + " " + adv.get("affected_text", "")).lower()
        adv_oss = set()
        for m in oss_rx.finditer(text):
            k = oss_names.get(m.group(1).lower())
            if k:
                adv_oss.add(k)
        d["oss_hits"].update(adv_oss)
        # Advisory-level AV distribution, as a fallback for CVEs with no per-CVE vector
        adv_avs = re.findall(r"AV:([NALP])", adv.get("affected_text", ""))
        adv_mode_av = ""
        if adv_avs:
            adv_mode_av = max(set(adv_avs), key=adv_avs.count)
        # per-CVE metadata
        vmeta = {v["cve"]: v for v in adv.get("vulns", [])}
        for cve in adv["cves"]:
            meta = vmeta.get(cve, {"cve": cve})
            if cve not in d["vulns"] or (not d["vulns"][cve].get("cvss_v3_vector") and meta.get("cvss_v3_vector")):
                m2 = dict(meta)
                m2["source_advisory"] = adv["advisory_id"]
                m2["adv_oss"] = sorted(adv_oss)
                m2["adv_mode_av"] = adv_mode_av
                # A CVE whose justification upstream (CISA CSAF) already stated is carried
                # through as-is.
                up = (upstream.get(adv["advisory_id"]) or {}).get(cve)
                if up:
                    m2["upstream_vex"] = {"status": "not_affected",
                                          "justification": up[0],
                                          "source": "cisa-csaf",
                                          "advisory": adv["advisory_id"]}
                d["vulns"][cve] = m2

    findings = []
    dev_rows = []
    n_written = 0
    for _key, d in sorted(devices.items()):
        vend, prod = d["vendor"], d["product"]
        # Filename = the ICSA id. It is a natural unique key, so a collision or an
        # overwrite is impossible in principle.
        dev_slug = slug(d["advisory_id"])
        dev_ref = "device:%s" % dev_slug

        # Component composition: attributed OSS plus a vendor-module remainder
        comps = {}          # bom-ref -> component dict
        cve_to_ref = {}
        for cve, meta in d["vulns"].items():
            oss_key = oss_by_cve.get(cve)   # a confirmed catalogue attribution
            if not oss_key and len(d["oss_hits"]) == 1:
                oss_key = next(iter(d["oss_hits"]))   # the advisory names a single OSS
            if oss_key:
                spec = OSS[oss_key]
                ref = "pkg:oss:%s" % oss_key.replace("_", "-")
                is_closed = oss_key in CLOSED_OSS
                tier = "E" if is_closed else ("A" if cve in oss_by_cve else "C")
                origin = "vendor-proprietary" if is_closed else "third-party-open-source"
                if ref not in comps:
                    comps[ref] = {
                        # --- the KISA specification's components[] field order ---
                        "type": "library", "bom-ref": ref, "name": spec["name"],
                        "version": "NOASSERTION",
                        "description": spec.get("desc", ""),
                        "scope": "required",
                        "publisher": spec["publisher"],
                        "manufacturer": org(spec["publisher"]),   # per spec: name only
                        "supplier": org(spec["publisher"]),
                        "tags": sorted(set(spec.get("tags", []))),
                        "licenses": [{"license": {"id": spec["license"]}}],
                        "copyright": "NOASSERTION",
                        "purl": spec["purl"],
                        # --- CycloneDX extensions (a superset of the spec, needed for
                        #     SBOM -> CVE matching) ---
                        "cpe": "cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*" % (spec["cpe_vendor"], spec["cpe_product"]),
                        "properties": [
                            {"name": "component:origin", "value": origin},
                            {"name": "component:source-availability", "value": tier},
                        ],
                    }
                cve_to_ref[cve] = (ref, tier, "oss")
            else:
                ref = "mod:%s:firmware" % dev_slug
                if ref not in comps:
                    comps[ref] = {
                        # --- the KISA specification's components[] field order ---
                        "type": "firmware", "bom-ref": ref,
                        "name": "%s Vendor Firmware/Application" % prod[:48],
                        "version": "NOASSERTION",
                        "description": "Vendor firmware/application inventory placeholder; source not publicly available.",
                        "scope": "required",
                        "publisher": vend,
                        "manufacturer": org(vend),   # per spec: name only
                        "supplier": org(vend),
                        "tags": ["firmware", "vendor-proprietary"],
                        "licenses": [{"license": {"id": "NOASSERTION"}}],
                        "copyright": "NOASSERTION",
                        "purl": "pkg:generic/%s" % slug(prod),
                        # --- CycloneDX extensions ---
                        "properties": [
                            {"name": "component:origin", "value": "vendor-proprietary"},
                            {"name": "component:source-availability", "value": "E"},
                        ],
                    }
                cve_to_ref[cve] = (ref, "E", "vendor")

        # The vulnerability objects
        vulns = []
        for cve, meta in sorted(d["vulns"].items()):
            ref, tier, arm = cve_to_ref[cve]
            vec = meta.get("cvss_v3_vector") or ""
            pv = parse_vector(vec)
            av_src = "per-cve"
            if not pv.get("AV") and meta.get("adv_mode_av"):
                pv["AV"] = meta["adv_mode_av"]        # advisory-mode AV fallback
                av_src = "advisory-mode"
            sig = signals.get(cve, {})
            score = meta.get("cvss_v3_score")
            _rsrc, _rvec = "CISA", vec
            _n = _NVD_CVSS.get(cve) or {}
            if score is None and _n.get("score") is not None:
                score = _n["score"]; _rsrc = "NVD"; _rvec = _n.get("vector") or vec
                if not pv.get("AV") and _n.get("vector"):
                    _pn = parse_vector(_n["vector"])
                    if _pn.get("AV"):
                        pv["AV"] = _pn["AV"]; av_src = "nvd"
            sev = None
            if score is not None:
                sev = ("critical" if score >= 9 else "high" if score >= 7 else
                       "medium" if score >= 4 else "low")
                if _rsrc == "NVD" and _n.get("severity"):
                    sev = _n["severity"]
            ratings = []
            if score is not None:
                ratings = [{"source": {"name": _rsrc}, "score": score, "severity": sev,
                            "method": "CVSSv31", "vector": _rvec or "NOASSERTION"}]
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
                "analysis": ({"state": "not_affected",
                              "justification": _CDX_JUST.get(
                                  meta["upstream_vex"]["justification"], "code_not_reachable"),
                              "detail": ("Asserted by CISA CSAF %s as %s (upstream VEX, not derived here)."
                                         % (meta["upstream_vex"]["advisory"],
                                            meta["upstream_vex"]["justification"]))}
                             if meta.get("upstream_vex") else
                             {"state": "in_triage",
                              "detail": "Identified from CISA ICS advisory. VEX adjudication pending."}),
            })

            findings.append({
                "device": dev_slug, "vendor": vend, "product": prod,
                "cve": cve, "component": ref, "tier": tier, "arm": arm,
                "cwe": meta.get("cwe", ""), "cvss_v3_score": score if score is not None else "",
                "severity": sev or "", "av": pv.get("AV", ""), "av_source": av_src, "ac": pv.get("AC", ""),
                "pr": pv.get("PR", ""), "ui": pv.get("UI", ""),
                "kev": bool(sig.get("kev")), "epss": sig.get("epss") if sig.get("epss") is not None else "",
                "source_advisory": meta.get("source_advisory", ""),
                # A verdict stated upstream (CISA CSAF) - not one we derived
                "upstream_status": (meta.get("upstream_vex") or {}).get("status", ""),
                "upstream_justification": (meta.get("upstream_vex") or {}).get("justification", ""),
                "upstream_source": (meta.get("upstream_vex") or {}).get("source", ""),
            })

        # The top-level device component, plus the document
        base_platform = "linux" if ("linux_kernel" in d["oss_hits"] or "busybox" in d["oss_hits"]) else (
            "vxworks" if "ipnet" in d["oss_hits"] else "vendor-firmware")
        advs_sorted = sorted(set(d["advisories"]))
        primary_adv = advs_sorted[0] if advs_sorted else ""
        top = {
            # --- the KISA specification's metadata.component field order ---
            "type": "device", "bom-ref": dev_ref, "name": "%s %s" % (vend, prod),
            "version": "NOASSERTION",
            "description": ("ICS/OT asset '%s' by %s, reverse-built from CISA ICS-CERT advisory %s."
                            % (prod, vend, primary_adv)),
            "scope": "required",
            "publisher": vend,
            "purl": "pkg:generic/%s@NOASSERTION" % slug(prod),
            "copyright": "NOASSERTION",
            "cpe": "cpe:2.3:o:%s:%s:*:*:*:*:*:*:*:*" % (slug(vend), slug(prod)),
            "manufacturer": org_full(vend),
            "supplier": org_full(vend),
            "tags": sorted(set([base_platform, slug(vend), "ics", "reverse-sbom"])),
            "hashes": [{"alg": "SHA-256", "content": det_sha256(dev_ref)}],
            "licenses": [{"license": {"id": "NOASSERTION"}}],
            # externalReferences.url is a STRING field in both the spec and CycloneDX. The
            # previous code (1) defined the same key twice, so the first block vanished
            # silently, and (2) put an array in url, which leaves the spec. Several
            # advisories therefore get several entries, each with a string url.
            # The 1:1 comparison key against CISA CSAF:
            # cisagov/CSAF csaf_files/OT/white/<year>/<id>.json
            "externalReferences": [
                {"type": "advisory",
                 "url": "https://www.cisa.gov/news-events/ics-advisories/%s" % a,
                 "comment": "Source CISA ICS-CERT advisory %s" % a}
                for a in advs_sorted
            ] or [{"type": "advisory",
                   "url": "https://www.cisa.gov/news-events/ics-advisories",
                   "comment": "No source advisory id"}],
            # --- CycloneDX extensions (a superset of the spec) ---
            "properties": [
                {"name": "ics:vendor", "value": vend},
                {"name": "ics:product", "value": prod},
                {"name": "ics:base-platform", "value": base_platform},
                {"name": "ics:source-advisories", "value": ",".join(advs_sorted)},
                {"name": "dataset:provenance", "value": "cisa-ics-advisory-reverse"},
                {"name": "dataset:synthetic-inventory", "value": "true"},
            ],
        }
        dependencies = [{"ref": dev_ref, "dependsOn": [c["bom-ref"] for c in comps.values()]}]
        doc = {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "serialNumber": "urn:uuid:%s" % uuid.uuid5(NS, "reverse::" + dev_slug),
            "version": 1,
            "properties": [
                {"name": "SBOM_CREATION_DATE", "value": DOC_DATE_TIME},
                {"name": "SBOM_MODIFY_DATE", "value": DOC_DATE_TIME},
            ],
            "metadata": {
                "timestamp": DOC_TIMESTAMP,
                "lifecycles": [{"phase": "operations"}],
                "manufacturer": DOC_ORG,
                "tools": {"components": [{
                    "type": "application",
                    "bom-ref": "tool:ics-vex-reverse-sbom-builder",
                    "name": "ICS-VEX Reverse SBOM Builder",
                    "version": "2026.04",
                    "publisher": "Chonnam SSRC — ICS-VEX",
                    "description": "Reverse-builds a CycloneDX SBOM-CVE per ICS device from the CISA ICS-CERT advisory corpus.",
                    "externalReferences": [{"type": "documentation",
                        "url": ["https://kakyung98.github.io/ics-vex-dashboard/"],
                        "comment": "ICS-VEXForge web console"}],
                }]},
                "distributionConstraints": {"tlp": "CLEAR"},
                "component": top,
            },
            "dependencies": dependencies,
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
          "cvss_v3_score", "severity", "av", "av_source", "ac", "pr", "ui", "kev", "epss", "source_advisory",
          "upstream_status", "upstream_justification", "upstream_source"]
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
