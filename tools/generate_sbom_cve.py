#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SBOM -> CVE 식별기 (CycloneDX 1.7 VDR)

sbom/ 의 각 SBOM 을 읽어 components[] 의 cpe / purl / version 만으로
취약점 지식베이스(KB)와 대조하여 해당 자산에 존재하는 CVE 를 식별하고,
동일한 CycloneDX 구조에 vulnerabilities[] 를 추가한 문서를 생성한다.

  sbom-cve/<원본이름>-CVE.json          자산별 CVE 식별 결과 (SBOM 전체 + vulnerabilities[])
  sbom-cve/index.csv                     자산별 심각도 집계
  sbom-cve/cve_summary.csv               CVE별 영향 자산 집계
  sbom-cve/matching_report.txt           정답셋 대비 매칭 정확도 검증 결과

CVE 메타데이터(CVSS, CWE, 설명, 발행일, 참조)는 data/nvd_cache.json 의
NVD API 2.0 실측 데이터를 사용한다. 캐시가 없으면 해당 필드는 생략되고
match:metadata-source property 에 unavailable 로 표기된다.

주의: 매칭기는 SBOM 문서에 기록된 식별자만 입력으로 사용하며
ground_truth CSV 를 참조하지 않는다. 정답셋은 사후 검증에만 쓰인다.
"""

import collections
import csv
import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_ics_sbom import OSS, NS  # noqa: E402

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SBOM_DIR = os.path.join(BASE_DIR, "sbom")
OUT_DIR = os.path.join(BASE_DIR, "sbom-cve")
NVD_CACHE = os.path.join(BASE_DIR, "data", "nvd_cache.json")

ANALYSIS_DATE = "2026-04-10"
ANALYSIS_TS = "2026-04-10T00:00:00Z"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "none", "unknown"]


# ---------------------------------------------------------------------------
# 취약점 지식베이스
# ---------------------------------------------------------------------------

def build_kb():
    """(cpe_vendor, cpe_product, version) 및 (purl_base, version) -> [CVE]"""
    by_cpe = {}
    by_purl = {}
    for spec in OSS.values():
        for ver, cves in spec["versions"]:
            if not cves:
                continue
            by_cpe[(spec["cpe_vendor"].lower(), spec["cpe_product"].lower(), ver)] = list(cves)
            by_purl[(spec["purl"].lower(), ver)] = list(cves)
    return by_cpe, by_purl


CPE_RE = re.compile(r"^cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]+):")


def parse_cpe(cpe):
    m = CPE_RE.match(cpe or "")
    if not m:
        return None
    return m.group(1).lower(), m.group(2).lower(), m.group(3)


def parse_purl(purl):
    if not purl or "@" not in purl:
        return None
    base, ver = purl.rsplit("@", 1)
    return base.lower(), ver


def identify(component, by_cpe, by_purl):
    """컴포넌트 1건에 대한 CVE 식별. (cve목록, 매칭방식) 반환."""
    cpe_key = parse_cpe(component.get("cpe"))
    if cpe_key and cpe_key in by_cpe:
        return by_cpe[cpe_key], "cpe-exact"
    purl_key = parse_purl(component.get("purl"))
    if purl_key and purl_key in by_purl:
        return by_purl[purl_key], "purl-exact"
    return [], None


# ---------------------------------------------------------------------------
# CycloneDX vulnerability 객체 조립
# ---------------------------------------------------------------------------

def load_nvd():
    if os.path.exists(NVD_CACHE):
        with open(NVD_CACHE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def cwe_numbers(cwes):
    out = []
    for c in cwes or []:
        m = re.match(r"CWE-(\d+)$", c)
        if m:
            out.append(int(m.group(1)))
    return out


def make_vuln(cve_id, hits, nvd, asset_props):
    """hits: [(bom_ref, name, version, match_method), ...]"""
    meta = nvd.get(cve_id) or {}
    has_meta = bool(meta) and not meta.get("error")

    v = {
        "bom-ref": "vuln:%s" % cve_id,
        "id": cve_id,
        "source": {"name": "NVD",
                   "url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id},
    }

    if has_meta:
        if meta.get("description"):
            v["description"] = meta["description"]
        metric = meta.get("metric")
        if metric and metric.get("score") is not None:
            v["ratings"] = [{
                "source": {"name": "NVD",
                           "url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id},
                "score": metric["score"],
                "severity": metric["severity"],
                "method": metric["method"],
                "vector": metric.get("vector") or "NOASSERTION",
            }]
        nums = cwe_numbers(meta.get("cwes"))
        if nums:
            v["cwes"] = nums
        if meta.get("published"):
            v["published"] = meta["published"]
        if meta.get("lastModified"):
            v["updated"] = meta["lastModified"]
        if meta.get("references"):
            v["references"] = [{"id": cve_id, "source": {"url": u}}
                               for u in meta["references"]]

    # 식별 단계이므로 VEX 판정은 내리지 않고 in_triage 로 둔다.
    v["analysis"] = {
        "state": "in_triage",
        "detail": "Identified by SBOM component matching. VEX adjudication "
                  "(exploitability in this ICS deployment) not yet performed.",
    }

    v["affects"] = [{
        "ref": ref,
        "versions": [{"version": ver, "status": "affected"}],
    } for ref, _name, ver, _m in hits]

    props = [
        {"name": "match:method", "value": hits[0][3]},
        {"name": "match:confidence", "value": "high"},
        {"name": "match:metadata-source", "value": "nvd-api-2.0" if has_meta else "unavailable"},
        {"name": "match:affected-components",
         "value": ",".join("%s@%s" % (n, ver) for _r, n, ver, _m in hits)},
    ]
    props.extend(asset_props)
    v["properties"] = props
    return v


def severity_of(v):
    if v.get("ratings"):
        return (v["ratings"][0].get("severity") or "unknown").lower()
    return "unknown"


def score_of(v):
    if v.get("ratings"):
        return v["ratings"][0].get("score") or 0.0
    return 0.0


# ---------------------------------------------------------------------------
# 실행
# ---------------------------------------------------------------------------

def main():
    by_cpe, by_purl = build_kb()
    nvd = load_nvd()
    os.makedirs(OUT_DIR, exist_ok=True)

    files = sorted(f for f in os.listdir(SBOM_DIR) if f.endswith("_SBOM.json"))
    if not files:
        print("no SBOM files in %s" % SBOM_DIR)
        return

    index_rows = []
    cve_assets = collections.defaultdict(set)
    cve_sev = {}
    produced = {}   # file -> {bom_ref: set(cve)}  (검증용)
    meta_missing = set()

    for fname in files:
        with open(os.path.join(SBOM_DIR, fname), encoding="utf-8") as f:
            sbom = json.load(f)

        top = sbom["metadata"]["component"]
        tprops = {p["name"]: p["value"] for p in top.get("properties", [])}
        asset_id = tprops.get("ics:asset-id", "")
        asset_props = [
            {"name": "ics:asset-id", "value": asset_id},
            {"name": "ics:device-class", "value": tprops.get("ics:device-class", "")},
            {"name": "ics:purdue-level", "value": tprops.get("ics:purdue-level", "")},
            {"name": "ics:network-exposure", "value": tprops.get("ics:network-exposure", "")},
        ]

        # --- 컴포넌트별 CVE 식별 -> CVE 기준으로 집계 ---------------------
        per_cve = collections.defaultdict(list)
        prod = collections.defaultdict(set)
        for comp in sbom.get("components", []):
            cves, method = identify(comp, by_cpe, by_purl)
            for cid in cves:
                per_cve[cid].append((comp["bom-ref"], comp["name"], comp["version"], method))
                prod[comp["bom-ref"]].add(cid)
        produced[fname] = prod

        vulns = [make_vuln(cid, hits, nvd, asset_props)
                 for cid, hits in sorted(per_cve.items())]
        vulns.sort(key=lambda v: (-score_of(v), v["id"]))

        for v in vulns:
            sev = severity_of(v)
            if sev == "unknown":
                meta_missing.add(v["id"])
            cve_assets[v["id"]].add(asset_id)
            cve_sev[v["id"]] = sev

        counts = collections.Counter(severity_of(v) for v in vulns)

        # --- 출력 문서 조립 (원본 SBOM 구조 유지 + vulnerabilities[]) -----
        out = dict(sbom)
        out["serialNumber"] = "urn:uuid:%s" % uuid.uuid5(NS, "sbom-cve::" + fname)
        out["properties"] = list(sbom.get("properties", [])) + [
            {"name": "SBOM_CVE_ANALYSIS_DATE", "value": ANALYSIS_DATE},
            {"name": "SBOM_CVE_TOTAL", "value": str(len(vulns))},
            {"name": "SBOM_CVE_CRITICAL", "value": str(counts.get("critical", 0))},
            {"name": "SBOM_CVE_HIGH", "value": str(counts.get("high", 0))},
            {"name": "SBOM_CVE_MEDIUM", "value": str(counts.get("medium", 0))},
            {"name": "SBOM_CVE_LOW", "value": str(counts.get("low", 0))},
        ]

        md = dict(sbom["metadata"])
        md["timestamp"] = ANALYSIS_TS
        md["lifecycles"] = [{"phase": "operations"}]
        tools = json.loads(json.dumps(sbom["metadata"]["tools"]))
        tools["components"].append({
            "type": "application",
            "bom-ref": "tool:ics-vex-cve-identifier",
            "name": "ICS-VEX SBOM CVE Identifier",
            "version": "2026.04",
            "publisher": "ICS-VEX Reference Dataset Author",
            "description": "Matches SBOM component CPE/PURL identifiers against a CVE "
                           "knowledge base and enriches findings with NVD API 2.0 metadata",
            "externalReferences": [{
                "type": "documentation",
                "url": ["https://example.invalid/ics-vex/cve-identifier"],
                "comment": "Placeholder documentation for the CVE identification stage",
            }],
        })
        md["tools"] = tools

        # 원본 SBOM 으로의 역참조 추가
        top_out = json.loads(json.dumps(top))
        top_out.setdefault("externalReferences", []).append({
            "type": "bom",
            "url": ["%s/1#%s" % (sbom["serialNumber"].replace("urn:uuid:", "urn:cdx:"),
                                 top["bom-ref"])],
            "comment": "Source SBOM this vulnerability analysis was derived from | file=%s" % fname,
        })
        md["component"] = top_out
        out["metadata"] = md
        out["vulnerabilities"] = vulns

        outname = fname.replace("_SBOM.json", "_SBOM-CVE.json")
        with open(os.path.join(OUT_DIR, outname), "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
            f.write("\n")

        index_rows.append({
            "file": outname,
            "source_sbom": fname,
            "asset_id": asset_id,
            "vendor": top.get("publisher", ""),
            "product": top.get("name", ""),
            "device_class": tprops.get("ics:device-class", ""),
            "purdue_level": tprops.get("ics:purdue-level", ""),
            "network_exposure": tprops.get("ics:network-exposure", ""),
            "sector": tprops.get("ics:sector", ""),
            "component_count": len(sbom.get("components", [])),
            "affected_component_count": len(prod),
            "cve_total": len(vulns),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "unknown": counts.get("unknown", 0),
            "max_cvss": max([score_of(v) for v in vulns] or [0.0]),
        })

    # --- index.csv --------------------------------------------------------
    idx_fields = list(index_rows[0].keys())
    with open(os.path.join(OUT_DIR, "index.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=idx_fields)
        w.writeheader()
        w.writerows(index_rows)

    # --- cve_summary.csv --------------------------------------------------
    with open(os.path.join(OUT_DIR, "cve_summary.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "severity", "cvss_score", "cwes", "affected_asset_count", "published"])
        for cid in sorted(cve_assets, key=lambda c: (-len(cve_assets[c]), c)):
            m = nvd.get(cid) or {}
            metric = m.get("metric") or {}
            w.writerow([cid, cve_sev.get(cid, "unknown"), metric.get("score", ""),
                        ";".join(m.get("cwes", [])), len(cve_assets[cid]),
                        (m.get("published") or "")[:10]])

    # --- 정답셋 대비 검증 --------------------------------------------------
    gt_path = os.path.join(SBOM_DIR, "ground_truth_vulnerable_components.csv")
    report = []
    if os.path.exists(gt_path):
        expected = collections.defaultdict(lambda: collections.defaultdict(set))
        with open(gt_path, encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                expected[r["file"]][r["bom_ref"]].update(r["known_cves"].split(";"))
        tp = fp = fn = 0
        for fname in files:
            exp = expected.get(fname, {})
            got = produced.get(fname, {})
            for ref in set(exp) | set(got):
                e, g = exp.get(ref, set()), got.get(ref, set())
                tp += len(e & g)
                fp += len(g - e)
                fn += len(e - g)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        report = [
            "SBOM -> CVE 매칭 검증 (정답셋: ground_truth_vulnerable_components.csv)",
            "",
            "  true positive : %d" % tp,
            "  false positive: %d" % fp,
            "  false negative: %d" % fn,
            "  precision     : %.4f" % prec,
            "  recall        : %.4f" % rec,
            "",
            "매칭은 SBOM 문서의 cpe/purl 식별자만 입력으로 사용하며 정답셋을 참조하지 않는다.",
        ]
        with open(os.path.join(OUT_DIR, "matching_report.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(report) + "\n")

    total_cve_refs = sum(r["cve_total"] for r in index_rows)
    print("SBOM-CVE files    : %d" % len(index_rows))
    print("unique CVEs       : %d" % len(cve_assets))
    print("CVE findings      : %d (자산별 CVE 항목 합계)" % total_cve_refs)
    print("NVD metadata      : %d/%d CVE 보유" %
          (len(cve_assets) - len(meta_missing), len(cve_assets)))
    print("output dir        : %s" % OUT_DIR)
    if report:
        print()
        print("\n".join(report[:7]))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
