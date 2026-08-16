#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NVD CVE 메타데이터 수집기.

generate_ics_sbom.py 의 OSS 카탈로그에 등장하는 모든 CVE ID 에 대해
NVD API 2.0 에서 실제 메타데이터(CVSS, CWE, 설명, 발행일, 참조)를 조회하여
data/nvd_cache.json 에 캐시한다.

- API 키 없이 동작하도록 rolling window(5 req / 30s) 보다 여유 있게 throttle 한다.
- 캐시가 이미 있으면 미수집 CVE 만 이어서 조회한다(재실행 가능).
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_ics_sbom import OSS  # noqa: E402

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
CACHE = os.path.join(DATA_DIR, "nvd_cache.json")

API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
DELAY = 6.2          # 초. 무인증 rolling limit(5req/30s) 대비 여유
MAX_RETRY = 4


def all_cve_ids():
    ids = set()
    for spec in OSS.values():
        for _ver, cves in spec["versions"]:
            ids.update(cves)
    return sorted(ids)


def load_cache():
    if os.path.exists(CACHE):
        with open(CACHE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = CACHE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, CACHE)


def pick_metric(metrics):
    """CVSS v3.1 > v3.0 > v2 순으로 선택."""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = metrics.get(key) or []
        if not arr:
            continue
        primary = next((m for m in arr if m.get("type") == "Primary"), arr[0])
        data = primary.get("cvssData", {})
        sev = data.get("baseSeverity") or primary.get("baseSeverity")
        return {
            "method": "CVSSv31" if ver == "3.1" else ("CVSSv3" if ver == "3.0" else "CVSSv2"),
            "score": data.get("baseScore"),
            "severity": (sev or "unknown").lower(),
            "vector": data.get("vectorString"),
            "source": primary.get("source"),
        }
    return None


def parse(cve):
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    refs = [r.get("url") for r in cve.get("references", [])[:6] if r.get("url")]
    return {
        "id": cve.get("id"),
        "description": desc,
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "cwes": cwes,
        "metric": pick_metric(cve.get("metrics", {})),
        "references": refs,
        "source": cve.get("sourceIdentifier"),
    }


def fetch(cve_id):
    req = urllib.request.Request(API % cve_id,
                                 headers={"User-Agent": "ics-vex-research/1.0"})
    for attempt in range(MAX_RETRY):
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                payload = json.load(resp)
            items = payload.get("vulnerabilities", [])
            if not items:
                return {"id": cve_id, "error": "not-found"}
            return parse(items[0]["cve"])
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                wait = DELAY * (attempt + 2)
                print("  rate/again %s (%s) sleep %.0fs" % (cve_id, e.code, wait), flush=True)
                time.sleep(wait)
                continue
            return {"id": cve_id, "error": "http-%d" % e.code}
        except Exception as e:  # 네트워크 순간 오류
            wait = DELAY * (attempt + 2)
            print("  retry %s (%s) sleep %.0fs" % (cve_id, type(e).__name__, wait), flush=True)
            time.sleep(wait)
    return {"id": cve_id, "error": "max-retry"}


def main():
    ids = all_cve_ids()
    cache = load_cache()
    todo = [c for c in ids if c not in cache or cache[c].get("error")]
    print("total=%d cached=%d todo=%d" % (len(ids), len(ids) - len(todo), len(todo)), flush=True)

    for n, cve_id in enumerate(todo, 1):
        cache[cve_id] = fetch(cve_id)
        if n % 5 == 0 or n == len(todo):
            save_cache(cache)
            ok = sum(1 for v in cache.values() if not v.get("error"))
            print("[%d/%d] %s  (ok=%d)" % (n, len(todo), cve_id, ok), flush=True)
        if n < len(todo):
            time.sleep(DELAY)

    save_cache(cache)
    ok = sum(1 for v in cache.values() if not v.get("error"))
    bad = [k for k, v in cache.items() if v.get("error")]
    print("DONE ok=%d error=%d" % (ok, len(bad)), flush=True)
    if bad:
        print("errors:", ", ".join(bad[:20]), flush=True)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
