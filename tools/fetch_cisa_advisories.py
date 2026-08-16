#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISA ICS 어드바이저리 전량 수집기 (역방향 파이프라인의 시드).

CISA 사이트맵에서 모든 ICS 어드바이저리(icsa-*) URL 을 열거하고,
각 페이지를 파싱하여 "실제 장비 <-> 실제 CVE" 매핑을 구조화한다.
이 매핑이 이후 가상 SBOM 생성의 근거(ground truth)가 된다.

수집 필드(어드바이저리당):
  advisory_id, url, year, title, vendor(best-effort),
  cves[], cwes[], cvss_scores[], affected_text(원문 일부, 재파싱용)

출력: data/cisa_advisories.json   { advisory_id: {...} }
재실행 가능(이미 수집한 항목은 건너뜀).
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import html as htmllib

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
CACHE = os.path.join(DATA_DIR, "cisa_advisories.json")
SITEMAP = "https://www.cisa.gov/default/sitemap.xml"
UA = {"User-Agent": "ics-vex-research/1.0 (academic SBOM/VEX dataset research)"}
DELAY = 0.4
MAX_RETRY = 4

ADV_RE = re.compile(r"https://www\.cisa\.gov/news-events/ics-advisories/(icsa?-\d{2}-\d{3}-\d{2}[a-z]?)")


def fetch(url, timeout=45):
    for attempt in range(MAX_RETRY):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(DELAY * (attempt + 2))
        except Exception:
            time.sleep(DELAY * (attempt + 2))
    return None


def enumerate_urls():
    sm = fetch(SITEMAP)
    urls = {}
    for m in ADV_RE.finditer(sm or ""):
        aid = m.group(1)
        urls[aid] = m.group(0)
    return urls


def clean_text(page):
    t = re.sub(r"(?is)<script.*?</script>", " ", page)
    t = re.sub(r"(?is)<style.*?</style>", " ", t)
    t = re.sub(r"<[^>]+>", " ", t)
    return htmllib.unescape(re.sub(r"\s+", " ", t)).strip()


def parse_vulns(txt):
    """CVE별 블록에서 CWE / CVSS v3·v4 (점수+벡터)를 추출한다.

    CISA 표준 문구:
      '... CWE-NNN ... CVE-YYYY-NNNN has been assigned to this vulnerability.
       A CVSS v3 base score of X.Y ... vector string is ( CVSS:3.1/AV:.../... ).
       A CVSS v4 score ... base score of X.Y ... vector string is ( AV:.../... ).'
    """
    vulns = {}
    for m in re.finditer(r"(CVE-\d{4}-\d{4,7})\s+has\s+been\s+assigned", txt):
        cve = m.group(1)
        start = m.start()
        back = txt[max(0, start - 700):start]
        cwe_list = re.findall(r"CWE-\d{1,4}", back)
        fwd = txt[start:start + 800]
        v3 = re.search(r"CVSS\s*v3[^.]*?base score of\s*(\d{1,2}(?:\.\d)?)[^(]*?\(\s*(CVSS:3\.\d/[A-Z:/]+)", fwd)
        v4 = re.search(r"CVSS\s*v4[^.]*?base score of\s*(\d{1,2}(?:\.\d)?)[^(]*?\(\s*(AV:[NALP]/[A-Z:/]+)", fwd)
        vulns[cve] = {
            "cve": cve,
            "cwe": cwe_list[-1] if cwe_list else "",
            "cvss_v3_score": float(v3.group(1)) if v3 else None,
            "cvss_v3_vector": v3.group(2) if v3 else "",
            "cvss_v4_score": float(v4.group(1)) if v4 else None,
            "cvss_v4_vector": v4.group(2) if v4 else "",
        }
    return vulns


def parse(aid, url, page):
    txt = clean_text(page)
    title_m = re.search(r"<title>([^<]+)</title>", page)
    title = title_m.group(1).replace("| CISA", "").strip() if title_m else ""

    # vendor: 명시 라벨 우선, 없으면 제목 첫 토큰
    vend = ""
    vm = re.search(r"Vendor:\s*([A-Za-z0-9 &.,\-/]+?)(?:\s+(?:Equipment|Product|Report|CVSS|Affected))", txt)
    if vm:
        vend = vm.group(1).strip()
    elif title:
        vend = title.split()[0]

    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", page)))
    cwes = sorted(set(re.findall(r"CWE-\d{1,4}", page)))
    vulns = parse_vulns(txt)

    yy = int(aid.split("-")[1])
    year = 2000 + yy

    # 재파싱용 원문 보존: 취약점 개요 + 영향 제품 구간
    ov = txt.find("VULNERABILITY OVERVIEW")
    ap = txt.find("Affected Products")
    lo = min([i for i in (ov, ap) if i >= 0] or [0])
    snippet = txt[lo:lo + 9000]

    return {
        "advisory_id": aid,
        "url": url,
        "year": year,
        "title": title,
        "vendor": vend,
        "cves": cves,
        "cwes": cwes,
        "vulns": list(vulns.values()),
        "affected_text": snippet,
    }


def load_cache():
    if os.path.exists(CACHE):
        with open(CACHE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(c):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = CACHE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, CACHE)


def main():
    urls = enumerate_urls()
    print("enumerated advisories: %d" % len(urls), flush=True)
    cache = load_cache()
    todo = [(a, u) for a, u in sorted(urls.items()) if a not in cache]
    print("cached=%d todo=%d" % (len(cache), len(todo)), flush=True)

    for n, (aid, url) in enumerate(todo, 1):
        page = fetch(url)
        if page is None:
            cache[aid] = {"advisory_id": aid, "url": url, "error": "fetch-failed"}
        else:
            cache[aid] = parse(aid, url, page)
        if n % 25 == 0 or n == len(todo):
            save_cache(cache)
            ok = sum(1 for v in cache.values() if not v.get("error"))
            withcve = sum(1 for v in cache.values() if v.get("cves"))
            print("[%d/%d] %s  ok=%d withCVE=%d" % (n, len(todo), aid, ok, withcve), flush=True)
        time.sleep(DELAY)

    save_cache(cache)
    ok = [v for v in cache.values() if not v.get("error")]
    allcves = set()
    for v in ok:
        allcves.update(v.get("cves", []))
    print("DONE advisories=%d unique_CVEs=%d" % (len(ok), len(allcves)), flush=True)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
