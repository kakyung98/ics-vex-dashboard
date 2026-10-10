#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch the NVD CPE dictionary — the authority for (vendor, product, version).

Test item #3 has to decide whether a component's CPE triple is internally coherent
and whether it agrees with the component's purl. Neither question needs hand
labelling: NVD publishes the full product dictionary (1,853,595 entries), so a
triple that appears in it exists, and the mismatched triples built by swapping one
field do not. The dictionary also carries each product's human-readable `titles`,
which pairs a display name with its CPE key —

    "Siemens SIMATIC S7-1500"  <->  cpe:2.3:o:siemens:simatic_s7-1500_firmware

— and that pairing is exactly the transform the matcher is being scored on, 1.85M
examples of it, free.

NOTE ON NEGATIVES. "Absent from the dictionary" does not mean "false". NVD's
coverage of ICS vendor firmware is thin, which is why so many components in this
corpus have no CPE at all. Negatives must be built by SWAPPING a field of a known
entry (vendor, product or version) and confirming the result is absent, never by
taking an unmatched real-world string as a negative — that would train on NVD's
gaps instead of on real mismatches.

The run is long (≈186 pages at 10k/page, rate-limited) so it checkpoints every page
and `--resume` picks up where it stopped.

Out: data/cpe_dictionary.jsonl   {cpe, part, vendor, product, version, title}
     data/cpe_dictionary.state   {next_index, total, fetched}
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, "data", "cpe_dictionary.jsonl")
STATE = os.path.join(BASE, "data", "cpe_dictionary.state")
API = "https://services.nvd.nist.gov/rest/json/cpes/2.0?resultsPerPage=%d&startIndex=%d"
API_VENDOR = ("https://services.nvd.nist.gov/rest/json/cpes/2.0"
              "?cpeMatchString=cpe:2.3:*:%s&resultsPerPage=%d&startIndex=%d")
CPE_INDEX = os.path.join(BASE, "data", "cpe_index.json")
PAGE = 10000            # NVD's maximum for this endpoint
DELAY = 6.2             # unauthenticated rolling limit is 5 req / 30 s
MAX_RETRY = 4
NEWLINE = chr(10)
UA = {"User-Agent": "Mozilla/5.0 (ICS-VEX CPE dictionary)"}


def ics_vendors():
    """The vendors our corpus actually needs.

    data/cpe_index.json is built from the applicability of ICSA CVEs, so its vendor
    set is not "ICS vendors" but "every vendor an ICS advisory's CVEs are filed
    under" — which is why the embedded OSS comes along for free: CISA names a
    Mitsubishi device, NVD files that CVE under openssl, and `openssl` lands in the
    set. A hand-written ICS vendor list would have missed `haxx` (curl's CPE vendor)
    and every other library whose CPE name differs from its common name.

    Fetching all 1.85M dictionary entries instead would be 93% irrelevant domains,
    and products the corpus never references only add false-positive surface to the
    retrieval index.
    """
    try:
        idx = json.load(open(CPE_INDEX, encoding="utf-8"))
    except Exception:
        return []
    out = set()
    for entries in (idx.get("by_product") or {}).values():
        for e in entries:
            if e.get("vendor"):
                out.add(e["vendor"])
    return sorted(out)


def parse_cpe(name):
    """cpe:2.3:part:vendor:product:version:... -> the four fields we index on."""
    parts = str(name or "").split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4],
            "version": parts[5]}


def english_title(titles):
    for t in titles or []:
        if t.get("lang") == "en" and t.get("title"):
            return t["title"]
    for t in titles or []:
        if t.get("title"):
            return t["title"]
    return None


def fetch_page(start, page, vendor=None):
    url = (API_VENDOR % (urllib.parse.quote(vendor, safe=""), page, start)
           if vendor else API % (page, start))
    last = None
    for attempt in range(MAX_RETRY):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            last = "HTTP %s" % e.code
            # 403/503 here means the rolling limit was hit; back off rather than spin
            time.sleep(DELAY * (attempt + 2))
        except Exception as e:
            last = type(e).__name__
            time.sleep(DELAY * (attempt + 1))
    raise RuntimeError("page %d failed: %s" % (start, last))


def load_state():
    if os.path.isfile(STATE):
        try:
            return json.load(open(STATE, encoding="utf-8"))
        except Exception:
            pass
    return {"next_index": 0, "total": None, "fetched": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendors", action="store_true",
                    help="fetch only the vendors data/cpe_index.json references "
                         "(the ICS corpus plus the OSS it embeds) instead of all of NVD")
    ap.add_argument("--resume", action="store_true",
                    help="continue from data/cpe_dictionary.state")
    ap.add_argument("--max-vendors", type=int, default=0,
                    help="stop after N vendors (bounded trial run)")
    ap.add_argument("--max-pages", type=int, default=0,
                    help="whole-dictionary mode only: stop after N pages")
    ap.add_argument("--page", type=int, default=PAGE)
    a = ap.parse_args()

    state = load_state() if a.resume else {}
    if not a.resume and os.path.isfile(OUT):
        # the previous version deleted OUT unconditionally, so a rerun without
        # --resume silently threw away hours of fetching
        print("%s already exists. Pass --resume to continue it, or delete it to "
              "start over." % os.path.relpath(OUT, BASE))
        return

    out = open(OUT, "a" if a.resume else "w", encoding="utf-8")
    kept = state.get("fetched", 0)
    try:
        if a.vendors:
            vendors = ics_vendors()
            done = set(state.get("done_vendors") or [])
            todo = [v for v in vendors if v not in done]
            if a.max_vendors:
                todo = todo[:a.max_vendors]
            print("ICS vendors: %d  (done %d, todo %d)"
                  % (len(vendors), len(done), len(todo)))
            for i, vendor in enumerate(todo, 1):
                start, got = 0, 0
                while True:
                    payload = fetch_page(start, a.page, vendor)
                    products = payload.get("products") or []
                    total = payload.get("totalResults") or 0
                    for p in products:
                        c = (p or {}).get("cpe") or {}
                        if c.get("deprecated"):
                            continue
                        f = parse_cpe(c.get("cpeName"))
                        if not f:
                            continue
                        f["cpe"] = c.get("cpeName")
                        f["title"] = english_title(c.get("titles"))
                        out.write(json.dumps(f, ensure_ascii=False) + NEWLINE)
                        kept += 1
                        got += 1
                    start += len(products)
                    if not products or start >= total:
                        break
                    time.sleep(DELAY)
                out.flush()
                done.add(vendor)
                state.update({"done_vendors": sorted(done), "fetched": kept,
                              "mode": "vendors"})
                json.dump(state, open(STATE, "w", encoding="utf-8"), ensure_ascii=False)
                print("[%d/%d] %-28s +%-5d kept=%d" % (i, len(todo), vendor, got, kept),
                      flush=True)
                time.sleep(DELAY)
        else:
            state.setdefault("next_index", 0)
            pages = 0
            while True:
                payload = fetch_page(state["next_index"], a.page)
                total = payload.get("totalResults") or 0
                state["total"] = total
                products = payload.get("products") or []
                if not products:
                    break
                for p in products:
                    c = (p or {}).get("cpe") or {}
                    if c.get("deprecated"):
                        continue
                    f = parse_cpe(c.get("cpeName"))
                    if not f:
                        continue
                    f["cpe"] = c.get("cpeName")
                    f["title"] = english_title(c.get("titles"))
                    out.write(json.dumps(f, ensure_ascii=False) + NEWLINE)
                    kept += 1
                out.flush()
                state["next_index"] += len(products)
                state["fetched"] = kept
                json.dump(state, open(STATE, "w", encoding="utf-8"), ensure_ascii=False)
                pages += 1
                print("[%d] %d / %d  kept=%d"
                      % (pages, state["next_index"], total, kept), flush=True)
                if state["next_index"] >= total:
                    break
                if a.max_pages and pages >= a.max_pages:
                    print("(--max-pages reached; rerun with --resume)")
                    break
                time.sleep(DELAY)
    finally:
        out.close()

    print("DONE  kept=%d" % kept)
    print("->", OUT)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
