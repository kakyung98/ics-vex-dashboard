#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ICS-VEX REST API service (dynamic backend — the counterpart to the static Pages).

GitHub Pages can only host static HTML. This is a real running service: a FastAPI
app that serves the hybrid-pipeline data over REST and computes VEX for an uploaded
SBOM live. Interactive Swagger docs are auto-served at /docs (and /redoc).

Endpoints
  GET  /                      -> the interactive web page (SBOM -> VEX + live stats)
  GET  /api/health            -> service + data status
  GET  /api/summary           -> corpus static-VEX summary (by verdict/tier/source_class)
  GET  /api/candidates        -> reproduction candidates (?status=ready&top=15)
  GET  /api/findings/{cve}    -> aggregated static verdict for one CVE
  POST /api/vex               -> {sbom, exposure} -> per-component CVE + live VEX
  GET  /docs                  -> Swagger UI (auto)

Run
  python src/api_server.py --port 8100
  # or:  uvicorn src.api_server:app --port 8100
The VEX computation here is the deterministic static leg (component match ->
CVSS AV x exposure reachability); it needs no GPU/models, so the service starts
instantly. For the full SecureBERT/CodeBERT/sLLM path use src/vex_pipeline.py.
"""
import os, sys, json, argparse, difflib, csv, re
from collections import defaultdict, Counter

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))
import build_ground_truth as G  # reachability(), exposure_for(), CWE_NAME
import vex_source_unavailable as VT  # decision tree for source-uncollectable CVEs

# Official MITRE CWE names (Title Case). Covers every CWE shown in the
# collectable-CVE pool + common corpus weaknesses. Overrides the informal
# lowercase names in build_ground_truth.CWE_NAME.
CWE_OFFICIAL = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    "CWE-74": "Improper Neutralization of Special Elements (Injection)",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-94": "Improper Control of Generation of Code (Code Injection)",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-130": "Improper Handling of Length Parameter Inconsistency",
    "CWE-187": "Partial String Comparison",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-193": "Off-by-one Error",
    "CWE-208": "Observable Timing Discrepancy",
    "CWE-222": "Truncation of Security-relevant Information",
    "CWE-254": "Security Features",
    "CWE-281": "Improper Preservation of Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-362": "Race Condition (Concurrent Execution using Shared Resource)",
    "CWE-364": "Signal Handler Race Condition",
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-428": "Unquoted Search Path or Element",
    "CWE-440": "Expected Behavior Violation",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-665": "Improper Initialization",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-787": "Out-of-bounds Write",
    "CWE-835": "Loop with Unreachable Exit Condition (Infinite Loop)",
    "CWE-843": "Access of Resource Using Incompatible Type (Type Confusion)",
    "CWE-924": "Improper Enforcement of Message Integrity During Transmission",
    "CWE-1104": "Use of Unmaintained Third Party Components",
}
CWE_NAMES = {**getattr(G, "CWE_NAME", {}), **CWE_OFFICIAL}

RESULTS = os.path.join(BASE, "results")
DATA = os.path.join(BASE, "data")
KB_PATH = os.path.join(RESULTS, "cve_kb.json")

AFFECTED, NOT_AFFECTED, UNDER_INV = "LIKELY_AFFECTED", "LIKELY_NOT_AFFECTED", "UNDER_INVESTIGATION"
EXPOSURES = ["isolated-cell", "control-network", "dmz-routable", "remote-accessible"]


def _load(path, default=None):
    return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else default


# Canonical vendor names — merge short/long variants of the same company so they
# don't split the counts (e.g. "Rockwell" + "Rockwell Automation").
_VENDOR_CANON = {
    "rockwell": "Rockwell Automation",
    "rockwell automation": "Rockwell Automation",
    "schneider": "Schneider Electric",
    "schneider electric": "Schneider Electric",
    "mitsubishi": "Mitsubishi Electric",
    "mitsubishi electric": "Mitsubishi Electric",
    "siemens": "Siemens",
    "siemens ag": "Siemens",
    "ge": "GE",
    "general electric": "GE",
    "honeywell": "Honeywell",
    "honeywell international": "Honeywell",
}

def _norm_vendor(v):
    """Clean whitespace/zero-width duplicates and canonicalize known vendor variants
    (e.g. '\\u200bSiemens' -> 'Siemens'; 'Rockwell' / 'Rockwell Automation' -> one name)."""
    v = (v or "").replace("​", "").strip().strip(",").strip()
    if not v:
        return "Unknown"
    return _VENDOR_CANON.get(v.lower(), v)


def _canon_cwe(rows):
    """A CVE's CWE = the most common non-empty CWE across its findings (the
    worst-VEX row can lack a CWE while another row carries it)."""
    cws = [r.get("cwe") for r in rows if r.get("cwe")]
    return Counter(cws).most_common(1)[0][0] if cws else ""


def _device_type(name):
    """ICS-aware device categorization from the product/device slug."""
    d = (name or "").lower()
    if any(k in d for k in ("vxworks", "ipnet", "tcp-ip", "tcpip", "rtos", "treck",
                            "interpeak", "freertos", "stack")):
        return "OS / Protocol stack"
    if any(k in d for k in ("scalance", "ruggedcom", "switch", "router", "gateway",
                            "sinec", "telecontrol", "firewall", "vpn", "modem", "ethernet")):
        return "Network / Comms"
    if any(k in d for k in ("simatic", "s7-", "-cpu", "plc", "logix", "modicon",
                            "controller", "logic")):
        return "PLC / Controller"
    if any(k in d for k in ("sinamics", "drive", "motion", "servo", "inverter", "robot")):
        return "Drive / Motion"
    if any(k in d for k in ("hmi", "scada", "wincc", "historian", "workstation",
                            "-server", "nms", "-ins")):
        return "HMI / SCADA / Server"
    return "Other / Field device"


class Store:
    """Loads the corpus artifacts once; refresh() re-reads them."""
    def __init__(self):
        self.refresh()

    def refresh(self):
        self.summary = _load(os.path.join(RESULTS, "vex_batch_summary.json"), {})
        self.candidates = _load(os.path.join(RESULTS, "verify_candidates.json"),
                                {"candidates": []})
        self.code_ev = _load(os.path.join(DATA, "code_evidence.json"), {})
        # CVEs whose vulnerable source was collected by the source collector
        # (data/source_snapshots/<CVE>/), from the collector's report.
        _dp = _load(os.path.join(RESULTS, "data_processor_report.json"), {})
        self.collected_src = {r.get("cve") for r in (_dp.get("records") or [])
                              if r.get("status") == "collected" and r.get("cve")}
        self.sbom_index = _load(os.path.join(BASE, "sbom_index.json"), {"generated": 0, "assets": []})
        # CISA ICS advisories (the corpus provenance)
        adv_raw = _load(os.path.join(DATA, "cisa_advisories.json"), {})
        adv = list(adv_raw.values()) if isinstance(adv_raw, dict) else (adv_raw or [])
        adv_yr = Counter(str(a.get("year")) for a in adv if a.get("year"))
        adv_ven = Counter(_norm_vendor(a.get("vendor")) for a in adv if a.get("vendor"))
        self.advisories = {
            "total": len(adv),
            "vendors": len(adv_ven),
            "by_year": {y: adv_yr[y] for y in sorted(adv_yr, key=lambda x: int(x))},
            "top_vendors": [{"vendor": v, "count": n} for v, n in adv_ven.most_common(8)],
        }
        # slim searchable advisory list (for the Source-data search engine)
        self.advisories_list = sorted(
            [{"id": a.get("advisory_id", ""), "title": a.get("title", ""),
              "vendor": _norm_vendor(a.get("vendor")), "year": a.get("year"),
              "cves": a.get("cves", []), "url": a.get("url", "")} for a in adv],
            key=lambda x: str(x["id"]), reverse=True)
        # full per-advisory detail (served on demand; not in the slim list)
        self.adv_detail = {}
        for a in adv:
            aid = a.get("advisory_id", "")
            if not aid:
                continue
            self.adv_detail[aid] = {
                "id": aid, "title": a.get("title", ""),
                "vendor": a.get("vendor", ""), "year": a.get("year"),
                "url": a.get("url", ""), "cves": a.get("cves", []),
                "cwes": a.get("cwes", []),
                "overview": (a.get("affected_text") or "").strip(),
                "vulns": a.get("vulns", [])}
        kb = _load(KB_PATH, {"components": []})["components"]
        self.kb_idx = {}
        for comp in kb:
            for key in {comp["key"], comp["name"].lower(), comp.get("cpe_product", "")}:
                if key:
                    self.kb_idx[key.lower()] = comp
        # per-CVE static verdicts from the batch (for /api/findings/{cve})
        self.by_cve = defaultdict(list)
        p = os.path.join(RESULTS, "vex_batch.jsonl")
        if os.path.exists(p):
            for line in open(p, encoding="utf-8"):
                try:
                    r = json.loads(line)
                    self.by_cve[r["cve"]].append(r)
                except Exception:
                    continue
        self.pairs = {k for k, v in self.code_ev.items()
                      if isinstance(v, dict) and v.get("vuln_code") and v.get("patched_code")}
        # distinct KB components + their match strings (for CPE normalization)
        self.kb_comps = list({id(c): c for c in self.kb_idx.values()}.values())
        self.kb_match = [(c, [s.lower() for s in
                              {c.get("name", ""), c.get("cpe_product", ""), c.get("key", "")} if s])
                         for c in self.kb_comps]
        # CVE -> CVSS base score. NVD (tools/fetch_nvd_cvss_bulk.py) is authoritative,
        # then findings.csv / NVD cache / CISA advisory metrics fill any gaps.
        self.cvss = {}
        _ncp = os.path.join(DATA, "nvd_cvss.json")
        if os.path.exists(_ncp):
            for _c, _v in _load(_ncp, {}).items():
                if _c != "__cursor__" and isinstance(_v, dict) and _v.get("score") is not None:
                    try:
                        self.cvss[_c] = float(_v["score"])
                    except (TypeError, ValueError):
                        pass
        fp = os.path.join(DATA, "findings.csv")
        if os.path.exists(fp):
            for r in csv.DictReader(open(fp, encoding="utf-8-sig")):
                sc = r.get("cvss_v3_score")
                if not sc:
                    continue
                try:
                    sc = float(sc)
                except ValueError:
                    continue
                if sc > self.cvss.get(r["cve"], -1):
                    self.cvss[r["cve"]] = sc
        # fill gaps from the NVD cache (metric.score) so every KB CVE gets a real base score
        _nvd = _load(os.path.join(DATA, "nvd_cache.json"), {})
        for _cid, _e in (_nvd.items() if isinstance(_nvd, dict) else []):
            if _cid in self.cvss:
                continue
            _m = (_e or {}).get("metric") or {}
            _sc = _m.get("score") if isinstance(_m, dict) else None
            if _sc is not None:
                try:
                    self.cvss[_cid] = float(_sc)
                except (TypeError, ValueError):
                    pass
        # broadest source: CISA advisory per-CVE metrics (v3 then v4)
        _adv_raw2 = _load(os.path.join(DATA, "cisa_advisories.json"), {})
        for _a in (_adv_raw2.values() if isinstance(_adv_raw2, dict) else []):
            for _vu in (_a.get("vulns") or []):
                _c = _vu.get("cve")
                if not _c or _c in self.cvss:
                    continue
                _s = _vu.get("cvss_v3_score")
                if _s is None:
                    _s = _vu.get("cvss_v4_score")
                if _s is not None:
                    try:
                        self.cvss[_c] = float(_s)
                    except (TypeError, ValueError):
                        pass
        for comp in self.kb_comps:
            for lst in comp.get("versions", {}).values():
                for cv in lst:
                    cv["cvss"] = self.cvss.get(cv["id"])
        # per-CVE index for the clickable "related CVEs" drill-down
        srank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        vrank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}
        self.cve_index = {}
        for cve, rows in self.by_cve.items():
            w = max(rows, key=lambda r: vrank.get(r["final_vex"], 0))
            sev = max((r.get("sev", "") for r in rows), key=lambda s: srank.get(s, 0))
            parts = cve.split("-")
            ev = self.code_ev.get(cve) or {}
            repo = ev.get("repo")
            self.cve_index[cve] = {
                "cve": cve, "vex": w["final_vex"], "reachability": w.get("reachability"),
                "severity": sev if sev in srank else "unrated",
                "cvss": self.cvss.get(cve),
                "cwe": _canon_cwe(rows), "kev": any(r.get("kev") for r in rows),
                "year": int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None,
                "source_available": any(r.get("tier") == "A" for r in rows),
                "has_code_pair": cve in self.pairs,
                "vendors": sorted({_norm_vendor(r.get("vendor")) for r in rows}),
                "device_types": sorted({_device_type(r.get("device")) for r in rows}),
                "component": w.get("product") or w.get("component"),
                "repo_url": (f"https://github.com/{repo}" if repo and "/" in repo else None),
            }
        # CVE-level view (unique CVEs, worst-case verdict across assets)
        rank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}
        cve_worst, cve_tier = {}, {}
        for cve, rows in self.by_cve.items():
            w = max(rows, key=lambda r: rank.get(r["final_vex"], 0))
            cve_worst[cve] = w["final_vex"]
            cve_tier[cve] = w.get("evidence_tier")
        # unique CVE count by CVE-ID year
        yr = Counter()
        for cve in cve_worst:
            parts = cve.split("-")
            if len(parts) >= 2 and parts[1].isdigit():
                yr[int(parts[1])] += 1
        self.by_year = {str(y): yr[y] for y in sorted(yr)}
        self.cve_level = {
            "total_cves": len(cve_worst),
            "by_vex": dict(Counter(cve_worst.values())),
            "by_tier": dict(Counter(t for t in cve_tier.values() if t)),
        }
        # tier-A = OSS-attributed, source-code collectable (the "110" after closed-source reclass)
        a_worst = {}
        ven_cves, dtype_cves = defaultdict(set), defaultdict(set)
        for cve, rows in self.by_cve.items():
            a_rows = [r for r in rows if r.get("tier") == "A"]
            if not a_rows:
                continue
            a_worst[cve] = max(a_rows, key=lambda r: rank.get(r["final_vex"], 0))
            for r in a_rows:
                ven_cves[_norm_vendor(r.get("vendor"))].add(cve)
                dtype_cves[_device_type(r.get("device"))].add(cve)
        sev_norm = lambda s: s if s in ("critical", "high", "medium", "low") else "unrated"
        # canonical CWE per CVE (non-empty), so counts match the CVE's real weakness
        _a_cwe = {cve: self.cve_index[cve]["cwe"] for cve in a_worst}
        _cwe_ctr = Counter(c for c in _a_cwe.values() if c)
        self.tier_a = {
            "total_cves": len(a_worst),
            "code_collected": sum(1 for cve, w in a_worst.items()
                                   if w.get("has_code_pair") or cve in self.collected_src),
            "pending_collection": sum(1 for cve, w in a_worst.items()
                                      if not (w.get("has_code_pair") or cve in self.collected_src)),
            "kev": sum(1 for w in a_worst.values() if w.get("kev")),
            "by_vex": dict(Counter(w["final_vex"] for w in a_worst.values())),
            "by_severity": dict(Counter(sev_norm(w.get("sev", "")) for w in a_worst.values())),
            "by_reachability": dict(Counter(w.get("reachability") for w in a_worst.values())),
            "top_cwe": [{"cwe": c, "name": CWE_NAMES.get(c, ""), "count": n} for c, n in
                        _cwe_ctr.most_common()],
            "cwe_other": {"count": 0, "types": 0},
            "cwe_none": sum(1 for c in _a_cwe.values() if not c),
            "top_vendors": [{"vendor": v, "count": len(cs)} for v, cs in
                            sorted(ven_cves.items(), key=lambda kv: -len(kv[1]))[:8]],
            "device_types": [{"type": t, "count": len(cs)} for t, cs in
                             sorted(dtype_cves.items(), key=lambda kv: -len(kv[1]))],
        }


STORE = Store()


# ---------------------------------------------------------------------------
# live SBOM -> VEX (deterministic static leg, no models)
# ---------------------------------------------------------------------------
def _cve_ids(comp, ver):
    """CVE ids a KB component exposes for a version (pinned, else union of all)."""
    if not comp:
        return []
    vmap = comp.get("versions", {})
    cves = vmap.get(ver)
    if cves is None:
        seen, cves = set(), []
        for lst in vmap.values():
            for cv in lst:
                if cv["id"] not in seen:
                    seen.add(cv["id"]); cves.append(cv)
    return [cv["id"] for cv in cves]


def _ro_best_match(name):
    """Ratcliff-Obershelp (difflib) nearest KB component for a component name.
    Returns (component, best_ratio, matched_string) over its name/cpe/key strings."""
    n = (name or "").lower()
    best, best_r, best_s = None, 0.0, None
    for comp, strs in STORE.kb_match:
        for s in strs:
            r = difflib.SequenceMatcher(None, n, s).ratio()
            if r > best_r:
                best_r, best, best_s = r, comp, s
    return best, round(best_r, 3), best_s


def vex_compare_sbom(sbom, exposure=None, threshold=0.7):
    """Compare CVE identification: exact component match vs a CPE normalized by
    Ratcliff-Obershelp (difflib) fuzzy matching to the KB, then re-identified."""
    comps = [((c.get("name") or "").strip(), (c.get("version") or "").strip())
             for c in sbom.get("components", []) if (c.get("name") or "").strip()]
    rows, exact_set, norm_set = [], set(), set()
    for name, ver in comps:
        exact = STORE.kb_idx.get(name.lower())
        ex_ids = _cve_ids(exact, ver)
        exact_set.update(ex_ids)
        ncomp, ratio, matched_str = _ro_best_match(name)
        normalized = ncomp if ratio >= threshold else None
        nm_ids = _cve_ids(normalized, ver)
        norm_set.update(nm_ids)
        rows.append({
            "component": name, "version": ver or "(unpinned)",
            "exact_match": exact["name"] if exact else None,
            "normalized_match": normalized["name"] if normalized else None,
            "best_match": ncomp["name"] if ncomp else None,   # closest, even below threshold
            "matched_string": matched_str,                    # the KB string RO matched on
            "ro_ratio": ratio, "matched_by_normalization": bool(normalized and not exact),
            "exact_cve_count": len(ex_ids), "normalized_cve_count": len(nm_ids),
        })
    return {
        "threshold": threshold, "components": len(comps), "normalization": rows,
        "comparison": {
            "exact_total": len(exact_set), "normalized_total": len(norm_set),
            "both": sorted(exact_set & norm_set),
            "only_exact": sorted(exact_set - norm_set),
            "only_normalized": sorted(norm_set - exact_set),
        },
    }


def vex_for_sbom(sbom, exposure=None):
    comps = [((c.get("name") or "").strip(), (c.get("version") or "").strip())
             for c in sbom.get("components", []) if (c.get("name") or "").strip()]
    rank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}
    by_cve = {}  # unique CVE -> worst-case row
    for name, ver in comps:
        comp = STORE.kb_idx.get(name.lower())
        if not comp:
            continue
        vmap = comp.get("versions", {})
        cves = vmap.get(ver)
        pinned = cves is not None
        if cves is None:
            seen = set(); cves = []
            for lst in vmap.values():
                for cv in lst:
                    if cv["id"] not in seen:
                        seen.add(cv["id"]); cves.append(cv)
        for cv in cves:
            av = cv.get("av", "N")
            exp = exposure or G.exposure_for(comp["name"])
            reach = G.reachability(av, exp)
            has_pair = cv["id"] in STORE.pairs
            if reach == "no":
                status, just = NOT_AFFECTED, "vulnerable_code_cannot_be_controlled_by_adversary"
                basis = "AV:P physical access" if av == "P" else f"AV:{av} unreachable at '{exp}'"
            else:
                status, just, _v, basis, _c, reach = G.estimate(
                    av, exp, "per-cve", "A" if has_pair else "C", bool(cv.get("kev")))
            tier = ("static-reasoned" if status in (AFFECTED, NOT_AFFECTED)
                    else "under-investigation")
            row = {
                "cve": cv["id"], "component": comp["name"], "version": ver or "(unpinned)",
                "version_pinned": pinned, "severity": cv.get("sev", ""),
                "cvss": cv.get("cvss"),
                "source_collectable": bool(
                    STORE.cve_index.get(cv["id"], {}).get("source_available")
                    or cv["id"] in STORE.pairs),
                "av": av, "kev": bool(cv.get("kev")), "epss": cv.get("epss"),
                "exposure": exp, "reachability": reach, "has_code_pair": has_pair,
                "final_vex": status, "justification": just, "basis": basis,
                "evidence_tier": tier,
            }
            prev = by_cve.get(cv["id"])
            if prev is None or rank.get(status, 0) > rank.get(prev["final_vex"], 0):
                by_cve[cv["id"]] = row
    # Also honor CVEs embedded in the SBOM's own VDR (vulnerabilities[]), e.g. a
    # reverse_sbom SBOM-CVE whose closed-firmware component has no OSS KB match.
    ref2name = {c.get("bom-ref"): (c.get("name") or "") for c in sbom.get("components", [])}
    ref2tier = {}
    for _c in sbom.get("components", []):
        for _p in (_c.get("properties") or []):
            if _p.get("name") == "component:source-availability":
                ref2tier[_c.get("bom-ref")] = _p.get("value")
    _top = (sbom.get("metadata") or {}).get("component") or {}
    if _top.get("bom-ref"):
        ref2name[_top["bom-ref"]] = _top.get("name") or ""
    for v in (sbom.get("vulnerabilities", []) or []):
        cid = v.get("id")
        if not cid or cid in by_cve:
            continue
        props = {p.get("name"): p.get("value") for p in (v.get("properties") or [])}
        score, sev = None, ""
        for r in (v.get("ratings") or []):
            if r.get("score") is not None:
                try: score = float(r["score"])
                except (TypeError, ValueError): pass
            if r.get("severity"):
                sev = str(r["severity"]).lower()
        if score is None:
            score = STORE.cvss.get(cid)
        if not sev:
            sev = (STORE.cve_index.get(cid, {}) or {}).get("severity", "")
        av = ""
        _m = re.search(r"AV:([NALP])", props.get("cisa:cvss-v3-vector", "") or "")
        if _m:
            av = _m.group(1)
        kev = str(props.get("signal:kev", "")).lower() == "true"
        aff = ((v.get("affects") or [{}])[0] or {}).get("ref")
        exp = exposure or G.exposure_for(_top.get("name") or ref2name.get(aff, "") or "device")
        if av:
            reach = G.reachability(av, exp)
            if reach == "no":
                status, just = NOT_AFFECTED, "vulnerable_code_cannot_be_controlled_by_adversary"
                basis = "AV:P physical access" if av == "P" else f"AV:{av} unreachable at '{exp}'"
            else:
                status, just, _v, basis, _c, reach = G.estimate(av, exp, "per-cve", "C", kev)
        else:
            status, just, basis, reach = UNDER_INV, None, "no CVSS attack vector in the source advisory", "unknown"
        try:
            epss = float(props["signal:epss"]) if props.get("signal:epss") not in (None, "NA", "") else None
        except (TypeError, ValueError):
            epss = None
        by_cve[cid] = {
            "cve": cid, "component": ref2name.get(aff, aff or _top.get("name") or ""),
            "version": "NOASSERTION", "version_pinned": False, "severity": sev, "cvss": score,
            "source_collectable": (False if ref2tier.get(aff) == "E"
                                    else True if ref2tier.get(aff) in ("A", "C")
                                    else bool(STORE.cve_index.get(cid, {}).get("source_available") or cid in STORE.pairs)),
            "av": av, "kev": kev, "epss": epss,
            "exposure": exp, "reachability": reach, "has_code_pair": cid in STORE.pairs,
            "final_vex": status, "justification": just, "basis": basis,
            "evidence_tier": ("static-reasoned" if status in (AFFECTED, NOT_AFFECTED) else "under-investigation"),
            "from_vdr": True,
        }
    cves = sorted(by_cve.values(),
                  key=lambda r: (-rank.get(r["final_vex"], 0), r["cve"]))
    by = Counter(r["final_vex"] for r in cves)
    return {"components": len(comps), "cves_matched": len(cves),
            "summary": {"by_vex": dict(by)}, "cves": cves}


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
def build_app():
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel

    app = FastAPI(title="ICS-VEX API", version="1.0",
                  description="Hybrid VEX pipeline — static triage over the corpus + "
                              "live SBOM→VEX. No PoC is generated or executed.")

    class SbomReq(BaseModel):
        sbom: dict
        exposure: str | None = None

    @app.get("/api/health")
    def health():
        return {"ok": True, "kb_components": len(set(id(v) for v in STORE.kb_idx.values())),
                "corpus_cves": STORE.cve_level.get("total_cves"),
                "candidates": len(STORE.candidates.get("candidates", [])),
                "exposures": EXPOSURES}

    @app.get("/api/summary")
    def summary():
        """CVE-level corpus summary (unique CVEs, worst-case verdict)."""
        if not STORE.cve_level.get("total_cves"):
            raise HTTPException(404, "run src/vex_batch.py first")
        return STORE.cve_level

    @app.get("/api/cves")
    def cves_by(dim: str, value: str, scope: str = "corpus", limit: int = 400):
        """Related CVEs for a chart selection (drill-down).
        dim: cwe|vendor|device_type|year|vex|reachability|severity ; scope: corpus|source_available."""
        srank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unrated": 0}
        vrank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}

        def ok(r):
            if scope == "source_available" and not r["source_available"]:
                return False
            if dim == "cwe":            return r["cwe"] == value
            if dim == "vendor":         return value in r["vendors"]
            if dim == "device_type":    return value in r["device_types"]
            if dim == "year":           return str(r["year"]) == str(value)
            if dim == "vex":            return r["vex"] == value
            if dim == "reachability":   return r["reachability"] == value
            if dim == "severity":       return r["severity"] == value
            return False

        hits = [r for r in STORE.cve_index.values() if ok(r)]
        hits.sort(key=lambda r: (-int(r["kev"]), -vrank.get(r["vex"], 0),
                                 -srank.get(r["severity"], 0), r["cve"]))
        return {"dim": dim, "value": value, "scope": scope, "count": len(hits),
                "cves": [{"cve": r["cve"], "vex": r["vex"], "severity": r["severity"],
                          "cvss": r.get("cvss"),
                          "kev": r["kev"], "reachability": r["reachability"],
                          "vendor": ", ".join(r["vendors"][:2]), "component": r["component"],
                          "cwe": r["cwe"], "has_code_pair": r["has_code_pair"],
                          "repo_url": r["repo_url"]} for r in hits[:limit]]}

    @app.get("/api/advisories")
    def advisories():
        """CISA ICS advisory provenance stats (total, by year, top vendors)."""
        if not STORE.advisories.get("total"):
            raise HTTPException(404, "data/cisa_advisories.json not found")
        return STORE.advisories

    @app.get("/api/advisories/list")
    def advisories_list():
        """Full slim advisory list for the Source-data search engine."""
        return {"count": len(STORE.advisories_list), "advisories": STORE.advisories_list}

    @app.get("/api/advisory/{aid}")
    def advisory_detail(aid: str):
        """Full CISA ICS-CERT advisory content (overview, CWEs, CVEs, metrics)."""
        d = STORE.adv_detail.get(aid)
        if not d:
            raise HTTPException(404, "advisory not found")
        return d

    @app.get("/api/sbom_index")
    def sbom_index():
        """Compact index of the synthetic ICS-SBOM dataset (assets + components + CVEs)."""
        return STORE.sbom_index

    @app.get("/reverse_sbom/{name}")
    def reverse_sbom_file(name: str):
        """Serve a raw CycloneDX SBOM-CVE file (parity with GitHub Pages static hosting)."""
        from fastapi.responses import FileResponse
        if "/" in name or "\\" in name or not name.endswith(".json"):
            raise HTTPException(400, "bad name")
        path = os.path.join(BASE, "reverse_sbom", name)
        if not os.path.isfile(path):
            raise HTTPException(404, "SBOM not found")
        return FileResponse(path, media_type="application/json")

    @app.get("/api/cve_search")
    def cve_search(q: str = "", limit: int = 100):
        """Search the corpus CVEs (id / CWE / vendor / component)."""
        ql = (q or "").strip().lower()
        vrank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}
        hits = []
        for r in STORE.cve_index.values():
            if not ql or ql in r["cve"].lower() or ql in (r.get("cwe") or "").lower() \
                    or any(ql in v.lower() for v in r.get("vendors", [])) \
                    or ql in (r.get("component") or "").lower():
                hits.append(r)
        hits.sort(key=lambda r: (-int(r["kev"]), -vrank.get(r["vex"], 0), r["cve"]))
        return {"count": len(hits),
                "cves": [{"cve": r["cve"], "cvss": r.get("cvss"), "severity": r["severity"],
                          "cwe": r.get("cwe"), "kev": r["kev"], "vex": r["vex"],
                          "vendor": ", ".join(r.get("vendors", [])[:2]),
                          "component": r.get("component")} for r in hits[:limit]]}

    @app.get("/api/by_year")
    def by_year():
        """Unique CVE count by CVE-ID year (all 11,336)."""
        if not STORE.by_year:
            raise HTTPException(404, "run src/vex_batch.py first")
        return {"total_cves": sum(STORE.by_year.values()), "by_year": STORE.by_year}

    @app.get("/api/source_available")
    def source_available():
        """Stats for the source-code-collectable (tier-A) CVEs — the '110'."""
        if not STORE.tier_a.get("total_cves"):
            raise HTTPException(404, "run src/vex_batch.py first")
        return STORE.tier_a

    @app.get("/api/candidates")
    def candidates(status: str | None = None, top: int | None = None):
        items = STORE.candidates.get("candidates", [])
        if status:
            items = [c for c in items if c.get("status") == status]
        if top:
            items = items[:top]
        return {"count": len(items), "candidates": items}

    @app.get("/api/findings/{cve}")
    def finding(cve: str):
        rows = STORE.by_cve.get(cve.upper())
        if not rows:
            raise HTTPException(404, f"{cve} not in corpus")
        worst = max(rows, key=lambda r: {"LIKELY_AFFECTED": 3, "UNDER_INVESTIGATION": 2,
                                         "LIKELY_NOT_AFFECTED": 1}.get(r["final_vex"], 0))
        return {"cve": cve.upper(), "finding_count": len(rows),
                "assets": sorted({r.get("device") for r in rows if r.get("device")}),
                "worst_case": worst}

    @app.post("/api/vex")
    def vex(req: SbomReq):
        if req.exposure and req.exposure not in EXPOSURES:
            raise HTTPException(400, f"exposure must be one of {EXPOSURES}")
        return vex_for_sbom(req.sbom, req.exposure)

    class CompareReq(BaseModel):
        sbom: dict
        exposure: str | None = None
        threshold: float = 0.7

    @app.post("/api/vex_compare")
    def vex_compare(req: CompareReq):
        """CPE normalization (Ratcliff-Obershelp) + CVE re-identification vs exact."""
        return vex_compare_sbom(req.sbom, req.exposure, req.threshold)

    class TreeReq(BaseModel):
        av: str | None = None
        answers: dict = {}

    @app.get("/api/vex_tree")
    def vex_tree_def():
        """The source-uncollectable-CVE decision tree definition (for the walker)."""
        return VT.TREE

    @app.post("/api/vex_tree")
    def vex_tree(req: TreeReq):
        """Walk the source-uncollectable decision tree with the given answers."""
        return VT.classify(req.av, req.answers or {})

    @app.post("/api/refresh")
    def refresh():
        STORE.refresh()
        return {"ok": True, "reloaded": True}

    @app.get("/", response_class=HTMLResponse)
    @app.get("/index.html", response_class=HTMLResponse)
    def index():
        return make_page("analyzer")

    @app.get("/vex-method.html", response_class=HTMLResponse)
    def vex_method():
        return make_page("vex-method")

    @app.get("/corpus.html", response_class=HTMLResponse)
    def corpus():
        return make_page("corpus")

    @app.get("/collectable.html", response_class=HTMLResponse)
    def collectable():
        return make_page("collectable")

    @app.get("/source.html", response_class=HTMLResponse)
    def source():
        return make_page("source")

    @app.get("/ics-sbom.html", response_class=HTMLResponse)
    def ics_sbom_page():
        return make_page("ics-sbom")

    return app


# ---------------------------------------------------------------------------
# frontend (single page, calls the API above)
# ---------------------------------------------------------------------------
FRONTEND_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ICS-VEX API console</title>
<style>
@font-face{font-family:'Paperlogy';src:url('https://fastly.jsdelivr.net/gh/projectnoonnu/2408-3@1.0/Paperlogy-5Medium.woff2') format('woff2');font-weight:500;font-display:swap}
@font-face{font-family:'Paperlogy';src:url('https://fastly.jsdelivr.net/gh/projectnoonnu/2408-3@1.0/Paperlogy-7Bold.woff2') format('woff2');font-weight:700;font-display:swap}
@font-face{font-family:'Paperlogy';src:url('https://fastly.jsdelivr.net/gh/projectnoonnu/2408-3@1.0/Paperlogy-8ExtraBold.woff2') format('woff2');font-weight:800;font-display:swap}
:root{--bg:#0b1116;--card:#111a20;--card2:#16222a;--ink:#e6edf2;--ink2:#93a3ad;--ink3:#657580;
--line:#25333c;--accent:#38ccd9;--aff:#e5675c;--safe:#43be7c;--und:#e0b24c;
--mono:ui-monospace,Consolas,monospace;--sans:system-ui,Segoe UI,Roboto,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:18px}
.layout{display:grid;grid-template-columns:300px minmax(0,1fr);max-width:1720px;margin:0 auto;min-height:100vh}
.side{border-right:1px solid var(--line);padding:22px 16px;position:sticky;top:0;align-self:start;height:100vh;overflow:auto}
.main{padding:28px clamp(18px,3vw,48px) 64px;min-width:0}
.side-brand{display:flex;justify-content:center;margin:4px 0 6px}
.side-brand a{display:inline-flex;border-radius:50%;transition:transform .12s,filter .12s}
.side-brand a:hover{transform:scale(1.04);filter:brightness(1.15)}
.side-brand .ssrc{width:84px;height:84px;cursor:pointer}
@media(max-width:860px){.layout{grid-template-columns:1fr}.side{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line)}}
.eyebrow{font-family:var(--mono);font-size:13px;letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}
h1{margin:.2em 0;font-size:clamp(30px,3.6vw,44px)}.sub{color:var(--ink2);max-width:80ch;font-size:16px}
h3{font-size:18px}.hint{font-size:13px}
.nav{display:flex;flex-direction:column;gap:3px;margin-top:20px}
.nav .navlabel{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink3);font-weight:700;margin:14px 8px 4px}
.navtab{font-size:15px;font-weight:600;text-decoration:none;color:var(--ink2);padding:10px 14px;border-radius:9px;border:1px solid transparent;white-space:nowrap}
.navtab:hover{color:var(--ink);background:var(--card2)}
.navtab.on{color:var(--accent);background:var(--card2);border-color:var(--line)}
@media(max-width:860px){.nav{flex-direction:row;flex-wrap:wrap}.nav .navlabel{display:none}}
.treepath{display:grid;gap:6px}.treestep{font-size:14px;color:var(--ink2);padding:8px 12px;background:var(--card2);border-radius:8px;border-left:3px solid var(--accent)}
.treestep b{color:var(--ink)}
.treeq{margin-top:16px;padding:16px;border:1px solid var(--accent);border-radius:10px;background:color-mix(in srgb,var(--accent) 7%,transparent)}
.treeres{margin-top:16px;padding:18px;border:2px solid var(--line);border-radius:12px;background:var(--card2)}
.treebtn{font-size:12.5px;font-weight:700;padding:4px 10px;border-radius:7px;border:1px solid var(--und);background:transparent;color:var(--und);cursor:pointer;white-space:nowrap}
.treebtn:hover{background:color-mix(in srgb,var(--und) 15%,transparent)}
.treecve{border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px;background:var(--card2)}
.treecve-h{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tc-hi{outline:2px solid var(--und);outline-offset:2px;transition:outline .2s}
.srch{width:100%;background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:12px 15px;font-size:15px}
.srch:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 18%,transparent)}
.srch-wrap{max-height:620px;overflow:auto;border:1px solid var(--line);border-radius:11px;margin-top:10px}
.srch-wrap table{margin:0;font-size:14.5px}
.srch-wrap thead th{position:sticky;top:0;background:var(--card);z-index:1;padding:11px 14px;border-bottom:1px solid var(--line)}
.srch-wrap td{padding:11px 14px;border-bottom:1px solid color-mix(in srgb,var(--line) 60%,transparent)}
.srch-wrap tbody tr:last-child td{border-bottom:none}
.srch-wrap tbody tr:hover{background:color-mix(in srgb,var(--accent) 8%,transparent)}
.idcell{white-space:nowrap;font-family:var(--mono);font-weight:600}
.idcell a{text-decoration:none}.idcell a:hover{text-decoration:underline}
.cvecount{display:inline-block;min-width:24px;text-align:center;font-family:var(--mono);font-size:12.5px;background:var(--card2);border:1px solid var(--line);border-radius:20px;padding:2px 9px}
.srch-meta{font-size:13px;color:var(--ink3);margin-bottom:2px}.srch-meta b{color:var(--ink)}
a{color:var(--accent)}.row{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:end}
@media(max-width:640px){.row{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px 24px;margin-top:20px}
h3{font-size:16px}
label{font-size:13px;color:var(--ink2)}textarea{width:100%;min-height:190px;background:var(--bg);color:var(--ink);
border:1px solid var(--line);border-radius:8px;padding:12px;font-family:var(--mono);font-size:13px;transition:border-color .12s,background .12s}
textarea.dragover{border-color:var(--accent);border-style:dashed;background:color-mix(in srgb,var(--accent) 8%,var(--bg))}
select,button{font-family:var(--sans);font-size:14px;padding:9px 14px;border-radius:8px;border:1px solid var(--line);
background:var(--card2);color:var(--ink)}button.primary{background:var(--accent);color:#04120c;font-weight:700;border:none;cursor:pointer}
.kpis{display:flex;flex-wrap:wrap;gap:12px}.kpi{background:var(--card2);border:1px solid var(--line);border-radius:11px;padding:14px 20px;flex:1;min-width:150px}
.kpi b{font-size:30px}.kpi span{display:block;font-size:13px;color:var(--ink3);font-family:var(--mono);margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:16px;margin-top:6px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
th{font-size:13px;color:var(--ink3);text-transform:uppercase}.mono{font-family:var(--mono)}
.badge{font-family:var(--mono);font-size:13px;font-weight:700;padding:2px 9px;border-radius:5px}
.err{color:var(--aff);font-size:14px}
#sa-charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:24px}
.chart{margin-bottom:6px}.ct{font-size:15px;font-weight:600;color:var(--ink2);margin-bottom:8px}
.mb{display:flex;height:26px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}.mb>div{height:100%}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:9px;font-size:14px}
.legend .lg{display:flex;align-items:center;gap:6px}.legend i{width:12px;height:12px;border-radius:3px;display:inline-block}
.cwe{display:grid;gap:7px}.cwerow{display:grid;grid-template-columns:minmax(260px,440px) 1fr 44px;align-items:center;gap:12px;font-size:14px}
.cwerow>span:first-child{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.foot{margin-top:44px;padding-top:22px;border-top:1px solid var(--line);text-align:center;font-size:14px;color:var(--ink3)}
.brand{display:flex;align-items:center;gap:16px;margin-bottom:8px}
.ssrc{width:70px;height:70px;flex:none}
.btxt .bk{font-family:'Paperlogy',var(--sans);font-size:25px;font-weight:800;color:#ffffff;letter-spacing:.5px;line-height:1.15}
.btxt .be{font-family:'Paperlogy',var(--sans);font-size:14px;font-weight:700;color:#c8d3da;letter-spacing:.4px}
.brand-sm{justify-content:center;margin-bottom:10px}
.brand-sm .ssrc{width:50px;height:50px}.brand-sm .bk{font-size:18px}.brand-sm .be{font-size:12px}
.cright{color:var(--ink3);font-size:13px}
.cwebar{background:var(--card2);border-radius:5px;height:15px;overflow:hidden}.cwebar>i{display:block;height:100%;background:var(--accent);border-radius:5px}
.cwerow b{text-align:right;font-family:var(--mono)}
.clk{cursor:pointer}
.vexf{display:block;margin:9px 0}.vexf>span{display:block;margin-bottom:3px}.vexf input,.vexf select{width:100%}
.vexset .badge{outline:2px solid var(--accent)}.clk:hover{opacity:.8}
.cwename{color:var(--ink3);font-size:12px;margin-left:6px}
/* drill-down modal */
.ov{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:flex-start;justify-content:center;z-index:50;padding:40px 16px;overflow:auto}
.ov.on{display:flex}
.modal{background:var(--card);border:1px solid var(--line);border-radius:14px;max-width:1100px;width:100%;padding:22px 24px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.modal .mh{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}
.modal h3{margin:0}.xbtn{cursor:pointer;background:var(--card2);border:1px solid var(--line);color:var(--ink);border-radius:8px;padding:6px 12px;font-size:15px}
.satwo{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px}
.dtt{font-size:13px}.dtt td{padding:7px 8px}
.ybars{display:flex;align-items:flex-end;gap:6px;height:230px;overflow-x:auto;padding-top:6px}
.ycol{flex:1;min-width:44px;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.yval{font-family:var(--mono);font-size:12px;color:var(--ink2);margin-bottom:4px;white-space:nowrap}
.ybar{width:78%;background:var(--accent);border-radius:5px 5px 0 0;min-height:3px}
.yr{font-family:var(--mono);font-size:12px;color:var(--ink3);margin-top:6px}

.vm-flow{display:flex;flex-direction:column;align-items:center;gap:6px}
.vm-box{background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:12px 18px;text-align:center;max-width:760px;width:100%;font-weight:600}
.vm-box .vm-sub,.vm-step .vm-sub{display:block;font-weight:400;color:var(--ink3);font-size:13px;margin-top:3px}
.vm-in{border-color:var(--accent);color:var(--accent)}
.vm-dec{background:color-mix(in srgb,var(--und) 14%,transparent);border-color:var(--und);border-radius:26px}
.vm-out{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,transparent)}
.vm-arrow{color:var(--ink3);font-size:20px;line-height:1}
.vm-mini{color:var(--ink3);font-size:13px;line-height:1}
.vm-split{display:grid;grid-template-columns:1fr 1fr;gap:22px;width:100%;margin:6px 0}
.vm-lane{border:1px solid var(--line);border-radius:14px;padding:12px;display:flex;flex-direction:column;align-items:center;gap:5px}
.vm-yes{background:color-mix(in srgb,var(--safe) 7%,transparent)}
.vm-no{background:color-mix(in srgb,var(--und) 7%,transparent)}
.vm-laneh{font-weight:700;margin-bottom:4px;text-align:center}
.vm-yes .vm-laneh{color:var(--safe)}.vm-no .vm-laneh{color:var(--und)}
.vm-step{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:8px 12px;width:100%;font-size:14px}
.vm-verd{border-radius:9px;padding:9px 12px;width:100%;font-size:13.5px;text-align:center}
.vm-vgreen{background:color-mix(in srgb,var(--safe) 15%,transparent);border:1px solid var(--safe)}
.vm-vamber{background:color-mix(in srgb,var(--und) 15%,transparent);border:1px solid var(--und)}
.vm-cols{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
.vm-list{margin:0;padding-left:18px}.vm-list li{margin:5px 0;font-size:14.5px}
@media(max-width:820px){.vm-split,.vm-cols{grid-template-columns:1fr}}
</style></head><body><div class="layout">
<aside class="side">
  <div class="side-brand"><a href="index.html" title="Go to Analyzer" aria-label="ICS-VEXForge Analyzer"><svg class="ssrc" viewBox="0 0 120 120"><circle cx="60" cy="60" r="55" fill="none" stroke="#37b24d" stroke-width="3"/><circle cx="60" cy="60" r="47" fill="none" stroke="#37b24d" stroke-width="1.5"/><text x="60" y="52" text-anchor="middle" font-weight="800" font-size="30" fill="#37b24d" font-family="Arial,sans-serif">SSRC</text><text x="60" y="72" text-anchor="middle" font-size="9" letter-spacing="1.5" fill="#37b24d" font-weight="700">SYSTEM SECURITY</text><text x="60" y="87" text-anchor="middle" font-size="8" letter-spacing="1" fill="#69db7c" font-weight="600">★ EST. 2000 ★</text></svg></a></div>
  __NAV__
</aside>
<main class="main">
__CONTENT__
<div class="foot"><div class="brand brand-sm"><svg class="ssrc" viewBox="0 0 120 120"><circle cx="60" cy="60" r="55" fill="none" stroke="#37b24d" stroke-width="3"/><circle cx="60" cy="60" r="47" fill="none" stroke="#37b24d" stroke-width="1.5"/><text x="60" y="55" text-anchor="middle" font-weight="800" font-size="31" fill="#37b24d" font-family="Arial,sans-serif">SSRC</text><text x="60" y="74" text-anchor="middle" font-size="9" letter-spacing="1.5" fill="#37b24d" font-weight="700">SYSTEM SECURITY</text><text x="60" y="89" text-anchor="middle" font-size="8" letter-spacing="1" fill="#69db7c" font-weight="600">★ EST. 2000 ★</text></svg><div class="btxt"><div class="bk">시스템보안연구센터</div><div class="be">System Security Research Center</div></div></div>
<div class="cright">© 2026 System Security Research Center, Chonnam National University. All rights reserved.</div></div>
</main>
</div>

<div class="ov" id="ov" onclick="if(event.target===this)closeCves()"><div class="modal">
  <div class="mh"><h3 id="mtitle">Related CVEs</h3><button class="xbtn" onclick="closeCves()">✕ Close</button></div>
  <div id="mbody" class="hint">loading…</div>
</div></div>

<script>
const VEX_TREE=__VEX_TREE__;
const C={LIKELY_AFFECTED:'var(--aff)',LIKELY_NOT_AFFECTED:'var(--safe)',UNDER_INVESTIGATION:'var(--und)'};
const L={LIKELY_AFFECTED:'Affected',LIKELY_NOT_AFFECTED:'Not affected',UNDER_INVESTIGATION:'Under investigation'};
function jsoncParse(txt){var BS=String.fromCharCode(92),NL=String.fromCharCode(10),CR=String.fromCharCode(13);var s='',i=0,n=txt.length,inStr=false,esc=false;while(i<n){var c=txt[i];if(inStr){s+=c;if(esc){esc=false;}else if(c===BS){esc=true;}else if(c==='"'){inStr=false;}i++;continue;}if(c==='"'){inStr=true;s+=c;i++;continue;}if(c==='/'&&txt[i+1]==='/'){while(i<n&&txt[i]!==NL&&txt[i]!==CR){i++;}continue;}if(c==='/'&&txt[i+1]==='*'){i+=2;while(i+1<n&&!(txt[i]==='*'&&txt[i+1]==='/')){i++;}i+=2;continue;}s+=c;i++;}var WS=' '+String.fromCharCode(9)+String.fromCharCode(10)+String.fromCharCode(13);var re=new RegExp(',(['+WS+']*)(}|])','g');return JSON.parse(s.replace(re,'$1$2'));}
async function run(){
  const o=document.getElementById('out');o.innerHTML='<span class="hint">analyzing…</span>';
  let sbom;try{sbom=jsoncParse(document.getElementById('sbom').value)}catch(e){o.innerHTML='<span class="err">invalid JSON</span>';return}
  _treeState={};   // fresh decision trees for this SBOM
  compareNorm(sbom,document.getElementById('exp').value);
  const r=await fetch('/api/vex',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({sbom,exposure:document.getElementById('exp').value})});
  if(!r.ok){o.innerHTML='<span class="err">error '+r.status+'</span>';return}
  const d=await r.json();
  if(!d.cves_matched){o.innerHTML='<span class="hint">'+d.components+' components, no known CVEs matched.</span>';return}
  _lastVex=d;
  const bv=d.summary.by_vex||{};
  let h='<div class="hint">'+d.components+' components · <b>'+d.cves_matched+' CVEs</b> · '
    +'affected '+(bv.LIKELY_AFFECTED||0)+' · not affected '+(bv.LIKELY_NOT_AFFECTED||0)+' · under inv '+(bv.UNDER_INVESTIGATION||0)+'</div>';
  h+='<table><thead><tr><th>CVE</th><th>VEX</th><th>SSVC</th><th>Component</th><th>CVSS</th><th>KEV</th><th>AV</th><th>Reach</th><th>Source / next step</th></tr></thead><tbody>';
  for(const f of d.cves){const c=C[f.final_vex]||'var(--ink3)';
    const nextcol = f.source_collectable
      ? '<span class="hint">source available &middot; execution-verified VEX</span>'
      : '<span class="hint">source-uncollectable &middot; SSVC + estimation</span>';
    h+='<tr><td class="mono">'+f.cve+'</td>'
      +'<td id="vexcell-'+f.cve+'">'+_vexCellInner(f.cve)+'</td>'
      +(function(){var ss=ssvcFor(f.cve);var sd=ssvcDecide(ss);return '<td id="ssvccell-'+f.cve+'"><span class="badge" title="'+ssvcVector(ss)+'" style="background:'+(SSVC_COL[sd]||'var(--ink3)')+'22;color:'+(SSVC_COL[sd]||'var(--ink3)')+'">'+sd+'</span></td>';})()
      +'<td>'+f.component+' '+f.version+'</td><td class="mono" title="CVSS v3 base score">'+cvssFmt(f.cvss,f.severity)+'</td>'
      +'<td class="mono">'+(f.kev?'KEV':'')+'</td><td class="mono">'+f.av+'</td>'
      +'<td class="mono hint">'+f.reachability+'</td><td>'+nextcol+'</td></tr>';}
  h+='</tbody></table>';
  h+='<div style="margin-top:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap"><span class="hint">Export VEX (after deciding source-uncollectable CVEs via the tree):</span>'+'<button class="treebtn" onclick="exportOpenVex()">Download OpenVEX</button>'+'<button class="treebtn" onclick="exportCsaf()">Download CSAF VEX</button></div>';
  o.innerHTML=h;
}
let _lastSbom=null,_lastExp=null;
async function compareNorm(sbom,exp){
  _lastSbom=sbom;_lastExp=exp;
  const th=parseFloat((document.getElementById('ro-th')||{}).value||0.7);
  let d=null;
  try{const r=await fetch('/api/vex_compare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sbom,exposure:exp,threshold:th})});if(r.ok)d=await r.json();}catch(e){}
  renderCompare(d);
}
function renderCompare(d){
  const card=document.getElementById('cmp'),body=document.getElementById('cmp-body');
  if(!d||!d.components){card.style.display='none';return;}
  card.style.display='';const cm=d.comparison;
  let h='<div style="overflow:auto"><table><thead><tr><th>Component</th><th>Exact CPE</th><th>RO-normalized CPE (closest)</th><th>RO ratio</th><th>Exact CVEs</th><th>Norm CVEs</th></tr></thead><tbody>';
  for(const r of d.normalization){const flag=r.matched_by_normalization?' <span class="tag" style="color:var(--und)">fuzzy</span>':'';
    let ncol;
    if(r.normalized_match)ncol='<b>'+esc(r.normalized_match)+'</b>'+flag;
    else if(r.best_match)ncol='<span class="hint">closest: '+esc(r.best_match)+' (&lt; threshold)</span>';
    else ncol='<span class="hint">—</span>';
    h+='<tr title="'+(r.matched_string?'RO matched on: '+esc(r.matched_string):'')+'"><td class="mono">'+esc(r.component)+' '+esc(r.version)+'</td>'
      +'<td>'+(r.exact_match?esc(r.exact_match):'<span class="hint">no exact match</span>')+'</td>'
      +'<td>'+ncol+'</td>'
      +'<td class="mono">'+Number(r.ro_ratio).toFixed(2)+'</td><td class="mono">'+r.exact_cve_count+'</td><td class="mono">'+r.normalized_cve_count+'</td></tr>';}
  h+='</tbody></table></div>';
  h+='<div class="kpis" style="margin-top:14px">'
    +'<div class="kpi"><b>'+cm.exact_total+'</b><span>exact CVEs</span></div>'
    +'<div class="kpi"><b>'+cm.normalized_total+'</b><span>normalized CVEs</span></div>'
    +'<div class="kpi"><b style="color:var(--safe)">'+cm.both.length+'</b><span>in both</span></div>'
    +'<div class="kpi"><b style="color:var(--und)">'+cm.only_normalized.length+'</b><span>only via RO</span></div>'
    +'<div class="kpi"><b style="color:var(--aff)">'+cm.only_exact.length+'</b><span>only exact</span></div></div>';
  if(cm.only_normalized.length){h+='<div class="ct" style="margin-top:14px">CVEs recovered by RO-normalized CPE ('+cm.only_normalized.length+')</div><div class="hint">'
    +cm.only_normalized.map(c=>'<a class="mono" href="https://nvd.nist.gov/vuln/detail/'+c+'" target="_blank" rel="noopener" style="margin-right:12px;white-space:nowrap">'+c+'</a>').join('')+'</div>';}
  body.innerHTML=h;
}
function ex(){document.getElementById('sbom').value=JSON.stringify({bomFormat:"CycloneDX",specVersion:"1.5",
  components:[{name:"OpenSSL",version:"1.1.1k"},{name:"zlib",version:"1.2.11"},{name:"BusyBox",version:"1.31.1"}]},null,2);
  document.getElementById('fname').textContent='';}
function loadFile(f){
  if(!f)return;
  const fn=document.getElementById('fname');fn.textContent='reading '+f.name+'…';
  const rd=new FileReader();
  rd.onload=function(){
    try{jsoncParse(rd.result);}catch(err){fn.innerHTML='<span class="err">'+f.name+' is not valid JSON</span>';return;}
    document.getElementById('sbom').value=rd.result;
    fn.textContent='loaded '+f.name+' — analyzing…';
    run();
  };
  rd.readAsText(f);
}
const _ta=document.getElementById('sbom');
if(_ta){   // analyzer page only
  document.getElementById('file').addEventListener('change',function(e){loadFile(e.target.files[0]);e.target.value='';});
  ['dragenter','dragover'].forEach(ev=>_ta.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();_ta.classList.add('dragover');}));
  ['dragleave','dragend'].forEach(ev=>_ta.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();_ta.classList.remove('dragover');}));
  _ta.addEventListener('drop',e=>{e.preventDefault();e.stopPropagation();_ta.classList.remove('dragover');
    const f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0];if(f)loadFile(f);});
  window.addEventListener('dragover',e=>e.preventDefault());
  window.addEventListener('drop',e=>e.preventDefault());
}
async function stats(){
  try{const s=await(await fetch('/api/summary')).json();const v=s.by_vex||{};
    const k=document.getElementById('kpis');k.innerHTML='';
    k.innerHTML+='<div class="kpi"><b>'+(s.total_cves||0).toLocaleString()+'</b><span>unique CVEs</span></div>';
    for(const key of ['LIKELY_AFFECTED','LIKELY_NOT_AFFECTED','UNDER_INVESTIGATION'])
      k.innerHTML+='<div class="kpi"><b style="color:'+C[key]+'">'+(v[key]||0).toLocaleString()+'</b><span>'+L[key]+'</span></div>';
    const sa=await(await fetch('/api/source_available')).json();
    document.getElementById('cand').textContent=(sa.code_collected||0).toLocaleString()+' CVEs';
  }catch(e){document.getElementById('kpis').innerHTML='<span class="err">stats unavailable — run src/vex_batch.py</span>';}
}
const SEVC={critical:'var(--aff)',high:'#e08d5b',medium:'var(--und)',low:'var(--safe)',unrated:'var(--ink3)'};
const REC={yes:'var(--aff)',conditional:'var(--und)',no:'var(--safe)',unknown:'var(--ink3)'};
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function openCves(dim,value,scope,label){
  document.getElementById('mtitle').textContent=label;
  document.getElementById('mbody').innerHTML='loading…';
  document.getElementById('ov').classList.add('on');
  try{const d=await(await fetch('/api/cves?dim='+encodeURIComponent(dim)+'&value='+encodeURIComponent(value)+'&scope='+scope)).json();
    if(!d.count){document.getElementById('mbody').innerHTML='<span class="hint">no CVEs.</span>';return;}
    let h='<div class="srch-meta"><b>'+d.count+'</b> CVEs</div>'+
      '<div class="srch-wrap"><table><thead><tr><th>CVE</th><th>VEX</th><th style="text-align:center">CVSS</th><th style="text-align:center">KEV</th><th>Reach</th><th>Vendor</th><th>Component</th><th>Code</th></tr></thead><tbody>';
    for(const f of d.cves){const c=C[f.vex]||'var(--ink3)';
      h+='<tr><td class="idcell"><a href="https://nvd.nist.gov/vuln/detail/'+f.cve+'" target="_blank" rel="noopener">'+f.cve+'</a></td>'
        +'<td><span class="badge" style="background:'+c+'22;color:'+c+'">'+(L[f.vex]||f.vex)+'</span></td>'
        +'<td class="mono" style="text-align:center" title="CVSS v3 base score">'+cvssFmt(f.cvss,f.severity)+'</td><td class="mono" style="text-align:center">'+(f.kev?'KEV':'')+'</td><td class="mono hint">'+esc(f.reachability)+'</td>'
        +'<td>'+esc(f.vendor)+'</td><td class="hint">'+esc(f.component||'')+'</td>'
        +'<td class="mono">'+(f.repo_url?'<a href="'+f.repo_url+'" target="_blank" rel="noopener">repo</a>':'')+'</td></tr>';}
    document.getElementById('mbody').innerHTML=h+'</tbody></table></div>';
  }catch(e){document.getElementById('mbody').innerHTML='<span class="err">error loading CVEs</span>';}
}
function closeCves(){document.getElementById('ov').classList.remove('on');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeCves();});
function bar(counts,order,cmap,total,dim,scope,lmap){
  let segs='',leg='';
  for(const k of order){const v=counts[k]||0;if(!v)continue;const w=100*v/total;
    const lbl=(lmap&&lmap[k])||k;const cl=dim?' class="clk"':'';
    const clk=dim?' onclick="openCves(\\''+dim+'\\',\\''+k+'\\',\\''+scope+'\\',\\''+lbl.replace(/'/g,'')+' — related CVEs\\')"':'';
    segs+='<div'+cl+clk+' style="width:'+w.toFixed(2)+'%;background:'+(cmap[k]||'var(--ink3)')+'" title="'+lbl+': '+v+'"></div>';
    leg+='<span class="lg'+(dim?' clk':'')+'"'+clk+'><i style="background:'+(cmap[k]||'var(--ink3)')+'"></i>'+lbl+' <b>'+v+'</b></span>';}
  return '<div class="mb">'+segs+'</div><div class="legend">'+leg+'</div>';
}
async function sourceAvail(){
  try{const s=await(await fetch('/api/source_available')).json();
    const t=s.total_cves;
    document.getElementById('sa-kpis').innerHTML=
      '<div class="kpi"><b>'+t+'</b><span>collectable CVEs</span></div>'+
      '<div class="kpi"><b style="color:var(--safe)">'+s.code_collected+'</b><span>code collected</span></div>'+
      '<div class="kpi"><b style="color:var(--und)">'+s.pending_collection+'</b><span>pending collection</span></div>'+
      '<div class="kpi"><b style="color:var(--aff)">'+s.kev+'</b><span>KEV</span></div>';
    document.getElementById('sa-charts').innerHTML=
      '<div class="chart"><div class="ct">VEX verdict</div>'+bar(s.by_vex,['LIKELY_AFFECTED','LIKELY_NOT_AFFECTED','UNDER_INVESTIGATION'],C,t,'vex','source_available',{LIKELY_AFFECTED:'Affected',LIKELY_NOT_AFFECTED:'Not affected',UNDER_INVESTIGATION:'Under inv'})+'</div>'+
      '<div class="chart"><div class="ct">CVSS severity</div>'+bar(s.by_severity,['critical','high','medium','low','unrated'],SEVC,t,'severity','source_available')+'</div>'+
      '<div class="chart"><div class="ct">Reachability</div>'+bar(s.by_reachability,['yes','conditional','no','unknown'],REC,t,'reachability','source_available')+'</div>';
    let cwe='<div class="ct">CWE types <span class="hint">click to list CVEs · '+t+' collectable CVEs total</span></div><div class="cwe">';
    const mx=Math.max(...s.top_cwe.map(x=>x.count));
    for(const x of s.top_cwe)cwe+='<div class="cwerow clk" title="'+x.cwe+' '+esc(x.name||'')+'" onclick="openCves(\\'cwe\\',\\''+x.cwe+'\\',\\'source_available\\',\\''+x.cwe+' '+esc(x.name||'')+' — CVEs\\')">'+
      '<span><span class="mono">'+x.cwe+'</span><span class="cwename">'+esc(x.name||'')+'</span></span>'+
      '<span class="cwebar"><i style="width:'+(100*x.count/mx)+'%"></i></span><b>'+x.count+'</b></div>';
    if(s.cwe_other&&s.cwe_other.count)cwe+='<div class="cwerow"><span class="hint">Other ('+s.cwe_other.types+' more types)</span>'+
      '<span class="cwebar"><i style="width:'+(100*s.cwe_other.count/mx)+'%;background:var(--ink3)"></i></span><b>'+s.cwe_other.count+'</b></div>';
    if(s.cwe_none)cwe+='<div class="cwerow clk" onclick="openCves(\\'cwe\\',\\'\\',\\'source_available\\',\\'CVEs with no CWE assigned\\')"><span class="hint">No CWE assigned</span>'+
      '<span class="cwebar"><i style="width:'+(100*s.cwe_none/mx)+'%;background:var(--ink3)"></i></span><b>'+s.cwe_none+'</b></div>';
    document.getElementById('sa-cwe').innerHTML=cwe+'</div>';
    // top vendors
    let vn='<div class="ct">Top vendors <span class="hint">click to list CVEs</span></div><div class="cwe">';
    const vmx=Math.max(...s.top_vendors.map(x=>x.count));
    for(const x of s.top_vendors)vn+='<div class="cwerow clk" onclick="openCves(\\'vendor\\',\\''+esc(x.vendor)+'\\',\\'source_available\\',\\''+esc(x.vendor)+' — CVEs\\')"><span>'+esc(x.vendor)+'</span>'+
      '<span class="cwebar"><i style="width:'+(100*x.count/vmx)+'%"></i></span><b>'+x.count+'</b></div>';
    document.getElementById('sa-vendors').innerHTML=vn+'</div>';
    // device-type mapping table
    let dt='<div class="ct">Device-type mapping <span class="hint">click a row to list CVEs</span></div>'+
      '<table class="dtt"><thead><tr><th>Equipment type</th><th style="text-align:right">CVEs</th></tr></thead><tbody>';
    for(const x of s.device_types)dt+='<tr class="clk" onclick="openCves(\\'device_type\\',\\''+esc(x.type)+'\\',\\'source_available\\',\\''+esc(x.type)+' — CVEs\\')"><td>'+esc(x.type)+'</td><td style="text-align:right" class="mono">'+x.count+'</td></tr>';
    dt+='</tbody></table><div class="hint" style="margin-top:5px">One CVE can span multiple types (shared component).</div>';
    document.getElementById('sa-devtype').innerHTML=dt;
  }catch(e){document.getElementById('sa-kpis').innerHTML='<span class="err">unavailable — run src/vex_batch.py</span>';}
}
function yearBars(y,noteTotal,noteLabel){
  const keys=Object.keys(y).map(Number).sort((a,b)=>a-b);
  const pre=keys.filter(k=>k<2010).reduce((a,k)=>a+y[k],0);
  const show=keys.filter(k=>k>=2010);
  const mx=Math.max(...show.map(k=>y[k]));
  let h='<div class="ybars">';
  for(const k of show){const c=y[k];const hp=Math.max(4,100*c/mx);
    h+='<div class="ycol clk" onclick="openCves(\\'year\\',\\''+k+'\\',\\'corpus\\',\\'CVEs published in '+k+'\\')"><div class="yval">'+c.toLocaleString()+'</div>'
     +'<div class="ybar" style="height:'+hp+'%" title="'+k+': '+c+' — click for CVEs"></div>'
     +'<div class="yr">’'+String(k).slice(2)+'</div></div>';}
  return h+'</div><div class="hint" style="margin-top:8px">'+noteTotal.toLocaleString()+' '+noteLabel
    +(pre?' · '+pre+' before 2010 (not shown)':'')+' · click a bar for its CVEs</div>';
}
async function yearChart(){
  try{const s=await(await fetch('/api/by_year')).json();
    document.getElementById('year').innerHTML=yearBars(s.by_year,s.total_cves,'CVEs total');
  }catch(e){document.getElementById('year').innerHTML='<span class="err">unavailable — run src/vex_batch.py</span>';}
}
async function advisories(){
  try{const s=await(await fetch('/api/advisories')).json();
    document.getElementById('adv-kpis').innerHTML=
      '<div class="kpi"><b>'+s.total.toLocaleString()+'</b><span>advisories</span></div>'+
      '<div class="kpi"><b>'+s.vendors.toLocaleString()+'</b><span>vendors</span></div>'+
      '<div class="kpi"><b>2010–2026</b><span>coverage</span></div>';
    document.getElementById('adv-year').innerHTML=yearBars(s.by_year,s.total,'advisories total');
    let v='<div class="ct">Top vendors</div><div class="cwe">';
    const mx=Math.max(...s.top_vendors.map(x=>x.count));
    for(const x of s.top_vendors)v+='<div class="cwerow"><span>'+x.vendor+'</span>'+
      '<span class="cwebar"><i style="width:'+(100*x.count/mx)+'%"></i></span><b>'+x.count+'</b></div>';
    document.getElementById('adv-ven').innerHTML=v+'</div>';
  }catch(e){document.getElementById('adv-kpis').innerHTML='<span class="err">advisory data unavailable</span>';}
}
// ---- VEX decision tree walker (source-uncollectable CVEs) ----
function avBranch(av){av=(av||'').toUpperCase();if(av==='N'||av==='A')return 'network';if(av==='L')return 'local';if(av==='P')return 'physical';return null;}
function classifyTree(av,ans){const nodes=VEX_TREE.nodes;let nid=VEX_TREE.start;const path=[];
  while(true){const node=nodes[nid];
    if(nid==='av_split'){const br=avBranch(av);path.push({node:nid,q:node.q,answer:(br||'미기재')});if(!br)return{status:'under_investigation',justification:'attack_vector_unstated',path:path,complete:false};nid=node.branch[br];continue;}
    const a=ans[nid];
    if(a===undefined||a===null)return{status:null,path:path,complete:false,pending:nid,question:node.q};
    path.push({node:nid,q:node.q,answer:!!a});
    const target=a?node.yes:node.no;
    if(Array.isArray(target))return{status:target[0],justification:target[1],path:path,complete:true};
    nid=target;}}
// per-CVE decision tree: only source-uncollectable CVEs from the SBOM appear,
// each walked independently (pre-seeded affected-range=yes, source-obtainable=no).
let _treeState={};
let _lastVex=null;
let _vexFields={};   // cve -> {status, justification, remediation, action_statement, fixed_version, patch_reference, verification_result, investigation_progress, missing_evidence, planned_update}
const VEX_JUST=[['component_not_present','Component not present'],['vulnerable_code_not_present','Vulnerable code not present'],['vulnerable_code_not_in_execute_path','Vulnerable code not in execute path'],['vulnerable_code_cannot_be_controlled_by_adversary','Vulnerable code cannot be controlled by adversary'],['inline_mitigations_already_exist','Inline mitigations already exist']];
const VEX_REMED=[['patch_or_firmware_upgrade','Patch or firmware upgrade'],['temporary_mitigation','Temporary mitigation'],['feature_disablement','Feature disablement'],['network_access_restriction','Network access restriction']];
const VEX_STATUSES=[['affected','affected'],['not_affected','not_affected'],['fixed','fixed'],['under_investigation','under_investigation']];
// ---- SSVC (CISA/SEI Deployer tree; System Exposure from deployment context) ----
const SSVC_EXPL=[['none','none'],['poc','poc'],['active','active']];
const SSVC_EXPO=[['small','small'],['controlled','controlled'],['open','open']];
const SSVC_AUTO=[['no','no'],['yes','yes']];
const SSVC_HI=[['low','low'],['medium','medium'],['high','high'],['very high','very high']];
const SSVC_TABLE={"none|small|no|low":"defer","none|small|no|medium":"defer","none|small|no|high":"scheduled","none|small|no|very high":"scheduled","none|small|yes|low":"defer","none|small|yes|medium":"scheduled","none|small|yes|high":"scheduled","none|small|yes|very high":"scheduled","none|controlled|no|low":"defer","none|controlled|no|medium":"scheduled","none|controlled|no|high":"scheduled","none|controlled|no|very high":"scheduled","none|controlled|yes|low":"scheduled","none|controlled|yes|medium":"scheduled","none|controlled|yes|high":"scheduled","none|controlled|yes|very high":"scheduled","none|open|no|low":"defer","none|open|no|medium":"scheduled","none|open|no|high":"scheduled","none|open|no|very high":"scheduled","none|open|yes|low":"scheduled","none|open|yes|medium":"scheduled","none|open|yes|high":"scheduled","none|open|yes|very high":"out-of-cycle","poc|small|no|low":"defer","poc|small|no|medium":"scheduled","poc|small|no|high":"scheduled","poc|small|no|very high":"scheduled","poc|small|yes|low":"scheduled","poc|small|yes|medium":"scheduled","poc|small|yes|high":"scheduled","poc|small|yes|very high":"scheduled","poc|controlled|no|low":"defer","poc|controlled|no|medium":"scheduled","poc|controlled|no|high":"scheduled","poc|controlled|no|very high":"scheduled","poc|controlled|yes|low":"scheduled","poc|controlled|yes|medium":"scheduled","poc|controlled|yes|high":"scheduled","poc|controlled|yes|very high":"out-of-cycle","poc|open|no|low":"scheduled","poc|open|no|medium":"scheduled","poc|open|no|high":"scheduled","poc|open|no|very high":"out-of-cycle","poc|open|yes|low":"scheduled","poc|open|yes|medium":"scheduled","poc|open|yes|high":"out-of-cycle","poc|open|yes|very high":"out-of-cycle","active|small|no|low":"scheduled","active|small|no|medium":"scheduled","active|small|no|high":"out-of-cycle","active|small|no|very high":"out-of-cycle","active|small|yes|low":"scheduled","active|small|yes|medium":"out-of-cycle","active|small|yes|high":"out-of-cycle","active|small|yes|very high":"out-of-cycle","active|controlled|no|low":"scheduled","active|controlled|no|medium":"scheduled","active|controlled|no|high":"out-of-cycle","active|controlled|no|very high":"out-of-cycle","active|controlled|yes|low":"out-of-cycle","active|controlled|yes|medium":"out-of-cycle","active|controlled|yes|high":"out-of-cycle","active|controlled|yes|very high":"out-of-cycle","active|open|no|low":"scheduled","active|open|no|medium":"out-of-cycle","active|open|no|high":"out-of-cycle","active|open|no|very high":"immediate","active|open|yes|low":"out-of-cycle","active|open|yes|medium":"out-of-cycle","active|open|yes|high":"immediate","active|open|yes|very high":"immediate"};
const SSVC_COL={"immediate":"var(--aff)","out-of-cycle":"var(--und)","scheduled":"var(--und)","defer":"var(--safe)"};
function _expToSsvc(e){return {'isolated-cell':'small','control-network':'controlled','dmz-routable':'controlled','remote-accessible':'open'}[e]||'controlled';}
function _deployExp(){var el=document.getElementById('exp');return _expToSsvc((el&&el.value)||(typeof _lastExp!=='undefined'?_lastExp:''));}
function ssvcAuto(f){var kev=!!f.kev;var epss=f.epss;epss=(typeof epss==='number')?epss:parseFloat(epss)||0;var expl=kev?'active':(epss>=0.1?'poc':'none');var av=String(f.av||'').toUpperCase();var autom=(av==='N'||av==='A')?'yes':'no';return {exploitation:expl,exposure:_deployExp(),automatable:autom,human_impact:'medium'};}
function ssvcDecide(p){return SSVC_TABLE[[p.exploitation,p.exposure,p.automatable,p.human_impact].join('|')]||'defer';}
function ssvcVector(p){var E={none:'N',poc:'P',active:'A'},X={small:'S',controlled:'C',open:'O'},A={no:'N',yes:'Y'},H={'low':'L','medium':'M','high':'H','very high':'VH'};return 'SSVCv2/E:'+E[p.exploitation]+'/X:'+X[p.exposure]+'/A:'+A[p.automatable]+'/H:'+H[p.human_impact]+'/P:'+ssvcDecide(p);}
function ssvcFor(cve){var f=((_lastVex&&_lastVex.cves)||[]).find(function(x){return x.cve===cve;})||{};var ov=(_vexFields[cve]||{}).ssvc||{};return Object.assign(ssvcAuto(f),ov);}

function _remedCsaf(r){return {patch_or_firmware_upgrade:'vendor_fix',temporary_mitigation:'mitigation',feature_disablement:'workaround',network_access_restriction:'mitigation'}[r]||'mitigation';}
function _canonStatus(s){s=String(s||'');
  if(s==='LIKELY_AFFECTED')return 'affected';
  if(s==='LIKELY_NOT_AFFECTED')return 'not_affected';
  if(s==='UNDER_INVESTIGATION')return 'under_investigation';
  if(s==='not_affected')return 'not_affected';
  if(s==='route_to_icsvexforge')return 'under_investigation';
  if(s.indexOf('likely_affected')===0)return 'affected';
  if(s==='under_investigation')return 'under_investigation';
  if(s==='fixed')return 'fixed';
  return 'under_investigation';}
function _ovJust(j){j=String(j||'');
  if(/component_not_present/.test(j))return 'component_not_present';
  if(/vulnerable_code_not_present/.test(j))return 'vulnerable_code_not_present';
  if(/not_in_execute_path|not_reachable|code_not_reachable|requires_configuration|requires_environment/.test(j))return 'vulnerable_code_not_in_execute_path';
  if(/cannot_be_controlled_by_adversary/.test(j))return 'vulnerable_code_cannot_be_controlled_by_adversary';
  if(/perimeter|mitigat|protected/.test(j))return 'inline_mitigations_already_exist';
  return 'vulnerable_code_not_in_execute_path';}
function _autoStatus(cve){
  const f=(_lastVex&&_lastVex.cves||[]).find(x=>x.cve===cve)||{};
  let raw=f.final_vex, just=f.justification||'';
  return {status:_canonStatus(raw), justification:just, cvss:f.cvss, component:f.component||'', av:f.av||''};}
const EST_OPTS=[['likely_affected','likely_affected'],['likely_not_affected','likely_not_affected'],['likely_fixed','likely_fixed'],['unable_to_determine','unable_to_determine']];
function _estimationAuto(auto){return {not_affected:'likely_not_affected',affected:'likely_affected',fixed:'likely_fixed',under_investigation:'unable_to_determine'}[auto.status]||'unable_to_determine';}
function _rowStatus(cve){var f=((_lastVex&&_lastVex.cves)||[]).find(function(x){return x.cve===cve;})||{};var auto=_autoStatus(cve);var ov=_vexFields[cve]||{};if(!f.source_collectable){return {status:'under_investigation',estimation:(ov.estimation||_estimationAuto(auto)),source_collectable:false};}return {status:(ov.status||auto.status),estimation:null,source_collectable:true};}
function _vexCellInner(cve){var rs=_rowStatus(cve);var col=_statCol(rs.status);var est=rs.estimation?(' <span class="hint" title="estimation (source-uncollectable)">est: '+rs.estimation+'</span>'):'';return '<span class="badge" style="background:'+col+'22;color:'+col+'">'+_statLabel(rs.status)+'</span>'+est+' <button class="treebtn" style="padding:2px 7px;font-size:12px" onclick="openVexEditor(\\''+cve+'\\')">&#9998; VEX</button>';}
function _vexRows(){const rows=[];for(const f of ((_lastVex&&_lastVex.cves)||[])){const rs=_rowStatus(f.cve);const ov=_vexFields[f.cve]||{};const r=Object.assign({cve:f.cve,component:f.component||'',cvss:f.cvss,av:f.av||'',kev:!!f.kev,justification:_autoStatus(f.cve).justification},ov);r.status=rs.status;r.estimation=rs.estimation;r.source_collectable=rs.source_collectable;const ss=Object.assign(ssvcAuto(f),ov.ssvc||{});r.ssvc=ss;r.ssvc_decision=ssvcDecide(ss);r.ssvc_vector=ssvcVector(ss);rows.push(r);}return rows;}
function _sbomProduct(){
  const c=(_lastSbom&&_lastSbom.metadata&&_lastSbom.metadata.component)||{};
  return {name:c.name||'SBOM target', ref:c['bom-ref']||'PRODUCT-1', purl:c.purl||''};}
function _isoNow(){return new Date().toISOString();}
function _dl(name,obj){const b=new Blob([JSON.stringify(obj,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1500);}
function _opt(list,cur){return list.map(o=>'<option value="'+o[0]+'"'+(o[0]===cur?' selected':'')+'>'+esc(o[1])+'</option>').join('');}
function _fld(id,label,val){return '<label class="vexf"><span class="hint">'+esc(label)+'</span><input id="'+id+'" class="srch" value="'+esc(val||'')+'"></label>';}
function _ssvcPanel(cve){var p=ssvcFor(cve);var h='<label class="vexf"><span class="hint">Exploitation (auto: KEV/EPSS)</span><select id="vf-e" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_EXPL,p.exploitation)+'</select></label>';h+='<label class="vexf"><span class="hint">System Exposure (auto: deployment exposure)</span><select id="vf-x" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_EXPO,p.exposure)+'</select></label>';h+='<label class="vexf"><span class="hint">Automatable (auto: CVSS AV)</span><select id="vf-a" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_AUTO,p.automatable)+'</select></label>';h+='<label class="vexf"><span class="hint">Human Impact (safety/mission &mdash; operator input)</span><select id="vf-h" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_HI,p.human_impact)+'</select></label>';h+='<div id="vf-ssvc-dec" class="vm-verd" style="margin-top:4px"></div>';return h;}function _ssvcCur(){return {exploitation:_v('vf-e'),exposure:_v('vf-x'),automatable:_v('vf-a'),human_impact:_v('vf-h')};}function ssvcRecalc(){var p=_ssvcCur();var d=ssvcDecide(p);var el=document.getElementById('vf-ssvc-dec');if(el)el.innerHTML='SSVC priority: <b style="color:'+(SSVC_COL[d]||'var(--ink)')+'">'+d+'</b> &middot; <span class="mono hint">'+ssvcVector(p)+'</span>';}
function openVexEditor(cve){
  const auto=_autoStatus(cve); const f=Object.assign({},auto,_vexFields[cve]||{});
  document.getElementById('mtitle').textContent='VEX statement — '+cve;
  let h='<div class="srch-meta">'+esc(f.component)+' · auto status: <b>'+esc(auto.status)+'</b>'+(auto.cvss!=null?(' · CVSS '+auto.cvss):'')+'</div>';
  var _unc=!(((_lastVex&&_lastVex.cves)||[]).find(function(x){return x.cve===cve;})||{}).source_collectable;
  if(_unc){h+='<div class="srch-meta">Source-uncollectable &rarr; status is <b>under_investigation</b>; set the estimation below.</div>';}
  else{h+='<label class="vexf"><span class="hint">VEX status</span><select id="vf-status" class="srch" onchange="vexStatusChange(\\''+cve+'\\')">'+_opt(VEX_STATUSES,f.status)+'</select></label>';}
  h+='<div id="vf-body">'+_vexEditorBody(cve,f)+'</div>';
  h+='<div style="border-top:1px solid var(--line);margin:14px 0 8px"></div><div class="srch-meta">SSVC priority (CISA Coordinator)</div>';h+=_ssvcPanel(cve);h+='<div style="margin-top:14px;display:flex;gap:10px"><button class="treebtn" onclick="saveVexFields(\\''+cve+'\\')">Save VEX fields</button><button class="xbtn" onclick="closeCves()">Cancel</button></div>';
  document.getElementById('mbody').innerHTML=h;document.getElementById('ov').classList.add('on');ssvcRecalc();}
function _vexEditorBody(cve,f){
  f=f||Object.assign({},_autoStatus(cve),_vexFields[cve]||{});
  var _uncb=!(((_lastVex&&_lastVex.cves)||[]).find(function(x){return x.cve===cve;})||{}).source_collectable;
  if(_uncb){return '<label class="vexf"><span class="hint">Estimation (VEX sub-field)</span><select id="vf-est" class="srch">'+_opt(EST_OPTS,(f.estimation||_estimationAuto(_autoStatus(cve))))+'</select></label>'+_fld('vf-prog','Investigation progress',f.investigation_progress)+_fld('vf-missing','Missing evidence',f.missing_evidence)+_fld('vf-plan','Planned update',f.planned_update);}
  const st=f.status;
  if(st==='not_affected')
    return '<label class="vexf"><span class="hint">Justification (flags)</span><select id="vf-just" class="srch">'+_opt(VEX_JUST,f.justification&&VEX_JUST.some(j=>j[0]===f.justification)?f.justification:_ovJust(f.justification))+'</select></label>'
      +_fld('vf-impact','Impact statement (optional)',f.action_statement);
  if(st==='affected')
    return '<label class="vexf"><span class="hint">Remediation (action_statement)</span><select id="vf-remed" class="srch">'+_opt(VEX_REMED,f.remediation||'patch_or_firmware_upgrade')+'</select></label>'
      +_fld('vf-action','Action detail (optional)',f.action_statement);
  if(st==='fixed')
    return _fld('vf-fixver','Fixed version',f.fixed_version)+_fld('vf-patch','Patch reference',f.patch_reference)+_fld('vf-verify','Verification result',f.verification_result);
  return _fld('vf-prog','Investigation progress',f.investigation_progress)+_fld('vf-missing','Missing evidence',f.missing_evidence)+_fld('vf-plan','Planned update',f.planned_update);
}
function vexStatusChange(cve){const st=document.getElementById('vf-status').value;const f=Object.assign({},_autoStatus(cve),_vexFields[cve]||{},{status:st});document.getElementById('vf-body').innerHTML=_vexEditorBody(cve,f);}
function _v(id){const e=document.getElementById(id);return e?e.value.trim():'';}
function saveVexFields(cve){
  var _unc=!(((_lastVex&&_lastVex.cves)||[]).find(function(x){return x.cve===cve;})||{}).source_collectable;
  var o;
  if(_unc){o={status:'under_investigation',estimation:_v('vf-est'),investigation_progress:_v('vf-prog'),missing_evidence:_v('vf-missing'),planned_update:_v('vf-plan')};}
  else{var st=_v('vf-status');o={status:st};
    if(st==='not_affected'){o.justification=_v('vf-just');o.action_statement=_v('vf-impact');}
    else if(st==='affected'){o.remediation=_v('vf-remed');o.action_statement=_v('vf-action');}
    else if(st==='fixed'){o.fixed_version=_v('vf-fixver');o.patch_reference=_v('vf-patch');o.verification_result=_v('vf-verify');}
    else{o.investigation_progress=_v('vf-prog');o.missing_evidence=_v('vf-missing');o.planned_update=_v('vf-plan');o.estimation=_v('vf-est');}}
  o.ssvc=_ssvcCur(); _vexFields[cve]=o; closeCves(); refreshVexRow(cve);
}function exportOpenVex(){
  const rows=_vexRows(); if(!rows.length){alert('Run an analysis first.');return;}
  const p=_sbomProduct(); const pid=p.purl||('pkg:generic/'+encodeURIComponent(p.name));
  const stmts=rows.map(r=>{const st={vulnerability:{name:r.cve},
      products:[Object.assign({"@id":pid},p.purl?{identifiers:{purl:p.purl}}:{})],
      status:r.status};
    if(r.status==='not_affected'){st.justification=r.justification&&VEX_JUST.some(j=>j[0]===r.justification)?r.justification:_ovJust(r.justification);if(r.action_statement)st.impact_statement=r.action_statement;}
    else if(r.status==='affected'){st.action_statement=(r.remediation?(r.remediation+': '):'')+(r.action_statement||'Apply vendor update or mitigation for '+r.component+'.');}
    else if(r.status==='fixed'){const bits=[];if(r.fixed_version)bits.push('fixed in '+r.fixed_version);if(r.patch_reference)bits.push('patch: '+r.patch_reference);if(r.verification_result)bits.push('verified: '+r.verification_result);if(bits.length)st.impact_statement=bits.join('; ');}
    else {const bits=[];if(r.investigation_progress)bits.push('progress: '+r.investigation_progress);if(r.missing_evidence)bits.push('missing: '+r.missing_evidence);if(r.planned_update)bits.push('planned: '+r.planned_update);if(bits.length)st.impact_statement=bits.join('; ');}
    if(r.estimation)st.estimation=r.estimation;
    st.ssvc={decision:r.ssvc_decision,vector:r.ssvc_vector};
    return st;});
  const doc={"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://kakyung98.github.io/ics-vex-dashboard/vex/openvex-"+Date.now(),
    author:"ICS-VEXForge (Chonnam SSRC)",role:"Document Creator",timestamp:_isoNow(),version:1,tooling:"ICS-VEXForge",statements:stmts};
  _dl('openvex-'+(p.name.replace(/[^a-z0-9]+/gi,'-').toLowerCase())+'.json',doc);}
function exportCsaf(){
  const rows=_vexRows(); if(!rows.length){alert('Run an analysis first.');return;}
  const p=_sbomProduct(); const pid=p.ref||'PRODUCT-1'; const now=_isoNow();
  const B2C={affected:'known_affected',not_affected:'known_not_affected',fixed:'fixed',under_investigation:'under_investigation'};
  const vulns=rows.map(r=>{
    const v={cve:r.cve,product_status:{}};v.product_status[B2C[r.status]]=[pid];
    const notes=[{category:'other',title:'ICS-VEXForge assessment',text:'status='+r.status+'; component='+r.component+(r.cvss!=null?('; cvss='+r.cvss):'')+(r.av?('; av='+r.av):'')}];
    if(r.status==='not_affected'){const j=r.justification&&VEX_JUST.some(x=>x[0]===r.justification)?r.justification:_ovJust(r.justification);v.flags=[{label:j,product_ids:[pid]}];if(r.action_statement)notes.push({category:'description',title:'Impact',text:r.action_statement});}
    else if(r.status==='affected'){v.remediations=[{category:_remedCsaf(r.remediation),details:(r.action_statement||('Apply '+(r.remediation||'patch_or_firmware_upgrade')+' for '+r.component)),product_ids:[pid]}];}
    else if(r.status==='fixed'){const bits=[];if(r.fixed_version)bits.push('Fixed version: '+r.fixed_version);if(r.patch_reference)bits.push('Patch reference: '+r.patch_reference);if(r.verification_result)bits.push('Verification: '+r.verification_result);if(bits.length)notes.push({category:'details',title:'Fix',text:bits.join(' | ')});if(r.fixed_version)v.remediations=[{category:'vendor_fix',details:'Fixed in '+r.fixed_version+(r.patch_reference?(' ('+r.patch_reference+')'):''),product_ids:[pid]}];}
    else {const bits=[];if(r.investigation_progress)bits.push('Progress: '+r.investigation_progress);if(r.missing_evidence)bits.push('Missing evidence: '+r.missing_evidence);if(r.planned_update)bits.push('Planned update: '+r.planned_update);if(bits.length)notes.push({category:'details',title:'Investigation',text:bits.join(' | ')});}
    if(r.estimation)notes.push({category:'other',title:'estimation',text:r.estimation});
    v.threats=[{category:'impact',details:'SSVC '+r.ssvc_decision+' | '+r.ssvc_vector,product_ids:[pid]}];
    v.notes=notes; return v;});
  const doc={document:{category:'csaf_vex',csaf_version:'2.0',title:'ICS-VEXForge VEX — '+p.name,
      publisher:{category:'vendor',name:'ICS-VEXForge (Chonnam SSRC)',namespace:'https://kakyung98.github.io/ics-vex-dashboard/'},
      tracking:{id:'ICSVEXFORGE-'+Date.now(),status:'final',version:'1',initial_release_date:now,current_release_date:now,
        revision_history:[{number:'1',date:now,summary:'Initial VEX generated by ICS-VEXForge.'}],generator:{engine:{name:'ICS-VEXForge',version:'2026.04'}}}},
    product_tree:{full_product_names:[Object.assign({product_id:pid,name:p.name},p.purl?{product_identification_helper:{purl:p.purl}}:{})]},
    vulnerabilities:vulns};
  _dl('csaf-vex-'+(p.name.replace(/[^a-z0-9]+/gi,'-').toLowerCase())+'.json',doc);}


function renderTreeList(cves){
  const un=(cves||[]).filter(f=>!f.source_collectable);
  const card=document.getElementById('vextree'); if(!card)return;
  if(!un.length){card.style.display='none';return;}
  card.style.display='';
  const cnt=document.getElementById('tree-count'); if(cnt)cnt.textContent='('+un.length+')';
  for(const f of un){if(!_treeState[f.cve])_treeState[f.cve]={av:f.av||'N',answers:{affected_range:true,source_check:false}};}
  document.getElementById('tree-list').innerHTML=un.map(f=>'<div class="treecve" id="tc-'+f.cve+'">'+renderCveTree(f.cve)+'</div>').join('');
}
function renderCveTree(cve){
  const s=_treeState[cve];const r=classifyTree(s.av,s.answers);
  let h='<div class="treecve-h"><a class="mono" href="https://nvd.nist.gov/vuln/detail/'+cve+'" target="_blank" rel="noopener" style="font-weight:700">'+esc(cve)+'</a> <span class="hint">AV:'+esc(s.av)+'</span>';
  if(r.complete){const st=r.status;const col=st==='not_affected'?'var(--safe)':(st==='under_investigation'?'var(--und)':'var(--accent)');
    h+=' <span class="badge" style="background:'+col+'22;color:'+col+'">'+esc(st)+'</span> <span class="mono hint">'+esc(r.justification||'')+'</span>'
     +'<button class="treebtn" style="margin-left:auto" onclick="treeReset(\\''+cve+'\\')">restart</button>';}
  h+='</div>';
  if(r.path.length>2){h+='<div class="treepath" style="margin-top:8px">';
    for(const p of r.path){if(p.node==='affected_range'||p.node==='source_check')continue;const ans=(p.answer===true)?'Yes':(p.answer===false)?'No':esc(p.answer);
      h+='<div class="treestep">'+esc(p.q)+' → <b>'+ans+'</b></div>';}
    h+='</div>';}
  if(!r.complete&&r.pending){h+='<div class="treeq"><div class="ct" style="font-size:15px;margin-bottom:8px">'+esc(r.question)+'</div>'
    +'<button class="primary" onclick="treeAnswerFor(\\''+cve+'\\',true)">Yes</button> <button onclick="treeAnswerFor(\\''+cve+'\\',false)">No</button></div>';}
  return h;
}
function _statLabel(st){return {affected:'affected',not_affected:'not_affected',under_investigation:'under investigation',fixed:'fixed'}[st]||st;}
function _statCol(st){return {affected:'var(--aff)',not_affected:'var(--safe)',under_investigation:'var(--und)',fixed:'var(--accent)'}[st]||'var(--ink3)';}
function refreshVexRow(cve){
  const auto=_autoStatus(cve); const ov=_vexFields[cve]||{}; const st=ov.status||auto.status;
  const vc=document.getElementById('vexcell-'+cve);
  if(vc){vc.innerHTML=_vexCellInner(cve);}
  const sc=document.getElementById('ssvccell-'+cve);
  if(sc){const ss=ssvcFor(cve);const sd=ssvcDecide(ss);sc.innerHTML='<span class="badge" title="'+ssvcVector(ss)+'" style="background:'+(SSVC_COL[sd]||'var(--ink3)')+'22;color:'+(SSVC_COL[sd]||'var(--ink3)')+'">'+sd+'</span>';}
}
function treeAnswerFor(cve,v){const s=_treeState[cve];const r=classifyTree(s.av,s.answers);if(r.pending)s.answers[r.pending]=v;document.getElementById('tc-'+cve).innerHTML=renderCveTree(cve);refreshVexRow(cve);}
function treeReset(cve){_treeState[cve]={av:_treeState[cve].av,answers:{affected_range:true,source_check:false}};document.getElementById('tc-'+cve).innerHTML=renderCveTree(cve);refreshVexRow(cve);}
function treeForCve(cve,av){const el=document.getElementById('tc-'+cve);if(el){el.scrollIntoView({behavior:'smooth',block:'center'});el.classList.add('tc-hi');setTimeout(()=>el.classList.remove('tc-hi'),1600);}}

// ---- Source data: ICS-CERT advisory + NVD CVE search ----
async function tryJson(urls){for(const u of urls){try{const r=await fetch(u);if(r.ok)return await r.json();}catch(e){}}return null;}
let ADV_LIST=[];
async function initSource(){
  await loadSbomIndex();
  const d=await tryJson(['/api/advisories/list','advisories_list.json']);
  ADV_LIST=(d&&d.advisories)||[];
  const hint=document.getElementById('adv-hint');if(hint)hint.textContent=ADV_LIST.length.toLocaleString()+' loaded';
  advSearch();
}
let _advPage=1;let _advQ=null;const ADV_PS=100;
function advPage(d){_advPage+=d;advSearch();document.getElementById('adv-results').scrollIntoView({block:'nearest'});}
function advSearch(){
  const q=(document.getElementById('adv-q').value||'').trim().toLowerCase();
  if(q!==_advQ){_advQ=q;_advPage=1;}
  let items=ADV_LIST;
  if(q)items=ADV_LIST.filter(a=>String(a.id).toLowerCase().includes(q)||(a.title||'').toLowerCase().includes(q)||(a.vendor||'').toLowerCase().includes(q)||String(a.year).includes(q)||(a.cves||[]).some(c=>String(c).toLowerCase().includes(q)));
  const total=items.length;const pages=Math.max(1,Math.ceil(total/ADV_PS));
  if(_advPage>pages)_advPage=pages;if(_advPage<1)_advPage=1;
  const start=(_advPage-1)*ADV_PS;items=items.slice(start,start+ADV_PS);
  let meta='<b>'+total.toLocaleString()+'</b> advisor'+(total===1?'y':'ies');
  if(total>ADV_PS)meta+=' · '+(start+1).toLocaleString()+'&ndash;'+(start+items.length).toLocaleString()
    +' <button class="treebtn" onclick="advPage(-1)"'+(_advPage<=1?' disabled':'')+'>&larr; Prev</button>'
    +' <span class="mono">'+_advPage+' / '+pages+'</span> '
    +'<button class="treebtn" onclick="advPage(1)"'+(_advPage>=pages?' disabled':'')+'>Next &rarr;</button>';
  let h='<div class="srch-meta">'+meta+'</div>';
  h+='<div class="srch-wrap"><table><thead><tr><th>Advisory</th><th>Title</th><th>Vendor</th><th style="text-align:center">Year</th><th style="text-align:center">CVEs</th></tr></thead><tbody>';
  for(const a of items){
    h+='<tr class="clk" onclick="openAdvisory(\\''+esc(String(a.id))+'\\')"><td class="idcell">'+esc(a.id)+'</td><td>'+esc(a.title||'')+'</td><td>'+esc(a.vendor||'')+'</td><td class="mono" style="text-align:center">'+esc(a.year||'')+'</td><td style="text-align:center"><span class="cvecount">'+((a.cves||[]).length)+'</span></td></tr>';}
  document.getElementById('adv-results').innerHTML=h+'</tbody></table></div>';
}
function cveSearchLocal(q){if(typeof CVE_INDEX==='undefined'||!CVE_INDEX.length)return [];const ql=q.toLowerCase();const rk={LIKELY_AFFECTED:3,UNDER_INVESTIGATION:2,LIKELY_NOT_AFFECTED:1};
  let h=CVE_INDEX.filter(r=>r.cve.toLowerCase().includes(ql)||(r.cwe||'').toLowerCase().includes(ql)||(r.vendors||[]).some(v=>v.toLowerCase().includes(ql))||(r.component||'').toLowerCase().includes(ql));
  h.sort((a,b)=>((b.kev?1:0)-(a.kev?1:0))||(rk[b.vex]-rk[a.vex])||a.cve.localeCompare(b.cve));
  return h.slice(0,100).map(r=>({cve:r.cve,cvss:r.cvss,severity:r.severity,cwe:r.cwe,kev:r.kev,vex:r.vex,vendor:(r.vendors||[]).slice(0,2).join(', '),component:r.component}));}
let _cveTimer=null;
function cveSearchGo(){clearTimeout(_cveTimer);_cveTimer=setTimeout(cveSearchRun,220);}
async function cveSearchRun(){
  const q=(document.getElementById('cve-q').value||'').trim();const out=document.getElementById('cve-results');
  const nvd=/^cve-\d{4}-\d+$/i.test(q)?'<div class="hint" style="margin-bottom:6px">Open on NVD: <a class="mono" href="https://nvd.nist.gov/vuln/detail/'+esc(q.toUpperCase())+'" target="_blank" rel="noopener">'+esc(q.toUpperCase())+'</a></div>':'';
  if(q.length<2){out.innerHTML=nvd||'<span class="hint">Type at least 2 characters…</span>';return;}
  let items=null;
  try{const r=await fetch('/api/cve_search?q='+encodeURIComponent(q));if(r.ok)items=(await r.json()).cves;}catch(e){}
  if(items===null)items=cveSearchLocal(q);
  let h=nvd+'<div class="srch-meta"><b>'+items.length+(items.length===100?'+':'')+'</b> CVEs</div>';
  h+='<div class="srch-wrap"><table><thead><tr><th>CVE</th><th style="text-align:center">CVSS</th><th>CWE</th><th style="text-align:center">KEV</th><th>Vendor</th><th>Component</th></tr></thead><tbody>';
  for(const f of items){h+='<tr><td class="idcell"><a href="https://nvd.nist.gov/vuln/detail/'+f.cve+'" target="_blank" rel="noopener">'+f.cve+'</a></td>'
    +'<td class="mono" style="text-align:center">'+cvssFmt(f.cvss,f.severity)+'</td><td class="mono hint">'+esc(f.cwe||'')+'</td>'
    +'<td class="mono" style="text-align:center">'+(f.kev?'KEV':'')+'</td><td>'+esc(f.vendor||'')+'</td><td class="hint">'+esc(f.component||'')+'</td></tr>';}
  out.innerHTML=h+'</tbody></table></div>';
}

if(document.getElementById('kpis'))stats();
if(document.getElementById('adv-kpis'))advisories();
if(document.getElementById('year'))yearChart();
if(document.getElementById('sa-kpis'))sourceAvail();
// ---- ICS-SBOM dataset + advisory<->SBOM cross-reference ----
let SBOM_INDEX=[], CVE2SBOM={};
let CVE2ADV={};
let VEND2SBOM={},VEND2ADV={};
let ADV2SBOM={};
function normVendor(v){var t=String(v||'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim().split(' ');return t[0]||'';}
var PROD_STOP={series:1,product:1,products:1,control:1,controller:1,controllers:1,system:1,systems:1,module:1,modules:1,software:1,firmware:1,server:1,servers:1,gateway:1,update:1,and:1,for:1,the:1,with:1,cpu:1,inc:1,corp:1,corporation:1,ltd:1,gmbh:1,energy:1,automation:1,electric:1,electronics:1,solutions:1,technologies:1,industrial:1,group:1,company:1,version:1,vulnerability:1,vulnerabilities:1};
function hasDigit(w){return /[0-9]/.test(w);}
function prodTokens(str){var out=[];String(str||'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim().split(' ').forEach(function(w){if(!w||PROD_STOP[w])return;if(hasDigit(w)&&w.length>=3)out.push(w);else if(w.length>=5&&!hasDigit(w))out.push(w);});return out;}
function prodHit(at,st){var ad=at.filter(hasDigit),sd=st.filter(hasDigit);for(var i=0;i<ad.length;i++)if(sd.indexOf(ad[i])>=0)return true;return false;}
function cvGrade(x){x=+x;if(x>=9)return 'Critical';if(x>=7)return 'High';if(x>=4)return 'Medium';if(x>0)return 'Low';return 'None';}
function cvCap(x){x=String(x||'');return x?x.charAt(0).toUpperCase()+x.slice(1):'';}
function cvssFmt(score,sev){if(score!=null&&score!==''&&!isNaN(+score)){var g=(sev&&sev!=='unrated')?cvCap(sev):cvGrade(score);return (+score)+' ('+g+')';}if(sev&&sev!=='unrated')return cvCap(sev);return '\u2014';}
function buildCve2Adv(){CVE2ADV={};VEND2ADV={};for(const a of (ADV_LIST||[])){const vk=normVendor(a.vendor);if(vk)(VEND2ADV[vk]=VEND2ADV[vk]||[]).push(a);for(const c of (a.cves||[])){(CVE2ADV[c]=CVE2ADV[c]||[]).push(a);}}}
async function loadAdvList(){if((ADV_LIST||[]).length){if(!Object.keys(CVE2ADV).length)buildCve2Adv();return;}const d=await tryJson(['/api/advisories/list','advisories_list.json']);ADV_LIST=(d&&d.advisories)||[];buildCve2Adv();}
function buildCve2Sbom(){CVE2SBOM={};ADV2SBOM={};for(const a of SBOM_INDEX){for(const c of (a.cves||[])){(CVE2SBOM[c.id]=CVE2SBOM[c.id]||[]).push(a);}for(const ad of (a.advisories||[])){(ADV2SBOM[ad]=ADV2SBOM[ad]||[]).push(a);}}}
async function loadSbomIndex(){if(SBOM_INDEX.length)return;const d=await tryJson(['/api/sbom_index','sbom_index.json']);SBOM_INDEX=(d&&d.assets)||[];buildCve2Sbom();}
async function initIcsSbom(){const el=document.getElementById('sbom-results');if(el)el.innerHTML='<span class="hint">loading…</span>';await loadSbomIndex();await loadAdvList();const h=document.getElementById('sbom-hint');if(h)h.textContent=SBOM_INDEX.length.toLocaleString()+' advisory-grounded SBOMs loaded';sbomSearch();}
let _sbomPage=1;let _sbomQ=null;const SBOM_PS=100;
function sbomPage(d){_sbomPage+=d;sbomSearch();document.getElementById('sbom-results').scrollIntoView({block:'nearest'});}
function sbomSearch(){const q=(document.getElementById('sbom-q').value||'').trim().toLowerCase();
  if(q!==_sbomQ){_sbomQ=q;_sbomPage=1;}
  let items=SBOM_INDEX;
  if(q)items=SBOM_INDEX.filter(a=>(a.vendor||'').toLowerCase().includes(q)||(a.product||'').toLowerCase().includes(q)||(a.base_platform||'').toLowerCase().includes(q)||(a.advisories||[]).some(x=>x.toLowerCase().includes(q))||(a.cves||[]).some(c=>c.id.toLowerCase().includes(q)));
  const total=items.length;const pages=Math.max(1,Math.ceil(total/SBOM_PS));
  if(_sbomPage>pages)_sbomPage=pages;if(_sbomPage<1)_sbomPage=1;
  const start=(_sbomPage-1)*SBOM_PS;items=items.slice(start,start+SBOM_PS);
  let meta='<b>'+total.toLocaleString()+'</b> SBOM'+(total===1?'':'s');
  if(total>SBOM_PS)meta+=' · '+(start+1).toLocaleString()+'&ndash;'+(start+items.length).toLocaleString()
    +' <button class="treebtn" onclick="sbomPage(-1)"'+(_sbomPage<=1?' disabled':'')+'>&larr; Prev</button>'
    +' <span class="mono">'+_sbomPage+' / '+pages+'</span> '
    +'<button class="treebtn" onclick="sbomPage(1)"'+(_sbomPage>=pages?' disabled':'')+'>Next &rarr;</button>';
  let h='<div class="srch-meta">'+meta+'</div>';
  h+='<div class="srch-wrap"><table><thead><tr><th>Vendor</th><th>Product</th><th>Advisory</th><th style="text-align:center">Comp</th><th style="text-align:center">CVEs</th></tr></thead><tbody>';
  for(const a of items){h+='<tr class="clk" onclick="openSbom(\\''+a.asset_id+'\\')"><td>'+esc(a.vendor||'')+'</td><td>'+esc(a.product||'')+'</td><td class="mono hint">'+(a.advisories||[]).join(', ')+'</td><td class="mono" style="text-align:center">'+a.component_count+'</td><td style="text-align:center"><span class="cvecount">'+(a.cves||[]).length+'</span></td></tr>';}
  document.getElementById('sbom-results').innerHTML=h+'</tbody></table></div>';}
let _curSbomFile='';
async function toggleSbomJson(){
  const pre=document.getElementById('sbomjson');const btn=document.getElementById('sbomjson-btn');if(!pre)return;
  if(pre.style.display!=='none'){pre.style.display='none';btn.innerHTML='&#128196; View CycloneDX JSON';return;}
  pre.style.display='block';btn.innerHTML='&#128196; Hide CycloneDX JSON';
  if(!pre.dataset.loaded){pre.textContent='loading…';
    try{const r=await fetch('reverse_sbom/'+encodeURIComponent(_curSbomFile));let t=await r.text();
      try{t=JSON.stringify(JSON.parse(t),null,2);}catch(e){}
      pre.textContent=t;pre.dataset.loaded='1';
    }catch(e){pre.textContent='failed to load '+_curSbomFile;}}
}
async function openSbom(id){await loadAdvList();const a=SBOM_INDEX.find(x=>x.asset_id===id);if(!a)return;
  document.getElementById('mtitle').textContent=(a.product||a.asset_id)+' — '+(a.vendor||'');
  _curSbomFile=a.file||'';
  const _btn='display:inline-block;padding:7px 14px;border-radius:8px;font-weight:600;cursor:pointer;border:1px solid var(--line);background:var(--accent);color:#04121b';
  let h='<div class="srch-meta">'+esc(a.vendor||'')+' · '+esc(a.base_platform||'')+' · <span class="mono">'+esc(a.file||'')+'</span></div>';
  h+='<div style="margin:10px 0 4px"><button id="sbomjson-btn" style="'+_btn+'" onclick="toggleSbomJson()">&#128196; View CycloneDX JSON</button></div>'
    +'<pre id="sbomjson" style="display:none;max-height:380px;overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;margin:0 0 4px;white-space:pre;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.5"></pre>';
  const src=(a.advisories||[]).map(x=>ADV_LIST.find(y=>String(y.id)===String(x))||{id:x});
  h+='<h4 style="margin:12px 0 4px">Source ICS-CERT advisories ('+src.length+')</h4>';
  if(src.length){h+='<div class="srch-wrap"><table><thead><tr><th>Advisory</th><th>Title</th><th style="text-align:center">Year</th></tr></thead><tbody>';
    for(const ad of src)h+='<tr class="clk" onclick="openAdvisory(\\''+ad.id+'\\')"><td class="idcell">'+esc(ad.id)+'</td><td>'+esc(ad.title||'')+'</td><td class="mono" style="text-align:center">'+esc(ad.year||'')+'</td></tr>';
    h+='</tbody></table></div>';}else h+='<span class="hint">none</span>';
  h+='<h4 style="margin:14px 0 4px">Components ('+(a.components||[]).length+')</h4><div class="srch-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Description</th></tr></thead><tbody>';
  for(const c of (a.components||[]))h+='<tr><td>'+esc(c.name||'')+'</td><td class="mono">'+esc(c.version||'')+'</td><td class="hint">'+esc(c.description||'')+'</td></tr>';
  h+='</tbody></table></div>';
  h+='<h4 style="margin:14px 0 4px">Identified CVEs ('+(a.cves||[]).length+')</h4>';
  if((a.cves||[]).length){h+='<div class="srch-wrap"><table><thead><tr><th>CVE</th><th>CVSS</th><th>CWE</th></tr></thead><tbody>';
    for(const c of a.cves)h+='<tr><td class="idcell"><a href="https://nvd.nist.gov/vuln/detail/'+c.id+'" target="_blank" rel="noopener">'+esc(c.id)+'</a></td><td class="mono">'+cvssFmt(c.cvss,c.severity)+'</td><td class="mono hint">'+esc(c.cwe||'')+'</td></tr>';
    h+='</tbody></table></div>';}else h+='<span class="hint">none</span>';
  document.getElementById('mbody').innerHTML=h;document.getElementById('ov').classList.add('on');}
async function openAdvisory(id){await loadSbomIndex();let a=ADV_LIST.find(x=>String(x.id)===String(id))||{id:id};
  const det=await tryJson(['/api/advisory/'+encodeURIComponent(id),'adv/'+id+'.json']);if(det)a=Object.assign({},a,det);
  const cves=a.cves||[];
  document.getElementById('mtitle').textContent=a.id+' — '+(a.title||'');
  let h='<div class="srch-meta">'+esc(a.vendor||'')+' · '+esc(a.year||'')+(a.url?' · <a href="'+esc(a.url)+'" target="_blank" rel="noopener">open advisory</a>':'')+'</div>';
  if(a.overview)h+='<h4 style="margin:12px 0 4px">Advisory content <span class="hint">(CISA ICS-CERT)</span></h4><div class="hint" style="white-space:pre-wrap;max-height:380px;overflow:auto;line-height:1.55">'+esc(a.overview)+'</div>';
  if(a.cwes&&a.cwes.length)h+='<div class="srch-meta" style="margin-top:8px">CWE: <span class="mono">'+a.cwes.map(esc).join(', ')+'</span></div>';
  const rel={};for(const s of (ADV2SBOM[a.id]||[]))rel[s.asset_id]={a:s,cves:[],exact:true};
  for(const c of cves){for(const s of (CVE2SBOM[c]||[])){if(!rel[s.asset_id])rel[s.asset_id]={a:s,cves:[],exact:false};rel[s.asset_id].cves.push(c);}}
  let relArr=Object.values(rel);relArr.sort((x,y)=>(y.exact?1:0)-(x.exact?1:0)||y.cves.length-x.cves.length);const relN=relArr.length;relArr=relArr.slice(0,150);
  h+='<h4 style="margin:12px 0 4px">Related ICS-SBOM assets ('+relN+')</h4>';
  if(relN){h+='<div class="srch-wrap"><table><thead><tr><th>Vendor</th><th>Product</th><th>Match</th></tr></thead><tbody>';
    for(const r of relArr)h+='<tr class="clk" onclick="openSbom(\\''+r.a.asset_id+'\\')"><td>'+esc(r.a.vendor||'')+'</td><td>'+esc(r.a.product||'')+'</td><td class="mono hint">'+(r.exact?'this advisory':(r.cves.length?esc(r.cves.join(', ')):''))+'</td></tr>';
    h+='</tbody></table></div>';}else h+='<span class="hint">No ICS-SBOM asset for this advisory.</span>';
  h+='<h4 style="margin:14px 0 4px">Advisory CVEs ('+cves.length+')</h4>';
  if(cves.length){h+='<div class="srch-wrap"><table><thead><tr><th>CVE</th><th style="text-align:center">In SBOM assets</th></tr></thead><tbody>';
    for(const c of cves){const n=(CVE2SBOM[c]||[]).length;h+='<tr><td class="idcell"><a href="https://nvd.nist.gov/vuln/detail/'+c+'" target="_blank" rel="noopener">'+esc(c)+'</a></td><td style="text-align:center">'+(n?'<span class="cvecount">'+n+'</span>':'—')+'</td></tr>';}
    h+='</tbody></table></div>';}else h+='<span class="hint">none</span>';
  document.getElementById('mbody').innerHTML=h;document.getElementById('ov').classList.add('on');}
if(document.getElementById('sbom-q'))initIcsSbom();

if(document.getElementById('adv-q'))initSource();
</script></body></html>"""

# ---- page content blocks (split across 3 pages) --------------------------
ANALYZER_HTML = """<div class="card"><div class="row">
  <div><label>CycloneDX SBOM (JSON) — paste, upload, or drag a .json file here</label><textarea id="sbom" placeholder='Drag a .json SBOM file here, or paste: {"components":[{"name":"OpenSSL","version":"1.1.1k"}]}'></textarea></div>
  <div><label>Deployment exposure</label><br><select id="exp">
    <option value="isolated-cell">Isolated cell</option><option value="control-network" selected>Control network</option>
    <option value="dmz-routable">DMZ routable</option><option value="remote-accessible">Remote accessible</option></select>
    <br><br><input type="file" id="file" accept=".json,application/json" style="display:none">
    <button class="primary" onclick="run()">Analyze ▶</button>
    <button onclick="document.getElementById('file').click()">Upload JSON</button>
    <button onclick="ex()">Example</button>
    <div id="fname" class="hint" style="margin-top:6px"></div></div>
</div><div id="out" style="margin-top:12px"></div></div>

<div class="card" id="cmp" style="display:none"><h3 style="margin:0 0 4px">CPE normalization &mdash; exact vs Ratcliff&ndash;Obershelp</h3>
<p class="hint" style="margin:0 0 8px">Each SBOM component is fuzzy-matched to a CPE with the Ratcliff&ndash;Obershelp similarity (Python difflib); CVEs are re-identified from the normalized CPE and compared to the exact-match CVEs.</p>
<div class="hint" style="margin:0 0 12px">Similarity threshold <input type="range" id="ro-th" min="0.3" max="1" step="0.05" value="0.7" style="vertical-align:middle;width:180px" oninput="document.getElementById('ro-thv').textContent=Number(this.value).toFixed(2);if(_lastSbom)compareNorm(_lastSbom,_lastExp)"> <b id="ro-thv" class="mono">0.70</b> &middot; components below it stay unmatched (closest CPE still shown)</div>
<div id="cmp-body"></div></div>"""

CORPUS_HTML = """<div class="card"><h3 style="margin:0 0 8px">Target CVE</h3><div id="kpis" class="kpis hint">loading…</div>
<p class="hint" style="margin-top:10px">Source collected (execution-verification ready): <span id="cand">…</span></p></div>

<div class="card"><h3 style="margin:0 0 4px">CISA ICS advisories <span class="hint">corpus source · 2010–2026</span></h3>
<div id="adv-kpis" class="kpis" style="margin-top:8px">loading…</div>
<div id="adv-year" style="margin-top:14px"></div>
<div id="adv-ven" style="margin-top:14px"></div></div>

<div class="card"><h3 style="margin:0 0 4px">CVEs by year <span class="hint">all 11,336 · by CVE-ID year</span></h3>
<div id="year" style="margin-top:12px">loading…</div></div>"""

COLLECTABLE_HTML = """<div class="card"><h3 style="margin:0 0 4px">Source Code Available CVEs</h3>
<p class="hint" style="margin:0 0 12px">CVEs whose OSS source can be collected — the pool eligible for execution-based verification (build &rarr; reproduce &rarr; run).</p>
<div id="sa-kpis" class="kpis">loading…</div>
<div id="sa-charts" style="margin-top:16px"></div>
<div class="satwo" style="margin-top:16px">
  <div id="sa-vendors"></div>
  <div id="sa-devtype"></div>
</div>
<div id="sa-cwe" style="margin-top:16px"></div></div>"""

TREE_HTML = """<div class="card" id="vextree" style="display:none">
<h3 style="margin:0 0 4px">VEX decision tree &mdash; source-uncollectable CVEs <span class="hint" id="tree-count"></span></h3>
<p class="hint" style="margin:0 0 12px">These CVEs' source cannot be obtained (closed firmware / no OSS code), so VEX is decided by the operational decision tree, branched by each CVE's CVSS attack vector. Answer each question Yes/No; every CVE is walked independently.</p>
<div id="tree-list"></div></div>"""

# Analyzer + VEX decision tree live on one page (one flow: SBOM -> source-available
# CVEs get VEX analysis; source-uncollectable CVEs continue into the decision tree).
_ANALYZER_PAGE = ('<h1 style="margin:0 0 2px">ICS-VEXForge</h1>'
                  '<p class="sub" style="margin:0 0 18px;white-space:nowrap;max-width:none;overflow-x:auto">Paste / upload / drag a CycloneDX SBOM. '
                  'Source-available CVEs get a code-grounded VEX; source-uncollectable CVEs stay under_investigation with an estimation and an SSVC priority.</p>' + ANALYZER_HTML)
SOURCE_HTML = """<div class="card">
<h3 style="margin:0 0 4px">ICS-CERT Advisories</h3>
<p class="hint" style="margin:0 0 10px">Search CISA ICS-CERT advisories by ID, title, vendor, CVE, or year. <span id="adv-hint"></span></p>
<input id="adv-q" class="srch" oninput="advSearch()" placeholder="e.g. Siemens · ICSA-24 · CVE-2023-… · 2024">
<div id="adv-results" style="margin-top:12px"><span class="hint">Loading advisories…</span></div></div>

<div class="card">
<h3 style="margin:0 0 4px">NVD CVE search</h3>
<p class="hint" style="margin:0 0 10px">Search the corpus CVEs by ID, CWE, vendor, or component — each result links to its NVD detail page.</p>
<input id="cve-q" class="srch" oninput="cveSearchGo()" placeholder="e.g. CVE-2021-44228 · CWE-416 · OpenSSL · Siemens">
<div id="cve-results" style="margin-top:12px"></div></div>"""

_ICSSBOM_PAGE = """<h1 style="margin:0 0 8px">Synthetic SBOM dataset</h1>
<p class="hint" style="margin:0 0 16px">CycloneDX SBOMs reverse-built per ICS device from the CISA ICS-CERT corpus — each keyed to its source advisory. Search by vendor, product, advisory ID, or CVE. Click a row to see its source advisories, components, and identified CVEs.</p>
<div class="card">
<h3 style="margin:0 0 4px">ICS-SBOM assets <span class="hint" id="sbom-hint"></span></h3>
<p class="hint" style="margin:0 0 10px">Synthetic asset inventory reverse-built from the CISA ICS-CERT corpus; components and versions reference real OSS but hashes, serials and contacts are placeholders.</p>
<input id="sbom-q" class="srch" oninput="sbomSearch()" placeholder="e.g. Siemens · SIMATIC · icsa-24 · CVE-2022-0778">
<div id="sbom-results" style="margin-top:12px"><span class="hint">loading…</span></div></div>
"""

_VEXMETHOD_PAGE = """<h1 style="margin:0 0 8px">VEX Analysis Method</h1>
<p class="hint" style="margin:0 0 18px">How ICS-VEXForge decides each component-CVE. The path splits on one question — <b>can the vulnerable source code be obtained?</b> Source-available CVEs are confirmed by <b>execution</b>: the affected version is rebuilt and a reproducer is run against it, yielding an <b>execution-verified</b> verdict. Source-uncollectable CVEs are held as <b>under_investigation</b> with an <b>estimation</b> and ranked by an <b>SSVC</b> priority.</p>

<div class="card">
<div class="vm-flow">
  <div class="vm-box vm-in">CycloneDX SBOM<span class="vm-sub">paste / upload / drag</span></div>
  <div class="vm-arrow">&darr;</div>
  <div class="vm-box">Component &harr; CVE identification<span class="vm-sub">CPE/purl &rarr; KB match (Ratcliff&ndash;Obershelp) + embedded VDR</span></div>
  <div class="vm-arrow">&darr;</div>
  <div class="vm-box vm-dec">Can the vulnerable source code be obtained?</div>

  <div class="vm-split">
    <div class="vm-lane vm-yes">
      <div class="vm-laneh">YES &middot; source-available &rarr; <b>Execution-verified VEX</b></div>
      <div class="vm-step"><b>1. Resolve upstream</b> — map the component to its repo + vulnerable commit/version (CVE/NVD refs)</div>
      <div class="vm-mini">&darr;</div>
      <div class="vm-step"><b>2. Rebuild the environment</b> — clone at the vulnerable version, resolve prerequisites, compile in an isolated sandbox (build critic loop)</div>
      <div class="vm-mini">&darr;</div>
      <div class="vm-step"><b>3. Synthesize a reproducer</b> — craft an input/PoC that drives the vulnerable path (CWE + patch-diff guided)</div>
      <div class="vm-mini">&darr;</div>
      <div class="vm-step"><b>4. Execute &amp; verify</b> — run it in the sandbox; a crash / sanitizer / assert confirms the trigger (verifier critic)</div>
      <div class="vm-mini">&darr;</div>
      <div class="vm-verd vm-vgreen">Evidence tier: <b>execution-verified</b> (reproducer triggers on the vulnerable build) / <b>build-only</b> if the trigger isn't reached</div>
    </div>

    <div class="vm-lane vm-no">
      <div class="vm-laneh">NO &middot; source-uncollectable &rarr; <b>under_investigation + SSVC</b></div>
      <div class="vm-step"><b>1. Status is forced to</b> <span class="mono">under_investigation</span><span class="vm-sub">no code &rarr; no defensible not_affected/affected</span></div>
      <div class="vm-mini">&darr;</div>
      <div class="vm-step"><b>2. Estimation sub-field</b>: <span class="mono">likely_affected</span> &middot; <span class="mono">likely_not_affected</span> &middot; <span class="mono">likely_fixed</span> &middot; <span class="mono">unable_to_determine</span></div>
      <div class="vm-mini">&darr;</div>
      <div class="vm-step"><b>3. SSVC (SEI Deployer)</b> priority<span class="vm-sub">Exploitation (KEV/EPSS) &times; System&nbsp;Exposure &times; Automatable (AV) &times; Human&nbsp;Impact</span></div>
      <div class="vm-mini">&darr;</div>
      <div class="vm-verd vm-vamber">Held: <b>under_investigation</b> + estimation &middot; SSVC: <span class="mono">defer / scheduled / out-of-cycle / immediate</span></div>
    </div>
  </div>

  <div class="vm-arrow">&darr;</div>
  <div class="vm-box vm-out">VEX status + justification<span class="vm-sub">export &rarr; OpenVEX v0.2.0 &middot; CSAF 2.0 (csaf_vex)</span></div>
</div>
</div>

<div class="vm-cols">
  <div class="card">
    <h3 style="margin:0 0 6px">Source-available path (execution-based verification)</h3>
    <p class="hint" style="margin:0 0 8px">When the vulnerable source is obtainable, the verdict is <b>confirmed by execution</b> — the affected version is actually built and a reproducer is run against it. This is the strongest VEX evidence, not metadata inference.</p>
    <ul class="vm-list">
      <li>A <b>multi-agent developer&rarr;critic loop</b> runs fully locally (Ollama, $0): a builder rebuilds the environment, an exploiter writes a reproducer, a verifier confirms the trigger — each stage gated by a critic that must accept the evidence before proceeding.</li>
      <li><b>Environment reconstruction</b>: clone the upstream repo at the vulnerable commit/version, resolve build prerequisites, and compile inside an isolated Docker sandbox.</li>
      <li><b>Reproducer synthesis</b>: build an input/PoC that drives the vulnerable code path, guided by the CVE description, CWE, and patch diff.</li>
      <li><b>Execution &amp; verification</b>: run the reproducer in the sandbox — an observed crash / sanitizer report / assert confirms the vulnerability is reachable and exploitable &rarr; <span class="mono">affected</span> (execution-verified). Running it against the patched build that no longer triggers &rarr; <span class="mono">fixed</span>/<span class="mono">not_affected</span> (execution-verified).</li>
      <li>Confirmed tier = <b>execution-verified</b>; if the environment builds but the trigger isn't reached within budget it falls back to <b>build-only</b> &rarr; <span class="mono">under_investigation</span>.</li>
    </ul>
  </div>
  <div class="card">
    <h3 style="margin:0 0 6px">Source-uncollectable path (under_investigation + SSVC)</h3>
    <p class="hint" style="margin:0 0 8px">Closed vendor firmware has no obtainable source, so no code-grounded verdict is defensible. The status is held at <span class="mono">under_investigation</span>; the reader is still given a best-effort <b>estimation</b> and an operational <b>SSVC priority</b>.</p>
    <ul class="vm-list">
      <li>Status is always <span class="mono">under_investigation</span> &mdash; a not_affected/affected claim would be unsupported without code.</li>
      <li><b>estimation</b> sub-field records the leaning: <span class="mono">likely_affected</span>, <span class="mono">likely_not_affected</span>, <span class="mono">likely_fixed</span>, or <span class="mono">unable_to_determine</span>. It is carried into the exported OpenVEX/CSAF document.</li>
      <li><b>SSVC</b> (SEI <i>Deployer</i> tree) ranks remediation urgency from <b>Exploitation</b> (KEV/EPSS), <b>System Exposure</b> (from the deployment exposure selector), <b>Automatable</b> (CVSS attack vector), and <b>Human Impact</b> &rarr; <span class="mono">defer / scheduled / out-of-cycle / immediate</span>.</li>
      <li>If the source later becomes obtainable, the case is routed into the execution-based verification path for a confirmed verdict.</li>
    </ul>
  </div>
</div>
<p class="hint" style="margin:14px 2px 0">Note: SBOM/AAS describe the asset's static composition; the operational inputs above (exposure, exploitation, automatability, human impact) are supplied separately &mdash; that is what turns identification into a VEX decision and an SSVC priority.</p>
"""

PAGES = {
    "analyzer": ("SBOM → VEX Analyzer", _ANALYZER_PAGE),
    "vex-method": ("VEX Analysis Method", _VEXMETHOD_PAGE),
    "source": ("ICS-CERT Advisories",
               '<h1 style="margin:0 0 18px">ICS-CERT Advisories</h1>' + SOURCE_HTML),
    "corpus": ("Corpus statistics",
               '<h1 style="margin:0 0 18px">Corpus statistics</h1>' + CORPUS_HTML),
    "collectable": ("Source Code Available CVEs",
                    '<h1 style="margin:0 0 18px">Source Code Available CVEs</h1>' + COLLECTABLE_HTML),
    "ics-sbom": ("Synthetic SBOM dataset", _ICSSBOM_PAGE),
}
_NAV = [("analyzer", "index.html", "ICS-VEXForge Analyzer"),
        ("vex-method", "vex-method.html", "VEX Analysis Method"),
        ("corpus", "corpus.html", "ICS Advisories-based CVE Corpus"),
        ("collectable", "collectable.html", "Source Code Available CVEs"),
        ("source", "source.html", "ICS-CERT Advisories"),
        ("ics-sbom", "ics-sbom.html", "Synthetic SBOM")]


def nav_html(active):
    tabs = "".join(
        f'<a class="navtab{" on" if key == active else ""}" href="{href}">{label}</a>'
        for key, href, label in _NAV)
    return f'<nav class="nav"><div class="navlabel">Menu</div>{tabs}</nav>'


def make_page(active):
    _sub, content = PAGES[active]
    return (FRONTEND_TEMPLATE
            .replace("__VEX_TREE__", json.dumps(VT.TREE, ensure_ascii=False))
            .replace("__NAV__", nav_html(active))
            .replace("__CONTENT__", content))


app = build_app()


def _lan_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8100)
    # 0.0.0.0 = reachable from other computers on the LAN (use --host 127.0.0.1
    # to restrict to this machine only).
    ap.add_argument("--host", default="0.0.0.0")
    a = ap.parse_args()
    import uvicorn
    print(f"ICS-VEXForge API - this machine: http://localhost:{a.port}", flush=True)
    if a.host == "0.0.0.0":
        print(f"  other computers on your network: http://{_lan_ip()}:{a.port}", flush=True)
        print(f"  (allow inbound TCP {a.port} in Windows Firewall the first time)", flush=True)
    print(f"  REST docs: /docs", flush=True)
    uvicorn.run(app, host=a.host, port=a.port, log_level="info")


if __name__ == "__main__":
    main()
