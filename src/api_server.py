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
import os, sys, json, argparse, difflib, csv
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


def _norm_vendor(v):
    """Merge whitespace/zero-width duplicates (e.g. '\\u200bSiemens' -> 'Siemens')."""
    return (v or "").replace("​", "").strip().strip(",").strip() or "Unknown"


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
        self.candidates = _load(os.path.join(RESULTS, "genie_candidates.json"),
                                {"candidates": []})
        self.code_ev = _load(os.path.join(DATA, "code_evidence.json"), {})
        # CISA ICS advisories (the corpus provenance)
        adv_raw = _load(os.path.join(DATA, "cisa_advisories.json"), {})
        adv = list(adv_raw.values()) if isinstance(adv_raw, dict) else (adv_raw or [])
        adv_yr = Counter(str(a.get("year")) for a in adv if a.get("year"))
        adv_ven = Counter(a.get("vendor") for a in adv if a.get("vendor"))
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
        # CVE -> max CVSS v3 base score (from findings.csv); enrich KB versions
        self.cvss = {}
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
        # tier-A = OSS-attributed, source-code collectable (the "132")
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
            "code_collected": sum(1 for w in a_worst.values() if w.get("has_code_pair")),
            "pending_collection": sum(1 for w in a_worst.values() if not w.get("has_code_pair")),
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
        """Stats for the source-code-collectable (tier-A) CVEs — the '132'."""
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

    @app.get("/corpus.html", response_class=HTMLResponse)
    def corpus():
        return make_page("corpus")

    @app.get("/collectable.html", response_class=HTMLResponse)
    def collectable():
        return make_page("collectable")

    @app.get("/source.html", response_class=HTMLResponse)
    def source():
        return make_page("source")

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
.layout{display:grid;grid-template-columns:236px minmax(0,1fr);max-width:1720px;margin:0 auto;min-height:100vh}
.side{border-right:1px solid var(--line);padding:22px 16px;position:sticky;top:0;align-self:start;height:100vh;overflow:auto}
.main{padding:28px clamp(18px,3vw,48px) 64px;min-width:0}
.side-brand{display:flex;justify-content:center;margin:4px 0 6px}
.side-brand .ssrc{width:84px;height:84px}
@media(max-width:860px){.layout{grid-template-columns:1fr}.side{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line)}}
.eyebrow{font-family:var(--mono);font-size:13px;letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}
h1{margin:.2em 0;font-size:clamp(30px,3.6vw,44px)}.sub{color:var(--ink2);max-width:80ch;font-size:16px}
h3{font-size:18px}.hint{font-size:13px}
.nav{display:flex;flex-direction:column;gap:3px;margin-top:20px}
.nav .navlabel{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink3);font-weight:700;margin:14px 8px 4px}
.navtab{font-size:15px;font-weight:600;text-decoration:none;color:var(--ink2);padding:10px 14px;border-radius:9px;border:1px solid transparent}
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
.srch{width:100%;background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:9px;padding:11px 14px;font-size:15px}
.srch:focus{outline:none;border-color:var(--accent)}
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
.clk{cursor:pointer}.clk:hover{opacity:.8}
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
</style></head><body><div class="layout">
<aside class="side">
  <div class="side-brand"><svg class="ssrc" viewBox="0 0 120 120"><circle cx="60" cy="60" r="55" fill="none" stroke="#37b24d" stroke-width="3"/><circle cx="60" cy="60" r="47" fill="none" stroke="#37b24d" stroke-width="1.5"/><text x="60" y="52" text-anchor="middle" font-weight="800" font-size="30" fill="#37b24d" font-family="Arial,sans-serif">SSRC</text><text x="60" y="72" text-anchor="middle" font-size="9" letter-spacing="1.5" fill="#37b24d" font-weight="700">SYSTEM SECURITY</text><text x="60" y="87" text-anchor="middle" font-size="8" letter-spacing="1" fill="#69db7c" font-weight="600">★ EST. 2000 ★</text></svg></div>
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
async function run(){
  const o=document.getElementById('out');o.innerHTML='<span class="hint">analyzing…</span>';
  let sbom;try{sbom=JSON.parse(document.getElementById('sbom').value)}catch(e){o.innerHTML='<span class="err">invalid JSON</span>';return}
  _treeState={};   // fresh decision trees for this SBOM
  compareNorm(sbom,document.getElementById('exp').value);
  const r=await fetch('/api/vex',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({sbom,exposure:document.getElementById('exp').value})});
  if(!r.ok){o.innerHTML='<span class="err">error '+r.status+'</span>';return}
  const d=await r.json();
  if(!d.cves_matched){o.innerHTML='<span class="hint">'+d.components+' components, no known CVEs matched.</span>';return}
  const bv=d.summary.by_vex||{};
  let h='<div class="hint">'+d.components+' components · <b>'+d.cves_matched+' CVEs</b> · '
    +'affected '+(bv.LIKELY_AFFECTED||0)+' · not affected '+(bv.LIKELY_NOT_AFFECTED||0)+' · under inv '+(bv.UNDER_INVESTIGATION||0)+'</div>';
  h+='<table><thead><tr><th>CVE</th><th>VEX</th><th>Component</th><th>CVSS</th><th>KEV</th><th>AV</th><th>Reach</th><th>Source / next step</th></tr></thead><tbody>';
  for(const f of d.cves){const c=C[f.final_vex]||'var(--ink3)';
    const nextcol = f.source_collectable
      ? '<span class="hint">source available &middot; code VEX</span>'
      : '<button class="treebtn" onclick="treeForCve(\\''+f.cve+'\\',\\''+(f.av||'N')+'\\')">Decide via tree &rarr;</button>';
    h+='<tr><td class="mono">'+f.cve+'</td>'
      +'<td><span class="badge" style="background:'+c+'22;color:'+c+'">'+L[f.final_vex]+'</span></td>'
      +'<td>'+f.component+' '+f.version+'</td><td class="mono" title="CVSS v3 base score">'+(f.cvss!=null?f.cvss:(f.severity||'—'))+'</td>'
      +'<td class="mono">'+(f.kev?'KEV':'')+'</td><td class="mono">'+f.av+'</td>'
      +'<td class="mono hint">'+f.reachability+'</td><td>'+nextcol+'</td></tr>';}
  o.innerHTML=h+'</tbody></table>';
  renderTreeList(d.cves);
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
    try{JSON.parse(rd.result);}catch(err){fn.innerHTML='<span class="err">'+f.name+' is not valid JSON</span>';return;}
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
    const cand=await(await fetch('/api/candidates?status=ready')).json();
    document.getElementById('cand').textContent=cand.count+' ready';
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
    let h='<div class="hint" style="margin-bottom:8px"><b>'+d.count+'</b> CVEs</div>'+
      '<div style="overflow:auto"><table><thead><tr><th>CVE</th><th>VEX</th><th>CVSS</th><th>KEV</th><th>Reach</th><th>Vendor</th><th>Component</th><th>Code</th></tr></thead><tbody>';
    for(const f of d.cves){const c=C[f.vex]||'var(--ink3)';
      h+='<tr><td class="mono"><a href="https://nvd.nist.gov/vuln/detail/'+f.cve+'" target="_blank" rel="noopener">'+f.cve+'</a></td>'
        +'<td><span class="badge" style="background:'+c+'22;color:'+c+'">'+(L[f.vex]||f.vex)+'</span></td>'
        +'<td class="mono" title="CVSS v3 base score">'+(f.cvss!=null?f.cvss:(f.severity?esc(f.severity):'—'))+'</td><td class="mono">'+(f.kev?'KEV':'')+'</td><td class="mono hint">'+esc(f.reachability)+'</td>'
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
    let cwe='<div class="ct">CWE types <span class="hint">click to list CVEs · 132 collectable CVEs total</span></div><div class="cwe">';
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
function treeAnswerFor(cve,v){const s=_treeState[cve];const r=classifyTree(s.av,s.answers);if(r.pending)s.answers[r.pending]=v;document.getElementById('tc-'+cve).innerHTML=renderCveTree(cve);}
function treeReset(cve){_treeState[cve]={av:_treeState[cve].av,answers:{affected_range:true,source_check:false}};document.getElementById('tc-'+cve).innerHTML=renderCveTree(cve);}
function treeForCve(cve,av){const el=document.getElementById('tc-'+cve);if(el){el.scrollIntoView({behavior:'smooth',block:'center'});el.classList.add('tc-hi');setTimeout(()=>el.classList.remove('tc-hi'),1600);}}

// ---- Source data: ICS-CERT advisory + NVD CVE search ----
async function tryJson(urls){for(const u of urls){try{const r=await fetch(u);if(r.ok)return await r.json();}catch(e){}}return null;}
let ADV_LIST=[];
async function initSource(){
  const d=await tryJson(['/api/advisories/list','advisories_list.json']);
  ADV_LIST=(d&&d.advisories)||[];
  const hint=document.getElementById('adv-hint');if(hint)hint.textContent=ADV_LIST.length.toLocaleString()+' loaded';
  advSearch();
}
function advSearch(){
  const q=(document.getElementById('adv-q').value||'').trim().toLowerCase();
  let items=ADV_LIST;
  if(q)items=ADV_LIST.filter(a=>String(a.id).toLowerCase().includes(q)||(a.title||'').toLowerCase().includes(q)||(a.vendor||'').toLowerCase().includes(q)||String(a.year).includes(q)||(a.cves||[]).some(c=>String(c).toLowerCase().includes(q)));
  const total=items.length;items=items.slice(0,100);
  let h='<div class="hint" style="margin-bottom:6px">'+total.toLocaleString()+' match'+(total===1?'':'es')+(total>100?' (showing 100)':'')+'</div>';
  h+='<div style="overflow:auto"><table><thead><tr><th>Advisory</th><th>Title</th><th>Vendor</th><th>Year</th><th>CVEs</th></tr></thead><tbody>';
  for(const a of items){const idl=a.url?'<a href="'+esc(a.url)+'" target="_blank" rel="noopener">'+esc(a.id)+'</a>':esc(a.id);
    h+='<tr><td class="mono">'+idl+'</td><td>'+esc(a.title||'')+'</td><td>'+esc(a.vendor||'')+'</td><td class="mono">'+esc(a.year||'')+'</td><td class="mono">'+((a.cves||[]).length)+'</td></tr>';}
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
  let h=nvd+'<div class="hint" style="margin-bottom:6px">'+items.length+(items.length===100?'+':'')+' CVEs</div>';
  h+='<div style="overflow:auto"><table><thead><tr><th>CVE</th><th>CVSS</th><th>CWE</th><th>KEV</th><th>Vendor</th><th>Component</th></tr></thead><tbody>';
  for(const f of items){h+='<tr><td class="mono"><a href="https://nvd.nist.gov/vuln/detail/'+f.cve+'" target="_blank" rel="noopener">'+f.cve+'</a></td>'
    +'<td class="mono">'+(f.cvss!=null?f.cvss:(f.severity||'—'))+'</td><td class="mono hint">'+esc(f.cwe||'')+'</td>'
    +'<td class="mono">'+(f.kev?'KEV':'')+'</td><td>'+esc(f.vendor||'')+'</td><td class="hint">'+esc(f.component||'')+'</td></tr>';}
  out.innerHTML=h+'</tbody></table></div>';
}

if(document.getElementById('kpis'))stats();
if(document.getElementById('adv-kpis'))advisories();
if(document.getElementById('year'))yearChart();
if(document.getElementById('sa-kpis'))sourceAvail();
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
<p class="hint" style="margin-top:10px">Reproduction candidates: <span id="cand">…</span> ready (code collected)</p></div>

<div class="card"><h3 style="margin:0 0 4px">CISA ICS advisories <span class="hint">corpus source · 2010–2026</span></h3>
<div id="adv-kpis" class="kpis" style="margin-top:8px">loading…</div>
<div id="adv-year" style="margin-top:14px"></div>
<div id="adv-ven" style="margin-top:14px"></div></div>

<div class="card"><h3 style="margin:0 0 4px">CVEs by year <span class="hint">all 11,336 · by CVE-ID year</span></h3>
<div id="year" style="margin-top:12px">loading…</div></div>"""

COLLECTABLE_HTML = """<div class="card"><h3 style="margin:0 0 4px">Source-code collectable CVEs</h3>
<p class="hint" style="margin:0 0 12px">CVEs whose OSS source can be collected — the pool eligible for CodeBERT diff and execution reproduction.</p>
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
                  '<p class="sub" style="margin:0 0 18px">Paste / upload / drag a CycloneDX SBOM. '
                  'Source-available CVEs are judged directly; source-uncollectable CVEs continue into '
                  'the decision tree below.</p>' + ANALYZER_HTML + "\n" + TREE_HTML)
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

PAGES = {
    "analyzer": ("SBOM → VEX Analyzer", _ANALYZER_PAGE),
    "source": ("Source data",
               '<h1 style="margin:0 0 18px">Source data</h1>' + SOURCE_HTML),
    "corpus": ("Corpus statistics",
               '<h1 style="margin:0 0 18px">Corpus statistics</h1>' + CORPUS_HTML),
    "collectable": ("Source-collectable CVEs",
                    '<h1 style="margin:0 0 18px">Source-collectable CVEs</h1>' + COLLECTABLE_HTML),
}
_NAV = [("analyzer", "index.html", "Analyzer"),
        ("source", "source.html", "Source data"),
        ("corpus", "corpus.html", "Corpus"),
        ("collectable", "collectable.html", "Collectable CVEs")]


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
