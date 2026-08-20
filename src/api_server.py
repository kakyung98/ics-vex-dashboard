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
import os, sys, json, argparse
from collections import defaultdict, Counter

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))
import build_ground_truth as G  # reachability(), exposure_for(), CWE_NAME

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

    @app.post("/api/refresh")
    def refresh():
        STORE.refresh()
        return {"ok": True, "reloaded": True}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return FRONTEND

    return app


# ---------------------------------------------------------------------------
# frontend (single page, calls the API above)
# ---------------------------------------------------------------------------
FRONTEND = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ICS-VEX API console</title>
<style>
:root{--bg:#0b1116;--card:#111a20;--card2:#16222a;--ink:#e6edf2;--ink2:#93a3ad;--ink3:#657580;
--line:#25333c;--accent:#38ccd9;--aff:#e5675c;--safe:#43be7c;--und:#e0b24c;
--mono:ui-monospace,Consolas,monospace;--sans:system-ui,Segoe UI,Roboto,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:18px}
.wrap{max-width:1560px;margin:0 auto;padding:34px clamp(20px,4vw,56px) 72px}
.eyebrow{font-family:var(--mono);font-size:13px;letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}
h1{margin:.2em 0;font-size:clamp(30px,3.6vw,44px)}.sub{color:var(--ink2);max-width:80ch;font-size:16px}
h3{font-size:18px}.hint{font-size:13px}
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
.btxt .bk{font-size:24px;font-weight:800;color:#ffffff;letter-spacing:.5px;line-height:1.15}
.btxt .be{font-size:14px;font-weight:600;color:#c8d3da;letter-spacing:.4px}
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
</style></head><body><div class="wrap">
<div class="eyebrow" style="color:#37b24d">System Security Research Center</div>
<h1>ICS-VEXForge</h1>

<div class="card"><div class="row">
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

<div class="card"><h3 style="margin:0 0 8px">Target CVE</h3><div id="kpis" class="kpis hint">loading…</div>
<p class="hint" style="margin-top:10px">Reproduction candidates: <span id="cand">…</span> · full view:
<a href="https://kakyung98.github.io/ics-vex-dashboard/pipeline.html" target="_blank">pipeline.html</a></p></div>

<div class="card"><h3 style="margin:0 0 4px">CISA ICS advisories <span class="hint">corpus source · 2010–2026</span></h3>
<div id="adv-kpis" class="kpis" style="margin-top:8px">loading…</div>
<div id="adv-year" style="margin-top:14px"></div>
<div id="adv-ven" style="margin-top:14px"></div></div>

<div class="card"><h3 style="margin:0 0 4px">CVEs by year <span class="hint">all 11,336 · by CVE-ID year</span></h3>
<div id="year" style="margin-top:12px">loading…</div></div>

<div class="card"><h3 style="margin:0 0 4px">Source-code collectable CVEs</h3>
<p class="hint" style="margin:0 0 12px">CVEs whose OSS source can be collected — the pool eligible for CodeBERT diff and execution reproduction.</p>
<div id="sa-kpis" class="kpis">loading…</div>
<div id="sa-charts" style="margin-top:16px"></div>
<div class="satwo" style="margin-top:16px">
  <div id="sa-vendors"></div>
  <div id="sa-devtype"></div>
</div>
<div id="sa-cwe" style="margin-top:16px"></div></div>

<div class="foot"><div class="brand brand-sm"><svg class="ssrc" viewBox="0 0 120 120"><circle cx="60" cy="60" r="55" fill="none" stroke="#37b24d" stroke-width="3"/><circle cx="60" cy="60" r="47" fill="none" stroke="#37b24d" stroke-width="1.5"/><text x="60" y="55" text-anchor="middle" font-weight="800" font-size="31" fill="#37b24d" font-family="Arial,sans-serif">SSRC</text><text x="60" y="74" text-anchor="middle" font-size="9" letter-spacing="1.5" fill="#37b24d" font-weight="700">SYSTEM SECURITY</text><text x="60" y="89" text-anchor="middle" font-size="8" letter-spacing="1" fill="#69db7c" font-weight="600">★ EST. 2000 ★</text></svg><div class="btxt"><div class="bk">시스템보안연구센터</div><div class="be">System Security Research Center</div></div></div>
<div class="cright">© 2026 System Security Research Center, Chonnam National University. All rights reserved.</div></div>

<div class="ov" id="ov" onclick="if(event.target===this)closeCves()"><div class="modal">
  <div class="mh"><h3 id="mtitle">Related CVEs</h3><button class="xbtn" onclick="closeCves()">✕ Close</button></div>
  <div id="mbody" class="hint">loading…</div>
</div></div>

<script>
const C={LIKELY_AFFECTED:'var(--aff)',LIKELY_NOT_AFFECTED:'var(--safe)',UNDER_INVESTIGATION:'var(--und)'};
const L={LIKELY_AFFECTED:'Affected',LIKELY_NOT_AFFECTED:'Not affected',UNDER_INVESTIGATION:'Under investigation'};
async function run(){
  const o=document.getElementById('out');o.innerHTML='<span class="hint">analyzing…</span>';
  let sbom;try{sbom=JSON.parse(document.getElementById('sbom').value)}catch(e){o.innerHTML='<span class="err">invalid JSON</span>';return}
  const r=await fetch('/api/vex',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({sbom,exposure:document.getElementById('exp').value})});
  if(!r.ok){o.innerHTML='<span class="err">error '+r.status+'</span>';return}
  const d=await r.json();
  if(!d.cves_matched){o.innerHTML='<span class="hint">'+d.components+' components, no known CVEs matched.</span>';return}
  const bv=d.summary.by_vex||{};
  let h='<div class="hint">'+d.components+' components · <b>'+d.cves_matched+' CVEs</b> · '
    +'affected '+(bv.LIKELY_AFFECTED||0)+' · not affected '+(bv.LIKELY_NOT_AFFECTED||0)+' · under inv '+(bv.UNDER_INVESTIGATION||0)+'</div>';
  h+='<table><thead><tr><th>CVE</th><th>VEX</th><th>Component</th><th>Sev</th><th>KEV</th><th>AV</th><th>Reach</th></tr></thead><tbody>';
  for(const f of d.cves){const c=C[f.final_vex]||'var(--ink3)';
    h+='<tr><td class="mono">'+f.cve+'</td>'
      +'<td><span class="badge" style="background:'+c+'22;color:'+c+'">'+L[f.final_vex]+'</span></td>'
      +'<td>'+f.component+' '+f.version+'</td><td>'+(f.severity||'—')+'</td>'
      +'<td class="mono">'+(f.kev?'KEV':'')+'</td><td class="mono">'+f.av+'</td>'
      +'<td class="mono hint">'+f.reachability+'</td></tr>';}
  o.innerHTML=h+'</tbody></table>';
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
document.getElementById('file').addEventListener('change',function(e){loadFile(e.target.files[0]);e.target.value='';});
// drag & drop a .json SBOM anywhere on the input textarea
const _ta=document.getElementById('sbom');
['dragenter','dragover'].forEach(ev=>_ta.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();_ta.classList.add('dragover');}));
['dragleave','dragend'].forEach(ev=>_ta.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();_ta.classList.remove('dragover');}));
_ta.addEventListener('drop',e=>{e.preventDefault();e.stopPropagation();_ta.classList.remove('dragover');
  const f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0];if(f)loadFile(f);});
// stop the browser from opening a file dropped outside the textarea
window.addEventListener('dragover',e=>e.preventDefault());
window.addEventListener('drop',e=>e.preventDefault());
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
      '<div style="overflow:auto"><table><thead><tr><th>CVE</th><th>VEX</th><th>Sev</th><th>KEV</th><th>Reach</th><th>Vendor</th><th>Component</th><th>Code</th></tr></thead><tbody>';
    for(const f of d.cves){const c=C[f.vex]||'var(--ink3)';
      h+='<tr><td class="mono"><a href="https://nvd.nist.gov/vuln/detail/'+f.cve+'" target="_blank" rel="noopener">'+f.cve+'</a></td>'
        +'<td><span class="badge" style="background:'+c+'22;color:'+c+'">'+(L[f.vex]||f.vex)+'</span></td>'
        +'<td>'+esc(f.severity)+'</td><td class="mono">'+(f.kev?'KEV':'')+'</td><td class="mono hint">'+esc(f.reachability)+'</td>'
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
      '<div class="chart"><div class="ct">Severity</div>'+bar(s.by_severity,['critical','high','medium','low','unrated'],SEVC,t,'severity','source_available')+'</div>'+
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
stats(); advisories(); yearChart(); sourceAvail();
</script></body></html>"""


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
