#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ICS-VEX API: SBOM identification and operational-context VEX review.

Run: python src/api_server.py --host 127.0.0.1 --port 8100
The browser and API share the same question, answer and validated-export path.
CVE/advisory metadata is loaded at startup; local models are loaded on demand.
"""
import os, sys, json, argparse, difflib, csv, re, uuid
from collections import defaultdict, Counter

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))
sys.path.insert(0, BASE)
import build_ground_truth as G  # exposure_for(), CWE_NAME
import sbom_match as SM              # identifier-first matching + NVD version ranges
import cert_eval as CERT             # test items #3/#4, scored via tools/eval_*.score
from cert_page import CERT_PAGE      # the /cert.html markup + client script
from context_vex_page import CONTEXT_VEX_PAGE  # the /context-vex.html markup + client script
from asset_vex_page import ASSET_VEX_PAGE, ASSET_AV_MODAL_JS, ASSET_AV_CLIENT_JS  # /asset-vex.html + shared JS
import asset_av_judge as AV                # source-less exploitability logic (v1: AV only)
import vex_context_judge as CJ            # v3: full CVSS vector x ICS operational context
import ics_context as ICTX                # the asset context schema and its evaluation
import sbom_cve_problems as P6W           # the 6W problem taxonomy, measured from the corpus
import context_standards as CSTD          # standards basis for the context schema
# Operational-context review and deterministic status gates.
import oc_context as OCX                  # v4: the OT operational-context (OC) model
import oc_vex_judge as OCJ                # v4: OC slots -> VEX status
import cve_requirements as CREQ           # v4: what a CVE requires of its environment
from src import vex_roles as VR
try:
    import cpe_match_l0l3 as L0       # L0+P3: full NVD CPE index (needs data/cpe_index.json)
except Exception:
    L0 = None

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
from src.cwe_taxonomy import display_names as _cwe_display_names
CWE_NAMES = {**getattr(G, "CWE_NAME", {}), **CWE_OFFICIAL, **_cwe_display_names()}

RESULTS = os.path.join(BASE, "results")
DATA = os.path.join(BASE, "data")
KB_PATH = os.path.join(RESULTS, "cve_kb.json")

AFFECTED, NOT_AFFECTED, UNDER_INV = "LIKELY_AFFECTED", "LIKELY_NOT_AFFECTED", "UNDER_INVESTIGATION"
# The corpus vocabulary is hedged ("LIKELY_") because a corpus-level verdict rests on an
# argument, not a run. FIXED is the exception and is NOT hedged: it is set only by the
# patch pre-gate, which requires the fix commit's own lines to be present in the tree AND
# NVD's product-matched range to have moved past the snapshot. That is a reading of the
# code, so there is nothing "likely" about it. CSAF has a distinct product_status.fixed,
# which is why it is not folded into NOT_AFFECTED on export.
FIXED = "LIKELY_FIXED"
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

# CVEs that are OSS-attributed (tier A) but whose affected-version source is NOT
# actually obtainable, so they should not count as "source-collectable".
# goahead 3.6.5: the upstream release tag was removed from embedthis/goahead.
UNCOLLECTABLE_CVES = {"CVE-2017-17562", "CVE-2019-5096", "CVE-2019-5097"}

def _norm_vendor(v):
    """Clean whitespace/zero-width duplicates and canonicalize known vendor variants
    (e.g. '\\u200bSiemens' -> 'Siemens'; 'Rockwell' / 'Rockwell Automation' -> one name)."""
    v = (v or "").replace("​", "").strip().strip(",").strip()
    if not v:
        return "Unknown"
    return _VENDOR_CANON.get(v.lower(), v)


_UNPINNED_V = {"", "noassertion", "unknown", "none", "n/a", "*"}


def _tidy_version(v):
    """A readable version/range from a CSAF component's trailing constraint.
    `vers:intdot/<4.3.4` -> `<4.3.4`; `vers:Relion_670/>=2.2.2.0|<2.2.2.6` ->
    `>=2.2.2.0, <2.2.2.6`; `vers:all/*` -> `all versions`; `<1.04.420` stays."""
    v = (v or "").strip()
    if not v:
        return ""
    if v.startswith("vers:"):
        tail = v.split("/", 1)[1] if "/" in v else v[5:]
        if tail.strip() in ("*", "all", ""):
            return "all versions"
        return tail.replace("|", ", ").strip()
    return v


def _split_component(comp):
    """Separate one SBOM component into (vendor, product, version) for display.

    reverse_sbom mashes all three into `name` (e.g. publisher 'OPCFoundation',
    name 'OPCFoundation UA-LDS-Installers <1.04.420', version 'NOASSERTION'): the
    vendor is repeated as a prefix and the affected RANGE is appended, while the
    `version` field is NOASSERTION. So vendor comes from `publisher`, and product
    and version are split out of the name at the first `vers:`/comparison token.
    """
    vendor = (comp.get("publisher") or "").strip()
    name = (comp.get("name") or "").strip()
    core = name
    if vendor and core.lower().startswith(vendor.lower()):
        core = core[len(vendor):].strip()
    m = re.search(r"(vers:|[<>])", core)
    if m:
        product = core[:m.start()].strip()
        version = _tidy_version(core[m.start():].strip())
    else:
        product = core
        v = (comp.get("version") or "").strip()
        version = "" if v.lower() in _UNPINNED_V else v
    return (vendor or "—"), (product or core or name or "—"), version


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
        # Published CISA VEX flags (vendor assertions): 12 ICSA, 18 ICSA x CVE pairs.
        self.gt_icsa = _load(os.path.join(DATA, "gt_icsa", "manifest.json"), {"tier1": [], "tier2": []})
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
        # Corpus metadata is rebuilt from advisories. Historical source verdicts
        # are research artifacts and do not enter current asset reviews.
        from src.public_corpus import current_findings
        self.corpus_freshness = _load(os.path.join(DATA, 'public_corpus_freshness.json'), {})
        self.by_cve = current_findings({}, adv_raw, _load(os.path.join(DATA, 'nvd_cache.json'), {}))
        # distinct KB components + their match strings (for CPE normalization)
        self.kb_comps = list({id(c): c for c in self.kb_idx.values()}.values())
        self.kb_match = [(c, [s.lower() for s in
                              {c.get("name", ""), c.get("cpe_product", ""), c.get("key", "")} if s])
                         for c in self.kb_comps]
        # CVE -> CVSS base score. NVD (tools/fetch_nvd_cvss_bulk.py) is authoritative,
        # then findings.csv / NVD cache / CISA advisory metrics fill any gaps.
        # CVE -> Attack Vector letter (N/A/L/P), used by the asset-attribute estimate.
        self.cvss = {}
        self.av = {}
        _ncp = os.path.join(DATA, "nvd_cvss.json")
        if os.path.exists(_ncp):
            for _c, _v in _load(_ncp, {}).items():
                if _c == "__cursor__" or not isinstance(_v, dict):
                    continue
                _a = __import__("asset_av_judge").parse_av(_v.get("vector"))
                if _a:
                    self.av[_c] = _a
                if _v.get("score") is not None:
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
                if r['cve'] not in self.cvss:
                    self.cvss[r["cve"]] = sc
        # fill gaps from the NVD cache (metric.score) so every KB CVE gets a real base score
        _nvd = _load(os.path.join(DATA, "nvd_cache.json"), {})
        self.nvd_metadata = _nvd
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
            self.cve_index[cve] = {
                "cve": cve, "vex": w["final_vex"],
                "description": (_nvd.get(cve) or {}).get('description', ''),
                "published": (_nvd.get(cve) or {}).get('published'),
                "last_modified": (_nvd.get(cve) or {}).get('lastModified'),
                "nvd_status": (_nvd.get(cve) or {}).get('vulnStatus'),
                "severity": sev if sev in srank else "unrated",
                "cvss": self.cvss.get(cve),
                "av": self.av.get(cve),
                "cwe": _canon_cwe(rows), "kev": any(r.get("kev") for r in rows),
                "year": int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None,
                "vendors": sorted({_norm_vendor(r.get("vendor")) for r in rows}),
                "device_types": sorted({_device_type(r.get("device")) for r in rows}),
                "component": w.get("product") or w.get("component"),

            }
        # CVE-level view (unique CVEs, worst-case verdict across assets)
        rank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}
        cve_worst, cve_tier = {}, {}
        for cve, rows in self.by_cve.items():
            w = max(rows, key=lambda r: rank.get(r["final_vex"], 0))
            cve_worst[cve] = w["final_vex"]
            cve_tier[cve] = w.get("evidence_tier")
            # Collection is observed independently of old verdict caches or tiers.
        # unique CVE count by CVE-ID year
        yr = Counter()
        for cve in cve_worst:
            parts = cve.split("-")
            if len(parts) >= 2 and parts[1].isdigit():
                yr[int(parts[1])] += 1
        self.by_year = {str(y): yr[y] for y in sorted(yr)}
        # Four axes: source (advisory) / document (device = SBOM) / statement
        # (device x CVE) / vulnerability (distinct CVE)
        _fi = [r for rows in self.by_cve.values() for r in rows]
        _dev = {r.get("device") for r in _fi if r.get("device")}
        _fin_vex = Counter(r["final_vex"] for r in _fi)
        _fin_just = Counter(r.get("justification") for r in _fi if r.get("justification"))
        _per_dev = Counter(r.get("device") for r in _fi if r.get("device"))
        _med = (sorted(_per_dev.values())[len(_per_dev) // 2] if _per_dev else 0)
        # CVE-centric: a CVE can get different verdicts on different products.
        _per_cve = defaultdict(set)
        for r in _fi:
            _per_cve[r["cve"]].add(r["final_vex"])
        _cve_split = sum(1 for v in _per_cve.values() if len(v) > 1)
        _cve_prod = Counter(r["cve"] for r in _fi)
        _cve_prod_med = (sorted(_cve_prod.values())[len(_cve_prod) // 2] if _cve_prod else 0)
        self.cve_level = {
            "freshness": self.corpus_freshness,
            "axes": {
                # A VEX statement is about a vulnerability, so the CVE is the reference axis.
                "cves": len(cve_worst),
                "statements": len(_fi),
                "advisories_with_cves": len(_dev),
                "advisories_collected": self.advisories.get("total", 0),
                "cve_split": _cve_split,            # CVEs whose verdict differs by product
                "products_per_cve_median": _cve_prod_med,
                "products_per_cve_max": (max(_cve_prod.values()) if _cve_prod else 0),
                "statements_per_advisory_median": _med,
                "statements_per_advisory_max": (max(_per_dev.values()) if _per_dev else 0),
            },
            # Per-statement verdicts - the originals, not collapsed to a worst case
            "by_vex_statement": dict(_fin_vex),
            "by_justification": dict(_fin_just),
            "total_cves": len(cve_worst),
            "by_vex": dict(Counter(cve_worst.values())),
            "by_tier": dict(Counter(t for t in cve_tier.values() if t)),
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
    comp, r, sstr, _runner = _ro_ranked(name)
    return comp, r, sstr


def _ro_ranked(name):
    """As above, plus the runner-up ratio from a DIFFERENT component.

    The margin matters: `openssl` scores 0.857 against `openssh`, so a bare best
    match silently swaps one product's CVE set for another's. Two candidates
    within a hair of each other mean the name simply does not identify the
    component."""
    n = (name or "").lower()
    best, best_r, best_s = None, 0.0, None
    second = 0.0
    for comp, strs in STORE.kb_match:
        cr = max((difflib.SequenceMatcher(None, n, s).ratio() for s in strs), default=0.0)
        if cr > best_r:
            second, best_r, best, best_s = best_r, cr, comp, max(
                strs, key=lambda s: difflib.SequenceMatcher(None, n, s).ratio())
        elif cr > second:
            second = cr
    return best, round(best_r, 3), best_s, round(second, 3)


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
    raw = [c for c in sbom.get("components", []) if isinstance(c, dict)]
    rank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}
    by_cve = {}  # unique CVE -> worst-case row
    unidentified = []
    for c in raw:
        name = (c.get("name") or "").strip()
        ver = (c.get("version") or "").strip()
        comp, how, detail = SM.identify(c, STORE.kb_idx, STORE.kb_match, _ro_ranked)
        if not comp:
            if name:
                unidentified.append({"component": name, "version": ver or "(unpinned)",
                                     "reason": detail})
            continue
        # Range-filtered: a CVE whose NVD range excludes this version is dropped
        # rather than reported. `decided` says whether the version was actually
        # checked - an unpinned or uncached version yields the CVE with the flag
        # off, never a silent claim that it applies.
        pairs = SM.cves_for(comp, ver)
        pinned = any(d for _cv, d in pairs)
        for cv, decided in pairs:
            av = cv.get("av", "N")
            exp = exposure or G.exposure_for(comp["name"])
            # No evidence means under_investigation. Deployment context is not a substitute.
            status, just = UNDER_INV, None
            basis = "operating-context review has not been completed for this component"
            tier = ("static-reasoned" if status in (AFFECTED, NOT_AFFECTED)
                    else "under-investigation")
            _cvn, _cpr, _cvr = _split_component(comp)
            row = {
                "cve": cv["id"], "component": comp["name"], "version": ver or "(unpinned)",
                "vendor": _cvn, "product": _cpr, "version_display": _cvr,
                "version_pinned": pinned, "version_decided": decided,
                "identified_by": how, "identified_detail": detail,
                "severity": cv.get("sev", ""),
                "cvss": cv.get("cvss"),
                "av": av, "kev": bool(cv.get("kev")), "epss": cv.get("epss"),
                "exposure": exp,
                "final_vex": status, "justification": just, "basis": basis,
                "evidence_tier": tier,
            }
            prev = by_cve.get(cv["id"])
            if prev is None or rank.get(status, 0) > rank.get(prev["final_vex"], 0):
                by_cve[cv["id"]] = row
    # L0+P3: identify via the full NVD CPE index (13,764 products vs the 42-entry
    # OSS KB), recovering ICS products the KB never had - "Sielco Sistemi Winlog
    # Lite" -> winlog_lite. Additive: only CVEs the KB pass did not already find.
    # Vendor evidence GRADES each match (anchored/canonical/co-listed), never a hard
    # filter. Degrades cleanly to the KB when data/cpe_index.json is absent.
    if L0 is not None and getattr(L0, "BY_PRODUCT", None):
        _top = (sbom.get("metadata") or {}).get("component") or {}
        _av = next((p.get("value") for p in (_top.get("properties") or [])
                    if p.get("name") == "ics:vendor"), "") or _top.get("publisher") or ""
        for c in raw:
            _name = (c.get("name") or "").strip()
            _ver = (c.get("version") or "").strip()
            # `unidentified` is filled by the KB pass above, which runs first.
            # A component this pass resolves is no longer unidentified, and
            # leaving it on the list would report an abstention that did not
            # happen - the list is about to be shown to the user, so it has to
            # mean what it says.
            _p, _how = L0.identify_product(c)
            if _p:
                unidentified = [u for u in unidentified if u["component"] != _name]
            for m in L0.cves_for(c, sbom_vendor=_av):
                cid = m["cve"]
                if cid in by_cve:
                    continue
                idx = STORE.cve_index.get(cid, {})
                _cvn, _cpr, _cvr = _split_component(c)
                by_cve[cid] = {
                    "cve": cid, "component": _name, "version": _ver or "(unpinned)",
                    "vendor": _cvn, "product": _cpr, "version_display": _cvr,
                    "version_pinned": bool(m["version_decided"]),
                    "version_decided": bool(m["version_decided"]),
                    "identified_by": "l0-" + m["how"],
                    "identified_detail": "NVD CPE index (%s, %s)" % (m["vendor"], m["confidence"]),
                    "severity": idx.get("severity", ""), "cvss": idx.get("cvss"),
                    "av": "", "kev": bool(idx.get("kev")), "epss": idx.get("epss"),
                    "exposure": exposure or "",
                    "final_vex": UNDER_INV, "justification": None,
                    "basis": "identified via NVD CPE index (L0); vendor evidence: " + m["confidence"],
                    "evidence_tier": "under-investigation",
                }
    # Also honor CVEs embedded in the SBOM's own VDR (vulnerabilities[]), e.g. a
    # reverse_sbom SBOM-CVE whose closed-firmware component has no OSS KB match.
    ref2name = {c.get("bom-ref"): (c.get("name") or "") for c in sbom.get("components", [])}
    ref2comp = {c.get("bom-ref"): c for c in sbom.get("components", [])}
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
        # --- the component_not_present lane ---
        # If the component the VDR names is absent from this SBOM's component list,
        # that absence is itself the grounds for CISA's `component_not_present`
        # justification. It needs no version comparison, which makes it the only
        # conclusive path that still holds when a component version is NOASSERTION.
        if aff and aff not in ref2name:
            status, just = NOT_AFFECTED, "component_not_present"
            basis = ("the affected component is not present in this SBOM "
                     f"(VDR ref '{aff}' has no matching component entry)")
        else:
            status, just = UNDER_INV, None
            basis = ("operating-context review has not been completed for this component" if av
                     else "no CVSS attack vector in the source advisory")
        try:
            epss = float(props["signal:epss"]) if props.get("signal:epss") not in (None, "NA", "") else None
        except (TypeError, ValueError):
            epss = None
        _cvn, _cpr, _cvr = _split_component(ref2comp.get(aff) or _top or {})
        by_cve[cid] = {
            "cve": cid, "component": ref2name.get(aff, aff or _top.get("name") or ""),
            "vendor": _cvn, "product": _cpr, "version_display": _cvr,
            "version": "NOASSERTION", "version_pinned": False, "severity": sev, "cvss": score,
            "av": av, "kev": kev, "epss": epss,
            "exposure": exp,
            "final_vex": status, "justification": just, "basis": basis,
            "evidence_tier": ("sbom-evidenced" if just == "component_not_present"
                              else "static-reasoned" if status in (AFFECTED, NOT_AFFECTED)
                              else "under-investigation"),
            "from_vdr": True,
        }
    cves = sorted(by_cve.values(),
                  key=lambda r: (-rank.get(r["final_vex"], 0), r["cve"]))
    by = Counter(r["final_vex"] for r in cves)
    return {"components": len(raw), "cves_matched": len(cves),
            # Components the identifiers could not resolve are reported, not
            # silently dropped and not guessed at - see sbom_match.identify().
            # The counts matter as much as the list: "38 components, 1 CVE"
            # alone reads as a broken identifier, when what happened is that
            # every component was run and every one abstained.
            "unidentified": unidentified,
            "identified": len(raw) - len(unidentified),
            "abstained": len(unidentified),
            "summary": {"by_vex": dict(by)}, "cves": cves}


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
# cisagov/CSAF's default branch is `develop`, not `main` - a raw URL
# built on `main` 404s silently.

def _csaf_product_map(csaf):
    """product_id -> {vendor, product, version} from the product_tree branches."""
    out = {}

    def walk(bs, vendor, product, version):
        for b in bs or []:
            cat, nm = b.get("category"), b.get("name")
            v, p, ver = vendor, product, version
            if cat == "vendor":
                v = nm
            elif cat in ("product_name", "product_family"):
                p = nm
            elif cat in ("product_version", "product_version_range"):
                ver = nm
            if "product" in b:
                pr = b["product"]
                out[pr.get("product_id")] = {
                    "vendor": v, "product": p or pr.get("name", ""), "version": ver,
                    "full": pr.get("name", ""),
                }
            walk(b.get("branches"), v, p, ver)

    pt = csaf.get("product_tree") or {}
    walk(pt.get("branches"), None, None, None)
    # Products also live outside branches, and missing these is why the Mobotix
    # advisory resolved to nothing: its flag names 200+ ids defined only as
    # relationships (a product installed on / bundled with another).
    for fp in pt.get("full_product_names") or []:
        out.setdefault(fp.get("product_id"),
                       {"vendor": None, "product": fp.get("name", ""),
                        "version": None, "full": fp.get("name", "")})
    for r in pt.get("relationships") or []:
        fp = r.get("full_product_name") or {}
        pid = fp.get("product_id")
        if not pid or pid in out:
            continue
        base = out.get(r.get("product_reference")) or {}
        out[pid] = {"vendor": base.get("vendor"),
                    "product": fp.get("name", ""),
                    "version": base.get("version"), "full": fp.get("name", "")}
    return out


def flagged_products(csaf, cve, label=None):
    """Products this CVE's flags name, as [{label, vendor, product, version}].

    Grouped by label on purpose: a CVE can carry different justifications for
    different products. CVE-2024-3596 in icsa-25-135-05 is
    `vulnerable_code_not_in_execute_path` on one product and
    `vulnerable_code_not_present` on five others - filtering to a single label
    silently dropped the majority of them."""
    pm = _csaf_product_map(csaf)
    out = []
    for v in csaf.get("vulnerabilities") or []:
        if v.get("cve") != cve:
            continue
        for f in v.get("flags") or []:
            if label and f.get("label") != label:
                continue
            for pid in f.get("product_ids") or []:
                info = pm.get(pid)
                if info:
                    out.append(dict(info, product_id=pid, label=f.get("label")))
    # a flag with no product_ids applies to the whole advisory
    if not out:
        for v in csaf.get("vulnerabilities") or []:
            if v.get("cve") != cve:
                continue
            for f in v.get("flags") or []:
                if not (f.get("product_ids") or []):
                    out.append({"vendor": None, "product": "(all products in this advisory)",
                                "version": None, "product_id": None, "label": f.get("label")})
    return out


CSAF_RAW = "https://raw.githubusercontent.com/cisagov/CSAF/develop/"


def build_app():
    from fastapi import FastAPI, HTTPException, File, Form, UploadFile
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel

    app = FastAPI(title="ICS-VEX API", version="1.0",
                  description="Hybrid VEX pipeline — static triage over the corpus + "
                              "live SBOM→VEX. No PoC is generated or executed.")
    from src.cluster_question_api import router as cluster_question_router
    app.include_router(cluster_question_router)
    from src.question_mining_api import router as question_mining_router
    app.include_router(question_mining_router)
    from src.operational_workflow_api import router as operational_workflow_router
    app.include_router(operational_workflow_router)
    from fastapi.middleware.cors import CORSMiddleware
    pages_origins=['https://kakyung98.github.io']
    app.add_middleware(CORSMiddleware,allow_origins=pages_origins,
                       allow_methods=['GET','POST'],allow_headers=['Content-Type'],allow_credentials=False)

    @app.middleware('http')
    async def pages_private_network(request,call_next):
        response=await call_next(request)
        if (request.method=='OPTIONS' and request.headers.get('origin') in pages_origins
                and request.headers.get('access-control-request-private-network')=='true'):
            response.headers['Access-Control-Allow-Private-Network']='true'
        return response

    class SbomReq(BaseModel):
        sbom: dict
        exposure: str | None = None

    @app.get("/api/health")
    def health():
        return {"ok": True, "kb_components": len(set(id(v) for v in STORE.kb_idx.values())),
                "corpus_cves": STORE.cve_level.get("total_cves"),
                "exposures": EXPOSURES}

    @app.get("/api/summary")
    def summary():
        """CVE-level corpus summary (unique CVEs, worst-case verdict)."""
        if not STORE.cve_level.get("total_cves"):
            raise HTTPException(404, "Corpus data is unavailable")
        return STORE.cve_level

    @app.get("/api/cves")
    def cves_by(dim: str, value: str, scope: str = "corpus", limit: int = 400):
        """Related CVEs for a chart selection (drill-down).
        dim: cwe|vendor|device_type|year|vex|severity ; scope: corpus."""
        srank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unrated": 0}
        vrank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}

        def ok(r):
            if dim == "cwe":            return r["cwe"] == value
            if dim == "vendor":         return value in r["vendors"]
            if dim == "device_type":    return value in r["device_types"]
            if dim == "year":           return str(r["year"]) == str(value)
            if dim == "vex":            return r["vex"] == value
            if dim == "severity":       return r["severity"] == value
            return False

        hits = [r for r in STORE.cve_index.values() if ok(r)]
        hits.sort(key=lambda r: (-int(r["kev"]), -vrank.get(r["vex"], 0),
                                 -srank.get(r["severity"], 0), r["cve"]))
        return {"dim": dim, "value": value, "scope": scope, "count": len(hits),
                "cves": [{"cve": r["cve"], "vex": r["vex"], "severity": r["severity"],
                          "cvss": r.get("cvss"),
                          "kev": r["kev"],
                          "vendor": ", ".join(r["vendors"][:2]), "component": r["component"],
                          "cwe": r["cwe"]} for r in hits[:limit]]}

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



    @app.get("/api/published_vex")
    def published_vex():
        """Explicit assertions recomputed from the locally collected CSAF snapshot."""
        from src.published_vex import collect
        return collect()

    @app.get('/api/published-vex/evidence/{advisory}')
    @app.get('/published_csaf/{advisory}.json')
    def published_vex_evidence(advisory: str):
        from src.published_vex import evidence
        try:return evidence(advisory)
        except ValueError as exc:raise HTTPException(400,str(exc)) from exc
        except FileNotFoundError as exc:raise HTTPException(404,'CSAF document unavailable') from exc

    def legacy_published_vex_snapshot():
        """Historical manifest retained for reproducibility; not used by the live route."""
        man = STORE.gt_icsa
        pairs, ldist, vendors = [], {}, {}
        for r in man.get("tier1", []):
            aid = r.get("advisory_id")
            title = r.get("title", "")
            vendor = title.split()[0] if title else "?"
            vendors[vendor] = vendors.get(vendor, 0) + 1
            for cve, labels in (r.get("flags") or {}).items():
                for lab in labels:
                    ldist[lab] = ldist.get(lab, 0) + 1
                pairs.append({
                    "advisory": aid, "cve": cve,
                    "title": title,
                    "justification": labels[0] if labels else None,
                    "labels": labels,
                    "url": r.get("cisa_url"),
                    # the flags this table reports live in the CSAF document,
                    # not on the advisory page - link the document itself
                    "csaf_url": (CSAF_RAW + r["source_file"]) if r.get("source_file") else None,
                    "csaf_local": "gt_icsa/%s.json" % r.get("advisory_id", ""),
                    "release": r.get("current_release_date") or r.get("initial_release_date"),
                })
        pairs.sort(key=lambda x: x["cve"])
        return {
            "advisories": len(man.get("tier1", [])),
            "pairs": len(pairs),
            "label_instances": sum(ldist.values()),
            "by_justification": ldist,
            "by_vendor": vendors,
            "note": ("The entire public ICS VEX label set. All justifications are "
                     "code/build-based; no environment-based justification appears."),
            "rows": pairs,
        }


    @app.get("/reverse_sbom/{name}")
    def reverse_sbom_file(name: str):
        """Serve a raw CycloneDX SBOM-CVE file (parity with GitHub Pages static hosting)."""
        from fastapi.responses import FileResponse
        if "/" in name or "\\" in name or not name.endswith(".json"):
            raise HTTPException(400, "bad name")
        from src.dataset_paths import public_sbom_directory
        directory = str(public_sbom_directory())
        path = os.path.abspath(os.path.join(BASE, directory, name))
        if os.path.commonpath([os.path.abspath(BASE), path]) != os.path.abspath(BASE):
            raise HTTPException(400, 'bad source directory')
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
        """Unique CVE count by CVE-ID year (total travels in the response)."""
        if not STORE.by_year:
            raise HTTPException(404, "Corpus data is unavailable")
        return {"total_cves": sum(STORE.by_year.values()), "by_year": STORE.by_year}



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

    class CandidateMatchReq(BaseModel):
        sbom: dict
        offline: bool = False
        agent_mode: str = 'unified'
        lookup_mode: str | None = None

    @app.post("/api/cve-match")
    def cve_match(req: CandidateMatchReq):
        """Auditable LangGraph candidate retrieval; never a final VEX verdict."""
        try:
            from candidate_match import match_candidates
        except ImportError as exc:
            raise HTTPException(503, "Install matcher dependencies from requirements.txt") from exc
        try:
            return match_candidates(req.sbom, req.offline, agent_mode=req.agent_mode,lookup_mode=req.lookup_mode)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        except (ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(400, "Invalid CycloneDX/SPDX SBOM: " + str(exc)) from exc

    @app.get('/api/cve-match/models')
    def candidate_models():
        from src.candidate_web import model_status
        return model_status()

    @app.post('/api/cve-match/models/unload')
    def candidate_unload_models():
        from src.identification_agents import release_runtime
        return release_runtime()

    class CandidateJobReq(BaseModel):
        sbom: dict
        agent_mode: str = 'unified'
        lookup_mode: str = 'local'

    @app.post('/api/cve-match/jobs',status_code=202)
    def candidate_job(req: CandidateJobReq):
        from src.candidate_web import submit
        try:return submit(req.sbom,req.agent_mode,req.lookup_mode)
        except OverflowError as exc:raise HTTPException(429,str(exc)) from exc
        except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
        except (ValueError,TypeError,AttributeError) as exc:raise HTTPException(400,str(exc)) from exc

    @app.get('/api/cve-match/jobs/{job_id}')
    def candidate_job_status(job_id: str):
        from src.candidate_web import get_job
        job=get_job(job_id)
        if job is None:raise HTTPException(404,'Task not found. The server may have restarted.')
        if job.get('result'):
            from copy import deepcopy
            from src.identification_diagnostics import explain_identification
            job=deepcopy(job)
            explain_identification(job['result'],job.get('input_sbom') or {})
        return job

    def candidate_vex_data(job_id):
        from src.candidate_web import get_job
        job=get_job(job_id)
        if job is None:raise HTTPException(404,'Identification task not found.')
        if job['status']!='completed':raise HTTPException(409,'Identification has not completed yet.')
        result=job['result'];records={};components=[]
        for component in list(result['components'])+([result['asset_analysis']] if result.get('asset_analysis') else []):
            comp=component['component']
            components.append({'bom-ref':comp['id'],'name':comp['name'],'version':comp['version']})
            for finding in component.get('cves',[]):
                cid=finding.get('cve_id','')
                if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cid) or finding.get('match_status')=='no_match':continue
                if cid not in records:
                    idx=STORE.cve_index.get(cid,{})
                    vector,description=_cve_facts(cid)
                    records[cid]={'cve':cid,'component':comp['name'],'version':comp['version'],
                        'cwe':idx.get('cwe'),
                        'vector':vector or '', 'description':description or '',
                        'cvss':idx.get('cvss'),'severity':idx.get('severity',''),'av':idx.get('av') or '',
                        'kev':bool(idx.get('kev')),'epss':idx.get('epss'),
                        'final_vex':UNDER_INV,'justification':None,'version_decided':True,'mappings':[]}
                row=records[cid]
                row['version_decided']=row['version_decided'] and finding['match_status']=='match'
                row['mappings'].append({'component':comp['name'],'component_id':comp['id'],
                    'version':comp['version'],'match_status':finding['match_status'],'evidence':finding.get('evidence',{}),
                    'identification_evidence':{'architecture':component.get('architecture',result.get('architecture','legacy')),
                        'identity':component.get('validation',{}),'version_observations':component.get('l3',{}).get('observations',[]),
                        'version_status':component.get('l3',{}).get('status'),
                        'model_stage_checks':{key:{k:(component.get(key,{}).get('agent') or {}).get(k)
                            for k in ('status','guard_accepted','executed','input_sha256')} for key in ('l2','l3','l4')}
                            if component.get('architecture',result.get('architecture'))=='unified-identification-v1' else None,
                        'dictionary_snapshot_sha256':result.get('dictionary_snapshot_sha256')}})
        rows=list(records.values())
        from copy import deepcopy
        handoff_sbom=deepcopy(job.get('input_sbom') or {'bomFormat':'CycloneDX','metadata':{'component':result.get('asset',{})},'components':components})
        if result.get('asset_analysis') and handoff_sbom.get('bomFormat')=='CycloneDX':
            handoff_sbom.setdefault('metadata',{}).setdefault('component',{}).setdefault('bom-ref',result['asset_analysis']['component']['id'])
        return {'job_id':job_id,'components':len(components),'cves_matched':len(rows),'cves':rows,
                'simulation':bool(result.get('input_notice')),
                'mapping_count':sum(len(r['mappings']) for r in rows),
                'summary':{'by_vex':{UNDER_INV:len(rows)}},
                'sbom':handoff_sbom}

    @app.get('/api/cve-match/jobs/{job_id}/vex')
    def candidate_vex(job_id: str):return candidate_vex_data(job_id)

    @app.get('/api/vex-review/models')
    def grounded_model_status():
        from src.operational_model_config import status as operational_status
        return {'model':'Qwen3-8B','roles':[{'role':role,'adapter':role+'-qwen3-8b-v1',
                'active':True,
                'weights_available':all(os.path.isfile(os.path.join(BASE,'models',role+'-qwen3-8b-v1',f))
                                        for f in ['training_complete.json','adapter_model.safetensors','adapter_config.json'])}
                for role in ['vex-writer']], 'shared_quantized_base':True,'outputs_require_review':True,
                'extraction_strategy':'deterministic_source_spans',
                'condition_self_review_enabled':False,
                'operational_models':operational_status(),
                'question_self_review_enabled':False,
                'base_inference_roles':[],'llm_policy':'fixed_operational_templates_and_final_writer',
                'primary_question_method':'fixed_operational_templates','question_model_active':False,
                'research_roles':[]}

    class CandidateContextReq(BaseModel):
        asset: dict = {}

    @app.post('/api/cve-match/jobs/{job_id}/oc')
    def candidate_context(job_id: str, req: CandidateContextReq):
        data=candidate_vex_data(job_id)
        known={f['cve']:f for f in data['cves']}
        prepared=VR.prepare(data['cves'],product=data['sbom']['metadata']['component'].get('name','unspecified-product'),
                            run_id=job_id,simulation=bool(data.get('simulation')))
        cases=[{'cve':f['cve'],'requirements':VR.requirements(CREQ.extract(f['cve'],f['vector'],f['description'],cwe_context=_cwe_details(f['cve'],f.get('cwe'))),f),
                'asset':req.asset,'component_present':True,'version_in_range':True} for f in prepared]
        result=OCJ.judge_many(cases)
        for statement in result['statements']:
            if statement['status']=='affected' and not known[statement['cve']]['version_decided']:
                statement.update(status='under_investigation',justification=None,
                    reason='Operational prerequisites are satisfied, but installed product/version applicability is unconfirmed. VEX affected cannot be established.',
                    identification_gate='version_or_applicability_unconfirmed')
        counts=Counter(s['status'] for s in result['statements']);n=len(result['statements'])
        deferred=counts.get('under_investigation',0)
        result.update(by_status=dict(counts),deferred=deferred,total=n,
            deferral_rate=round(deferred/n,4) if n else None,
            decision_rate=round((n-deferred)/n,4) if n else None,arm='operational-context',identification_job=job_id)
        from src.web_locale import english_statement
        result['statements']=[english_statement(s) for s in result['statements']]
        return VR.finish(result,prepared)

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
        """Retired with the VEX-v2 source arm. Kept so the old URL answers."""
        return {"retired": True, "reason": "the source-uncollectable decision tree was retired with the VEX-v2 source arm; the replacement is the OC operational-context model (docs/ICSVEX.md)"}

    @app.post("/api/vex_tree")
    def vex_tree(req: TreeReq):
        """Retired with the VEX-v2 source arm. Kept so the old URL answers."""
        return {"retired": True, "reason": "the source-uncollectable decision tree was retired with the VEX-v2 source arm; the replacement is the OC operational-context model (docs/ICSVEX.md)"}

    # ---- certification test items #3 / #4 -------------------------------
    # The page can run the measurement itself, so a reviewer does not have to take
    # the recorded figure on trust. Scoring happens in src/cert_eval, which calls
    # the same score() the CLI tools use; nothing is recomputed here.
    @app.get("/api/cve_av/{cve}")
    def cve_av(cve: str):
        """CVSS Attack Vector + description for one CVE, for the asset-vex form."""
        cve = cve.strip().upper()
        vec = None
        _cp = os.path.join(DATA, "nvd_cvss.json")
        if os.path.isfile(_cp):
            rec = _load(_cp, {}).get(cve)
            if isinstance(rec, dict):
                vec = rec.get("vector")
        desc = None
        _np = os.path.join(DATA, "nvd_cache.json")
        if os.path.isfile(_np):
            rec = _load(_np, {}).get(cve)
            if isinstance(rec, dict):
                desc = rec.get("description")
        av = AV.parse_av(vec)
        return {"found": bool(vec or desc), "cve": cve, "av": av,
                "vector": vec, "description": desc}

    class AssetVexReq(BaseModel):
        cve: str = ""
        av: str | None = None
        attributes: dict = {}
        extra: dict = {}

    @app.post("/api/asset-vex")
    def asset_vex(req: AssetVexReq):
        """Assess a source-less CVE from user-supplied asset attributes."""
        body = req.dict()
        cve = (body.get("cve") or "").strip().upper()
        av = body.get("av")
        if av is None:                                  # fall back to the cache
            _cp = os.path.join(DATA, "nvd_cvss.json")
            rec = _load(_cp, {}).get(cve) if os.path.isfile(_cp) else None
            if isinstance(rec, dict):
                av = AV.parse_av(rec.get("vector"))
        attrs = body.get("attributes") or {}
        extra = body.get("extra") or {}
        res = AV.assess(av, attrs, extra)
        res["cve"] = cve
        return res

    # ---- v3: the context arm (full CVSS vector x ICS operational context) ----
    # The v1 endpoint above reads one metric (AV) and matches it against an
    # attack-surface set. These read the whole vector, evaluate every precondition
    # it imposes, and keep a structural impossibility strictly apart from an
    # operator control - only the former may set not_affected. See
    # docs/METHODOLOGY_V3.md.

    @app.get("/api/problems-6w")
    def problems_6w():
        """The 6W problem taxonomy for S/HBOM -> CVE identification, with every
        figure recomputed from the corpus rather than read from a constant."""
        return P6W.report()

    @app.get("/api/context/fields")
    def context_fields():
        """The asset context schema, grouped by what each group is allowed to decide."""
        groups = {"structural": [], "control": [], "mission": []}
        for key, kind, typ, label, helptext in ICTX.CONTEXT_FIELDS:
            groups[kind].append({"key": key, "type": typ, "label": label,
                                 "help": helptext,
                                 "refs": CSTD.refs_for(key)})
        return {"groups": groups,
                "rule": {"structural": "a property of the hardware or build; its "
                                       "absence is a sound refutation and may set "
                                       "not_affected",
                         "control": "a configuration or procedure; it lowers the "
                                    "environmental score and exports as a CSAF "
                                    "mitigation, but never sets not_affected",
                         "mission": "what a successful exploit would cost; drives "
                                    "CR/IR/AR priority only, never the status"}}

    class ContextVexReq(BaseModel):
        cve: str = ""
        vector: str | None = None
        context: dict = {}
        cve_requirements: dict = {}
        component_present: bool = True
        version_in_range: bool = True
        patched: bool = False

    @app.post("/api/context-vex")
    def context_vex(req: ContextVexReq):
        """Judge one (asset, CVE) statement from the full vector and the context."""
        body = req.dict()
        cve = (body.get("cve") or "").strip().upper()
        vector = body.get("vector")
        if not vector:                                  # fall back to the cache
            rec = _load(os.path.join(DATA, "nvd_cvss.json"), {}).get(cve)
            if isinstance(rec, dict):
                vector = rec.get("vector")
        sig = _load(os.path.join(DATA, "exploit_signals.json"), {}).get(cve) or {}
        rem = _load(os.path.join(DATA, "remediations.json"), {}).get(cve) or {}
        res = CJ.judge(cve, vector, body.get("context") or {},
                       cve_requirements=body.get("cve_requirements") or {},
                       signals=sig,
                       remediation_categories=list(rem.get("categories") or {}),
                       component_present=body.get("component_present", True),
                       version_in_range=body.get("version_in_range", True),
                       patched=body.get("patched", False))
        res["readiness"] = CJ.readiness(body.get("context") or {})
        return res

    @app.get("/api/context/standards")
    def context_standards():
        """Traceability of the context schema to IEC 62443 / NIST SP 800-82 / the
        KISA critical-infrastructure guide, with the deliberate omissions and the
        verification caveats attached."""
        return CSTD.report([f[0] for f in ICTX.CONTEXT_FIELDS])

    @app.get("/api/context/sensitivity")
    def context_sensitivity():
        """The committed corpus-wide sensitivity measurement, if it has been run."""
        p = os.path.join(BASE, "results", "context_vex_sensitivity.json")
        if not os.path.isfile(p):
            return {"available": False,
                    "how": "python tools/eval_context_vex.py"}
        d = _load(p, {})
        d["available"] = True
        return d

    @app.get("/api/cert/items")
    def cert_items():
        return CERT.items()

    class CertRunReq(BaseModel):
        item: str
        variant: str | None = None
        gt_path: str | None = None

    @app.post("/api/cert/run")
    def cert_run(req: CertRunReq):
        # An uploaded dataset is only ever read from the upload directory. A
        # caller-supplied path is otherwise an arbitrary-file read, and the
        # bundled ground truth has its own route (gt_path omitted).
        uploaded = False
        if req.gt_path:
            p = os.path.abspath(req.gt_path)
            if not p.startswith(os.path.abspath(CERT.UPLOADS) + os.sep):
                raise HTTPException(400, "gt_path must be a file uploaded via "
                                         "/api/cert/upload")
            uploaded = True
        try:
            return CERT.start(req.item, req.variant, req.gt_path, uploaded=uploaded)
        except (ValueError, FileNotFoundError) as e:
            raise HTTPException(400, str(e))

    @app.get("/api/cert/job/{job_id}")
    def cert_job(job_id: str):
        j = CERT.job(job_id)
        if j is None:
            raise HTTPException(404, "no such job")
        return j

    @app.get("/api/cert/jobs")
    def cert_jobs():
        return CERT.jobs()

    @app.post("/api/cert/upload")
    async def cert_upload(item: str = Form(...), file: UploadFile = File(...)):
        data = await file.read()
        try:
            path = CERT.save_upload(item, file.filename, data)
        except ValueError as e:
            raise HTTPException(400, str(e))
        # Validated before it can be scored: a file in the wrong schema would
        # otherwise produce 0 TP / 0 FP and read as a legitimate 0.0000.
        valid = CERT.validate_gt(item, path)
        if not valid["ok"]:
            os.remove(path)
            return {"ok": False, "valid": valid}
        return {"ok": True, "path": path, "bytes": len(data), "valid": valid}

    def _cve_facts(cve):
        """CVSS vector + description for one CVE, from the local NVD caches.

        The analyzer's /api/vex rows carry `av` and a score but not the full
        vector or the description, and both arms need them: the vector states
        the preconditions, the description names the vulnerable function. Having
        the server look them up means a client that sends only a CVE id still
        gets a real judgment instead of an empty requirement set - and an empty
        requirement set is exactly what used to come back as `affected`.
        """
        cve = (cve or "").strip().upper()
        vec = desc = None
        rec = _load(os.path.join(DATA, "nvd_cvss.json"), {}).get(cve)
        if isinstance(rec, dict):
            vec = rec.get("vector")
        rec = STORE.nvd_metadata.get(cve)
        if isinstance(rec, dict):
            desc = rec.get("description")
        return vec, desc

    def _cwe_details(cve, supplied=None):
        from src.cwe_context import context
        return context(cve,nvd=STORE.nvd_metadata.get(cve),corpus_cwe=STORE.cve_index.get(cve,{}).get('cwe'),supplied=supplied)

    # ---- v4 · the two judgment arms ------------------------------------
    # Compatibility evidence-arm APIs. The default analyzer first uses
    # /api/item4/start to route by CWE Pillar, specific weakness and evidence.
    # All CVEs proceed through operating-context review.

    @app.get("/api/oc/fields")
    def oc_fields():
        """The asset questionnaire for the no-source branch, grouped by OC slot.

        Each field carries its Appendix A provenance (or EXTENDED when the CISA
        guide has no such field), because "where did these questions come from"
        is the first thing an assessor asks.
        """
        from src.web_locale import english_groups,GROUPS
        return {"model": OCX.OC_MODEL,
                "slots": [{"id": i, "label": GROUPS[i.lower()], "help": 'Compare CVE prerequisites with verified asset evidence.', "fields": f}
                          for i, l, h, f in OCX.OC_SLOTS],
                "groups": english_groups(OCX.fields_by_group()),
                "rule": {
                    "absent": "Structurally absent: may support not_affected with evidence",
                    "disabled": "Disabled by configuration: mitigation only, not clearance",
                    "unknown": "Missing evidence cannot clear a vulnerability",
                }}

    class OcJudgeReq(BaseModel):
        asset: dict = {}
        cves: list = []          # [{cve, vector?, description?, component_present?}]
        product: str = 'unspecified-product'
        simulation: bool = False

    @app.post("/api/oc/judge")
    def oc_judge(req: OcJudgeReq):
        """Operational-context VEX for every CVE in one go."""
        cases = []
        raw_cases=[]
        for c in (req.cves or []):
            cve = c.get("cve")
            if not cve:
                continue
            vec, desc = c.get("vector"), c.get("description")
            if not vec or not desc:
                _v, _d = _cve_facts(cve)
                vec, desc = vec or _v, desc or _d
            raw_cases.append({**c,'cve':cve,'vector':vec,'description':desc})
        prepared=VR.prepare(raw_cases,product=req.product,run_id=VR.fingerprint(req.asset),simulation=req.simulation)
        for c in prepared:
            cve,vec,desc=c['cve'],c.get('vector'),c.get('description')
            cases.append({
                "cve": cve,
                "requirements": VR.requirements(CREQ.extract(cve, vec, desc,cwe_context=_cwe_details(cve,c.get('cwes',c.get('cwe')))),c),
                "asset": req.asset or {},
                "component_present": c.get("component_present", True),
                "version_in_range": c.get("version_in_range", True),
            })
        res = OCJ.judge_many(cases)
        res["arm"] = "operational-context"
        from src.web_locale import english_statement
        res['statements']=[english_statement(s) for s in res['statements']]
        return VR.finish(res,prepared)

    class OperationalQuestionsReq(BaseModel):
        cves: list = []
        product: str = 'unspecified-product'
        simulation: bool = False
        identification_job: str | None = None

        model_config = {'extra': 'forbid'}



    @app.get('/api/operational-classification/catalog')
    def operational_classification_catalog():
        from src.operational_classification import catalog
        return catalog()

    @app.get('/api/operational-classification/{cve}')
    def operational_classification_explanation(cve: str):
        from src.operational_classification import explain
        try:return explain(cve)
        except ValueError as error:raise HTTPException(400,str(error))

    @app.post('/api/item4/preview')
    def item4_preview(req: OperationalQuestionsReq):
        from src.vex_routing import classify
        cases=candidate_vex_data(req.identification_job)['cves'] if req.identification_job else req.cves
        if not 1<=len(cases)<=100:raise HTTPException(400,'Provide 1 to 100 CVEs.')
        routes={}
        for case in cases:
            cve=case.get('cve','')
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):raise HTTPException(400,'Invalid CVE ID.')
            vector,description=_cve_facts(cve)
            routes[cve]=classify({**case,'description':description or case.get('description',''),
                'vector':vector or case.get('vector',''),'cwe_context':_cwe_details(cve,case.get('cwe'))})
        return {'routes':routes,'scope':'review priorities; no VEX decision'}

    @app.post('/api/item4/start')
    def item4_start(req: OperationalQuestionsReq):
        from src import item4_review as I4
        cases=req.cves;product=req.product;simulation=req.simulation;sbom=None
        if req.identification_job:
            data=candidate_vex_data(req.identification_job)
            cases=data['cves'];sbom=data['sbom'];simulation=bool(data.get('simulation'))
            product=((sbom.get('metadata') or {}).get('component') or {}).get('name',product)
        raw=[]
        for c in cases:
            cid=c.get('cve','')
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cid):raise HTTPException(400,'Invalid CVE ID.')
            vector,description=_cve_facts(cid)
            # Local records have precedence; caller text is explicitly supplied evidence when no record exists.
            raw.append({**c,'description':description or c.get('description',''),
                        'vector':vector or c.get('vector',''),'cwe_context':_cwe_details(cid,c.get('cwe'))})
        try:return I4.start(raw,product,simulation,sbom)
        except ValueError as e:raise HTTPException(400,str(e))

    @app.get('/api/item4/reviews/{review_id}')
    def item4_get(review_id: str):
        from src import item4_review as I4
        try:return I4.result(I4.get(review_id))
        except KeyError as e:raise HTTPException(404,str(e))

    @app.post('/api/item4/{review_id}/questions')
    def item4_questions(review_id: str):
        from src import item4_review as I4
        try:return I4.questions(review_id)
        except KeyError as e:raise HTTPException(404,str(e))
        except ValueError as e:raise HTTPException(400,str(e))

    @app.post('/api/item4/{review_id}/questions/{cve}/generate')
    def item4_generate_tuned_question_case(review_id: str, cve: str):
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):raise HTTPException(400,'Invalid CVE ID.')
        raise HTTPException(410,'The primary review uses fixed workflow templates. Prepare the questionnaire to select them; model question generation is disabled.')

    @app.post('/api/oc/questions')
    def operational_questions(req: OperationalQuestionsReq):
        from src import operational_questions as OQ
        cases=req.cves
        product=req.product;simulation=req.simulation;source_sbom=None
        if req.identification_job:
            data=candidate_vex_data(req.identification_job)
            cases=data['cves'];product=data['sbom']['metadata']['component'].get('name',product)
            simulation=bool(data.get('simulation'))
            source_sbom=data['sbom']
        if not 1<=len(cases)<=100:raise HTTPException(400,'Provide 1 to 100 CVEs.')
        raw=[]
        for c in cases:
            cid=c.get('cve','')
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cid):raise HTTPException(400,'Invalid CVE ID.')
            vector,description=_cve_facts(cid)
            raw.append({**c,'cve':cid,'description':description or c.get('description',''),
                        'vector':vector or c.get('vector',''),'cwe_context':_cwe_details(cid,c.get('cwe'))})
        try:return OQ.create(raw,product,uuid.uuid4().hex,simulation,sbom=source_sbom)
        except ValueError as e:raise HTTPException(400,str(e))

    class OperationalAnswersReq(BaseModel):
        plan_id: str
        answers: dict = {}
        component_facts: dict = {}
        operational_context: dict | None = None

    class EvidenceReviewReq(BaseModel):
        plan_id: str
        case: dict
        model_config = {'extra': 'forbid'}

    @app.post('/api/item4/{review_id}/evidence')
    def item4_evidence(review_id: str, req: EvidenceReviewReq):
        from src import item4_review as I4
        try:return I4.save_evidence(review_id, req.plan_id, req.case)
        except KeyError as error:raise HTTPException(404,str(error))
        except ValueError as error:raise HTTPException(400,str(error))

    @app.post('/api/item4/{review_id}/evidence/files')
    async def item4_evidence_file(review_id: str, cve: str = Form(...), asset_ref: str = Form(...), file: UploadFile = File(...)):
        from src import item4_review as I4
        try:
            content = await file.read(5*1024*1024+1)
            return I4.add_attachment(review_id, cve, asset_ref, file.filename, content)
        except KeyError as error:raise HTTPException(404,str(error))
        except ValueError as error:raise HTTPException(400,str(error))
        finally:await file.close()

    @app.get('/api/item4/{review_id}/evidence/files/{file_id}')
    def item4_evidence_download(review_id: str, file_id: str):
        from src import item4_review as I4
        from fastapi.responses import FileResponse
        try:
            record,path = I4.attachment(review_id, file_id)
            return FileResponse(path, media_type='application/octet-stream', filename=record['filename'],
                                headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
        except KeyError as error:raise HTTPException(404,str(error))
        except ValueError as error:raise HTTPException(400,str(error))

    @app.get('/api/item4/{review_id}/evidence/export/{format}')
    def item4_evidence_export(review_id: str, format: str):
        from src import item4_review as I4
        from fastapi.responses import JSONResponse
        try:
            document = I4.export_evidence(review_id, format)
            return JSONResponse(document, headers={'Content-Disposition':'attachment; filename="ics-vex-'+format+'.json"','Cache-Control':'no-store'})
        except KeyError as error:raise HTTPException(404,str(error))
        except ValueError as error:raise HTTPException(400,str(error))

    @app.post('/api/item4/{review_id}/answers')
    def item4_answers(review_id: str, req: OperationalAnswersReq):
        from src import item4_review as I4
        try:return I4.answers(review_id,req.answers,req.component_facts,plan_id=req.plan_id,operational_context=req.operational_context)
        except KeyError as e:raise HTTPException(404,str(e))
        except ValueError as e:raise HTTPException(400,str(e))

    @app.post('/api/oc/answers')
    def operational_answers(req: OperationalAnswersReq):
        from src import operational_questions as OQ
        try:return OQ.assess(req.plan_id,req.answers,req.component_facts,operational_context=req.operational_context)
        except KeyError as e:raise HTTPException(404,str(e))
        except ValueError as e:raise HTTPException(400,str(e))

    @app.get('/api/oc/reviews/{plan_id}/sbom')
    def operational_sbom(plan_id: str):
        from src.review_store import get
        result=get('review',plan_id)
        if not result:raise HTTPException(404,'Review not found or expired.')
        if not result.get('sbom_vex'):raise HTTPException(409,'No original CycloneDX SBOM was linked to this review.')
        return result['sbom_vex']

    @app.post("/api/refresh")
    def refresh():
        STORE.refresh()
        return {"ok": True, "reloaded": True}

    @app.get("/", response_class=HTMLResponse)
    @app.get("/index.html", response_class=HTMLResponse)
    def index():
        return make_page("analyzer", include_local_workbench=True)

    @app.get("/vex-method.html", response_class=HTMLResponse)
    def vex_method():
        # merged into the decision page; keep the old URL working
        return make_page("vex-decision")

    @app.get("/sbom-to-cve.html", response_class=HTMLResponse)
    def sbom_to_cve_page():
        return make_page("sbom-to-cve")

    @app.get("/cve-matcher.html", response_class=HTMLResponse)
    def cve_matcher_page():
        from fastapi.responses import RedirectResponse
        return RedirectResponse('/',status_code=307)

    @app.get("/vex-decision.html", response_class=HTMLResponse)
    def vex_decision_page():
        return make_page("vex-decision")

    @app.get("/dataset.html", response_class=HTMLResponse)
    def dataset():
        return make_page("dataset")

    # merged into /dataset.html; the old URLs still resolve
    @app.get("/corpus.html", response_class=HTMLResponse)
    def corpus():
        return make_page("dataset")

    @app.get("/collectable.html", response_class=HTMLResponse)
    def collectable():
        return make_page("dataset")

    @app.get("/published-vex.html", response_class=HTMLResponse)
    def published_vex_page():
        return make_page("published-vex")

    @app.get("/source.html", response_class=HTMLResponse)
    def source():
        return make_page("source")

    @app.get("/ics-sbom.html", response_class=HTMLResponse)
    def ics_sbom_page():
        return make_page("ics-sbom")

    @app.get("/cert.html", response_class=HTMLResponse)
    def cert_page():
        return make_page("cert")

    @app.get("/context-vex.html", response_class=HTMLResponse)
    def context_vex_html():
        from fastapi.responses import RedirectResponse
        return RedirectResponse('/',status_code=307)

    @app.get("/asset-vex.html", response_class=HTMLResponse)
    def asset_vex_page():
        # merged into the decision page; keep the old URL working
        return make_page("vex-decision")

    return app


# ---------------------------------------------------------------------------
# frontend (single page, calls the API above)
# ---------------------------------------------------------------------------
FRONTEND_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ICS-VEXForge · Vulnerability intelligence</title>
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
.nav .navlabel-sep{margin-top:20px;padding-top:14px;border-top:1px solid var(--line)}
.navtab{font-size:15px;font-weight:600;text-decoration:none;color:var(--ink2);padding:10px 14px;border-radius:9px;border:1px solid transparent;white-space:nowrap}
.navtab:hover{color:var(--ink);background:var(--card2)}
.navtab.on{color:var(--accent);background:var(--card2);border-color:var(--line)}
.navtab-main{font-weight:800;color:var(--accent);border-color:var(--accent);background:var(--card2)}
.navtab-main.on{box-shadow:inset 0 0 0 1px var(--accent)}
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
.kpis{display:flex;flex-wrap:wrap;gap:12px}.kpi{background:var(--card2);border:1px solid var(--line);border-radius:11px;padding:16px 20px;flex:1;min-width:150px;transition:border-color .12s}
.kpi:hover{border-color:color-mix(in srgb,var(--accent) 45%,var(--line))}
.kpi b{font-size:30px}.kpi span{display:block;font-size:13px;color:var(--ink3);font-family:var(--mono);margin-top:2px}
.kpi-n{font-size:32px;font-weight:800;color:var(--accent);line-height:1.05;letter-spacing:-.01em}
.kpi-l{font-size:12.5px;color:var(--ink3);margin-top:6px;line-height:1.35}
.kpi.warn .kpi-n{color:var(--und)}.kpi.bad .kpi-n{color:var(--aff)}
tr.grp td{padding-top:16px;border-bottom:none}
tr.grp b{font-size:14px;color:var(--ink);background:color-mix(in srgb,var(--accent) 10%,transparent);border-left:3px solid var(--accent);padding:4px 12px;border-radius:0 6px 6px 0;display:inline-block}
table{width:100%;border-collapse:collapse;font-size:16px;margin-top:6px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
th{font-size:13px;color:var(--ink3);text-transform:uppercase}.mono{font-family:var(--mono)}
.badge{font-family:var(--mono);font-size:13px;font-weight:700;padding:2px 9px;border-radius:5px}
.pill{display:inline-block;font-family:var(--mono);font-size:12px;font-weight:700;padding:2px 10px;border-radius:999px;border:1px solid var(--line);white-space:nowrap}
.pill-ok{color:var(--safe);background:color-mix(in srgb,var(--safe) 13%,transparent);border-color:color-mix(in srgb,var(--safe) 40%,transparent)}
.pill-und{color:var(--und);background:color-mix(in srgb,var(--und) 13%,transparent);border-color:color-mix(in srgb,var(--und) 40%,transparent)}
.pill-aff{color:var(--aff);background:color-mix(in srgb,var(--aff) 13%,transparent);border-color:color-mix(in srgb,var(--aff) 40%,transparent)}
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
.av-grp{margin:10px 0}.av-grp h4{margin:0 0 6px;font-size:13px;color:var(--ink2)}
.av-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:9px}
.av-f{display:flex;flex-direction:column;gap:3px;font-size:13px}.av-f span{color:var(--ink2)}
.av-f select,.av-f input{background:var(--card2);color:var(--ink);border:1px solid var(--line);border-radius:7px;padding:7px 9px;font-size:13px;font-family:var(--sans)}
.av-verdict{font-size:20px;font-weight:800;padding:10px 14px;border-radius:10px;margin-bottom:10px}
.av-aff{background:rgba(229,103,92,.15);color:var(--aff)}.av-safe{background:rgba(67,190,124,.15);color:var(--safe)}.av-und{background:rgba(224,178,76,.15);color:var(--und)}
.av-lik-aff{background:rgba(229,103,92,.08);color:var(--aff)}.av-lik-safe{background:rgba(67,190,124,.08);color:var(--safe)}.av-lik-mit{background:rgba(96,165,250,.12);color:var(--accent)}.av-lik-cd{background:rgba(224,178,76,.08);color:var(--und)}
.av-chip{display:inline-block;background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:3px 11px;margin:2px 4px 2px 0;font-size:12px;font-family:var(--mono)}
.btn-go{font-size:15px;padding:9px 20px}
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
  <div class="side-brand"><a href="index.html" title="Go to ICS-VEXForge" aria-label="ICS-VEXForge"><svg class="ssrc" viewBox="0 0 120 120"><circle cx="60" cy="60" r="55" fill="none" stroke="#37b24d" stroke-width="3"/><circle cx="60" cy="60" r="47" fill="none" stroke="#37b24d" stroke-width="1.5"/><text x="60" y="52" text-anchor="middle" font-weight="800" font-size="30" fill="#37b24d" font-family="Arial,sans-serif">SSRC</text><text x="60" y="72" text-anchor="middle" font-size="9" letter-spacing="1.5" fill="#37b24d" font-weight="700">SYSTEM SECURITY</text><text x="60" y="87" text-anchor="middle" font-size="8" letter-spacing="1" fill="#69db7c" font-weight="600">★ EST. 2000 ★</text></svg></a></div>
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
const C={LIKELY_AFFECTED:'var(--aff)',LIKELY_NOT_AFFECTED:'var(--safe)',UNDER_INVESTIGATION:'var(--und)'};
const L={LIKELY_AFFECTED:'Affected',LIKELY_NOT_AFFECTED:'Not affected',UNDER_INVESTIGATION:'Under investigation'};
function _statLabel(status){const labels={affected:'Affected',not_affected:'Not affected',fixed:'Fixed',under_investigation:'Under investigation',likely_affected:'Likely affected',likely_not_affected:'Likely not affected',likely_mitigated:'Likely mitigated',likely_cannot_determine:'Cannot determine'};return labels[String(status||'').toLowerCase()]||'Unknown';}
function _statCol(status){const key=String(status||'').toLowerCase();return ['affected','likely_affected'].includes(key)?'#b34747':['fixed','not_affected','likely_not_affected'].includes(key)?'#2e7752':'#8b743b';}
function jsoncParse(txt){var BS=String.fromCharCode(92),NL=String.fromCharCode(10),CR=String.fromCharCode(13);var s='',i=0,n=txt.length,inStr=false,esc=false;while(i<n){var c=txt[i];if(inStr){s+=c;if(esc){esc=false;}else if(c===BS){esc=true;}else if(c==='"'){inStr=false;}i++;continue;}if(c==='"'){inStr=true;s+=c;i++;continue;}if(c==='/'&&txt[i+1]==='/'){while(i<n&&txt[i]!==NL&&txt[i]!==CR){i++;}continue;}if(c==='/'&&txt[i+1]==='*'){i+=2;while(i+1<n&&!(txt[i]==='*'&&txt[i+1]==='/')){i++;}i+=2;continue;}s+=c;i++;}var WS=' '+String.fromCharCode(9)+String.fromCharCode(10)+String.fromCharCode(13);var re=new RegExp(',(['+WS+']*)(}|])','g');return JSON.parse(s.replace(re,'$1$2'));}
function _compCell(f){
  // vendor / product / version are split server-side (_split_component); fall back
  // to the mashed name for any record that predates the split.
  if(f.product||f.vendor){
    var ver=f.version_display||'';
    return '<div>'+esc(f.product||'—')+'</div>'
      +'<div class="hint" style="font-size:12px">'+esc(f.vendor||'—')
      +(ver?' &middot; <span class="mono">'+esc(ver)+'</span>':'')+'</div>';
  }
  return esc((f.component||'')+' '+(f.version||''));
}
async function run(){
  const o=document.getElementById('out');o.innerHTML='<span class="hint">analyzing…</span>';
  let sbom;try{sbom=jsoncParse(document.getElementById('sbom').value)}catch(e){o.innerHTML='<span class="err">invalid JSON</span>';return}
  _lastSbom=sbom;_pidMap=null;
  // Deployment exposure intentionally omitted: it never sets a VEX status (only an
  // SSVC priority), so the analyzer does not collect it on the main bar.
  const r=await fetch('/api/vex',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({sbom,exposure:''})});
  if(!r.ok){o.innerHTML='<span class="err">error '+r.status+'</span>';return}
  const d=await r.json();
  if(!d.cves_matched){o.innerHTML='<div class="hint">'+d.components+' components, no known CVEs matched.</div>'+_abstainBlock(d);return}
  _lastVex=d;
  const bv=d.summary.by_vex||{};
  let h='<div class="hint">'+d.components+' components · identified <b>'+(d.identified!=null?d.identified:'—')+'</b>'
    +' · abstained <b>'+(d.abstained!=null?d.abstained:'—')+'</b> · <b>'+d.cves_matched+' CVEs</b> · '
    +'affected '+(bv.LIKELY_AFFECTED||0)+' · not affected '+(bv.LIKELY_NOT_AFFECTED||0)+' · under inv '+(bv.UNDER_INVESTIGATION||0)+'</div>';
  h+='<table><thead><tr><th>CVE</th><th>VEX</th><th>Component</th><th>CVSS</th><th>KEV</th><th>AV</th><th>Reach</th><th>Source / next step</th></tr></thead><tbody>';
  for(const f of d.cves){const c=C[f.final_vex]||'var(--ink3)';
    const nextcol = '<span class="hint">Review operating context</span>';
    h+='<tr><td class="mono">'+f.cve+'</td>'
      +'<td id="vexcell-'+f.cve+'">'+_vexCellInner(f.cve)+'</td>'
      +'<td>'+_compCell(f)+'</td><td class="mono" title="CVSS v3 base score">'+cvssFmt(f.cvss,f.severity)+'</td>'
      +'<td class="mono">'+(f.kev?'KEV':'')+'</td><td class="mono">'+f.av+'</td>'
      +'<td>'+nextcol+'</td></tr>';}
  h+='</tbody></table>';
  h+=_abstainBlock(d);
  o.innerHTML=_armForkHtml()+'<details class="review-disclosure"><summary>View identified CVEs and initial evidence</summary>'+h+'</details>';
}

// Operating context is collected once and shared by the CVE questionnaire.
let _ocFields=null, _armResult=null, _operationPlan=null;
let _candidateJobId=null, _lastSbom=null;
let _item4ReviewId=null;
function _armForkHtml(){
 _item4ReviewId=null;_armResult=null;
 return '<div class="card" id="armfork" style="margin-top:14px">'
 +'<h3>Operating context and VEX review</h3>'
 +'<p>Review the shared asset context, installed-version records and CVE-specific operating conditions.</p>'
 +'<button class="primary" id="start-product-review" onclick="startItem4Review()">Start operating-context review &rarr;</button>'
 +'<div id="item4routes"></div><div id="armbody" style="margin-top:14px"></div></div>';
}
async function startItem4Review(){
 const box=document.getElementById('item4routes'),button=document.getElementById('start-product-review');
 if(button.disabled)return;button.disabled=true;
 try{
  box.innerHTML='<p>Preparing the operating-context review...</p>';
  const r=await fetch('/api/item4/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({identification_job:_candidateJobId||null,cves:_lastVex?.cves||[],product:_sbomProduct().name,simulation:!!_lastVex?.simulation})});
  if(!r.ok)throw new Error(await r.text());
  _armResult=await r.json();_item4ReviewId=_armResult.review_id;button.hidden=true;sessionStorage.setItem('icsvex-current-review',_item4ReviewId);
  renderItem4Routes();
  await renderOcForm(document.getElementById('armbody'));await generateOperationQuestions();
 }catch(e){box.innerHTML='<p class="err">'+esc(String(e))+'</p>';}
 finally{button.disabled=false;}
}
function renderItem4Routes(){
 const box=document.getElementById('item4routes');if(!box)return;
 box.innerHTML='<details class="review-disclosure"><summary>Operating-context review ('+_armResult.total+' CVEs)</summary>'
 +'<p>Review ID: <code>'+esc(_item4ReviewId)+'</code></p>'
 +'<p>All identified CVEs use shared operating context and individual operator answers. Missing or uncertain evidence remains under investigation.</p>'
 +'<button onclick="downloadOcReview()">Download current review JSON</button></details>';
}
async function renderOcForm(box){
  _operationPlan=null;
  box.innerHTML='<h3>Tell us how the asset is used</h3><p>Enter the shared operating context and installed-version facts first. Add CVE-specific answers where known, then submit to view the assessment.</p>'
    +'<p class="hint">These answers support a review; they do not establish verified code absence.</p>'
    +'<details class="review-help"><summary>How this review works</summary><p>Common asset facts are collected once. Fixed, versioned workflow questions are selected by each CVE’s operational classification. The classification panel shows the criterion and literal source matches. No model generates these questions. Answers are assessed by scope and version checks; the final writer explains the locked status.</p></details>'
    +'<button class="primary" id="generate-operation-questions" onclick="generateOperationQuestions()">Prepare operational questions</button><div id="operation-questions"></div><div id="ocverdict"></div>';
}
async function generateOperationQuestions(){
  const box=document.getElementById('operation-questions'),button=document.getElementById('generate-operation-questions');
  button.disabled=true;box.innerHTML='<p>Preparing shared operating facts, fixed workflow questions and classification evidence.</p>';
  try{
    const cves=(_lastVex?.cves||[]).map(f=>({cve:f.cve,description:f.description||f.summary||'',vector:f.vector||f.cvss_vector||'',cwe:f.cwe}));
    const r=await fetch('/api/item4/'+encodeURIComponent(_item4ReviewId)+'/questions',{method:'POST'});
    if(!r.ok)throw new Error(await r.text());
    _operationPlan=await r.json();button.hidden=true;
    box.innerHTML=renderSharedOperationalContext(_operationPlan)+renderComponentFacts(_operationPlan)+'<section class="card" id="cve-operating-questions"><h3>CVE-specific answers</h3><p>Select a CVE, review its classification evidence, then answer the fixed checks. Your other answers are retained.</p><label>CVE to review<select class="op-control" id="operation-case-select" onchange="showOperationalCase(this.value)">'+_operationPlan.cases.map(c=>'<option value="'+esc(c.cve)+'">'+esc(c.cve)+'</option>').join('')+'</select></label>'+_operationPlan.cases.map((c,ci)=>'<details id="operation_case_'+ci+'" class="card operation-case" '+(ci===0?'open':'hidden')+' style="margin-top:14px"><summary>'+esc(c.cve)+' · '+esc(String(c.questions.filter(q=>!q.deprecated_version_field).length))+' checks</summary><p>'+esc(c.description||'Review the cited CVE evidence before answering.')+'</p><p class="hint">'+esc(c.generation.method==='fixed_operational_templates'?'Fixed workflow templates selected for this CVE. Wording and purposes are versioned; no question model is called.':'Historical question plan; its original method is retained.')+'</p>'
      +renderOperationalClassification(c.operational_classification)
      +'<details class="review-disclosure"><summary>Rule and source record</summary><p class="hint">Method: '+esc(c.generation.method||'Rule templates')+' · Attempts retained: '+esc(String((c.generation.attempts||[]).length))+'</p></details>'
      +((c.generation.normalizations||[]).length?'<p class="hint">Presentation normalization was applied. Original model output and exact changes are retained below.</p>':'')
      +(c.generation.status!=='validated'?'<p class="err">The question plan requires review. No operational facts were fabricated.</p>':'')
      +c.questions.map((q,qi)=>q.deprecated_version_field?'':'<div class="operation-question"><span class="question-kind">'+esc(q.origin==='system'?'Installation record':q.scope==='common'?'Common check':'CVE-specific check')+'</span><label class="question-title" for="oq_'+ci+'_'+qi+'">'+esc(q.question)+'</label>'
        +'<details class="question-evidence"><summary>Why this question'+(q.evidence?' · View source':'')+'</summary>'+renderOperationalQuestionRationale(q)+'</details>'
        +(q.answer_type==='text'?'<textarea class="op-control" maxlength="500" id="oq_'+ci+'_'+qi+'" placeholder="Describe the known facts, or leave empty when unknown"></textarea>':ynControl('oq_'+ci+'_'+qi,'답변'))
        +ynControl('oqe_'+ci+'_'+qi,'이 답변을 뒷받침하는 설정 또는 점검 기록이 있습니까?')+'</div>').join('')
      +renderEvidenceWorkspace(c,ci,_operationPlan)
      +'<details><summary>Generation output and checks</summary><pre style="white-space:pre-wrap">'+esc(JSON.stringify(c.generation,null,2))+'</pre></details></details>').join('')+'</section>'
      +'<button class="primary" id="submit-operation-answers" onclick="judgeOc()">Save operating facts and review VEX</button><p class="hint">The questionnaire is stored locally and expires after 24 hours; a backend restart does not delete it. Download the review JSON to retain questions, answers and evidence.</p>';
    const saved=new Map((_armResult?.statements||[]).flatMap(s=>(s.operational_review?.questions_and_answers||[]).map(q=>[q.id,q.answer])));
    _operationPlan.cases.forEach((c,ci)=>c.questions.forEach((q,qi)=>{const a=saved.get(q.id);if(!a||q.deprecated_version_field)return;document.getElementById('oq_'+ci+'_'+qi).value=q.answer_type==='text'?(a.value||''):['yes','no','unknown'].includes(a.value)?a.value:'unknown';document.getElementById('oqe_'+ci+'_'+qi).value=a.record_available||'unknown';}));
    (_operationPlan.assets||[]).forEach((a,i)=>{const f=_armResult?.component_facts?.[a.ref];if(!f)return;for(const [field,key] of [['present','present'],['matches','sbom_identity_matches'],['record','record_available']])document.getElementById('of_'+field+'_'+i).value=f[key]||'unknown';document.getElementById('of_attest_'+i).value=f.facts_checked||(f.attested?'yes':'unknown');});
    initEvidenceWorkspaces(_operationPlan);
  }catch(e){button.hidden=false;box.innerHTML='<p class="err">'+esc(String(e))+'</p>';}finally{button.disabled=false;}
}
async function generateTunedQuestions(cve){
  alert('This review uses fixed workflow questions. Reopen the questionnaire to select the current versioned templates.');
}
function renderSharedOperationalContext(plan){
 const saved=_armResult?.operational_context||{};
 const select=(id,label)=>ynControl('ctx_'+id,label,saved[id]);
 return '<section class="card" id="shared-operating-context"><h3>Shared product operating context</h3><p>각 항목에 예·아니오·모름으로 답하세요. 확인하지 않은 항목은 모름으로 남겨 주세요.</p>'
 +select('deployment_known','이 제품의 배치 위치와 활성화된 서비스를 확인했습니까?')
 +select('scope_known','검토 대상 장비·인터페이스·데이터 경로의 범위를 알고 있습니까?')
 +(plan.assets||[]).map((a,i)=>ynControl('ctx_component_'+i,esc(a.name||a.ref)+' 구성요소를 실제로 확인했습니까?',(saved.component_refs||[]).includes(a.ref)?'yes':'unknown')).join('')
 +select('network_access','Can untrusted parties or untrusted data reach these components over any network path, including intermediaries?')
 +select('local_access','Can untrusted local users or processes access these components?')
 +select('controls_enforced','Are the stated access restrictions actively enforced and checked?')
 +select('record_available','설정·방화벽·점검 결과를 뒷받침하는 기록이 있습니까?')
 +select('coverage_confirmed','답변이 선택한 구성요소의 관련 인터페이스와 데이터 경로 전체를 포함합니까?')
 +select('facts_checked','실제 설정 또는 점검 기록과 대조해 답변했습니까?')+'</section>';
}
function ynControl(id,label,value){return '<label>'+label+'<select class="op-control" id="'+id+'">'+[['unknown','모름'],['yes','예'],['no','아니오']].map(([v,t])=>'<option value="'+v+'"'+(value===v?' selected':'')+'>'+t+'</option>').join('')+'</select></label>';}
function collectOperationalContext(){
 const result={};for(const k of ['deployment_known','scope_known','network_access','local_access','controls_enforced','record_available','coverage_confirmed','facts_checked'])result[k]=document.getElementById('ctx_'+k).value;
 result.component_refs=(_operationPlan.assets||[]).filter((a,i)=>document.getElementById('ctx_component_'+i).value==='yes').map(a=>a.ref);return result;
}
function renderComponentFacts(plan){
 let html='<style>.op-control{display:block;width:100%;box-sizing:border-box;margin:6px 0 10px;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--card2);color:var(--ink);font:inherit}.op-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}</style>'
  +'<section class="card"><h3>Shared component and installed-version facts</h3><p>Complete each actual component once. These facts are reused across its CVEs. Do not copy advisory versions as installed versions. Unselected or unknown components remain unresolved.</p>';
 (plan.assets||[]).forEach((a,i)=>{
  html+='<article class="card"><h4>'+esc(a.name)+'</h4><p class="hint">Component ref: '+esc(a.ref)+' · Original SBOM version: '+esc(a.reported_sbom_version||'unknown')+'</p><div class="op-facts">'
   +ynControl('of_present_'+i,'이 구성요소가 검토 대상 장비에 있습니까?')
   +ynControl('of_matches_'+i,'실제 제품과 버전이 위 SBOM 정보와 일치합니까?')
   +ynControl('of_record_'+i,'제품·설치 버전을 확인할 수 있는 기록이 있습니까?')+'</div>'
   +ynControl('of_attest_'+i,'실제 장비 또는 기록과 대조해 확인했습니까?')+'</article>';
 });
 return html+'</section>';
}
function collectComponentFacts(){
 const out={};(_operationPlan.assets||[]).forEach((a,i)=>{out[a.ref]={present:document.getElementById('of_present_'+i).value,
 product_name:document.getElementById('of_matches_'+i).value==='yes'?a.name:'',
 installed_version:document.getElementById('of_matches_'+i).value==='yes'?(a.reported_sbom_version||''):'',
 sbom_identity_matches:document.getElementById('of_matches_'+i).value,
 record_available:document.getElementById('of_record_'+i).value,
 facts_checked:document.getElementById('of_attest_'+i).value,
 evidence:'',attested:document.getElementById('of_attest_'+i).value==='yes'};});return out;
}
function downloadSbomVex(){
 if(Object.keys(_armResult?.evidence_reviews||{}).length)return exportEvidenceVex('cyclonedx');
 if(!_armResult?.sbom_vex){alert('No original CycloneDX SBOM was linked to this review.');return;}
 _dl('ics-sbom-with-vex.cdx.json',_armResult.sbom_vex);
}

async function judgeOc(){
  if(!_operationPlan)return;
  const v=document.getElementById('ocverdict'),button=document.getElementById('submit-operation-answers'),answers={};
  _operationPlan.cases.forEach((c,ci)=>c.questions.forEach((q,qi)=>{if(q.deprecated_version_field)return;answers[q.id]={value:document.getElementById('oq_'+ci+'_'+qi).value,record_available:document.getElementById('oqe_'+ci+'_'+qi).value};}));
  button.disabled=true;v.innerHTML='<p>Comparing scoped operating records and installed versions with CVE evidence...</p>';
  try{
    const r=await fetch('/api/item4/'+encodeURIComponent(_item4ReviewId)+'/answers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plan_id:_operationPlan.id,answers,component_facts:collectComponentFacts(),operational_context:collectOperationalContext()})});
    if(!r.ok)throw new Error(await r.text());
    _armResult=await r.json();
    renderItem4Routes();
    v.innerHTML=renderOperationalResults(_armResult);
  }catch(e){v.innerHTML='<p class="err">'+esc(String(e))+'</p>';}finally{button.disabled=false;}
}

function showOperationalCase(cve){
 (_operationPlan?.cases||[]).forEach((c,i)=>{const node=document.getElementById('operation_case_'+i);if(node){node.hidden=c.cve!==cve;node.open=c.cve===cve;}});
}
function editOperationalCase(cve){
 if(!_operationPlan)return;
 const selector=document.getElementById('operation-case-select');if(selector)selector.value=cve;
 showOperationalCase(cve);
 const i=_operationPlan.cases.findIndex(c=>c.cve===cve);const node=document.getElementById('operation_case_'+i);
 if(node){node.scrollIntoView({behavior:'smooth',block:'start'});const control=node.querySelector('.op-control');control?.focus({preventScroll:true});}
}
function editOperationalContext(){
 document.getElementById('shared-operating-context')?.scrollIntoView({behavior:'smooth',block:'start'});
 document.getElementById('ctx_deployment_known')?.focus({preventScroll:true});
}
function renderOperationalResults(result){
 return renderEvidenceDecisionSummary(result)+'<section class="card"><h3>Assessment results</h3><p>These are saved assessment results. Edit the input form to change an answer, then submit again.</p><button onclick="editOperationalContext()">Edit operating context</button></section>'
 +result.statements.filter(s=>s.operational_review).map(s=>{
  const review=s.operational_review;const rows=review.questions_and_answers.filter(q=>!q.deprecated_version_field);
  const recorded=rows.filter(q=>q.answer?.value&&q.answer.value!=='unknown').length;
  return '<section class="card"><div class="case-heading"><h3>'+esc(s.cve)+'</h3><span class="pill">'+esc(_statLabel(s.status))+'</span></div>'
   +'<p>Answered: '+recorded+' / '+rows.length+' · Standard VEX: '+esc(_statLabel(s.status))+'</p><p>'+esc(review.effective_assessment?.explanation||'No accepted effective assessment.')+'</p>'
   +renderOperationalClassification(s.operational_classification||s.analysis_route?.operational_classification)
   +'<button onclick="editOperationalCase(&#39;'+esc(s.cve)+'&#39;)">Edit answers for this CVE</button>'
   +'<table><thead><tr><th>Question</th><th>Saved answer</th><th>Supporting record</th></tr></thead><tbody>'+rows.map(q=>'<tr><td>'+esc(q.question)+'</td><td>'+esc(!q.answer?.value||q.answer.value==='unknown'?'Not answered / unknown':q.answer.value)+'</td><td>'+esc(q.answer?.evidence||'Not provided')+'</td></tr>').join('')+'</tbody></table>'
   +'<details><summary>Technical assessment record (JSON)</summary><pre style="white-space:pre-wrap">'+esc(JSON.stringify(review,null,2))+'</pre></details></section>';
 }).join('')+'<details><summary>Standard VEX statuses and export</summary>'+_verdictTable(result,'Operational questionnaire')+'</details><button onclick="downloadOcReview()">Download review log (JSON)</button>';
}

async function downloadOcReview(){
  if(Object.keys(_armResult?.evidence_reviews||{}).length){try{const response=await fetch('/api/item4/reviews/'+encodeURIComponent(_item4ReviewId));if(!response.ok)throw new Error('Review could not be refreshed.');_armResult=await response.json()}catch(error){alert(error.message);return}}
  const url=URL.createObjectURL(new Blob([JSON.stringify({schema:'ics-vex-context-review/1',..._armResult},null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='ics-vex-context-review.json';a.click();URL.revokeObjectURL(url);
}

function _versionEvidenceHtml(result){
 let h='';
 for(const s of result.statements||[]){
  const evaluation=s.operational_review?.version_evaluation;
  if(!evaluation)continue;
  h+='<section class="card"><h3>'+esc(s.cve)+' · Installed-version comparison</h3><table><thead><tr><th>Component</th><th>Reported product / version</th><th>Vendor evidence</th><th>Installation record</th></tr></thead><tbody>';
  for(const row of evaluation.components||[]){
   h+='<tr><td>'+esc(row.component_ref)+'</td><td>'+esc(row.product_name||'Unknown product')+' / '+esc(row.installed_version||'Unknown version')+'</td><td>'+esc(row.state)+'</td><td>'+esc(row.operator_attested&&row.operator_evidence?'Operator-attested record; not independently verified':'Missing or unattested')+'</td></tr>';
  }
  h+='</tbody></table><p class="hint">'+esc(evaluation.comparison_policy)+'</p></section>';
 }
 const schema=result.sbom_vex_validation;
 if(schema)h+='<p class="hint">SBOM export schema: '+esc(schema.status)+'. '+esc(schema.reason||'Schema validation checks document structure, not the accuracy of an asset assessment.')+'</p>';
 return h;
}

function _groundedPipelineHtml(result){
  if(!result.pipeline)return '';
  let html='<div class="card"><h3>Review progress</h3><p>CVE evidence extraction &rarr; operating-context review &rarr; VEX explanation</p>'
    +'<p>VEX explanations completed: '+result.pipeline.complete_cases+'</p></div>';
  for(const s of result.statements){
    if(s.extraction?.status==='not_run' && s.authoring?.status==='not_run')continue;
    const x=s.extraction||{},w=s.authoring||{},draft=s.document_draft;
    html+='<details class="card" style="margin-top:10px"><summary>'+esc(s.cve)+' · Extraction: '+esc(x.status||'unknown')+' · Authoring: '+esc(w.status||'unknown')+'</summary>'
      +'<p class="hint">Case: '+esc(s.case_id||'')+'</p>';
    if(x.usable){
      html+='<h4>Quoted condition candidates</h4><ul>'+(x.prediction.conditions||[]).map(c=>'<li>'+esc(c.kind)+': '+esc(c.evidence)+'</li>').join('')+'</ul>'
        +'<h4>Mentioned function candidates</h4><ul>'+(x.prediction.function_candidates||[]).map(f=>'<li>'+esc(f.name)+' · '+esc(f.evidence)+'</li>').join('')+'</ul>';
    }else html+='<p>Extraction was not accepted. '+esc(x.reason||'Schema, literal quotation or policy checks failed.')+'</p>';
    if(draft)html+='<h4>Generated VEX explanation (draft)</h4><p>'+esc(draft.impact_statement)+'</p>'
      +(draft.action_statement?'<p>'+esc(draft.action_statement)+'</p>':'')+'<p>Evidence IDs: '+esc(draft.evidence_refs.join(', '))+'</p>';
    else html+='<p>Generated explanation was not accepted. '+esc(w.error==='output_token_limit'?'The response reached the output limit before completing JSON.':w.error==='invalid_json_output'?'The model did not return a complete JSON object.':w.reason||JSON.stringify(w.diagnostics||{})||'Decision, identifier, evidence-reference or format checks failed.')+'</p>';
    html+='<details><summary>Model outputs and checks</summary><pre style="white-space:pre-wrap">'+esc(JSON.stringify({extraction:x,authoring:w},null,2))+'</pre></details>'
      +'<details><summary>Evidence supplied to the VEX writer</summary><pre style="white-space:pre-wrap">'+esc(JSON.stringify(s.evidence_packet,null,2))+'</pre></details></details>';
  }
  return html+_versionEvidenceHtml(result);
}

function _verdictTable(res,armLabel){
  const C2={affected:'var(--aff)',not_affected:'var(--safe)',under_investigation:'var(--ink3)',fixed:'var(--safe)'};
  // 판정률을 상태 분포와 같은 줄에 놓는다. 유보는 Precision 분모에서 빠지므로
  // 유보율을 가린 정밀도는 성취가 아니라 회피다 (docs/ICSVEX.md §8).
  let h='<div class="hint">'+esc(armLabel)+' · 전체 <b>'+res.total+'</b>'
    +' · 판정 <b>'+Math.round((res.decision_rate||0)*100)+'%</b>'
    +' · 유보 <b>'+res.deferred+'</b></div>'
    +'<table style="margin-top:8px"><thead><tr><th>CVE</th><th>VEX</th><th>정당화</th><th>근거</th></tr></thead><tbody>';
  for(const s of res.statements){
    const col=C2[s.status]||'var(--ink3)';
    h+='<tr><td class="mono">'+esc(s.cve)+'</td>'
      +'<td><span class="badge" style="background:color-mix(in srgb,'+col+' 12%,transparent);color:'+col+'">'+esc(_statLabel(s.status))+'</span></td>'
      +'<td class="mono" style="font-size:14px">'+esc(s.justification||'—')+'</td>'
      +'<td class="hint">'+esc(s.reason||'')+'</td></tr>';
  }
  return h+'</tbody></table><section class="export-actions"><h3>Download your assessment</h3><p class="hint">'+(res.sbom_vex?'SBOM + VEX keeps the original component inventory with its assessment. OpenVEX and CSAF are standalone VEX documents.':'OpenVEX and CSAF provide standalone VEX documents for this review.')+'</p>'
    +'<div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">'
    +'<button class="treebtn" onclick="exportOpenVex()">Download OpenVEX</button>'
    +'<button class="treebtn" onclick="exportCsaf()">Download CSAF VEX</button>'+(res.sbom_vex?'<button class="primary" onclick="downloadSbomVex()">Download SBOM + VEX (CycloneDX)</button>':'')+'</div></section>';
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
    fn.textContent='loaded '+f.name+' — press Analyze ▶';
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
  try{const s=await(await fetch('/api/summary')).json();
    const v=s.by_vex||{}, ax=s.axes||{};
    // Axis cards - the CVE is the unit a VEX verdict is about. Product and statement axes are not shown.
    const ak=document.getElementById('kpis-axes');
    if(ak){ak.innerHTML='';
      const AX=[['cves','unique CVEs','vulnerability identifiers'],
                ['advisories_collected','ICS advisories','source, 2010–2026'],
                ['advisories_with_cves','advisories with CVEs','not a unique-product count']];
      for(const [key,lab,sub] of AX)
        ak.innerHTML+='<div class="kpi"><b>'+(ax[key]||0).toLocaleString()+'</b><span>'+lab+'<br><span class="hint" style="font-size:11px">'+sub+'</span></span></div>';}

  }catch(e){const sk=document.getElementById('kpis-src');if(sk)sk.innerHTML='<span class="err">Source inventory unavailable — refresh the backend or public snapshot</span>';}
}
const SEVC={critical:'var(--aff)',high:'#e08d5b',medium:'var(--und)',low:'var(--safe)',unrated:'var(--ink3)'};
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function openCves(dim,value,scope,label){
 document.getElementById('mtitle').textContent=label;
 document.getElementById('ov').classList.add('on');
 try{
  const r=await fetch('/api/cves?dim='+encodeURIComponent(dim)+'&value='+encodeURIComponent(value)+'&scope=corpus');
  if(!r.ok)throw new Error('CVE lookup failed');const d=await r.json();
  document.getElementById('mbody').innerHTML='<p>'+d.count+' CVEs</p><table><thead><tr><th>CVE</th><th>Severity</th><th>Vendor</th><th>Component</th></tr></thead><tbody>'
  +d.cves.map(f=>'<tr><td><a href="https://nvd.nist.gov/vuln/detail/'+esc(f.cve)+'" target="_blank" rel="noopener">'+esc(f.cve)+'</a></td><td>'+esc(f.severity)+'</td><td>'+esc(f.vendor)+'</td><td>'+esc(f.component)+'</td></tr>').join('')+'</tbody></table>';
 }catch(e){document.getElementById('mbody').textContent=String(e);}
}
function closeCves(){document.getElementById('ov').classList.remove('on');}
function bar(counts,order,cmap,total,dim,scope,lmap){
  let segs='',leg='';
  for(const k of order){const v=counts[k]||0;if(!v)continue;const w=100*v/total;
    const lbl=(lmap&&lmap[k])||k;const cl=dim?' class="clk"':'';
    const clk=dim?' onclick="openCves(\\''+dim+'\\',\\''+k+'\\',\\''+scope+'\\',\\''+lbl.replace(/'/g,'')+' — related CVEs\\')"':'';
    segs+='<div'+cl+clk+' style="width:'+w.toFixed(2)+'%;background:'+(cmap[k]||'var(--ink3)')+'" title="'+lbl+': '+v+'"></div>';
    leg+='<span class="lg'+(dim?' clk':'')+'"'+clk+'><i style="background:'+(cmap[k]||'var(--ink3)')+'"></i>'+lbl+' <b>'+v+'</b></span>';}
  return '<div class="mb">'+segs+'</div><div class="legend">'+leg+'</div>';
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
    const yt=document.getElementById('year-total');
    if(yt)yt.textContent='all '+Number(s.total_cves).toLocaleString()+' · by CVE-ID year';
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
  if(s==='LIKELY_FIXED')return 'fixed';
  if(s==='UNDER_INVESTIGATION')return 'under_investigation';
  if(s==='not_affected')return 'not_affected';
  if(s==='route_to_icsvexforge')return 'under_investigation';
  if(s.indexOf('likely_affected')===0)return 'affected';
  if(s==='likely_not_affected')return 'not_affected';
  if(s==='likely_mitigated')return 'under_investigation';
  if(s==='likely_cannot_determine')return 'under_investigation';
  if(s==='under_investigation')return 'under_investigation';
  if(s==='fixed')return 'fixed';
  return 'under_investigation';}
// A CISA justification is attached only when there are grounds for it. With no match
// this returns null, and the caller gives up not_affected and falls to
// under_investigation. Deployment context (perimeter, segmentation, firewall) is not
// grounds for ANY justification, so it is not mapped here - a claim resting on it goes
// quietly false the moment the topology changes.
function _ovJust(j){j=String(j||'');
  if(!j)return null;
  if(/component_not_present/.test(j))return 'component_not_present';
  if(/vulnerable_code_not_present/.test(j))return 'vulnerable_code_not_present';
  if(/not_in_execute_path/.test(j))return 'vulnerable_code_not_in_execute_path';
  if(/cannot_be_controlled_by_adversary/.test(j))return 'vulnerable_code_cannot_be_controlled_by_adversary';
  if(/inline_mitigations_already_exist/.test(j))return 'inline_mitigations_already_exist';
  return null;}
// Whether not_affected may be emitted at all: only with a valid justification.
function _justOrNull(r){
  if(r.justification&&VEX_JUST.some(x=>x[0]===r.justification))return r.justification;
  return _ovJust(r.justification);}
function _effStatus(r){
  if(r.status==='not_affected'&&!_justOrNull(r)&&!(r.reviewed_evidence&&r.impact_statement))return 'under_investigation';
  return r.status;}
function _autoStatus(cve){
  const f=(_lastVex&&_lastVex.cves||[]).find(x=>x.cve===cve)||{};
  let raw=f.final_vex, just=f.justification||'';
  return {status:_canonStatus(raw), justification:just, cvss:f.cvss, component:f.component||'', av:f.av||''};}
function _rowStatus(cve){
 const statement=_armResult?.statements?.find(s=>s.cve===cve);
 return {status:statement?.status||'under_investigation'};
}
function _abstainBlock(d){
  // An abstention is a decision, not a gap. The matcher declines rather than
  // guess when no CPE product is a clear winner - picking one at 0.381 against
  // a 0.381 runner-up is how a Schneider I/O module's CVE lands on a VIVOTEK
  // camera. Showing the count and the reason is what separates "declined" from
  // "not implemented", which is otherwise indistinguishable on this screen.
  const u = d.unidentified || [];
  if(!u.length) return '';
  const rows = u.map(x =>
      '<tr><td>'+_esc(x.component)+'</td><td class="mono">'+_esc(x.version)+'</td>'
      +'<td class="hint">'+_esc(x.reason||'')+'</td></tr>').join('');
  return '<details style="margin-top:12px"><summary class="hint">'
    +u.length+' components not identified — see why</summary>'
    +'<p class="hint" style="margin:8px 0">When no candidate is clear the matcher <b>abstains '
    +'rather than guessing</b>. Many ICS devices have no entry at all in the NVD CPE '
    +'dictionary, so name-based matching cannot reach them.</p>'
    +'<table><thead><tr><th>Component</th><th>Version</th><th>Reason for abstaining</th></tr></thead><tbody>'
    +rows+'</tbody></table></details>';
}
function _esc(v){return String(v==null?'':v).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function _vexCellInner(cve){var rs=_rowStatus(cve);var col=_statCol(rs.status);var est=rs.estimated?' <span class="hint" style="font-size:11px">(asset-based)</span>':'';return '<span class="badge" style="background:'+col+'22;color:'+col+'">'+_statLabel(rs.status)+'</span>'+est+' <button class="treebtn" style="padding:2px 7px;font-size:12px" onclick="openVexEditor(\\''+cve+'\\')">&#9998; VEX</button>';}
// Export the locked operational decision and its accepted explanation.
function _applyGroundedVex(row){
  const s=(_armResult?.statements||[]).find(s=>s.cve===row.cve);if(!s)return row;
  const d=s.document_draft;
  return Object.assign({},row,{status:s.status,justification:s.justification||'',impact_statement:d?.impact_statement||s.reason||'',
    action_statement:d?.action_statement||null,evidence_refs:d?.evidence_refs||[],model_authoring_status:s.authoring?.status||'unavailable',review_required:true,reviewed_evidence:!!s.evidence_decision});
}
function _vexRows(){const rows=[];for(const f of ((_lastVex&&_lastVex.cves)||[])){const rs=_rowStatus(f.cve);const ov=_vexFields[f.cve]||{};const r=Object.assign({cve:f.cve,component:f.component||'',cvss:f.cvss,av:f.av||'',kev:!!f.kev,justification:_autoStatus(f.cve).justification},ov);r.status=rs.status;rows.push(_applyGroundedVex(r));}return rows;}
function _sbomProduct(){
  const c=(_lastSbom&&_lastSbom.metadata&&_lastSbom.metadata.component)||{};
  return {name:c.name||'SBOM target', ref:c['bom-ref']||'PRODUCT-1', purl:c.purl||''};}
// A VEX statement is about a component, not the whole product. Each SBOM component gets
// a stable CSAF product_id so flags/product_status can say WHICH component they mean.
let _pidMap=null;
function _componentPids(){
  if(_pidMap)return _pidMap;
  _pidMap={byName:{},list:[]};
  const comps=((_lastSbom&&_lastSbom.components)||[]);
  comps.forEach((c,i)=>{
    const nm=(c.name||'').trim(); if(!nm||_pidMap.byName[nm.toLowerCase()])return;
    const pid='CSAFPID-'+String(i+1).padStart(4,'0');
    _pidMap.byName[nm.toLowerCase()]=pid;
    const ver=(c.version||'').trim();
    _pidMap.list.push({product_id:pid,
      name:nm+(ver&&ver!=='NOASSERTION'?(' '+ver):''),
      purl:c.purl||''});});
  return _pidMap;}
function _pidFor(component){
  const m=_componentPids(); const k=String(component||'').trim().toLowerCase();
  return (k&&m.byName[k])||null;}
// The same SBOM gets the same document id - a fresh id per run would destroy traceability.
function _docId(name){let h=0;const t='ICSVEXFORGE|'+name;
  for(let i=0;i<t.length;i++){h=((h<<5)-h+t.charCodeAt(i))|0;}
  return 'ICSVEXFORGE-'+(h>>>0).toString(16).toUpperCase();}
function _isoNow(){return new Date().toISOString();}
function _dl(name,obj){const b=new Blob([JSON.stringify(obj,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1500);}
function _opt(list,cur){return list.map(o=>'<option value="'+o[0]+'"'+(o[0]===cur?' selected':'')+'>'+esc(o[1])+'</option>').join('');}
function _fld(id,label,val){return '<label class="vexf"><span class="hint">'+esc(label)+'</span><input id="'+id+'" class="srch" value="'+esc(val||'')+'"></label>';}
function _ssvcPanel(cve){var p=ssvcFor(cve);var h='<label class="vexf"><span class="hint">Exploitation (auto: KEV/EPSS)</span><select id="vf-e" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_EXPL,p.exploitation)+'</select></label>';h+='<label class="vexf"><span class="hint">System Exposure (auto: deployment exposure)</span><select id="vf-x" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_EXPO,p.exposure)+'</select></label>';h+='<label class="vexf"><span class="hint">Automatable (auto: CVSS AV)</span><select id="vf-a" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_AUTO,p.automatable)+'</select></label>';h+='<label class="vexf"><span class="hint">Human Impact (safety/mission &mdash; operator input)</span><select id="vf-h" class="srch" onchange="ssvcRecalc()">'+_opt(SSVC_HI,p.human_impact)+'</select></label>';h+='<div id="vf-ssvc-dec" class="vm-verd" style="margin-top:4px"></div>';return h;}function _ssvcCur(){return {exploitation:_v('vf-e'),exposure:_v('vf-x'),automatable:_v('vf-a'),human_impact:_v('vf-h')};}function ssvcRecalc(){var p=_ssvcCur();var d=ssvcDecide(p);var el=document.getElementById('vf-ssvc-dec');if(el)el.innerHTML='SSVC priority: <b style="color:'+(SSVC_COL[d]||'var(--ink)')+'">'+d+'</b> &middot; <span class="mono hint">'+ssvcVector(p)+'</span>';}
function openVexEditor(cve){
 if(!_item4ReviewId){startItem4Review();return;}
 editOperationalCase(cve);
}
function exportOpenVex(){
  if(typeof _armResult!=='undefined'&&Object.keys(_armResult?.evidence_reviews||{}).length)return exportEvidenceVex('openvex');
  const rows=_vexRows(); if(!rows.length){alert('Run an analysis first.');return;}
  const p=_sbomProduct(); const now=_isoNow();
  const stmts=rows.map(r=>{
    const cpid=_pidFor(r.component);
    const prodId=cpid?('pkg:generic/'+encodeURIComponent(r.component)):(p.purl||('pkg:generic/'+encodeURIComponent(p.name)));
    const st={vulnerability:{name:r.cve},
      products:[Object.assign({"@id":prodId},p.purl&&!cpid?{identifiers:{purl:p.purl}}:{})],
      timestamp:now,
      status:_effStatus(r)};
    // status_notes is a field of the OpenVEX spec. No non-standard field is hung on a statement.
    const sn=[];
    if(r.status==='not_affected'&&st.status==='not_affected'){
      st.justification=_justOrNull(r);
      if(r.impact_statement||r.action_statement)st.impact_statement=r.impact_statement||r.action_statement;}
    else if(st.status==='affected'){
      st.action_statement=(r.remediation?(r.remediation+': '):'')+(r.action_statement||('Apply vendor update or mitigation for '+r.component+'.'));}
    else if(st.status==='fixed'){
      const bits=[];if(r.fixed_version)bits.push('fixed in '+r.fixed_version);if(r.patch_reference)bits.push('patch: '+r.patch_reference);if(r.verification_result)bits.push('verified: '+r.verification_result);
      if(bits.length)st.impact_statement=bits.join('; ');}
    else{
      if(r.status==='not_affected')sn.push('downgraded from not_affected: no CISA justification could be evidenced');
      if(r.investigation_progress)sn.push('progress: '+r.investigation_progress);
      if(r.missing_evidence)sn.push('missing: '+r.missing_evidence);
      if(r.planned_update)sn.push('planned: '+r.planned_update);}
    if(r.impact_statement&&_effStatus(r)!=='not_affected')sn.push('Explanation: '+r.impact_statement);
    if(r.evidence_refs?.length)sn.push('Evidence IDs: '+r.evidence_refs.join(', '));
    if(r.review_required)sn.push('Draft for review; model authoring: '+r.model_authoring_status);
    if(sn.length)st.status_notes=sn.join(' | ');
    return st;});
  const doc={"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://kakyung98.github.io/ics-vex-dashboard/vex/"+_docId(p.name),
    author:"ICS-VEXForge (Chonnam SSRC)",role:"Document Creator",timestamp:now,version:1,tooling:"ICS-VEXForge",statements:stmts};
  _dl('openvex-'+(p.name.replace(/[^a-z0-9]+/gi,'-').toLowerCase())+'.json',doc);}
function exportCsaf(){
  if(typeof _armResult!=='undefined'&&Object.keys(_armResult?.evidence_reviews||{}).length)return exportEvidenceVex('csaf');
  const rows=_vexRows(); if(!rows.length){alert('Run an analysis first.');return;}
  const p=_sbomProduct(); const pid=p.ref||'PRODUCT-1'; const now=_isoNow();
  const B2C={affected:'known_affected',not_affected:'known_not_affected',fixed:'fixed',under_investigation:'under_investigation'};
  const used={};
  const vulns=rows.map(r=>{
    const st=_effStatus(r);
    // The statement is about a component; it falls back to the whole product only when
    // no component matches.
    const cpid=_pidFor(r.component)||pid; used[cpid]=1;
    const v={cve:r.cve,product_status:{}};v.product_status[B2C[st]]=[cpid];
    const notes=[{category:'other',title:'ICS-VEXForge assessment',
      text:'status='+st+'; component='+r.component+(r.cvss!=null?('; cvss='+r.cvss):'')+(r.av?('; av='+r.av):'')}];
    if(r.impact_statement)notes.push({category:'description',title:'Evidence-based explanation (draft)',text:r.impact_statement});
    if(r.evidence_refs?.length)notes.push({category:'other',title:'Evidence IDs',text:r.evidence_refs.join(', ')});
    if(r.review_required)notes.push({category:'other',title:'Review required',text:'Draft; model authoring: '+r.model_authoring_status});
    if(st==='not_affected'){
      // CSAF carries a justification as flags[].label. Nothing reaches here without grounds.
      v.flags=[{label:_justOrNull(r),product_ids:[cpid]}];
      const explanations={component_not_present:'The vulnerable component is absent from the assessed product.',vulnerable_code_not_present:'The component is present, but the CVE-specific vulnerable code is absent.',vulnerable_code_not_in_execute_path:'The CVE-specific vulnerable code is outside the assessed execution paths.',vulnerable_code_cannot_be_controlled_by_adversary:'An adversary cannot control the vulnerable code under the assessed conditions.',inline_mitigations_already_exist:'Built-in inline mitigations prevent exploitation under the assessed conditions.'};
      const impact=[explanations[_justOrNull(r)],r.impact_statement||r.action_statement||r.basis].filter(Boolean).join(' ');
      v.threats=[{category:'impact',details:impact,product_ids:[cpid]}];
      if(r.action_statement)notes.push({category:'description',title:'Impact',text:r.action_statement});}
    else if(st==='affected'){
      v.remediations=[{category:_remedCsaf(r.remediation),
        details:(r.action_statement||('Apply '+(r.remediation||'patch_or_firmware_upgrade')+' for '+r.component)),product_ids:[cpid]}];}
    else if(st==='fixed'){
      const bits=[];if(r.fixed_version)bits.push('Fixed version: '+r.fixed_version);if(r.patch_reference)bits.push('Patch reference: '+r.patch_reference);if(r.verification_result)bits.push('Verification: '+r.verification_result);
      if(bits.length)notes.push({category:'details',title:'Fix',text:bits.join(' | ')});
      if(r.fixed_version)v.remediations=[{category:'vendor_fix',details:'Fixed in '+r.fixed_version+(r.patch_reference?(' ('+r.patch_reference+')'):''),product_ids:[cpid]}];}
    else{
      const bits=[];
      if(r.status==='not_affected')bits.push('Downgraded from not_affected: no CISA justification could be evidenced');
      if(r.investigation_progress)bits.push('Progress: '+r.investigation_progress);
      if(r.missing_evidence)bits.push('Missing evidence: '+r.missing_evidence);
      if(r.planned_update)bits.push('Planned update: '+r.planned_update);
      if(bits.length)notes.push({category:'details',title:'Investigation',text:bits.join(' | ')});}
    if(r.kev)v.threats=[...(v.threats||[]),{category:'exploit_status',details:'Listed in CISA KEV (known exploited)',product_ids:[cpid]}];
    v.notes=notes; return v;});
  const comps=_componentPids().list.filter(c=>used[c.product_id]);
  const fpn=[Object.assign({product_id:pid,name:p.name},p.purl?{product_identification_helper:{purl:p.purl}}:{})]
    .concat(comps.map(c=>Object.assign({product_id:c.product_id,name:c.name},
      c.purl?{product_identification_helper:{purl:c.purl}}:{})));
  const doc={document:{category:'csaf_vex',csaf_version:'2.0',title:'ICS-VEXForge VEX — '+p.name,
      // We are not the product supplier; publishing as `vendor` would impersonate one.
      publisher:{category:'other',name:'ICS-VEXForge (Chonnam SSRC)',
        namespace:'https://kakyung98.github.io/ics-vex-dashboard/',
        issuing_authority:'Third-party SBOM-based analysis. Not the product supplier.'},
      tracking:{id:_docId(p.name),status:rows.some(r=>r.review_required)?'draft':'final',version:'1',initial_release_date:now,current_release_date:now,
        revision_history:[{number:'1',date:now,summary:'Initial VEX generated by ICS-VEXForge.'}],generator:{engine:{name:'ICS-VEXForge',version:'2026.08'}}}},
    product_tree:{full_product_names:fpn},
    vulnerabilities:vulns};
  _dl('csaf-vex-'+(p.name.replace(/[^a-z0-9]+/gi,'-').toLowerCase())+'.json',doc);}


function refreshVexRow(cve){
 const vc=document.getElementById('vexcell-'+cve);if(vc)vc.innerHTML=_vexCellInner(cve);
}
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
function cveSearchLocal(q){if(typeof CVE_INDEX==='undefined'||!CVE_INDEX.length)return [];const ql=q.toLowerCase();const rk={LIKELY_AFFECTED:3,UNDER_INVESTIGATION:2,LIKELY_NOT_AFFECTED:1,LIKELY_FIXED:0};
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
  for(const f of items){h+='<tr><td class="idcell"><a href="https://nvd.nist.gov/vuln/detail/'+esc(f.cve)+'" target="_blank" rel="noopener">'+esc(f.cve)+'</a><br><button onclick="showOperationalClassification(&#39;'+esc(f.cve)+'&#39;)">Type and evidence</button></td>'
    +'<td class="mono" style="text-align:center">'+cvssFmt(f.cvss,f.severity)+'</td><td class="mono hint">'+esc(f.cwe||'')+'</td>'
    +'<td class="mono" style="text-align:center">'+(f.kev?'KEV':'')+'</td><td>'+esc(f.vendor||'')+'</td><td class="hint">'+esc(f.component||'')+'</td></tr>';}
  out.innerHTML=h+'</tbody></table></div>';
}

const PVJUST_COL={component_not_present:'var(--safe)','vulnerable_code_not_present':'#37b24d','vulnerable_code_not_in_execute_path':'#69db7c','vulnerable_code_cannot_be_controlled_by_adversary':'var(--und)',inline_mitigations_already_exist:'var(--und)'};
async function publishedVex(){
  const box=document.getElementById('pv-rows');if(!box)return;
  try{
    const d=await tryJson(['/api/published_vex','published_vex.json']);
    const rows=(d&&d.rows)||[];const bj=(d&&d.by_justification)||{};
    const hint=document.getElementById('pv-hint');
    if(hint)hint.textContent=d?(d.advisories+' advisories · '+d.pairs+' (ICSA×CVE) pairs'):'';
    const snapshot=document.getElementById('pv-snapshot');if(snapshot)snapshot.textContent=d.available?('Collected snapshot: '+d.source_snapshot+' · Documents scanned: '+d.documents_scanned):'No collected CSAF snapshot available.';
    const environmentCount=(bj.vulnerable_code_cannot_be_controlled_by_adversary||0)+(bj.inline_mitigations_already_exist||0);
    document.getElementById('pv-kpis').innerHTML=
      '<div class="kpi"><b>'+(d.advisories||0)+'</b><span>advisories (documents)</span></div>'+
      '<div class="kpi"><b>'+(d.pairs||0)+'</b><span>ICSA × CVE pairs</span></div>'+
      '<div class="kpi"><b>'+(d.label_instances||0)+'</b><span>label instances<br><span class="hint" style="font-size:11px">one CVE may carry 2 labels</span></span></div>'+
      '<div class="kpi"><b style="color:var(--und)">'+environmentCount+'</b><span>environment-related label instances</span></div>';
    // justification distribution
    let ch='<div class="ct">Justification distribution (label instances)</div>';
    const tot=Object.values(bj).reduce((a,b)=>a+b,0)||1;
    for(const k of Object.keys(bj).sort((a,b)=>bj[b]-bj[a])){
      const w=Math.round(bj[k]/tot*100);const c=PVJUST_COL[k]||'var(--ink3)';
      ch+='<div style="margin:4px 0"><span class="mono" style="font-size:12px">'+esc(k)+'</span> <b>'+bj[k]+'</b>'+
          '<div style="height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:2px"><div style="height:100%;width:'+w+'%;background:'+c+'"></div></div></div>';}
    document.getElementById('pv-charts').innerHTML=ch;
    // rows table
    let h='<div class="srch-wrap"><table><thead><tr><th>CVE</th><th>Advisory</th><th>CSAF source</th><th>Vendor</th><th>Products the flag names</th><th>Justification</th></tr></thead><tbody>';
    for(const r of rows){const c=PVJUST_COL[r.justification]||'var(--ink3)';
      const labs=(r.labels||[]).map(l=>'<span class="badge" style="background:'+((PVJUST_COL[l]||'var(--ink3)'))+'22;color:'+((PVJUST_COL[l]||'var(--ink3)'))+'">'+esc(l)+'</span>').join(' ');
      h+='<tr><td class="idcell"><a href="https://nvd.nist.gov/vuln/detail/'+esc(r.cve)+'" target="_blank" rel="noopener">'+esc(r.cve)+'</a></td>'+
         '<td class="mono hint">'+(r.url?('<a href="'+esc(r.url)+'" target="_blank" rel="noopener">'+esc(r.advisory)+'</a>'):esc(r.advisory))+'</td>'+
         // the flags this row asserts live in the CSAF document, not on the
         // advisory page - link both the upstream JSON and our pinned copy
         '<td class="mono hint" style="white-space:nowrap">'+(r.csaf_url?('<a href="'+esc(r.csaf_url)+'" target="_blank" rel="noopener">upstream</a>'):'&mdash;')+(r.csaf_local?(' &middot; <a href="'+esc(r.csaf_local)+'" target="_blank" rel="noopener">pinned</a>'):'')+'</td>'+
         // a VEX statement is product x vulnerability x status, so name the
         // products the flag actually covers rather than the advisory title
         '<td class="hint">'+esc(r.vendor||'')+'</td>'+
         '<td class="hint">'+((r.products&&r.products.length)
           ? r.products.map(p=>'<div><span class="mono">'+esc(p.product||'')+'</span>'
               +(p.version?' <span class="hint" style="opacity:.7">'+esc(p.version)+'</span>':'')
               // a CVE can carry a different justification per product
               +((r.labels&&r.labels.length>1&&p.label)?(' <span class="badge" style="background:'+((PVJUST_COL[p.label]||'var(--ink3)'))+'22;color:'+((PVJUST_COL[p.label]||'var(--ink3)'))+'">'+esc(p.label)+'</span>'):'')
               +'</div>').join('')
               +((r.product_count>r.products.length)?('<div class="hint">+'+(r.product_count-r.products.length)+' more</div>'):'')
           : esc((r.title||'').replace(/^[A-Za-z]+ /,'')))+'</td>'+
         '<td>'+labs+'</td></tr>';}
    box.innerHTML=h+'</tbody></table></div>';
  }catch(e){box.innerHTML='<span class="err">published VEX unavailable</span>';}
}
if(document.getElementById('kpis-axes'))stats();
if(document.getElementById('adv-kpis'))advisories();
if(document.getElementById('year'))yearChart();



if(document.getElementById('pv-kpis'))publishedVex();
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
__OPERATIONAL_CLASSIFICATION_JS__
__EVIDENCE_WORKSPACE_JS__
__ASSET_AV_JS__
</script></body></html>"""

# ---- page content blocks (split across 3 pages) --------------------------
ANALYZER_HTML = """<div class="card"><div class="row">
  <div><label>CycloneDX SBOM (JSON) — paste, upload, or drag a .json file here</label><textarea id="sbom" placeholder='Drag a .json SBOM file here, or paste: {"components":[{"name":"OpenSSL","version":"1.1.1k"}]}'></textarea></div>
  <div><input type="file" id="file" accept=".json,application/json" style="display:none">
    <button class="primary" onclick="run()">Analyze ▶</button>
    <button onclick="document.getElementById('file').click()">Upload JSON</button>
    <button onclick="ex()">Example</button>
    <div id="fname" class="hint" style="margin-top:6px"></div></div>
</div><div id="out" style="margin-top:12px"></div></div>"""

CORPUS_HTML = """<div class="card"><h3 style="margin:0 0 8px">CVE coverage and advisory scope</h3><div id="kpis-axes" class="kpis hint">loading…</div>
<p class="hint" style="margin-top:10px">Advisories group the source material. These totals describe the corpus, not completed assessments. A VEX decision applies to a <b>product/component and CVE pair</b>; one advisory can cover several products and vulnerabilities.</p></div>
<div class="card"><h3 style="margin:0 0 4px">CISA ICS advisories <span class="hint">the source data · 2010–2026</span></h3>
<div id="adv-kpis" class="kpis" style="margin-top:8px">loading…</div>
<div id="adv-year" style="margin-top:14px"></div>
<div id="adv-ven" style="margin-top:14px"></div></div>

<div class="card"><h3 style="margin:0 0 4px">CVEs by year <span class="hint" id="year-total">by CVE-ID year</span></h3>
<div id="year" style="margin-top:12px">loading…</div></div>"""

PUBLISHED_VEX_HTML = """<div class="card"><h3 style="margin:0 0 4px">Published CISA VEX assertions <span class="hint" id="pv-hint"></span></h3>
<p class="hint" id="pv-snapshot">Reading the collected CSAF snapshot…</p>
<p class="hint">This page reads explicit <code>vulnerabilities[].flags</code> from the newest locally collected CSAF snapshot. Counts, labels, product scope and document hashes come from those files. A CVE/advisory pair can contain multiple label instances.</p>
<p class="hint">Published assertions describe the publisher's product scope. They are displayed separately from this system's VEX estimates and from construction-based evaluation gold. The snapshot date is the collection date; this is not a live claim about all current upstream documents.</p>
<div id="pv-kpis" class="kpis">loading…</div>
<div id="pv-charts" style="margin-top:16px"></div>
<div id="pv-rows" style="margin-top:16px"></div></div>"""

_ANALYZER_PAGE = '<h1>Operating-context VEX review</h1>' + ANALYZER_HTML
SOURCE_HTML = """<div class="card">
<h3 style="margin:0 0 4px">ICS-CERT Advisories</h3>
<p class="hint" style="margin:0 0 10px">Search CISA ICS-CERT advisories by ID, title, vendor, CVE, or year. <span id="adv-hint"></span></p>
<input id="adv-q" class="srch" oninput="advSearch()" placeholder="e.g. Siemens · ICSA-24 · CVE-2023-… · 2024">
<div id="adv-results" style="margin-top:12px"><span class="hint">Loading advisories…</span></div></div>

<div class="card">
<h3 style="margin:0 0 4px">NVD CVE search</h3>
<p class="hint" style="margin:0 0 10px">Search the corpus CVEs by ID, CWE, vendor, or component — each result links to its NVD detail page.</p>
<input id="cve-q" class="srch" oninput="cveSearchGo()" placeholder="e.g. CVE-2021-44228 · CWE-416 · OpenSSL · Siemens">
<div id="cve-results" style="margin-top:12px"></div><div id="classification-search-detail" aria-live="polite"></div></div>"""

_ICSSBOM_PAGE = """<h1 style="margin:0 0 8px">Synthetic SBOM dataset</h1>
<p class="hint" style="margin:0 0 16px">CycloneDX SBOMs reverse-built per ICS device from the CISA ICS-CERT corpus — each keyed to its source advisory. Search by vendor, product, advisory ID, or CVE. Click a row to see its source advisories, components, and identified CVEs.</p>
<div class="card">
<h3 style="margin:0 0 4px">ICS-SBOM assets <span class="hint" id="sbom-hint"></span></h3>
<p class="hint" style="margin:0 0 10px">Synthetic asset inventory reverse-built from the CISA ICS-CERT corpus; components and versions reference real OSS but hashes, serials and contacts are placeholders.</p>
<input id="sbom-q" class="srch" oninput="sbomSearch()" placeholder="e.g. Siemens · SIMATIC · icsa-24 · CVE-2022-0778">
<div id="sbom-results" style="margin-top:12px"><span class="hint">loading…</span></div></div>
"""



# --- VEX Flag Decision Logic page -------------------------------------------------
# cannot drift apart.

from src.operational_method_page import OPERATIONAL_METHOD_HTML
_DECISION_PAGE = OPERATIONAL_METHOD_HTML

# --- ICS-SBOM to CVE page ------------------------------------------------------
# Why the CPEs in an ICS SBOM cannot identify its CVEs on their own. Rendered
# from results/sbom_cpe_limits.json (tools/measure_sbom_cpe_limits.py), so every
# number here is recomputed from data rather than restated by hand.

def _vendor_precision_section():
    """Item #3's precision broken out per vendor.

    The single figure describes a corpus that is nowhere near uniform - Siemens
    alone is 47.6% of the components - so one number cannot answer "how does it
    do on OUR equipment". The alternative that was considered and rejected was
    SCOPING the test to the ten largest vendors: the matcher abstains on 43.9%
    inside those ten and 55.5% outside, so that scope would have raised the
    figure by removing the harder half. This repository already made that
    mistake once with a per-vendor cap, and lifting it moved the score from
    0.9870 to 0.9499. Publishing the split keeps the hard part in the number and
    still answers the question.
    """
    import json as _json, os as _os
    p = _os.path.join(RESULTS, "cpe_match_precision.json")
    if not _os.path.isfile(p):
        return ""
    try:
        r = _json.load(open(p, encoding="utf-8"))
    except Exception:
        return ""
    rows = [x for x in (r.get("by_vendor") or []) if x.get("components")]
    if not rows:
        return ""
    top = rows[:12]
    rest = rows[len(top):]
    tot_c = sum(x["components"] for x in rows)

    def _tr(x, bold=False):
        pr = ("%.4f" % x["precision"]) if x["precision"] is not None else "&mdash;"
        nm = ("<b>%s</b>" % x["vendor"]) if bold else x["vendor"]
        return ('<tr><td>%s</td><td style="text-align:right" class="mono">%s</td>'
                '<td style="text-align:right" class="mono">%s</td>'
                '<td style="text-align:right" class="mono">%s%%</td>'
                '<td style="text-align:right" class="mono">%s</td>'
                '<td style="text-align:right" class="mono">%s</td>'
                '<td style="text-align:right" class="mono"><b>%s</b></td></tr>'
                % (nm, "{:,}".format(x["components"]),
                   "{:,}".format(x["scored"]),
                   x["abstention_pct"] if x["abstention_pct"] is not None else "&mdash;",
                   "{:,}".format(x["TP"]), "{:,}".format(x["FP"]), pr))

    agg = {"vendor": "other %d vendors" % len(rest),
           "components": sum(x["components"] for x in rest),
           "scored": sum(x["scored"] for x in rest),
           "TP": sum(x["TP"] for x in rest), "FP": sum(x["FP"] for x in rest),
           "abstention_pct": (round(100.0 * sum(x["abstained"] for x in rest)
                                    / max(sum(x["components"] for x in rest), 1), 1)
                              if rest else None)}
    agg["precision"] = (agg["TP"] / (agg["TP"] + agg["FP"])
                        if (agg["TP"] + agg["FP"]) else None)

    return """
<div class="card" style="margin-top:18px">
  <h3 style="margin:0 0 6px">Identification precision per vendor &mdash; test item #3</h3>
  <p class="hint" style="margin:0 0 12px">
  The overall precision <b>%(prec).4f</b> (TP %(tp)s / FP %(fp)s) describes the whole corpus,
  and the corpus is nowhere near uniform &mdash; Siemens alone is <b>%(sie).1f%%</b> of the
  components. One figure therefore cannot answer &ldquo;how does it do on OUR equipment&rdquo;,
  so the split is published instead.</p>

  <div class="cert-warn" style="margin:0 0 12px">
  <b>The test was NOT scoped to the largest vendors.</b> The matcher abstains on 43.9%%
  of components inside the ten largest and 55.5%% outside them, so narrowing the scope
  would raise the figure by <b>removing the harder half</b>. This repository already made
  that mistake once with a per-vendor cap of 40, and lifting the cap moved the score from
  0.9870 to 0.9499. The lower number is the one that describes the corpus.</p>
  </div>

  <table class="tbl">
    <tr><th>vendor</th><th style="text-align:right">components</th>
        <th style="text-align:right">scored</th><th style="text-align:right">abstained</th>
        <th style="text-align:right">TP</th><th style="text-align:right">FP</th>
        <th style="text-align:right">precision</th></tr>
    %(rows)s
    %(rest)s
  </table>
  <p class="hint" style="margin-top:10px">
  Ordered by share of the corpus, not by precision &mdash; a table sorted by score invites
  reading its top as the result. <b>Scored</b> is the number of predictions that carried a
  ground-truth label and were actually graded; <b>abstained</b> is the share the matcher
  declined to identify because no candidate was clear. Read the two together: abstaining
  costs nothing under precision alone.</p>
</div>
""" % {"prec": r["precision"], "tp": "{:,}".format(r["TP"]),
       "fp": "{:,}".format(r["FP"]),
       "sie": 100.0 * rows[0]["components"] / max(tot_c, 1),
       "rows": "".join(_tr(x, bold=True) for x in top),
       "rest": _tr(agg) if rest else ""}


def _sbom_cve_page():
    try:
        d = json.load(open(os.path.join(RESULTS, "sbom_cpe_limits.json"), encoding="utf-8"))
    except Exception:
        return ('<h1 style="margin:0 0 8px">ICS-SBOM to CVE</h1><p class="hint">'
                'results/sbom_cpe_limits.json is missing - run '
                '<span class="mono">tools/measure_sbom_cpe_limits.py</span>.</p>')
    found = d["found_in_nvd"] or 1
    L = d["layer"]
    pct = lambda n, t=found: "%.1f%%" % (100.0 * n / t) if t else "-"  # noqa: E731
    vk = d["version_kinds"]
    nver = d["version_strings"] or 1

    def grade(g):
        col = {"measured": "var(--safe)", "proxy": "var(--und)",
               "case": "var(--und)", "definition": "var(--ink2)"}[g]
        return ('<span class="badge" style="background:%s22;color:%s">%s</span>'
                % (col, col, g))

    yrs = "".join('<tr><td class="mono">%s</td><td class="mono" style="text-align:right">%d</td>'
                  '<td class="mono" style="text-align:right">%d</td>'
                  '<td class="mono" style="text-align:right">%.1f%%</td></tr>'
                  % (y, v["cves"], v["no_cpe"], v["pct"])
                  for y, v in d["no_cpe_by_year"].items())
    comps = ", ".join('<span class="mono">%s</span> %d' % (c, n)
                      for c, n in d["top_embedded_components"][:8])
    vrows = "".join('<tr><td>%s</td><td class="mono" style="text-align:right">%d</td>'
                    '<td class="mono" style="text-align:right">%s</td><td class="mono hint">%s</td></tr>'
                    % (k, n, pct(n, nver), ", ".join(d["version_samples"].get(k, [])[:3]))
                    for k, n in sorted(vk.items(), key=lambda x: -x[1]))

    rows = [
        ("A", "No CPE to match", [
            ("1", "NVD has no CPE for the CVE",
             "%d of %d CVEs (%s), plus %d absent from NVD entirely. Concentrated in "
             "recent years - under 1%% for 2016-2022, 21%% for 2024, 44%% for 2025 - "
             "which is NVD's enrichment backlog, not a property of ICS."
             % (L.get("no_cpe", 0), found, pct(L.get("no_cpe", 0)), d["missing_from_nvd"]),
             "measured"),
            ("2", "The SBOM carries no CPE",
             "CISA's own identification of OT products carries a CPE on %d of %d (0.2%%) "
             "and a purl on none. This is the closest stand-in available; no real vendor "
             "SBOM sample was measured." % (d["csaf_ot_with_cpe"], d["csaf_ot_products"]),
             "proxy"),
        ]),
        ("B", "The CPE names a different layer", [
            ("3", "NVD's CPE is the embedded component, not the ICS product",
             "%d CVEs (%s): the vulnerable software sits inside the product - %s. An SBOM "
             "that lists products without their embedded components cannot reach these "
             "by CPE at all. (%d CVEs in this and the next bucket may be misfiled: the "
             "census kept at most 4 vendors per CVE.)"
             % (L.get("embedded_component", 0), pct(L.get("embedded_component", 0)), comps,
                d["layer_cap_uncertain"]),
             "measured"),
        ]),
        ("C", "The version cannot be decided", [
            ("4", "The CPE has no version range",
             "%d of %d CPE-bearing CVEs (%s) name a product with no version bound, so any "
             "installed version matches." % (d["cpe_without_range"], d["with_cpe"],
                                             pct(d["cpe_without_range"], d["with_cpe"])),
             "measured"),
            ("5", "ICS version notation does not compare with CPE ranges",
             "Only %d of %d version strings in our SBOMs (%s) are a plain dotted version. "
             "The rest are range expressions in two syntaxes, 'every version', or vendor "
             "service-pack notation (SP1_P01, R2). In our CSAF-derived SBOMs the field "
             "also holds the advisory's affected range, not an installed version."
             % (vk.get("plain dotted version", 0), nver,
                pct(vk.get("plain dotted version", 0), nver)),
             "measured"),
            ("6", "A multi-product record yields the wrong product's range",
             "NVD lists ranges for every product a CVE touches. Taking the first bounded "
             "one decided CVE-2018-25032 against nokogiri &lt; 1.13.4 instead of zlib "
             "&lt; 1.2.12. The rate is not measured.", "case"),
        ]),
        ("D", "The match is unreliable", [
            ("7", "Other IT products are co-listed",
             "%d CVEs (%s) carry CPEs only for unrelated IT products that ship the same "
             "code (NetApp, Oracle, Apple, Cisco...). Vendor-agnostic matching turns "
             "them into false positives." % (L.get("other_it_products", 0),
                                              pct(L.get("other_it_products", 0))),
             "measured"),
            ("8", "The advisory vendor cannot anchor the match",
             "%d CVEs come from 'Multiple'-vendor advisories (e.g. Amnesia:33, embedded "
             "TCP/IP stacks), so vendor scoping has nothing to scope to. Product-name "
             "divergence between CSAF and the CPE dictionary is a further source of "
             "error that is not measured here." % L.get("multiple_vendor_advisory", 0),
             "measured"),
        ]),
        ("E", "A match is not a finding", [
            ("9", "In the affected list is not the same as vulnerable code present",
             "A CPE match says this product/version is listed. It does not say the "
             "vulnerable code is in this build - a feature may be compiled out or a fix "
             "backported. That gap is what VEX exists to close: 12 CISA advisories "
             "already declare listed products not_affected for 18 CVEs.", "definition"),
        ]),
    ]
    body = ""
    for gid, gname, items in rows:
        body += ('<tr class="grp"><td colspan="4"><b>%s. %s</b></td></tr>'
                 % (gid, gname))
        for n, title, text, g in items:
            body += ('<tr><td class="mono">%s</td><td><b>%s</b></td>'
                     '<td class="hint" style="font-size:13px">%s</td><td>%s</td></tr>'
                     % (n, title, text, grade(g)))

    return """<h1 style="margin:0 0 8px">ICS-SBOM to CVE</h1>
<p class="hint" style="margin:0 0 18px">Taking an ICS SBOM and identifying its CVEs from
the CPEs inside it fails in nine distinct ways. Each is stated with how it was
established: <b>measured</b> over the full population, <b>proxy</b> measured on a
stand-in, <b>case</b> shown on instances with the rate unmeasured, or
<b>definition</b>. Recomputed from <span class="mono">results/sbom_cpe_limits.json</span>.</p>

<div class="card">
<div class="kpis">
  <div class="kpi"><div class="kpi-n">__POP__</div><div class="kpi-l">ICSA CVEs</div></div>
  <div class="kpi"><div class="kpi-n">__CPE__</div><div class="kpi-l">carry a CPE in NVD</div></div>
  <div class="kpi"><div class="kpi-n">__PROD__</div><div class="kpi-l">CPE names the product</div></div>
  <div class="kpi warn"><div class="kpi-n">__COMP__</div><div class="kpi-l">CPE names an embedded component</div></div>
  <div class="kpi bad"><div class="kpi-n">__NONE__</div><div class="kpi-l">no CPE</div></div>
</div>
</div>

<div class="card">
<h2 style="margin:0 0 10px;font-size:17px">The nine limits</h2>
<table class="tbl"><thead><tr><th>#</th><th>Limit</th><th>Evidence</th><th>Grade</th></tr></thead>
<tbody>__ROWS__</tbody></table>
</div>

<div class="card">
<h2 style="margin:0 0 10px;font-size:17px">Limit 1 in detail &mdash; CVEs without a CPE, by CVE year</h2>
<table class="tbl"><thead><tr><th>Year</th><th style="text-align:right">CVEs</th>
<th style="text-align:right">no CPE</th><th style="text-align:right">share</th></tr></thead>
<tbody>__YEARS__</tbody></table>
</div>

<div class="card">
<h2 style="margin:0 0 10px;font-size:17px">Limit 5 in detail &mdash; version strings in our SBOMs</h2>
<table class="tbl"><thead><tr><th>Kind</th><th style="text-align:right">Count</th>
<th style="text-align:right">Share</th><th>Examples</th></tr></thead>
<tbody>__VERS__</tbody></table>
</div>

<div class="card" style="border-left:3px solid #b8862b">
<h2 style="margin:0 0 8px;font-size:17px">What follows for matching</h2>
<p class="hint" style="margin:0">CPE matching is usable where the CPE names the product
itself (limit 3's complement) and a version can be decided (limits 4-6). Everywhere
else it has to be replaced or supplemented: an exact <b>model number</b> lookup for
device components, the <b>embedded components and their versions</b> listed in the SBOM
for the component layer, and a VEX judgement for limit 9. None of these limits is solved
by a better similarity threshold.</p>
</div>
""".replace("__POP__", "{:,}".format(d["population"])) \
   .replace("__CPE__", pct(d["with_cpe"])) \
   .replace("__PROD__", pct(L.get("product", 0))) \
   .replace("__COMP__", pct(L.get("embedded_component", 0))) \
   .replace("__NONE__", pct(L.get("no_cpe", 0))) \
   .replace("__ROWS__", body).replace("__YEARS__", yrs).replace("__VERS__", vrows)


from src.identification_method_page import IDENTIFICATION_METHOD_HTML
_SBOM_CVE_PAGE = IDENTIFICATION_METHOD_HTML


PAGES = {
    "analyzer": ("SBOM → VEX Analyzer", _ANALYZER_PAGE),
    "sbom-to-cve": ("ICS-SBOM to CVE", _SBOM_CVE_PAGE),
    "vex-decision": ("VEX Flag Decision Logic", _DECISION_PAGE),
    "source": ("ICS-CERT Advisories (CISA)",
               '<h1 style="margin:0 0 18px">ICS-CERT Advisories (CISA)</h1>' + SOURCE_HTML),
    # one page: the population, and the slice of it that has source
    "dataset": ("CVE Dataset", """<h1 style="margin:0 0 6px">CVE Dataset</h1>
<p class="hint" style="margin:0 0 18px">Current advisory CVEs and their published metadata. Asset VEX assessments use operating context and installed-version records.</p>"""
               + CORPUS_HTML),
    "published-vex": ("Published VEX (CISA)",
                      '<h1 style="margin:0 0 18px">Published VEX (CISA)</h1>' + PUBLISHED_VEX_HTML),
    "ics-sbom": ("Synthetic SBOM dataset", _ICSSBOM_PAGE),
    "cert": ("Certification performance metrics", CERT_PAGE),
    "asset-vex": ("Asset-attribute exploitability", ASSET_VEX_PAGE),
    "context-vex": ("6W problems & CVSS x context VEX", CONTEXT_VEX_PAGE),
}
# Two sections: the ANALYZER (interactive tools that take an SBOM and produce a VEX
# judgement, in pipeline order) and the DATASET (the reference corpus those tools are
# grounded in). Order within each follows the workflow / primary-first.
_NAV_GROUPS = [
    ("Analyzer", [
        ("analyzer", "index.html", "ICS-VEXForge"),
    ]),
    # The methodology pages: how SBOM->CVE identification is bounded, and the two
    # halves of the VEX decision (source-available tree + source-unavailable
    # asset-attribute estimate). Grouped apart from the analyzer tool.
    ("Method", [
        ("sbom-to-cve", "sbom-to-cve.html", "SBOM → CVE Method"),
        ("vex-decision", "vex-decision.html", "Operational VEX"),
    ]),
    ("Dataset", [
        ("dataset", "dataset.html", "CVE Dataset"),
        ("ics-sbom", "ics-sbom.html", "Synthetic SBOM"),
        ("source", "source.html", "ICS-CERT Advisories (CISA)"),
        ("published-vex", "published-vex.html", "Published VEX (CISA)"),
    ]),
]
# flat view for any code that just needs the (key, href, label) triples
_NAV = [item for _, items in _NAV_GROUPS for item in items]


def nav_html(active, exclude=(), include_local_workbench=False):
    """The sidebar. `exclude` drops pages by key, and drops a group that empties.

    The static GitHub Pages build excludes the certification page: it runs the
    measurement over /api/cert/*, which only the local server answers, so the
    published site must not advertise it.
    """
    exclude = set(exclude)
    parts = ['<nav class="nav">']
    gi = 0
    for group, items in _NAV_GROUPS:
        items = [i for i in items if i[0] not in exclude]
        if not items:
            continue
        parts.append(f'<div class="navlabel{" navlabel-sep" if gi else ""}">{group}</div>')
        gi += 1
        for key, href, label in items:
            cls = "navtab" + (" navtab-main" if key == "analyzer" else "") + (" on" if key == active else "")
            from src.ui_theme import nav_icon
            current=' aria-current="page"' if key==active else ''
            parts.append(f'<a class="{cls}" href="{href}"{current}>{nav_icon(key)}<span>{label}</span></a>')
    if include_local_workbench:
        parts.append('<a class="navtab" href="question-mining.html"><span>Operational VEX workspace</span></a>')
    parts.append('</nav>')
    return "".join(parts)


def make_page(active, include_local_workbench=False):
    if active == 'vex-decision':
        from src.operational_workflow_page import widget_parts as operational_parts
        content,operational_script=operational_parts()
    else:
        _sub, content = PAGES[active]
    if active == 'ics-sbom' and STORE.sbom_index.get('generated_at'):
        from html import escape
        s=STORE.sbom_index
        excluded=s.get('excluded_advisories',[])
        content += ('<section class="card" style="margin-top:18px"><h2>Generation coverage</h2>'
                    '<p>'+str(s.get('generated',0))+' synthetic SBOMs from '+str(s.get('advisory_records',0))+
                    ' advisory records. Generated '+escape(s['generated_at'])+'.</p>'
                    '<p class="hint">'+str(len(excluded))+' records excluded because the upstream advisory could not be collected: '+
                    escape(', '.join(x['advisory_id']+' ('+x['reason']+')' for x in excluded))+
                    '. These records are not represented by invented SBOMs.</p></section>')
    if active in {'source', 'dataset'} and STORE.corpus_freshness.get('status') == 'complete':
        from html import escape
        f = STORE.corpus_freshness
        content += ('<section class="card" style="margin-top:18px"><h2>Data freshness</h2>'
                    '<p>CISA CSAF latest revision: '+escape(str(f.get('latest_advisory_modified', '')))+
                    '<br>NVD feeds retrieved: '+escape(str(f.get('completed_at', '')))+
                    '<br>Refreshed NVD records: '+str(f.get('nvd_records_refreshed', 0))+
                    ' / '+str(f.get('cves_after', 0))+'</p>'
                    '<p class="hint">New advisory relationships are under investigation until assessed. '
                    'Historical training and evaluation datasets retain their original snapshots.</p></section>')
    extra=operational_script if active=='vex-decision' else ''
    if active=='analyzer':
        from src.candidate_widget import widget_parts,BRIDGE_SCRIPT
        content,widget_script=widget_parts()
        from src.operational_workflow_page import widget_parts as operational_parts
        operational_content,operational_script=operational_parts()
        content += operational_content.replace('id="operational-workspace"','id="operational-workspace" hidden',1)
        extra=widget_script+operational_script+BRIDGE_SCRIPT
    from pathlib import Path
    classification_js = (Path(BASE)/'src/operational_classification_ui.js').read_text(encoding='utf-8')
    evidence_js = (Path(BASE)/'src/evidence_workspace.js').read_text(encoding='utf-8')
    page=(FRONTEND_TEMPLATE
            .replace('__OPERATIONAL_CLASSIFICATION_JS__', classification_js)
            .replace('__EVIDENCE_WORKSPACE_JS__', evidence_js)
            .replace("__VEX_TREE__", "{}")
            .replace("__NAV__", nav_html(active, include_local_workbench=include_local_workbench))
            .replace("__CONTENT__", content)
            .replace("__ASSET_AV_JS__",
                     "window.__ICSVEX_RUNTIME=true;\n" + ASSET_AV_CLIENT_JS + ASSET_AV_MODAL_JS))
    from src.web_locale import english_ui
    from src.ui_theme import STYLE,TOPBAR
    if active in {'analyzer','vex-decision'}:
        # These views use the single BOM -> prerequisite -> context workflow.
        # Retire the embedded fixed-question and source/operational fork scripts.
        page=re.sub(r'<script\b[^>]*>.*?</script>','',page,flags=re.S|re.I)
    page=english_ui(page.replace('</body>',extra+'</body>') if extra else page)
    classification_style='''<style>
    .classification-panel{border:1px solid var(--line);border-radius:14px;padding:16px;margin:14px 0;overflow-wrap:anywhere}
    .classification-panel h4{margin:0 0 8px}.classification-type,.classification-policy{padding:12px 0;border-top:1px solid var(--line)}
    .classification-type>summary,.classification-policy>summary{cursor:pointer;font-weight:600;line-height:1.6}
    .classification-quote{margin:12px 0;padding:12px 15px;border-left:3px solid var(--purple);background:var(--card2);white-space:pre-wrap;overflow-wrap:anywhere}
    .classification-quote mark{background:#e4dcfa;color:#211b31;padding:1px 3px;border-radius:3px}
    .classification-panel pre,#classification-catalog pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
    .classification-notes{padding:12px;border-radius:10px;background:var(--card2)}
    .evidence-workspace{border:1px solid var(--line);border-radius:14px;padding:18px;margin:18px 0;overflow-wrap:anywhere}
    .evidence-workspace>summary,.ew-section>summary{font-weight:650;cursor:pointer;line-height:1.6}
    .ew-section{padding:16px 0;border-top:1px solid var(--line);margin:14px 0}
    .evidence-workspace label{display:block;line-height:1.55;margin:10px 0}.evidence-workspace label input:not([type=checkbox]),.evidence-workspace label select,.evidence-workspace label textarea{display:block;width:100%;box-sizing:border-box;margin-top:6px;max-width:100%}
    .ew-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 18px}.ew-grid>*{min-width:0}.evidence-workspace input,.evidence-workspace select,.evidence-workspace textarea{min-width:0}.ew-text{min-height:95px!important}.ew-multi{min-height:100px;max-width:100%}
    .ew-table{overflow:auto;max-width:100%;margin-top:15px}.ew-table table{min-width:600px}.ew-observation,.ew-result{border:1px solid var(--line);border-radius:12px;padding:15px;margin:12px 0}
    .ew-result h4{margin-top:0}.evidence-workspace button{margin:6px 5px 6px 0}.ew-result p,.ew-result li{overflow-wrap:anywhere}
    @media(max-width:650px){.ew-grid{grid-template-columns:1fr}.evidence-workspace{padding:12px}.evidence-workspace>summary{font-size:15px}
    #candidate-vex{padding:12px}#armfork{padding:0;border:0}#cve-operating-questions{padding:0;border:0}#cve-operating-questions .operation-case{padding:12px 0;border:0}.ew-result{padding:12px}}
    </style>'''
    page=page.replace('</head>',STYLE+classification_style+'</head>')
    page=page.replace('<main class="main">','<main class="main">'+TOPBAR,1)
    page=page.replace('</svg></a></div>','</svg></a><div class="side-brand-name">ICS-VEXForge<small>Vulnerability intelligence</small></div></div>',1)
    return page


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
