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
import build_ground_truth as G  # reachability(), exposure_for()

RESULTS = os.path.join(BASE, "results")
DATA = os.path.join(BASE, "data")
KB_PATH = os.path.join(RESULTS, "cve_kb.json")

AFFECTED, NOT_AFFECTED, UNDER_INV = "LIKELY_AFFECTED", "LIKELY_NOT_AFFECTED", "UNDER_INVESTIGATION"
EXPOSURES = ["isolated-cell", "control-network", "dmz-routable", "remote-accessible"]


def _load(path, default=None):
    return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else default


class Store:
    """Loads the corpus artifacts once; refresh() re-reads them."""
    def __init__(self):
        self.refresh()

    def refresh(self):
        self.summary = _load(os.path.join(RESULTS, "vex_batch_summary.json"), {})
        self.candidates = _load(os.path.join(RESULTS, "genie_candidates.json"),
                                {"candidates": []})
        self.code_ev = _load(os.path.join(DATA, "code_evidence.json"), {})
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
        # CVE-level view (unique CVEs, worst-case verdict across assets)
        rank = {AFFECTED: 3, UNDER_INV: 2, NOT_AFFECTED: 1}
        cve_worst, cve_tier = {}, {}
        for cve, rows in self.by_cve.items():
            w = max(rows, key=lambda r: rank.get(r["final_vex"], 0))
            cve_worst[cve] = w["final_vex"]
            cve_tier[cve] = w.get("evidence_tier")
        self.cve_level = {
            "total_cves": len(cve_worst),
            "by_vex": dict(Counter(cve_worst.values())),
            "by_tier": dict(Counter(t for t in cve_tier.values() if t)),
        }
        # tier-A = OSS-attributed, source-code collectable (the "132")
        a_worst = {}
        for cve, rows in self.by_cve.items():
            if any(r.get("tier") == "A" for r in rows):
                a_worst[cve] = max(rows, key=lambda r: rank.get(r["final_vex"], 0))
        sev_norm = lambda s: s if s in ("critical", "high", "medium", "low") else "unrated"
        self.tier_a = {
            "total_cves": len(a_worst),
            "code_collected": sum(1 for w in a_worst.values() if w.get("has_code_pair")),
            "pending_collection": sum(1 for w in a_worst.values() if not w.get("has_code_pair")),
            "kev": sum(1 for w in a_worst.values() if w.get("kev")),
            "by_vex": dict(Counter(w["final_vex"] for w in a_worst.values())),
            "by_severity": dict(Counter(sev_norm(w.get("sev", "")) for w in a_worst.values())),
            "by_reachability": dict(Counter(w.get("reachability") for w in a_worst.values())),
            "top_cwe": [{"cwe": c, "count": n} for c, n in
                        Counter(w.get("cwe") for w in a_worst.values() if w.get("cwe")).most_common(10)],
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
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans)}
.wrap{max-width:1000px;margin:0 auto;padding:28px 20px 60px}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}
h1{margin:.2em 0}.sub{color:var(--ink2);max-width:70ch;font-size:14px}
a{color:var(--accent)}.row{display:grid;grid-template-columns:1fr auto;gap:14px;align-items:end}
@media(max-width:640px){.row{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-top:18px}
label{font-size:12px;color:var(--ink2)}textarea{width:100%;min-height:150px;background:var(--bg);color:var(--ink);
border:1px solid var(--line);border-radius:8px;padding:10px;font-family:var(--mono);font-size:12px}
select,button{font-family:var(--sans);font-size:13px;padding:8px 12px;border-radius:8px;border:1px solid var(--line);
background:var(--card2);color:var(--ink)}button.primary{background:var(--accent);color:#04120c;font-weight:700;border:none;cursor:pointer}
.kpis{display:flex;flex-wrap:wrap;gap:10px}.kpi{background:var(--card2);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.kpi b{font-size:20px}.kpi span{display:block;font-size:11px;color:var(--ink3);font-family:var(--mono)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
th{font-size:11px;color:var(--ink3);text-transform:uppercase}.mono{font-family:var(--mono)}
.badge{font-family:var(--mono);font-size:11px;font-weight:700;padding:1px 7px;border-radius:5px}
.hint{font-size:12px;color:var(--ink3)}.err{color:var(--aff);font-size:13px}
.chart{margin-bottom:14px}.ct{font-size:12px;font-weight:600;color:var(--ink2);margin-bottom:5px}
.mb{display:flex;height:20px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}.mb>div{height:100%}
.legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:7px;font-size:12px}
.legend .lg{display:flex;align-items:center;gap:5px}.legend i{width:10px;height:10px;border-radius:3px;display:inline-block}
.cwe{display:grid;gap:5px}.cwerow{display:grid;grid-template-columns:110px 1fr 28px;align-items:center;gap:8px;font-size:12px}
.cwebar{background:var(--card2);border-radius:5px;height:12px;overflow:hidden}.cwebar>i{display:block;height:100%;background:var(--accent);border-radius:5px}
.cwerow b{text-align:right;font-family:var(--mono)}
</style></head><body><div class="wrap">
<div class="eyebrow">ICS-VEX</div>
<h1>SBOM → CVE → VEX</h1>

<div class="card"><div class="row">
  <div><label>CycloneDX SBOM (JSON)</label><textarea id="sbom" placeholder='{"components":[{"name":"OpenSSL","version":"1.1.1k"}]}'></textarea></div>
  <div><label>Deployment exposure</label><br><select id="exp">
    <option value="isolated-cell">Isolated cell</option><option value="control-network" selected>Control network</option>
    <option value="dmz-routable">DMZ routable</option><option value="remote-accessible">Remote accessible</option></select>
    <br><br><button class="primary" onclick="run()">Analyze ▶</button> <button onclick="ex()">Example</button></div>
</div><div id="out" style="margin-top:12px"></div></div>

<div class="card"><h3 style="margin:0 0 8px">Corpus by CVE</h3><div id="kpis" class="kpis hint">loading…</div>
<p class="hint" style="margin-top:10px">Reproduction candidates: <span id="cand">…</span> · full view:
<a href="https://kakyung98.github.io/ics-vex-dashboard/pipeline.html" target="_blank">pipeline.html</a></p></div>

<div class="card"><h3 style="margin:0 0 4px">Source-available CVEs <span class="hint">tier A · code-collectable</span></h3>
<p class="hint" style="margin:0 0 12px">CVEs whose OSS source can be collected — the pool eligible for CodeBERT diff and execution reproduction.</p>
<div id="sa-kpis" class="kpis">loading…</div>
<div id="sa-charts" style="margin-top:16px"></div>
<div id="sa-cwe" style="margin-top:14px"></div></div>

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
  components:[{name:"OpenSSL",version:"1.1.1k"},{name:"zlib",version:"1.2.11"},{name:"BusyBox",version:"1.31.1"}]},null,2);}
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
function bar(counts,order,cmap,total){
  let segs='',leg='';
  for(const k of order){const v=counts[k]||0;if(!v)continue;const w=100*v/total;
    segs+='<div style="width:'+w.toFixed(2)+'%;background:'+(cmap[k]||'var(--ink3)')+'" title="'+k+': '+v+'"></div>';
    leg+='<span class="lg"><i style="background:'+(cmap[k]||'var(--ink3)')+'"></i>'+k+' <b>'+v+'</b></span>';}
  return '<div class="mb">'+segs+'</div><div class="legend">'+leg+'</div>';
}
async function sourceAvail(){
  try{const s=await(await fetch('/api/source_available')).json();
    const t=s.total_cves;
    document.getElementById('sa-kpis').innerHTML=
      '<div class="kpi"><b>'+t+'</b><span>tier-A CVEs</span></div>'+
      '<div class="kpi"><b style="color:var(--safe)">'+s.code_collected+'</b><span>code collected</span></div>'+
      '<div class="kpi"><b style="color:var(--und)">'+s.pending_collection+'</b><span>pending collection</span></div>'+
      '<div class="kpi"><b style="color:var(--aff)">'+s.kev+'</b><span>KEV</span></div>';
    document.getElementById('sa-charts').innerHTML=
      '<div class="chart"><div class="ct">VEX verdict</div>'+bar(s.by_vex,['LIKELY_AFFECTED','LIKELY_NOT_AFFECTED','UNDER_INVESTIGATION'],C,t).replace(/LIKELY_AFFECTED/g,'Affected').replace(/LIKELY_NOT_AFFECTED/g,'Not affected').replace(/UNDER_INVESTIGATION/g,'Under inv')+'</div>'+
      '<div class="chart"><div class="ct">Severity</div>'+bar(s.by_severity,['critical','high','medium','low','unrated'],SEVC,t)+'</div>'+
      '<div class="chart"><div class="ct">Reachability</div>'+bar(s.by_reachability,['yes','conditional','no','unknown'],REC,t)+'</div>';
    let cwe='<div class="ct">Top CWE types</div><div class="cwe">';
    const mx=Math.max(...s.top_cwe.map(x=>x.count));
    for(const x of s.top_cwe)cwe+='<div class="cwerow"><span class="mono">'+x.cwe+'</span>'+
      '<span class="cwebar"><i style="width:'+(100*x.count/mx)+'%"></i></span><b>'+x.count+'</b></div>';
    document.getElementById('sa-cwe').innerHTML=cwe+'</div>';
  }catch(e){document.getElementById('sa-kpis').innerHTML='<span class="err">unavailable — run src/vex_batch.py</span>';}
}
stats(); sourceAvail();
</script></body></html>"""


app = build_app()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args()
    import uvicorn
    print(f"ICS-VEX API on http://{a.host}:{a.port}  (docs: /docs)", flush=True)
    uvicorn.run(app, host=a.host, port=a.port, log_level="info")


if __name__ == "__main__":
    main()
