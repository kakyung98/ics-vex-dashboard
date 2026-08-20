#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the STATIC GitHub Pages site from the dynamic api_server UI.

GitHub Pages can't run the FastAPI backend, so this bakes every dataset the
console needs into same-origin JSON files and rewrites the page's data access:
  - stat cards/charts fetch pre-computed *.json (same origin — works on Pages)
  - the CVE drill-down filters an embedded CVE index in the browser
  - SBOM -> VEX is computed in the browser (reachability over cve_kb)
The result is index.html + a handful of .json files, identical UI to the server.

Run:  python tools/build_site.py
"""
import os, json, shutil, sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))
import api_server as A          # reuses api_server.STORE (built on import) + FRONTEND

S = A.STORE


def dump(name, obj):
    json.dump(obj, open(os.path.join(BASE, name), "w", encoding="utf-8"),
              ensure_ascii=False, separators=(",", ":"))


# ---- 1) datasets the page fetches (same-origin) ---------------------------
dump("cve_level.json", S.cve_level)
dump("source_available.json", S.tier_a)
dump("by_year.json", {"total_cves": sum(S.by_year.values()), "by_year": S.by_year})
dump("advisories.json", S.advisories)
ready = [c for c in S.candidates.get("candidates", []) if c.get("status") == "ready"]
dump("candidates_ready.json", {"count": len(ready)})
dump("cve_index.json", list(S.cve_index.values()))
shutil.copyfile(os.path.join(BASE, "results", "cve_kb.json"),
                os.path.join(BASE, "cve_kb.json"))

# ---- 2) client-side JS injected in place of the /api/* backend ------------
INJECT = r"""
let CVE_INDEX=[], CVE_KB={}, KB_COMPS=[];
fetch('cve_index.json').then(r=>r.json()).then(d=>{CVE_INDEX=d;}).catch(()=>{});
fetch('cve_kb.json').then(r=>r.json()).then(d=>{const idx={};KB_COMPS=(d.components||[]);for(const c of KB_COMPS){for(const k of new Set([c.key,(c.name||'').toLowerCase(),c.cpe_product||''])){if(k)idx[String(k).toLowerCase()]=c;}}CVE_KB=idx;}).catch(()=>{});
function roMatches(a,b){let bi=0,bj=0,bs=0;for(let i=0;i<a.length;i++){for(let j=0;j<b.length;j++){let k=0;while(i+k<a.length&&j+k<b.length&&a[i+k]===b[j+k])k++;if(k>bs){bs=k;bi=i;bj=j;}}}if(bs===0)return 0;return bs+roMatches(a.slice(0,bi),b.slice(0,bj))+roMatches(a.slice(bi+bs),b.slice(bj+bs));}
function roRatio(a,b){a=(a||'').toLowerCase();b=(b||'').toLowerCase();const t=a.length+b.length;return t?2*roMatches(a,b)/t:0;}
function cveIdsFor(comp,ver){if(!comp)return [];const vmap=comp.versions||{};let cves=vmap[ver];if(cves==null){const seen=new Set();cves=[];for(const k in vmap)for(const cv of vmap[k])if(!seen.has(cv.id)){seen.add(cv.id);cves.push(cv);}}return cves.map(cv=>cv.id);}
function roBest(name){const n=(name||'').toLowerCase();let best=null,br=0;for(const c of KB_COMPS){for(const s of [c.name,c.cpe_product,c.key].filter(Boolean)){const r=roRatio(n,s);if(r>br){br=r;best=c;}}}return [best,Math.round(br*1000)/1000];}
function compareNormJs(sbom,exp,th){const comps=(sbom.components||[]).filter(c=>c&&c.name).map(c=>[String(c.name).trim(),String(c.version||'').trim()]);const rows=[];const ex=new Set(),nm=new Set();for(const [name,ver] of comps){const exact=CVE_KB[name.toLowerCase()];const exIds=cveIdsFor(exact,ver);exIds.forEach(x=>ex.add(x));const rb=roBest(name),nc=rb[0],ratio=rb[1];const normalized=ratio>=th?nc:null;const nmIds=cveIdsFor(normalized,ver);nmIds.forEach(x=>nm.add(x));rows.push({component:name,version:ver||'(unpinned)',exact_match:exact?exact.name:null,normalized_match:normalized?normalized.name:null,ro_ratio:ratio,matched_by_normalization:!!(normalized&&!exact),exact_cve_count:exIds.length,normalized_cve_count:nmIds.length});}const both=[...ex].filter(x=>nm.has(x)).sort();const onlyE=[...ex].filter(x=>!nm.has(x)).sort();const onlyN=[...nm].filter(x=>!ex.has(x)).sort();return {threshold:th,components:comps.length,normalization:rows,comparison:{exact_total:ex.size,normalized_total:nm.size,both:both,only_exact:onlyE,only_normalized:onlyN}};}
function reachability(av,exp){const t={'isolated-cell':0,'control-network':1,'dmz-routable':2,'remote-accessible':3}[exp];if(!av)return 'unknown';if(av==='N')return t===0?'no':(t===1?'conditional':'yes');if(av==='A')return t===0?'no':(t<=2?'conditional':'yes');if(av==='L')return 'conditional';if(av==='P')return 'no';return 'conditional';}
function computeVex(sbom,exp){const comps=(sbom.components||[]).filter(c=>c&&c.name).map(c=>[String(c.name).trim(),String(c.version||'').trim()]);const rank={LIKELY_AFFECTED:3,UNDER_INVESTIGATION:2,LIKELY_NOT_AFFECTED:1};const byCve={};for(const [name,ver] of comps){const comp=CVE_KB[name.toLowerCase()];if(!comp)continue;const vmap=comp.versions||{};let cves=vmap[ver];if(cves==null){const seen=new Set();cves=[];for(const k in vmap)for(const cv of vmap[k])if(!seen.has(cv.id)){seen.add(cv.id);cves.push(cv);}}for(const cv of cves){const av=cv.av||'N';const reach=reachability(av,exp);let status=reach==='yes'?'LIKELY_AFFECTED':(reach==='no'?'LIKELY_NOT_AFFECTED':'UNDER_INVESTIGATION');const row={cve:cv.id,component:comp.name,version:ver||'(unpinned)',severity:cv.sev||'',av:av,kev:!!cv.kev,reachability:reach,final_vex:status,evidence_tier:(status==='UNDER_INVESTIGATION'?'under-investigation':'static-reasoned')};const prev=byCve[cv.id];if(!prev||rank[status]>rank[prev.final_vex])byCve[cv.id]=row;}}const cves=Object.values(byCve).sort((a,b)=>rank[b.final_vex]-rank[a.final_vex]||a.cve.localeCompare(b.cve));const by={};for(const r of cves)by[r.final_vex]=(by[r.final_vex]||0)+1;return {components:comps.length,cves_matched:cves.length,summary:{by_vex:by},cves:cves};}
function queryCves(dim,value,scope){const rv={LIKELY_AFFECTED:3,UNDER_INVESTIGATION:2,LIKELY_NOT_AFFECTED:1};const rs={critical:4,high:3,medium:2,low:1,unrated:0};let hits=CVE_INDEX.filter(r=>{if(scope==='source_available'&&!r.source_available)return false;if(dim==='cwe')return r.cwe===value;if(dim==='vendor')return (r.vendors||[]).includes(value);if(dim==='device_type')return (r.device_types||[]).includes(value);if(dim==='year')return String(r.year)===String(value);if(dim==='vex')return r.vex===value;if(dim==='reachability')return r.reachability===value;if(dim==='severity')return r.severity===value;return false;});hits.sort((a,b)=>((b.kev?1:0)-(a.kev?1:0))||(rv[b.vex]-rv[a.vex])||(rs[b.severity]-rs[a.severity])||a.cve.localeCompare(b.cve));return {count:hits.length,cves:hits.slice(0,400).map(r=>({cve:r.cve,vex:r.vex,severity:r.severity,kev:r.kev,reachability:r.reachability,vendor:(r.vendors||[]).slice(0,2).join(', '),component:r.component,cwe:r.cwe,has_code_pair:r.has_code_pair,repo_url:r.repo_url}))};}
"""

html = A.FRONTEND

# stat endpoints -> static json
for old, new in [
    ("'/api/summary'", "'cve_level.json'"),
    ("'/api/source_available'", "'source_available.json'"),
    ("'/api/candidates?status=ready'", "'candidates_ready.json'"),
    ("'/api/by_year'", "'by_year.json'"),
    ("'/api/advisories'", "'advisories.json'"),
]:
    assert old in html, "missing: " + old
    html = html.replace(old, new)

# drill-down: server filter -> client filter
old_q = ("  try{const d=await(await fetch('/api/cves?dim='+encodeURIComponent(dim)+"
         "'&value='+encodeURIComponent(value)+'&scope='+scope)).json();")
assert old_q in html, "missing openCves fetch"
html = html.replace(old_q, "  try{const d=queryCves(dim,value,scope);")

# SBOM->VEX: server POST -> client compute
old_run = ("  const r=await fetch('/api/vex',{method:'POST',headers:{'Content-Type':'application/json'},\n"
           "    body:JSON.stringify({sbom,exposure:document.getElementById('exp').value})});\n"
           "  if(!r.ok){o.innerHTML='<span class=\"err\">error '+r.status+'</span>';return}\n"
           "  const d=await r.json();")
assert old_run in html, "missing run() fetch block"
html = html.replace(old_run, "  const d=computeVex(sbom,document.getElementById('exp').value);")

# CPE normalization compare: server endpoint -> client-side RO fallback
old_cmp = ("  try{const r=await fetch('/api/vex_compare',{method:'POST',headers:{'Content-Type':'application/json'},"
           "body:JSON.stringify({sbom,exposure:exp,threshold:0.7})});if(r.ok)d=await r.json();}catch(e){}")
assert old_cmp in html, "missing compareNorm fetch"
html = html.replace(old_cmp, "  d=compareNormJs(sbom,exp,0.7);")

# inject client-side engine right before run()
assert "async function run(){" in html
html = html.replace("async function run(){", INJECT + "\nasync function run(){", 1)

open(os.path.join(BASE, "index.html"), "w", encoding="utf-8").write(html)

sz = lambda n: os.path.getsize(os.path.join(BASE, n)) / 1024
print("wrote index.html (%.0f KB) + json:" % sz("index.html"))
for n in ["cve_index.json", "cve_level.json", "source_available.json", "by_year.json",
          "advisories.json", "candidates_ready.json", "cve_kb.json"]:
    print("  %-24s %.0f KB" % (n, sz(n)))
