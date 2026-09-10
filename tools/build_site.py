#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the STATIC GitHub Pages site from the dynamic api_server UI.

GitHub Pages can't run the FastAPI backend, so this bakes every dataset the
console needs into same-origin JSON files and rewrites the page's data access:
  - stat cards/charts fetch pre-computed *.json (same origin — works on Pages)
  - the CVE drill-down filters an embedded CVE index in the browser
  - SBOM -> VEX is computed in the browser (evidence tiers over cve_kb)
The result is index.html + a handful of .json files, identical UI to the server.

Run:  python tools/build_site.py
"""
import os, json, shutil, sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(BASE, "src"))
import api_server as A          # reuses api_server.STORE (built on import) + FRONTEND

S = A.STORE

# 정적 사이트 산출물(HTML + JSON + adv/)은 site/ 로 모은다 (루트 정리).
# 상대경로 fetch/링크가 site/ 안에서 자기완결적으로 해석된다.
# 주의: 런타임 서버(api_server)가 읽는 sbom_index.json 은 루트에 그대로 둔다.
SITE = os.path.join(BASE, "site")
os.makedirs(SITE, exist_ok=True)


def dump(name, obj):
    json.dump(obj, open(os.path.join(SITE, name), "w", encoding="utf-8"),
              ensure_ascii=False, separators=(",", ":"))


# ---- 1) datasets the page fetches (same-origin) ---------------------------
dump("cve_level.json", S.cve_level)
# pinned CSAF originals, so the Published VEX table's claims can be checked
# against the document they come from without leaving the site
_gt_src = os.path.join(BASE, "data", "gt_icsa", "tier1_justification", "cisa_csaf")
if os.path.isdir(_gt_src):
    _gt_dst = os.path.join(SITE, "gt_icsa")
    os.makedirs(_gt_dst, exist_ok=True)
    for _f in os.listdir(_gt_src):
        if _f.endswith(".json"):
            shutil.copyfile(os.path.join(_gt_src, _f), os.path.join(_gt_dst, _f))
    print("  copied %d pinned CSAF documents -> site/gt_icsa/"
          % len([f for f in os.listdir(_gt_dst) if f.endswith(".json")]))
# NVD affected ranges, so the browser can apply the same version test the server
# does (src/sbom_match.in_affected_range). Without this the static build falls
# back to "every CVE this component ever had".
try:
    dump("cve_version_ranges.json",
         json.load(open(os.path.join(BASE, "data", "cve_version_ranges.json"),
                        encoding="utf-8")))
except Exception as e:
    print("  !! cve_version_ranges.json not exported: %s" % e)
dump("source_available.json", S.tier_a)
dump("by_year.json", {"total_cves": sum(S.by_year.values()), "by_year": S.by_year})
dump("advisories.json", S.advisories)
ready = [c for c in S.candidates.get("candidates", []) if c.get("status") == "ready"]
dump("verify_results.json", S.verify)
dump("verify_coverage.json", S.verify_coverage)


def _published_vex(store):
    man = getattr(store, "gt_icsa", {"tier1": []})
    rows, ldist, vendors = [], {}, {}
    for r in man.get("tier1", []):
        title = r.get("title", "")
        vendor = title.split()[0] if title else "?"
        vendors[vendor] = vendors.get(vendor, 0) + 1
        for cve, labels in (r.get("flags") or {}).items():
            for lab in labels:
                ldist[lab] = ldist.get(lab, 0) + 1
            # resolve the flag to the products it actually names
            prods = []
            _src = os.path.join(BASE, "data", "gt_icsa", "tier1_justification",
                                "cisa_csaf", "%s.json" % (r.get("advisory_id") or ""))
            if os.path.exists(_src):
                try:
                    prods = A.flagged_products(json.load(open(_src, encoding="utf-8")), cve)
                except Exception:
                    prods = []
            rows.append({"advisory": r.get("advisory_id"), "cve": cve, "title": title,
                         "vendor": (prods[0]["vendor"] if prods else vendor),
                         "products": [{"product": p["product"], "version": p["version"],
                                       "label": p.get("label")}
                                      for p in prods][:12],
                         "product_count": len(prods),
                         "justification": labels[0] if labels else None, "labels": labels,
                         "url": r.get("cisa_url"),
                         "csaf_url": (("https://raw.githubusercontent.com/cisagov/CSAF/develop/" + r["source_file"]) if r.get("source_file")
                                      else None),
                         "csaf_local": "gt_icsa/%s.json" % r.get("advisory_id", ""),
                         "release": r.get("current_release_date") or r.get("initial_release_date")})
    rows.sort(key=lambda x: x["cve"])
    return {"advisories": len(man.get("tier1", [])), "pairs": len(rows),
            "label_instances": sum(ldist.values()), "by_justification": ldist,
            "by_vendor": vendors, "rows": rows,
            "note": ("The entire public ICS VEX label set. All justifications are "
                     "code/build-based; no environment-based justification appears.")}


dump("published_vex.json", _published_vex(S))
dump("cve_index.json", list(S.cve_index.values()))
dump("cve_kb.json", {"components": S.kb_comps})   # CVSS-enriched KB
dump("advisories_list.json", {"count": len(S.advisories_list),
                              "advisories": S.advisories_list})

# per-advisory full detail (lazy-loaded by the advisory modal)
_advdir = os.path.join(SITE, "adv")
os.makedirs(_advdir, exist_ok=True)
for _aid, _d in S.adv_detail.items():
    with open(os.path.join(_advdir, _aid + ".json"), "w", encoding="utf-8") as _f:
        json.dump(_d, _f, ensure_ascii=False, separators=(",", ":"))
print("wrote %d per-advisory detail files -> adv/" % len(S.adv_detail))

# ---- 2) client-side JS injected in place of the /api/* backend ------------
INJECT = r"""
let CVE_INDEX=[], CVE_KB={}, KB_COMPS=[], SRC_OK=new Set();
fetch('cve_index.json').then(r=>r.json()).then(d=>{CVE_INDEX=d;for(const r of d)if(r.source_available||r.has_code_pair)SRC_OK.add(r.cve);}).catch(()=>{});
fetch('cve_kb.json').then(r=>r.json()).then(d=>{const idx={};KB_COMPS=(d.components||[]);for(const c of KB_COMPS){for(const k of new Set([c.key,(c.name||'').toLowerCase(),c.cpe_product||''])){if(k)idx[String(k).toLowerCase()]=c;}}CVE_KB=idx;}).catch(()=>{});
function roMatches(a,b){let bi=0,bj=0,bs=0;for(let i=0;i<a.length;i++){for(let j=0;j<b.length;j++){let k=0;while(i+k<a.length&&j+k<b.length&&a[i+k]===b[j+k])k++;if(k>bs){bs=k;bi=i;bj=j;}}}if(bs===0)return 0;return bs+roMatches(a.slice(0,bi),b.slice(0,bj))+roMatches(a.slice(bi+bs),b.slice(bj+bs));}
function roRatio(a,b){a=(a||'').toLowerCase();b=(b||'').toLowerCase();const t=a.length+b.length;return t?2*roMatches(a,b)/t:0;}
function cveIdsFor(comp,ver){if(!comp)return [];const vmap=comp.versions||{};let cves=vmap[ver];if(cves==null){const seen=new Set();cves=[];for(const k in vmap)for(const cv of vmap[k])if(!seen.has(cv.id)){seen.add(cv.id);cves.push(cv);}}return cves.map(cv=>cv.id);}
// returns [component, bestRatio, matchedString, runnerUpRatio] - the runner-up
// is what makes ambiguity detectable; without it `openssl` silently wins over
// `openssh` at 0.857.
function roBest(name){const n=(name||'').toLowerCase();let best=null,br=0,bs=null,second=0;for(const c of KB_COMPS){let cr=0,cs=null;for(const s of [c.name,c.cpe_product,c.key].filter(Boolean)){const r=roRatio(n,s);if(r>cr){cr=r;cs=s;}}if(cr>br){second=br;br=cr;best=c;bs=cs;}else if(cr>second){second=cr;}}return [best,Math.round(br*1000)/1000,bs,Math.round(second*1000)/1000];}
function compareNormJs(sbom,exp,th){const comps=(sbom.components||[]).filter(c=>c&&c.name).map(c=>[String(c.name).trim(),String(c.version||'').trim()]);const rows=[];const ex=new Set(),nm=new Set();for(const [name,ver] of comps){const exact=CVE_KB[name.toLowerCase()];const exIds=cveIdsFor(exact,ver);exIds.forEach(x=>ex.add(x));const rb=roBest(name),nc=rb[0],ratio=rb[1],ms=rb[2];const normalized=ratio>=th?nc:null;const nmIds=cveIdsFor(normalized,ver);nmIds.forEach(x=>nm.add(x));rows.push({component:name,version:ver||'(unpinned)',exact_match:exact?exact.name:null,normalized_match:normalized?normalized.name:null,best_match:nc?nc.name:null,matched_string:ms,ro_ratio:ratio,matched_by_normalization:!!(normalized&&!exact),exact_cve_count:exIds.length,normalized_cve_count:nmIds.length});}const both=[...ex].filter(x=>nm.has(x)).sort();const onlyE=[...ex].filter(x=>!nm.has(x)).sort();const onlyN=[...nm].filter(x=>!ex.has(x)).sort();return {threshold:th,components:comps.length,normalization:rows,comparison:{exact_total:ex.size,normalized_total:nm.size,both:both,only_exact:onlyE,only_normalized:onlyN}};}

// --- component identity and version ranges (mirrors src/sbom_match.py) -------
// Name similarity must not decide identity: RO scores `openssl` against
// `openssh` at 0.857 and they share no CVEs. Identifiers first; a name only
// when it is exact, or fuzzy AND unambiguous.
var VRANGES={};
function _normPkg(x){return String(x||'').toLowerCase().replace(/^lib/,'');}
function _parseVer(s){if(!s)return null;var t=String(s).match(/\d+|[A-Za-z]+/g);if(!t)return null;
  return t.map(function(x){if(/^\d+$/.test(x))return parseInt(x,10);var n=0;
    x.toLowerCase().split('').forEach(function(c){var o=c.charCodeAt(0)-96;if(o>=1&&o<=26)n=n*26+o;});return n;});}
function _cmpVer(a,b){var ta=_parseVer(a),tb=_parseVer(b);if(!ta||!tb)return null;
  var n=Math.max(ta.length,tb.length);for(var i=0;i<n;i++){var x=ta[i]||0,y=tb[i]||0;if(x!==y)return x<y?-1:1;}return 0;}
var UNPINNED={'':1,'noassertion':1,'unknown':1,'none':1,'n/a':1,'*':1};
// true / false / null, where null means undecidable - never read null as false
function inAffectedRange(cve,product,version){
  if(!version||UNPINNED[String(version).toLowerCase()])return null;
  var rs=VRANGES[cve];if(!rs||!rs.length)return null;
  var pkg=_normPkg(product),cand=null;
  for(var i=0;i<rs.length;i++){var r=rs[i];
    if(!(r.startIncl||r.endExcl||r.endIncl))continue;
    var p=_normPkg(r.product);
    if(pkg&&(pkg===p||pkg.indexOf(p)>=0||p.indexOf(pkg)>=0)){cand=r;break;}
    if(!cand)cand=r;}
  if(!cand)return null;
  var c;
  if(cand.startIncl){c=_cmpVer(version,cand.startIncl);if(c===null)return null;if(c<0)return false;}
  if(cand.endExcl){c=_cmpVer(version,cand.endExcl);if(c===null)return null;if(c>=0)return false;}
  if(cand.endIncl){c=_cmpVer(version,cand.endIncl);if(c===null)return null;if(c>0)return false;}
  return true;}
function cvesForVersion(comp,ver){var out=[],seen={};var vmap=comp.versions||{};
  for(var k in vmap)for(var i=0;i<vmap[k].length;i++){var cv=vmap[k][i];
    if(seen[cv.id])continue;seen[cv.id]=1;
    var v=inAffectedRange(cv.id,comp.cpe_product||comp.key,ver);
    if(v===false)continue;            // version is outside the affected range
    cv=Object.assign({},cv,{_decided:v===true});out.push(cv);}
  return out;}
function identifyComp(c){
  var purl=String(c.purl||'').toLowerCase();
  if(purl){var m=purl.match(/^pkg:[^/]+\/(?:[^/@]+\/)?([^@?#]+)/);
    if(m&&CVE_KB[m[1]])return CVE_KB[m[1]];}
  var cpe=String(c.cpe||'').toLowerCase();
  if(cpe){var p=cpe.split(':');if(p.length>=5&&CVE_KB[p[4]])return CVE_KB[p[4]];}
  var name=String(c.name||'').trim();
  if(!name)return null;
  if(CVE_KB[name.toLowerCase()])return CVE_KB[name.toLowerCase()];
  var rb=roBest(name);
  // 0.90 absolute and 0.05 clear of the runner-up, else unidentified
  if(rb[0]&&rb[1]>=0.90&&(rb[1]-(rb[3]||0))>=0.05)return rb[0];
  return null;}

function computeVex(sbom,exp){const rawComps=(sbom.components||[]).filter(c=>c&&c.name);const comps=rawComps.map(c=>[String(c.name).trim(),String(c.version||'').trim()]);const rank={LIKELY_AFFECTED:3,UNDER_INVESTIGATION:2,LIKELY_NOT_AFFECTED:1};const byCve={};for(let ci=0;ci<comps.length;ci++){const name=comps[ci][0],ver=comps[ci][1];const comp=identifyComp(rawComps[ci]);if(!comp)continue;const cves=cvesForVersion(comp,ver);for(const cv of cves){const av=cv.av||'N';const status='UNDER_INVESTIGATION';const row={cve:cv.id,justification:null,component:comp.name,version:ver||'(unpinned)',severity:cv.sev||'',cvss:(cv.cvss!=null?cv.cvss:null),source_collectable:SRC_OK.has(cv.id),av:av,kev:!!cv.kev,final_vex:status,evidence_tier:'under-investigation'};const prev=byCve[cv.id];if(!prev||rank[status]>rank[prev.final_vex])byCve[cv.id]=row;}}var ref2name={};(sbom.components||[]).forEach(c=>{if(c&&c['bom-ref'])ref2name[c['bom-ref']]=c.name||'';});var ref2tier={};(sbom.components||[]).forEach(c=>{if(c&&c['bom-ref']){var t=null;(c.properties||[]).forEach(p=>{if(p.name==='component:source-availability')t=p.value;});ref2tier[c['bom-ref']]=t;}});var _top=((sbom.metadata||{}).component)||{};if(_top['bom-ref'])ref2name[_top['bom-ref']]=_top.name||'';for(const v of (sbom.vulnerabilities||[])){const cid=v.id;if(!cid||byCve[cid])continue;const props={};for(const p of (v.properties||[]))props[p.name]=p.value;let score=null,sev='';for(const r of (v.ratings||[])){if(r.score!=null)score=r.score;if(r.severity)sev=String(r.severity).toLowerCase();}let av='';const mm=/AV:([NALP])/.exec(props['cisa:cvss-v3-vector']||'');if(mm)av=mm[1];const aff=((v.affects||[])[0]||{}).ref;const absent=(aff&&!(aff in ref2name));const status=absent?'LIKELY_NOT_AFFECTED':'UNDER_INVESTIGATION';const just=absent?'component_not_present':null;byCve[cid]={cve:cid,justification:just,component:ref2name[aff]||aff||_top.name||'',version:'NOASSERTION',severity:sev,cvss:score,source_collectable:(ref2tier[aff]==='E'?false:(ref2tier[aff]==='A'||ref2tier[aff]==='C')?true:SRC_OK.has(cid)),av:av,kev:String(props['signal:kev']||'').toLowerCase()==='true',final_vex:status,evidence_tier:(absent?'sbom-evidenced':'under-investigation'),from_vdr:true};}const cves=Object.values(byCve).sort((a,b)=>rank[b.final_vex]-rank[a.final_vex]||a.cve.localeCompare(b.cve));const by={};for(const r of cves)by[r.final_vex]=(by[r.final_vex]||0)+1;return {components:comps.length,cves_matched:cves.length,summary:{by_vex:by},cves:cves};}
function queryCves(dim,value,scope){const rv={LIKELY_AFFECTED:3,UNDER_INVESTIGATION:2,LIKELY_NOT_AFFECTED:1};const rs={critical:4,high:3,medium:2,low:1,unrated:0};let hits=CVE_INDEX.filter(r=>{if(scope==='source_available'&&!r.source_available)return false;if(dim==='cwe')return r.cwe===value;if(dim==='vendor')return (r.vendors||[]).includes(value);if(dim==='device_type')return (r.device_types||[]).includes(value);if(dim==='year')return String(r.year)===String(value);if(dim==='vex')return r.vex===value;if(dim==='severity')return r.severity===value;return false;});hits.sort((a,b)=>((b.kev?1:0)-(a.kev?1:0))||(rv[b.vex]-rv[a.vex])||(rs[b.severity]-rs[a.severity])||a.cve.localeCompare(b.cve));return {count:hits.length,cves:hits.slice(0,400).map(r=>({cve:r.cve,vex:r.vex,severity:r.severity,kev:r.kev,vendor:(r.vendors||[]).slice(0,2).join(', '),component:r.component,cwe:r.cwe,has_code_pair:r.has_code_pair,repo_url:r.repo_url}))};}
"""

html = A.FRONTEND_TEMPLATE   # shared shell (head + script) with __NAV__/__CONTENT__

# stat endpoints -> static json
for old, new in [
    ("'/api/summary'", "'cve_level.json'"),
    ("'/api/source_available'", "'source_available.json'"),
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
           "body:JSON.stringify({sbom,exposure:exp,threshold:th})});if(r.ok)d=await r.json();}catch(e){}")
assert old_cmp in html, "missing compareNorm fetch"
html = html.replace(old_cmp, "  d=compareNormJs(sbom,exp,th);")

# inject client-side engine right before run()
assert "async function run(){" in html
html = html.replace("async function run(){", INJECT + "\nasync function run(){", 1)
# fetch the ranges once, same-origin, before the first analysis
html = html.replace("async function run(){",
                    "async function run(){\n"
                    "  if(!Object.keys(VRANGES).length){try{VRANGES=await(await fetch('cve_version_ranges.json')).json();}catch(e){}}\n",
                    1)

# emit one static file per page (same shared shell/script, different nav+content)
_tree_json = json.dumps(A.VT.TREE, ensure_ascii=False)
html = html.replace("__VEX_TREE__", _tree_json)
for key, fname in [("analyzer", "index.html"),
                   ("vex-decision", "vex-decision.html"),
                   # the merged page keeps answering the old URL
                   ("vex-decision", "vex-method.html"), ("source", "source.html"),
                   ("corpus", "corpus.html"), ("collectable", "collectable.html"),
                   ("published-vex", "published-vex.html"),
                   ("ics-sbom", "ics-sbom.html")]:
    page = html.replace("__NAV__", A.nav_html(key)).replace("__CONTENT__", A.PAGES[key][1])
    open(os.path.join(SITE, fname), "w", encoding="utf-8").write(page)

sz = lambda n: os.path.getsize(os.path.join(SITE, n)) / 1024
print("wrote site/ pages + json:")
for n in ["index.html", "source.html", "corpus.html", "collectable.html",
          "cve_index.json", "cve_level.json", "source_available.json", "by_year.json",
          "advisories.json", "advisories_list.json", "cve_kb.json"]:
    print("  %-24s %.0f KB" % (n, sz(n)))
