# -*- coding: utf-8 -*-
"""The /asset-vex.html page: the asset-attribute exploitability assessment.

For a source-less CVE the code-level tree (Q1-Q4) cannot run, so the user supplies
the asset's real attributes and the server derives the attack vectors on that asset
and matches them against the CVE's CVSS AV. Logic lives in src/asset_av_judge.py;
this is only the form and the result rendering, which call /api/asset-vex.
"""

# Each field: (key, label, type). type "bool" -> yes/no, "enum:a|b|c" -> a select.
# Grouped the way the NVAS spec groups the 22 asset attributes.
ASSET_FIELDS = [
    ("Mobile / maintenance device (PMMD)", [
        ("maint_port_sealed", "Maintenance-port physically sealed", "bool"),
        ("maint_device_used", "Maintenance device in use", "bool"),
    ]),
    ("Communication", [
        ("comm_connected", "Asset is network-connected", "bool"),
        ("unidirectional", "Communication is one-way only", "bool"),
        ("wireless_capable", "Has wireless capability", "bool"),
        ("wireless_enabled", "Wireless is enabled", "bool"),
        ("encrypted_comm", "Communication is encrypted", "bool"),
    ]),
    ("Supply chain / system environment", [
        ("sys_env_configured", "System environment is configured (apps/firmware/OS)", "bool"),
        ("vendor_remote_access", "Vendor remote access is possible", "bool"),
        ("account_mgmt", "Account management is supported", "bool"),
    ]),
    ("Location & physical", [
        ("physical_location", "Physical location", "enum:VA|OCA|PA"),
        ("physical_blocked", "Physically blocked / isolated", "bool"),
    ]),
    ("Security policy", [
        ("host_firewall", "Host firewall applied", "bool"),
        ("work_approval", "Work approval required", "bool"),
        ("access_right", "Asset access right", "enum:admin|operator|none"),
    ]),
]

# The CVE-derived facts of spec 3.5. Left as "unknown" they resolve conservatively.
EXTRA_FIELDS = [
    ("protocol_required", "AV:N/A &mdash; exploit requires a specific protocol/interface", "tri"),
    ("protocol_match", "&nbsp;&nbsp;&mdash; the asset carries a matching protocol/interface", "tri"),
    ("pmmd_required", "AV:P &mdash; exploit must use a portable maintenance device (PMMD)", "tri"),
]

_LOC_LABEL = {"VA": "VA &mdash; visitor-accessible area",
              "OCA": "OCA &mdash; operation-controlled area",
              "PA": "PA &mdash; protected area"}
_ACC_LABEL = {"admin": "admin (관리자)", "operator": "operator (취급자)", "none": "none (없음)"}


def _field_html(key, label, typ):
    if typ == "bool":
        opts = '<option value="">&mdash;</option><option value="y">Yes</option>' \
               '<option value="n">No</option>'
    elif typ == "tri":
        opts = '<option value="">unknown</option><option value="y">Yes</option>' \
               '<option value="n">No</option>'
    elif typ.startswith("enum:"):
        lab = _LOC_LABEL if key == "physical_location" else (
            _ACC_LABEL if key == "access_right" else {})
        opts = '<option value="">&mdash;</option>' + "".join(
            '<option value="%s">%s</option>' % (v, lab.get(v, v))
            for v in typ[5:].split("|"))
    else:
        opts = ""
    return ('<label class="av-f"><span>%s</span>'
            '<select data-k="%s">%s</select></label>' % (label, key, opts))


def _groups_html(groups):
    out = []
    for title, fields in groups:
        rows = "".join(_field_html(k, l, t) for k, l, t in fields)
        out.append('<div class="av-grp"><h4>%s</h4><div class="av-grid">%s</div></div>'
                   % (title, rows))
    return "".join(out)


ASSET_VEX_PAGE = """
<h1 style="margin:0 0 6px">Asset-attribute exploitability assessment</h1>
<p class="hint" style="margin:0 0 18px">
For a CVE whose source cannot be collected, the code-level tree (Q1-Q4) does not apply.
Enter the asset's real attributes instead: the server derives which <b>attack vectors</b>
physically exist on the asset (five NVAS flowcharts) and matches them against the CVE's
<b>CVSS Attack Vector</b> to decide <code>affected</code> / <code>not_affected</code> /
<code>under_investigation</code>. Every input is a fact about one asset &mdash; this is not
the retired synthetic-exposure estimate.</p>

<div class="card" style="margin-bottom:18px">
  <div class="av-cve">
    <label class="av-f" style="flex:1"><span>CVE ID</span>
      <input id="avCve" placeholder="CVE-2022-37434" spellcheck="false"></label>
    <button class="btn" onclick="avLoad()">Load CVE</button>
  </div>
  <div id="avMeta" class="hint" style="margin-top:10px"></div>
</div>

<div class="card" style="margin-bottom:18px">
  <h3 style="margin:0 0 4px">Asset attributes</h3>
  <p class="hint" style="margin:0 0 14px">All fields are required for a verdict. Any left
  blank &rarr; <code>under_investigation</code> (the vector set cannot be trusted).</p>
  __ASSET_GROUPS__
</div>

<div class="card" style="margin-bottom:18px">
  <h3 style="margin:0 0 4px">CVE-derived facts <span class="hint">(optional, from the CVE description)</span></h3>
  <p class="hint" style="margin:0 0 14px">Left <code>unknown</code> they resolve
  conservatively &mdash; an unknown requirement never becomes <code>affected</code> on its own.</p>
  <div class="av-grid">__EXTRA_FIELDS__</div>
</div>

<div style="margin-bottom:18px">
  <button class="btn btn-go" onclick="avAssess()">Assess</button>
  <span id="avStatus" class="hint" style="margin-left:10px"></span>
</div>

<div id="avResult"></div>

<style>
.av-cve{display:flex;gap:10px;align-items:flex-end}
.av-grp{margin-bottom:16px}.av-grp h4{margin:0 0 8px;font-size:14px;color:var(--ink2)}
.av-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.av-f{display:flex;flex-direction:column;gap:4px;font-size:14px}
.av-f span{color:var(--ink2)}
.av-f select,.av-f input{background:var(--card2);color:var(--ink);border:1px solid var(--line);
  border-radius:8px;padding:8px 10px;font-size:14px;font-family:var(--sans)}
.btn-go{font-size:16px;padding:10px 24px}
.av-verdict{font-size:26px;font-weight:800;padding:14px 18px;border-radius:12px;margin-bottom:12px}
.av-aff{background:rgba(229,103,92,.15);color:var(--aff)}
.av-safe{background:rgba(67,190,124,.15);color:var(--safe)}
.av-und{background:rgba(224,178,76,.15);color:var(--und)}
.av-lik-aff{background:rgba(229,103,92,.08);color:var(--aff)}
.av-lik-safe{background:rgba(67,190,124,.08);color:var(--safe)}
.av-lik-mit{background:rgba(96,165,250,.12);color:var(--accent)}
.av-lik-cd{background:rgba(224,178,76,.08);color:var(--und)}
.av-chip{display:inline-block;background:var(--card2);border:1px solid var(--line);
  border-radius:999px;padding:3px 12px;margin:2px 4px 2px 0;font-size:13px;font-family:var(--mono)}
</style>

<script>
var AV_META = null;
async function avLoad(){
  var cve=(document.getElementById('avCve').value||'').trim().toUpperCase();
  var box=document.getElementById('avMeta');
  if(!/^CVE-\d{4}-\d+$/.test(cve)){ box.innerHTML='<span style="color:var(--aff)">Enter a valid CVE ID.</span>'; return; }
  box.textContent='loading\u2026';
  // Runtime (window.__ICSVEX_RUNTIME): /api/cve_av gives AV + description.
  // Static site: no server, so read the AV from the published cve_index.json.
  if(window.__ICSVEX_RUNTIME){
    try{
      var r=await fetch('/api/cve_av/'+cve);
      if(r.ok){ var j=await r.json(); if(j.found){ AV_META=j;
        box.innerHTML='<b>CVSS AV: '+(j.av||'&mdash;')+'</b> &middot; <span class="mono">'+(j.vector||'no vector')+'</span>'
          +(j.description?'<div style="margin-top:6px">'+esc(j.description)+'</div>':''); return; }
        box.innerHTML='<span style="color:var(--aff)">CVE not found in the local NVD cache.</span>'; AV_META=null; return; }
    }catch(e){}
  }
  try{
    if(!window.__CVE_AV){ var ix=await (await fetch('cve_index.json')).json();
      window.__CVE_AV={}; ix.forEach(function(x){ if(x.av)window.__CVE_AV[x.cve]=x.av; }); }
    var av=window.__CVE_AV[cve];
    if(!av){ box.innerHTML='<span style="color:var(--aff)">CVE not found, or it has no CVSS Attack Vector.</span>'; AV_META=null; return; }
    AV_META={cve:cve, av:av, vector:null, description:null};
    box.innerHTML='<b>CVSS AV: '+av+'</b> <span class="hint">(from the published CVE index)</span>';
  }catch(e){ box.innerHTML='<span style="color:var(--aff)">'+e+'</span>'; AV_META=null; }
}
function avCollect(sel){
  var o={};
  document.querySelectorAll(sel+' select').forEach(function(s){
    var k=s.getAttribute('data-k'), v=s.value;
    if(v==='y')o[k]=true; else if(v==='n')o[k]=false; else if(v!=='')o[k]=v; else o[k]=null;
  });
  return o;
}
function avAssess(){
  var st=document.getElementById('avStatus');
  if(!AV_META){ st.innerHTML='<span style="color:var(--aff)">Load a CVE first.</span>'; return; }
  var attrs=avCollect('.av-grp'); var extraRaw=avCollect('.av-grid.ex');
  var j=avAssessLocal(AV_META.av, attrs, extraRaw); j.cve=AV_META.cve;
  st.textContent=''; avShow(j);
}
function avShow(j){
  var cls=(typeof avStatusCls==='function')?avStatusCls(j.status)
    :({affected:'av-aff',not_affected:'av-safe',under_investigation:'av-und'}[j.status]||'av-und');
  var h='<div class="card"><div class="av-verdict '+cls+'">'+j.status.replace(/_/g,' ').toUpperCase()+'</div>';
  if(j.estimated)h+='<p class="hint" style="margin:-4px 0 10px">estimate &mdash; the CVE carries no CVSS Attack Vector, so this reads the asset’s attack surface alone</p>';
  h+='<p style="margin:0 0 12px">'+esc(j.reason||'')+'</p>';
  if(j.vectors){
    h+='<div style="margin-bottom:8px"><b>Attack vectors identified on the asset</b></div>';
    h+= j.vectors.length ? j.vectors.map(function(v){return '<span class="av-chip">'+v+'</span>';}).join('')
       : '<span class="hint">none</span>';
  }
  if(j.missing && j.missing.length){
    h+='<div style="margin-top:10px"><b>Missing attributes ('+j.missing.length+')</b><div class="hint">'
      +j.missing.join(', ')+'</div></div>';
  }
  h+='<div style="margin-top:14px" class="hint">CVE '+esc(j.cve||'')+' &middot; CVSS AV: '+(j.cvss_av||'&mdash;')+'</div>';
  h+='</div>';
  document.getElementById('avResult').innerHTML=h;
}
// tag the extra-fields grid so avCollect can target it
document.addEventListener('DOMContentLoaded',function(){
  var grids=document.querySelectorAll('.av-grid');
  if(grids.length)grids[grids.length-1].classList.add('ex');
});
</script>
""".replace("__ASSET_GROUPS__", _groups_html(ASSET_FIELDS)) \
   .replace("__EXTRA_FIELDS__", "".join(_field_html(k, l, t) for k, l, t in EXTRA_FIELDS))


# --- shared with the analyzer's VEX editor modal --------------------------------
# The modal renders the same attribute form per source-uncollectable CVE. To keep
# one source of truth, the field schema is generated here from the SAME lists the
# standalone page uses, as a JS array, and injected into the shared frontend script
# (api_server __ASSET_AV_JS__). Both forms therefore ask for identical fields.
import json as _json


def _js_schema():
    def opts(typ, key):
        if typ in ("bool", "tri"):
            base = [["", "unknown" if typ == "tri" else "—"], ["y", "Yes"], ["n", "No"]]
            return base
        if typ.startswith("enum:"):
            lab = _LOC_LABEL if key == "physical_location" else (
                _ACC_LABEL if key == "access_right" else {})
            return [["", "—"]] + [[v, lab.get(v, v)] for v in typ[5:].split("|")]
        return []
    groups = [{"title": t, "fields": [{"k": k, "label": l, "type": ty, "opts": opts(ty, k)}
                                      for k, l, ty in fs]}
              for t, fs in ASSET_FIELDS]
    extra = [{"k": k, "label": l, "type": ty, "opts": opts(ty, k)}
             for k, l, ty in EXTRA_FIELDS]
    return _json.dumps({"groups": groups, "extra": extra}, ensure_ascii=False)


ASSET_AV_MODAL_JS = """
// Asset-attribute exploitability form, shared by /asset-vex.html and the analyzer's
// source-uncollectable VEX editor. Schema generated from src/asset_vex_page.py.
var ASSET_AV_SCHEMA = __SCHEMA__;
function _avOpts(opts, cur){return opts.map(function(o){
  return '<option value="'+o[0]+'"'+(o[0]===cur?' selected':'')+'>'+o[1]+'</option>';}).join('');}
function _avFieldHtml(f, pfx, vals){
  var cur=(vals&&vals[f.k])||'';
  return '<label class="av-f"><span>'+f.label+'</span>'
    +'<select data-avk="'+f.k+'" data-avp="'+pfx+'">'+_avOpts(f.opts,cur)+'</select></label>';}
function avAssetFormHtml(pfx, vals){
  var h='';
  ASSET_AV_SCHEMA.groups.forEach(function(g){
    h+='<div class="av-grp"><h4>'+g.title+'</h4><div class="av-grid">'
      +g.fields.map(function(f){return _avFieldHtml(f,pfx,vals);}).join('')+'</div></div>';});
  h+='<div class="av-grp"><h4>CVE-derived facts <span class="hint">(optional, from the CVE description)</span></h4>'
    +'<div class="av-grid">'+ASSET_AV_SCHEMA.extra.map(function(f){return _avFieldHtml(f,pfx,vals);}).join('')+'</div></div>';
  return h;}
// Snapshot every select's raw value (keyed by data-avk) for a given form prefix,
// so a caller can stash it and restore the form after it is rebuilt.
function avSnapshotForm(pfx){
  var m={};
  document.querySelectorAll('select[data-avp="'+pfx+'"]').forEach(function(s){
    if(s.value!=='')m[s.getAttribute('data-avk')]=s.value;});
  return m;}
function avCollectForm(pfx){
  var attrs={}, extra={}, extraKeys={};
  ASSET_AV_SCHEMA.extra.forEach(function(f){extraKeys[f.k]=1;});
  document.querySelectorAll('select[data-avp="'+pfx+'"]').forEach(function(s){
    var k=s.getAttribute('data-avk'), v=s.value, val;
    if(v==='y')val=true; else if(v==='n')val=false; else if(v!=='')val=v; else val=null;
    if(extraKeys[k]){ if(val!==null)extra[k]=val; } else { attrs[k]=val; }
  });
  return {attributes:attrs, extra:extra};}
function avAssessForm(pfx, cve, av, outId){
  // Computed client-side via avAssessLocal (ASSET_AV_CLIENT_JS) - the judge is
  // deterministic, so there is no server round-trip, which is what lets the same
  // code run on the static site with no backend. Async kept for existing callers.
  var out=document.getElementById(outId); if(out)out.textContent='assessing\u2026';
  var c=avCollectForm(pfx);
  var j=avAssessLocal(av, c.attributes, c.extra); j.cve=cve;
  if(out)out.innerHTML=avVerdictHtml(j);
  return Promise.resolve(j);}
function avStatusCls(s){return {affected:'av-aff',not_affected:'av-safe',under_investigation:'av-und',
  likely_affected:'av-lik-aff',likely_not_affected:'av-lik-safe',likely_mitigated:'av-lik-mit',
  likely_cannot_determine:'av-lik-cd'}[s]||'av-und';}
function avVerdictHtml(j){
  var cls=avStatusCls(j.status);
  var h='<div class="av-verdict '+cls+'">'+j.status.replace(/_/g,' ').toUpperCase()+'</div>';
  if(j.estimated)h+='<p class="hint" style="margin:-6px 0 8px">estimate &mdash; the CVE carries no CVSS Attack Vector, so this reads the asset&rsquo;s attack surface alone</p>';
  h+='<p style="margin:0 0 10px">'+(j.reason||'')+'</p>';
  if(j.vectors){h+='<div style="margin-bottom:6px"><b>Attack vectors on the asset</b></div>';
    h+= j.vectors.length ? j.vectors.map(function(v){return '<span class="av-chip">'+v+'</span>';}).join('') : '<span class="hint">none</span>';}
  if(j.missing&&j.missing.length)h+='<div class="hint" style="margin-top:8px">missing: '+j.missing.join(', ')+'</div>';
  return h;}
""".replace("__SCHEMA__", _js_schema())


# --- client-side port of the judge, for the STATIC site (no server) -------------
# asset_av_judge.judge/identify_vectors re-expressed in JS, so the published page
# runs the whole assessment in the browser with no /api call. Kept here beside the
# form schema so a change to one is an obvious prompt to check the other; the
# Python remains the source of truth and tools/check_asset_av_parity.py can diff
# the two by running identical cases through both.
ASSET_AV_CLIENT_JS = r"""
// Mirror of src/asset_av_judge.py. Keep in sync with the Python.
var AV_VECTORS={N:['wired','wireless','supply_chain'],A:['wired','wireless','supply_chain'],
  L:['wired','wireless','physical','pmmd','supply_chain'],P:['physical','pmmd']};
function _avPmmd(a){ if(a.maint_port_sealed)return false; if(!a.maint_device_used)return false;
  if(a.access_right==='admin')return false; return true; }
function _avSupply(a){ if(!a.sys_env_configured)return false;
  if(a.vendor_remote_access)return !a.work_approval;
  if(!a.account_mgmt)return true; return a.access_right==='none'; }
function _avWired(a){ if(!a.comm_connected)return false; if(!a.unidirectional)return true;
  return !a.host_firewall; }
function _avPhysical(a){ var loc=a.physical_location;
  if(loc==='OCA')return true;
  if(loc==='VA'){ if(!a.work_approval)return true; return a.access_right==='none'; }
  if(loc==='PA'){ if(!a.physical_blocked)return true; return a.access_right==='none'; }
  return false; }
function _avWireless(a){ if(!a.wireless_capable)return false; if(!a.wireless_enabled)return false;
  return !a.encrypted_comm; }
var _AV_FC={pmmd:_avPmmd,supply_chain:_avSupply,wired:_avWired,physical:_avPhysical,wireless:_avWireless};
var _AV_ATTRS=['maint_port_sealed','maint_device_used','sys_env_configured','vendor_remote_access',
  'work_approval','account_mgmt','comm_connected','unidirectional','host_firewall',
  'physical_location','physical_blocked','wireless_capable','wireless_enabled','encrypted_comm','access_right'];
function avIdentifyVectors(a){ var out=[]; for(var v in _AV_FC){ if(_AV_FC[v](a))out.push(v); } return out.sort(); }
function avMissing(a){ return _AV_ATTRS.filter(function(k){return a[k]===null||a[k]===undefined;}); }
function avJudge(av, present, extra){
  extra=extra||{};
  if(!av)return {status:'under_investigation',reason:'no CVSS Attack Vector available for this CVE'};
  var cand=AV_VECTORS[av]||[]; var overlap=cand.filter(function(v){return present.indexOf(v)>=0;});
  var shown=overlap.length?overlap.join(', '):'none';
  if(!overlap.length)return {status:'not_affected',reason:'the asset carries none of the attack vectors AV:'+av+' requires'};
  if(av==='L')return {status:'affected',reason:'AV:L - a local action is reachable via a present vector ('+shown+')'};
  if(av==='N'||av==='A'){
    var req=extra.protocol_required;
    if(req===null||req===undefined)return {status:'under_investigation',reason:'AV:'+av+' - whether a specific protocol/interface is required is unknown (needs the CVE description)'};
    if(req){ var m=extra.protocol_match;
      if(m===true)return {status:'affected',reason:'AV:'+av+' - the required protocol/interface is present'};
      if(m===false)return {status:'not_affected',reason:'AV:'+av+' - the required protocol/interface is not present on the asset'};
      return {status:'under_investigation',reason:'AV:'+av+' - a specific protocol/interface is required but the asset match is unknown'}; }
    return {status:'affected',reason:'AV:'+av+' - no specific protocol required and a network vector is present ('+shown+')'}; }
  if(av==='P'){ var pr=extra.pmmd_required;
    if(pr===true){ if(present.indexOf('pmmd')>=0)return {status:'affected',reason:'AV:P - the exploit needs a PMMD and one is present'};
      return {status:'not_affected',reason:'AV:P - the exploit needs a PMMD but none is present'}; }
    if(pr===false){ if(present.indexOf('physical')>=0)return {status:'affected',reason:'AV:P - physical access is present and no PMMD is required'};
      return {status:'under_investigation',reason:'AV:P - no PMMD required, but no physical-access vector is present; unresolved'}; }
    return {status:'under_investigation',reason:'AV:P - whether the exploit requires a PMMD is unknown (needs the CVE description)'}; }
  return {status:'under_investigation',reason:'unrecognised CVSS Attack Vector: '+av};
}
// 4.4 - soft estimate when the CVE has no CVSS AV. Mirror of
// asset_av_judge.semantic_estimate / active_controls. Keep in sync with the Python.
var AV_MITIGATING_CONTROLS=[['host_firewall','wired'],['unidirectional','wired'],
  ['encrypted_comm','wireless'],['maint_port_sealed','pmmd'],['physical_blocked','physical']];
function avActiveControls(a){ return AV_MITIGATING_CONTROLS.filter(function(c){return a[c[0]]===true;}); }
function avSemanticEstimate(present, attrs){
  if(present.length){ var shown=present.join(', ');
    return {status:'likely_affected',reason:'no CVSS AV for this CVE, but the asset exposes attack vector(s) ('+shown+'); with an open surface it is likely reachable'}; }
  // No attack vector present - why it is empty decides the estimate.
  var controls=avActiveControls(attrs);
  if(controls.length){
    var closed=controls.map(function(c){return c[1]+' via '+c[0];}).sort().join(', ');
    return {status:'likely_mitigated',reason:'no CVSS AV, and no attack vector is open because active controls close the paths ('+closed+'); mitigated, but reverts if a control is dropped'};
  }
  var latent=(attrs.wireless_capable&&!attrs.wireless_enabled)||(attrs.maint_device_used&&attrs.access_right==='admin');
  if(latent){
    return {status:'likely_cannot_determine',reason:'no CVSS AV, and no vector is open now, but the asset has latent capability (wireless present-but-disabled, or an admin-gated maintenance device) that configuration alone could reopen'};
  }
  return {status:'likely_not_affected',reason:'no CVSS AV, and the asset exposes no attack vector with no mitigating control or latent capability in force - structurally no reachable surface'};
}
function avAssessLocal(av, attrs, extra){
  var miss=avMissing(attrs);
  if(miss.length)return {status:'under_investigation',reason:'asset attributes not fully entered ('+miss.length+' missing)',missing:miss,vectors:null,cvss_av:av};
  var present=avIdentifyVectors(attrs);
  if(!av){ var e=avSemanticEstimate(present,attrs); e.vectors=present; e.cvss_av=null; e.estimated=true; return e; }
  var r=avJudge(av,present,extra);
  r.vectors=present; r.cvss_av=av; return r;
}
"""
