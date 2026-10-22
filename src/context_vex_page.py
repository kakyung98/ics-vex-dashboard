# -*- coding: utf-8 -*-
"""The /context-vex.html page — the 6W problem map and the context VEX judge.

Markup and client script only. Every figure on the page comes from
/api/problems-6w (recomputed from the corpus on each call) and every verdict from
/api/context-vex, which calls src/vex_context_judge.judge - the same function the
CLI and the sensitivity measurement use. Nothing is computed in the browser,
because a second implementation of the rule is a second rule.

The page is built around the one distinction the methodology turns on, so a
reviewer cannot miss it: the context form is split into three columns by what
each group of facts is ALLOWED TO DECIDE - structural facts may refute, controls
may only lower priority, mission facts may only rank. The result panel shows
every precondition the CVE's vector imposes next to the outcome the asset gave
it, so a verdict can be read back to the fact that produced it.
"""

CONTEXT_VEX_PAGE = """
<h1 style="margin:0 0 6px">S/HBOM &rarr; CVE: the 6W problems, and VEX from CVSS &times; context</h1>
<p class="hint" style="margin:0 0 16px">
Identifying a CVE from a bill of materials is six separate identity questions, and they
fail for different reasons with different prospects of repair. This page states each one,
its verdict (<b>solved / partial / unsolvable</b>) and its measured size &mdash; then runs the
VEX judgment that follows from those limits: the <b>complete CVSS vector</b> read as a set of
environmental preconditions, tested against the <b>asset's operational context</b>.
Full write-up: <code>docs/METHODOLOGY_V3.md</code>.
</p>

<div class="card" id="whyCard" style="margin-bottom:16px">
  <h3 style="margin:0 0 8px">Why the method changed</h3>
  <div id="whyNums" class="hint">measuring&hellip;</div>
</div>

<h2 style="margin:22px 0 8px;font-size:17px">1 &middot; The 6W problem map</h2>
<p class="hint" style="margin:0 0 10px">
<b>unsolvable</b> does not mean "hard". It means the answer is not in the document, so no
better algorithm recovers it. Each one is handled by narrowing the claim, declaring an
input, or refusing to answer &mdash; never by guessing.
</p>
<div id="w6Table" class="hint">loading&hellip;</div>

<h2 style="margin:26px 0 8px;font-size:17px">2 &middot; Judge one (asset, CVE) statement</h2>
<p class="hint" style="margin:0 0 10px">
Enter a CVE and the asset's facts. The vector is fetched from the NVD cache.
<b>A blank form clears nothing</b> &mdash; refutation needs structural facts, and that is the
intended failure mode rather than a bug.
</p>

<div class="cv-run">
  <input id="cvCve" placeholder="CVE-2021-22779" value="CVE-2021-22779" />
  <button id="cvGo" class="btn">Judge</button>
  <button id="cvFill" class="btn btn-sec">Fill: headless L1 PLC</button>
  <button id="cvClear" class="btn btn-sec">Clear</button>
  <span id="cvState" class="hint"></span>
</div>

<div id="cvForm" class="cv-cols"></div>
<div id="cvResult"></div>

<h2 style="margin:26px 0 8px;font-size:17px">3 &middot; Corpus-wide sensitivity</h2>
<p class="hint" style="margin:0 0 10px">
The corpus carries operational context for <b>0%</b> of its assets, so there is no real
context to measure against. What can be measured honestly is how much of the real
identified CVE population a realistic asset profile decides.
Regenerate with <code>python tools/eval_context_vex.py</code>.
</p>
<div id="cvSens" class="hint">loading&hellip;</div>

<style>
.cv-run{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 14px}
.cv-run input{background:#0d140d;border:1px solid var(--bd,#2b3a2b);color:inherit;
  border-radius:6px;padding:7px 10px;font-family:ui-monospace,Consolas,monospace;min-width:190px}
.cv-cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:14px}
.cv-grp{border:1px solid var(--bd,#2b3a2b);border-radius:8px;padding:12px 14px}
.cv-grp h4{margin:0 0 2px;font-size:14px}
.cv-grp .cv-rule{font-size:11.5px;color:#9aa;margin:0 0 10px;line-height:1.45}
.cv-f{display:grid;grid-template-columns:1fr auto;gap:4px 10px;align-items:center;
  padding:5px 0;border-top:1px dashed #243024}
.cv-f:first-of-type{border-top:0}
.cv-f label{font-size:12.5px;line-height:1.35}
.cv-f select{background:#0d140d;border:1px solid var(--bd,#2b3a2b);color:inherit;
  border-radius:5px;padding:3px 6px;font-size:12px}
.cv-help{grid-column:1/-1;font-size:11px;color:#7b8a7b;line-height:1.4;margin:1px 0 2px}
.cv-badge{font-weight:700;font-size:11px;padding:2px 7px;border-radius:9px}
.cv-s{background:#1f3d26;color:#8ce99a}
.cv-c{background:#3d351f;color:#ffd866}
.cv-m{background:#1f303d;color:#8cc9e9}
table.cv-t{width:100%;border-collapse:collapse;font-size:12.5px}
table.cv-t th,table.cv-t td{text-align:left;padding:5px 8px;border-bottom:1px solid #223022;
  vertical-align:top}
table.cv-t th{color:#9aa;font-weight:600;white-space:nowrap}
.v-solved{color:#8ce99a;font-weight:700}
.v-partial{color:#ffd866;font-weight:700}
.v-unsolvable{color:#ff8787;font-weight:700}
.o-impossible{color:#8ce99a;font-weight:700}
.o-mitigated{color:#ffd866;font-weight:700}
.o-satisfied{color:#ff8787;font-weight:700}
.o-unknown{color:#9aa;font-weight:700}
.cv-verdict{border:1px solid var(--bd,#2b3a2b);border-radius:8px;padding:14px 16px;margin-top:16px}
.cv-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.cv-st{font-size:18px;font-weight:800}
.st-not_affected{color:#8ce99a}.st-affected{color:#ff8787}
.st-under_investigation{color:#ffd866}.st-fixed{color:#8cc9e9}
.cv-note{font-size:12px;color:#ffd866;border-left:3px solid #6b5a1f;padding:4px 0 4px 9px;
  margin:7px 0;line-height:1.5}
.cv-sc{display:flex;gap:18px;flex-wrap:wrap;margin:10px 0;font-size:13px}
.cv-sc b{font-size:16px}
</style>

<script>
(function(){
 var F=null;
 function el(id){return document.getElementById(id);}
 function esc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){
   return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}

 // ---- 1. the 6W map -------------------------------------------------------
 fetch('/api/problems-6w').then(function(r){return r.json();}).then(function(d){
   var s=d.stats||{}, c=d.verdict_counts||{};
   el('whyNums').innerHTML=
     '<table class="cv-t"><tr><th>measured over the corpus</th><th>value</th><th>consequence</th></tr>'
     +row('components whose source is closed (of those declaring a tier)', s.source_closed_pct,
          'a source-based gate cannot be the primary method')
     +row('identified CVEs carrying a CVSS vector', s.cvss_absent_pct==null?null:
          (100-s.cvss_absent_pct).toFixed(2), 'the vector CAN speak for almost the whole population')
     +row('assets carrying any ICS operational property', s.asset_opcontext_pct,
          'context is an INPUT to declare, not something to infer')
     +row('components whose version field is NOASSERTION', s.version_noassertion_pct,
          'the deciding field is empty; the range comes from the name instead')
     +row('components carrying a CPE', s.component_cpe_pct,
          'identification runs on order codes and names, not identifiers')
     +'</table><p class="hint" style="margin:8px 0 0">corpus: '+esc(s.assets)+' assets, '
     +esc(s.components)+' components, '+esc(s.cves)+' distinct CVEs &middot; verdicts: '
     +'<span class="v-solved">'+esc(c.solved)+' solved</span>, '
     +'<span class="v-partial">'+esc(c.partial)+' partial</span>, '
     +'<span class="v-unsolvable">'+esc(c.unsolvable)+' unsolvable</span></p>';

   var ax={}, order=['WHO','WHAT','WHEN','WHERE','WHY','HOW'];
   (d.problems||[]).forEach(function(p){(ax[p.axis]=ax[p.axis]||[]).push(p);});
   var h='<table class="cv-t"><tr><th>axis</th><th>id</th><th>problem</th><th>verdict</th>'
        +'<th>measured</th><th>how it is handled</th></tr>';
   order.forEach(function(a){(ax[a]||[]).forEach(function(p,i){
     var m=p.measured&&p.measured.value!=null
       ? '<b>'+esc(p.measured.value)+'%</b><br><span style="color:#7b8a7b">'
         +esc(p.measured.label)+'</span>' : '&mdash;';
     h+='<tr><td>'+(i?'':'<b>'+esc(a)+'</b>')+'</td><td>'+esc(p.id)+'</td>'
       +'<td><b>'+esc(p.name)+'</b><br><span style="color:#8a988a">'+esc(p.problem)+'</span></td>'
       +'<td class="v-'+esc(p.verdict)+'">'+esc(p.verdict)+'</td><td>'+m+'</td>'
       +'<td>'+esc(p.mechanism)+'<br><span style="color:#7b8a7b">residual: '
       +esc(p.residual)+'</span></td></tr>';
   });});
   el('w6Table').innerHTML=h+'</table>';
 }).catch(function(e){el('w6Table').textContent='could not load /api/problems-6w: '+e;});

 function row(label,val,cons){
   return '<tr><td>'+esc(label)+'</td><td><b>'+(val==null?'&mdash;':esc(val)+'%')
     +'</b></td><td style="color:#8a988a">'+esc(cons)+'</td></tr>';
 }

 // ---- 2. the context form -------------------------------------------------
 var GRP=[['structural','Structural &mdash; may refute','cv-s'],
          ['control','Controls &mdash; priority only','cv-c'],
          ['mission','Mission &mdash; ranking only','cv-m']];

 fetch('/api/context/fields').then(function(r){return r.json();}).then(function(d){
   F=d; var h='';
   GRP.forEach(function(g){
     var fields=(d.groups||{})[g[0]]||[];
     h+='<div class="cv-grp"><h4><span class="cv-badge '+g[2]+'">'+g[1]+'</span></h4>'
       +'<p class="cv-rule">'+esc((d.rule||{})[g[0]])+'</p>';
     fields.forEach(function(f){
       h+='<div class="cv-f"><label for="f_'+f.key+'">'+f.label+'</label>'+sel(f)+
          (f.help?'<div class="cv-help">'+esc(f.help)+'</div>':'')+'</div>';
     });
     h+='</div>';
   });
   el('cvForm').innerHTML=h;
 }).catch(function(e){el('cvForm').textContent='could not load the schema: '+e;});

 function sel(f){
   var o='<option value="">&mdash; not stated</option>';
   if(f.type==='bool'||f.type==='tri'){o+='<option value="y">Yes</option><option value="n">No</option>';}
   else if(f.type.indexOf('enum:')===0){
     f.type.slice(5).split('|').forEach(function(v){
       o+='<option value="'+esc(v)+'">'+esc(v)+'</option>';});
   }
   return '<select id="f_'+f.key+'">'+o+'</select>';
 }

 function collect(){
   var ctx={};
   if(!F)return ctx;
   GRP.forEach(function(g){((F.groups||{})[g[0]]||[]).forEach(function(f){
     var e=el('f_'+f.key); if(!e||!e.value)return;
     ctx[f.key]= f.type==='bool'||f.type==='tri' ? (e.value==='y') : e.value;
   });});
   return ctx;
 }

 var PRESET={net_interface_present:'y',radio_hardware_present:'n',
   sole_path_hardware_diode:'n',physical_port_access:'sealed-policy',
   interactive_operator:'n',local_execution_possible:'n',account_subsystem:'none',
   network_exposure:'control-network',purdue_level:'1',host_firewall:'y',
   software_unidirectional:'n',auth_enforced:'n',transport_encrypted:'n',
   app_allowlisting:'n',removable_media_blocked:'y',cabinet_locked:'y',
   vendor_remote_access:'n',work_approval:'y',device_class:'plc',
   safety_function:'y',sil:'SIL2',availability_tolerance:'continuous',
   data_sensitivity:'none',patch_cadence:'frozen-validated-state'};

 el('cvFill').onclick=function(){
   Object.keys(PRESET).forEach(function(k){var e=el('f_'+k); if(e)e.value=PRESET[k];});
   el('cvState').textContent='filled a headless Level-1 PLC profile';
 };
 el('cvClear').onclick=function(){
   if(!F)return;
   GRP.forEach(function(g){((F.groups||{})[g[0]]||[]).forEach(function(f){
     var e=el('f_'+f.key); if(e)e.value='';});});
   el('cvResult').innerHTML=''; el('cvState').textContent='cleared';
 };

 el('cvGo').onclick=function(){
   var cve=(el('cvCve').value||'').trim().toUpperCase();
   if(!cve){el('cvState').textContent='enter a CVE id';return;}
   el('cvState').textContent='judging '+cve+'\\u2026';
   fetch('/api/context-vex',{method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({cve:cve,context:collect()})})
   .then(function(r){return r.json();}).then(render)
   .catch(function(e){el('cvState').textContent='failed: '+e;});
 };

 function render(d){
   el('cvState').textContent='';
   var cv=d.cvss||{}, sc=d.score||{};
   var h='<div class="cv-verdict"><div class="cv-head">'
     +'<span class="cv-st st-'+esc(d.status)+'">'+esc(String(d.status||'').toUpperCase())+'</span>'
     +(d.justification?'<code>'+esc(d.justification)+'</code>':'')
     +(d.scope?'<span class="hint">scope: '+esc(d.scope)+'</span>':'')+'</div>'
     +'<p style="margin:7px 0 0;font-size:13px">'+esc(d.reason)+'</p>';

   h+='<div class="cv-sc"><span>CVSS '+esc(cv.version||'?')+' base <b>'+esc(sc.base)
     +'</b></span><span>environmental <b>'+(sc.environmental==null?'&mdash;':esc(sc.environmental))
     +'</b></span>'+(sc.threat?'<span class="hint">threat E:'+esc(sc.threat.E)+' RL:'
     +esc(sc.threat.RL)+' RC:'+esc(sc.threat.RC)+'</span>':'')
     +(sc.modifiers&&Object.keys(sc.modifiers).length
       ?'<span class="hint">modifiers '+esc(JSON.stringify(sc.modifiers))+'</span>':'')
     +'</div>';

   if((d.preconditions||[]).length){
     h+='<table class="cv-t"><tr><th>precondition</th><th>metric</th>'
       +'<th>what the exploit needs</th><th>on this asset</th></tr>';
     d.preconditions.forEach(function(p){
       h+='<tr><td><code>'+esc(p.id)+'</code></td><td>'+esc(p.metric)+'</td>'
         +'<td>'+esc(p.need)+'</td><td class="o-'+esc(p.outcome)+'">'+esc(p.outcome)
         +'<br><span style="color:#8a988a;font-weight:400">'+esc(p.why)+'</span></td></tr>';
     });
     h+='</table>';
   }
   (d.notes||[]).forEach(function(n){h+='<div class="cv-note">'+esc(n)+'</div>';});
   if((d.mitigations||[]).length){
     h+='<p class="hint" style="margin:10px 0 0"><b>Controls in force</b> (exported as CSAF '
       +'<code>remediation / mitigation</code> on an <code>affected</code> statement &mdash; never as a '
       +'justification):</p><ul class="hint" style="margin:4px 0 0;padding-left:20px">';
     d.mitigations.forEach(function(m){h+='<li>'+esc(m.detail)+'</li>';});
     h+='</ul>';
   }
   if((sc.why||[]).length){
     h+='<p class="hint" style="margin:10px 0 2px"><b>How the score was derived</b></p>'
       +'<ul class="hint" style="margin:0;padding-left:20px">';
     sc.why.forEach(function(w){h+='<li>'+esc(w)+'</li>';});
     h+='</ul>';
   }
   var rd=d.readiness||{};
   h+='<p class="hint" style="margin:10px 0 0">evidence basis: '+esc(d.evidence_basis)
     +' &middot; attested by: '+esc(d.attested_by||'(nobody)')
     +' &middot; can refute with this context: <b>'+(rd.can_refute?'yes':'no')+'</b>'
     +((rd.missing_structural||[]).length?' &middot; unanswered structural facts: '
       +esc(rd.missing_structural.join(', ')):'')+'</p></div>';
   el('cvResult').innerHTML=h;
 }

 // ---- 3. sensitivity ------------------------------------------------------
 fetch('/api/context/sensitivity').then(function(r){return r.json();}).then(function(d){
   if(!d.available){el('cvSens').innerHTML='not measured yet &mdash; run <code>'
     +esc(d.how)+'</code>';return;}
   var h='<p class="hint" style="margin:0 0 8px">population <b>'+esc(d.population)
     +'</b> distinct CVEs, <b>'+esc(d.with_cvss)+'</b> with a vector</p>'
     +'<table class="cv-t"><tr><th>asset archetype</th><th>affected</th>'
     +'<th>not_affected</th><th>under_inv</th><th>env&ge;9</th>'
     +'<th>what refuted</th></tr>';
   Object.keys(d.archetypes||{}).forEach(function(k){
     var r=d.archetypes[k].result||{}, s=r.status||{}, rb=r.refuted_by||{};
     var top=Object.keys(rb).sort(function(a,b){return rb[b]-rb[a];})
              .map(function(x){return x+' \\u00d7'+rb[x];}).join(', ')||'&mdash;';
     h+='<tr><td>'+esc(k)+'</td><td>'+esc(s.affected||0)+'</td>'
       +'<td><b>'+esc(s.not_affected||0)+'</b></td><td>'+esc(s.under_investigation||0)+'</td>'
       +'<td>'+esc(r.affected_env_ge9)+'</td><td style="color:#8a988a">'+top+'</td></tr>';
   });
   el('cvSens').innerHTML=h+'</table>';
 }).catch(function(e){el('cvSens').textContent='could not load: '+e;});
})();
</script>
"""
