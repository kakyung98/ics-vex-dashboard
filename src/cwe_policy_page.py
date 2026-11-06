"""Public, searchable evidence-policy explanation. No inference or VEX verdicts."""
def explorer():
    return '''
<section class="method-notes" id="cwe-evidence-policy">
<h2>CWE evidence collection plans</h2>
<p>All 944 mapped active detailed CWEs have an individual policy record under the 10 Pillars. Every entry has an evidence collection plan with its own official definition and directly listed detection methods. Collection alternatives are separate from final asset-specific requirements.</p>
<details class="method-extra" id="cwe-policy-explorer"><summary>Search all 944 CWE profiles</summary>
<p>Plans use only methods listed on the individual CWE; no method is inherited. Multiple methods are alternatives, not cumulative requirements. Entries without methods start with CVE/vendor mechanism evidence. A collection plan does not prove source is mandatory or an operator questionnaire sufficient. Automated final routing remains disabled.</p>
<div id="cwe-policy-summary">Open this section to load the policy.</div>
<div id="cwe-pillar-results" style="overflow-x:auto"></div>
<label>CWE or weakness name <input id="cwe-policy-query" placeholder="CWE-862, SQL, permissions" style="width:100%;padding:10px;box-sizing:border-box"></label>
<label>Evidence collection route <select id="cwe-policy-source"><option value="">All plans</option><option value="source_review">Source review</option><option value="implementation_review">Implementation review</option><option value="compiled_artifact_review">Compiled-artifact review</option><option value="runtime_observation">Runtime observation records</option><option value="design_review">Design review</option><option value="formal_review">Formal review</option><option value="simulation_review">Simulation review</option><option value="case_evidence_review">Clarify case evidence</option><option value="cve_mechanism_first">CVE/vendor mechanism first</option></select></label>
<label>Pillar <select id="cwe-policy-pillar"><option value="">All Pillars</option></select></label>
<button id="cwe-policy-download" disabled>Download full policy JSON</button>
<p id="cwe-policy-count"></p><div id="cwe-policy-rows" style="overflow-x:auto"></div>
</details></section>
<script>
(()=>{
 const root=document.getElementById('cwe-policy-explorer');if(!root)return;
 const q=document.getElementById('cwe-policy-query'),source=document.getElementById('cwe-policy-source'),pillar=document.getElementById('cwe-policy-pillar');let data=null,loading=false;
 const e=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function planHTML(r){const p=r.evidence_plan;if(!p)return 'No plan record';return '<strong>'+e(p.route_labels_ko.join(' / '))+'</strong><p>'+e(p.next_action)+'</p><details><summary>Entry-specific definition and evidence</summary><p>'+e(p.claim_to_examine.text)+'</p>'+p.alternatives.map(a=>'<p><b>'+e(a.method)+'</b><br>'+e(a.artifacts_to_collect)+'</p><blockquote>'+e(a.evidence.description)+'</blockquote>').join('')+'<p>Methods are alternatives; no ancestor method is inherited. Source necessity and operator-only sufficiency are not established.</p></details>';}
 function show(){if(!data)return;const term=q.value.trim().toLowerCase();
  const rows=Object.values(data.profiles).filter(r=>(!term||(r.cwe+' '+r.name+' '+(r.evidence_plan?.route_labels_ko||[]).join(' ')+' '+(r.evidence_plan?.recommended_routes||[]).join(' ')).toLowerCase().includes(term))&&(!source.value||r.evidence_plan?.recommended_routes.includes(source.value))&&(!pillar.value||r.pillars.includes(pillar.value))).sort((a,b)=>Number(a.cwe.slice(4))-Number(b.cwe.slice(4)));
  document.getElementById('cwe-policy-count').textContent=rows.length+' matching CWEs. Showing the first 50; narrow the search or download all records.';
  document.getElementById('cwe-policy-rows').innerHTML='<table><thead><tr><th>CWE / Pillars</th><th>Baseline evidence requirement</th><th>Collection plan and direct evidence</th></tr></thead><tbody>'+rows.slice(0,50).map(r=>'<tr><td><a href="'+e(r.definition_url)+'" target="_blank" rel="noopener">'+e(r.cwe)+'</a><br>'+e(r.name)+'<br><small>'+e(r.pillars.join(', '))+'</small></td><td>Source baseline: '+e(r.source_requirement)+'<br>Operating baseline: '+e(r.operational_requirement)+'<ul>'+r.required_facts.map(f=>'<li>'+e(f.label)+' ('+e(f.location)+')</li>').join('')+'</ul></td><td>'+planHTML(r)+r.matched_rules.map(m=>'<p>'+e(m.rule_id)+'<br>'+e(m.anchors.map(a=>a.path.join(' → ')).join('; '))+'</p>').join('')+'</td></tr>').join('')+'</tbody></table>';
 }
 root.addEventListener('toggle',async()=>{if(!root.open||data||loading)return;loading=true;
  try{const response=await fetch('/api/item4/cwe-policy');if(!response.ok)throw new Error('Policy unavailable: '+response.status);data=await response.json();
   const s=data.summary,plans=s.evidence_plans;document.getElementById('cwe-policy-summary').textContent=s.version+': '+plans.total+' evidence collection plans. '+plans.entry_specific_method_available+' entries list their own detection methods; '+plans.mechanism_first+' start with CVE/vendor mechanism evidence. Alternatives are not mandatory requirements. Automatic evidence routing is disabled pending case-specific selection. Only CWE IDs already reported for the CVE are used; no new CWE is assigned.';
   document.getElementById('cwe-pillar-results').innerHTML='<h3>All 10 Pillars</h3><p>Membership counts overlap; there are 944 unique detailed CWEs. Every entry has a collection plan. A listed method is an alternative, not a mandatory source requirement.</p><table><thead><tr><th>Pillar / name</th><th>Memberships</th><th>Collection plans</th><th>Own detection methods</th><th>Mechanism first</th></tr></thead><tbody>'+Object.entries(s.per_pillar).map(([id,p])=>{const members=Object.values(data.profiles).filter(r=>r.pillars.includes(id));const direct=members.filter(r=>r.evidence_plan.alternatives.length).length;return '<tr><td>'+e(id)+'<br>'+e(p.name)+'</td><td>'+e(p.memberships)+'</td><td>'+e(members.length)+'</td><td>'+e(direct)+'</td><td>'+e(members.length-direct)+'</td></tr>';}).join('')+'</tbody></table>';
   for(const [id,p] of Object.entries(s.per_pillar)){const option=document.createElement('option');option.value=id;option.textContent=id+' · '+p.name;pillar.appendChild(option);}
   document.getElementById('cwe-policy-download').disabled=false;show();
  }catch(error){document.getElementById('cwe-policy-summary').textContent=String(error);}finally{loading=false;}
 });
 for(const control of [q,source,pillar])control.addEventListener('input',show);
 document.getElementById('cwe-policy-download').addEventListener('click',()=>{if(!data)return;const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='cwe-evidence-policy-v2.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
})();
</script>'''
