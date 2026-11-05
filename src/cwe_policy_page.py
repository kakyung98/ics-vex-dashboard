"""Public, searchable evidence-policy explanation. No inference or VEX verdicts."""
def explorer():
    return '''
<section class="method-notes" id="cwe-evidence-policy">
<h2>CWE evidence requirements</h2>
<p>All 944 mapped active detailed CWEs have an individual policy record under the 10 Pillars. Requirements describe where evidence must come from. They do not determine whether a product is affected.</p>
<details class="method-extra" id="cwe-policy-explorer"><summary>Search all 944 CWE profiles</summary>
<p>Baseline rules choose the nearest explicit detailed CWE ancestor. Equally specific requirements combine. CVE-specific implementation/configuration mechanisms can refine the baseline. No Pillar-wide source default applies. Hardware/design and unspecified mechanisms remain unresolved. This project policy has not been independently validated.</p>
<div id="cwe-policy-summary">Open this section to load the policy.</div>
<div id="cwe-pillar-results" style="overflow-x:auto"></div>
<label>CWE or weakness name <input id="cwe-policy-query" placeholder="CWE-862, SQL, permissions" style="width:100%;padding:10px;box-sizing:border-box"></label>
<label>Source requirement <select id="cwe-policy-source"><option value="">All</option><option value="required">Required</option><option value="not_required">Operational review</option><option value="undetermined">Unresolved / specialist evidence</option></select></label>
<label>Pillar <select id="cwe-policy-pillar"><option value="">All Pillars</option></select></label>
<button id="cwe-policy-download" disabled>Download full policy JSON</button>
<p id="cwe-policy-count"></p><div id="cwe-policy-rows" style="overflow-x:auto"></div>
</details></section>
<script>
(()=>{
 const root=document.getElementById('cwe-policy-explorer');if(!root)return;
 const q=document.getElementById('cwe-policy-query'),source=document.getElementById('cwe-policy-source'),pillar=document.getElementById('cwe-policy-pillar');let data=null,loading=false;
 const e=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function show(){if(!data)return;const term=q.value.trim().toLowerCase();
  const rows=Object.values(data.profiles).filter(r=>(!term||(r.cwe+' '+r.name).toLowerCase().includes(term))&&(!source.value||r.source_requirement===source.value)&&(!pillar.value||r.pillars.includes(pillar.value))).sort((a,b)=>Number(a.cwe.slice(4))-Number(b.cwe.slice(4)));
  document.getElementById('cwe-policy-count').textContent=rows.length+' matching CWEs. Showing the first 50; narrow the search or download all records.';
  document.getElementById('cwe-policy-rows').innerHTML='<table><thead><tr><th>CWE / Pillars</th><th>Baseline evidence requirement</th><th>Assignment, mapping and rationale</th></tr></thead><tbody>'+rows.slice(0,50).map(r=>'<tr><td><a href="'+e(r.definition_url)+'" target="_blank" rel="noopener">'+e(r.cwe)+'</a><br>'+e(r.name)+'<br><small>'+e(r.pillars.join(', '))+'</small></td><td>Source baseline: '+e(r.source_requirement)+'<br>Operating baseline: '+e(r.operational_requirement)+'<ul>'+r.required_facts.map(f=>'<li>'+e(f.label)+' ('+e(f.location)+')</li>').join('')+'</ul></td><td>'+e(r.resolution)+'<br>'+e(r.rationale)+'<p>CVE mapping usage: '+e(r.cve_mapping_gate?.usage||'Unknown')+(r.cve_mapping_gate?.requires_mapping_review?' · Mapping review needed.':'')+'</p>'+r.matched_rules.map(m=>'<p>'+e(m.rule_id)+'<br>'+e(m.anchors.map(a=>a.path.join(' → ')).join('; '))+'</p>').join('')+'</td></tr>').join('')+'</tbody></table>';
 }
 root.addEventListener('toggle',async()=>{if(!root.open||data||loading)return;loading=true;
  try{const response=await fetch('/api/item4/cwe-policy');if(!response.ok)throw new Error('Policy unavailable: '+response.status);data=await response.json();
   const s=data.summary;document.getElementById('cwe-policy-summary').textContent=s.version+': '+s.detailed_cwes+' detailed CWEs. Baselines: source '+(s.by_source_requirement.required||0)+', operational '+(s.by_source_requirement.not_required||0)+', unresolved/specialist '+(s.by_source_requirement.undetermined||0)+'. Actual CVE routes also apply mapping restrictions and mechanism evidence. Coverage is not accuracy.';
   document.getElementById('cwe-pillar-results').innerHTML='<h3>All 10 Pillars</h3><p>A CWE may belong to multiple Pillars. Membership counts overlap; there are 944 unique detailed CWEs. These are baseline evidence requirements, not VEX verdicts.</p><table><thead><tr><th>Pillar / name</th><th>Memberships</th><th>Source</th><th>Operational</th><th>Unresolved / specialist</th></tr></thead><tbody>'+Object.entries(s.per_pillar).map(([id,p])=>'<tr><td>'+e(id)+'<br>'+e(p.name)+'</td><td>'+e(p.memberships)+'</td><td>'+e(p.by_source_requirement.required||0)+'</td><td>'+e(p.by_source_requirement.not_required||0)+'</td><td>'+e(p.by_source_requirement.undetermined||0)+'</td></tr>').join('')+'</tbody></table>';
   for(const [id,p] of Object.entries(s.per_pillar)){const option=document.createElement('option');option.value=id;option.textContent=id+' · '+p.name;pillar.appendChild(option);}
   document.getElementById('cwe-policy-download').disabled=false;show();
  }catch(error){document.getElementById('cwe-policy-summary').textContent=String(error);}finally{loading=false;}
 });
 for(const control of [q,source,pillar])control.addEventListener('input',show);
 document.getElementById('cwe-policy-download').addEventListener('click',()=>{if(!data)return;const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='cwe-evidence-policy-v2.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
})();
</script>'''
