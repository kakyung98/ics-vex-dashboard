/* Shared explanation renderer. All source text is untrusted display data. */
function ocSafeUrl(value){
 try{const u=new URL(value);return ['https:','http:'].includes(u.protocol)&&!u.username&&!u.password?u.href:''}catch(_){return ''}
}
function ocSourceLink(origin){
 const url=ocSafeUrl(origin?.url);const name=origin?.advisory_id||origin?.kind||'Source';
 return url?'<a href="'+esc(url)+'" target="_blank" rel="noopener noreferrer">'+esc(name)+'</a>':esc(name);
}
function ocContext(e){
 const text=Array.from(String(e.context||e.quote||'')),start=Number(e.span?.[0])-Number(e.context_start||0),size=Array.from(String(e.quote||'')).length;
 if(start<0||text.slice(start,start+size).join('')!==e.quote)return esc(text.join(''));
 return esc(text.slice(0,start).join(''))+'<mark>'+esc(e.quote)+'</mark>'+esc(text.slice(start+size).join(''));
}
function renderOperationalClassification(data){
 if(!data)return '<p class="hint">No classification snapshot was saved with this review. Open the current CVE explanation separately.</p>';
 if(data.status!=='available')return '<section class="classification-panel"><h4>Operational classification</h4><p>'+esc(data.reason||'Classification unavailable.')+'</p><p class="hint">No type was invented. This is not a non-impact finding.</p></section>';
  let html='<section class="classification-panel"><h4>Weakness families and operating review</h4>';
  const cp=data.cvss_condition_profile;
  if(cp?.cluster_id){
   html+='<h4>CVSS condition profile</h4><p><strong>Source extraction:</strong> '+esc(cp.extraction_complete?'Reading complete; semantic review pending':'Pending or incomplete')+'</p>';
   html+='<p><strong>Published CVSS '+esc(cp.published?.version||'unknown')+':</strong> <code>'+esc(cp.published?.raw_vector||'Not available')+'</code></p>';
   html+='<p><strong>CVSS 4.0 source interpretations:</strong> '+Object.entries(cp.interpreted||{}).map(([m,v])=>esc(m)+'='+esc(v.join('/'))).join(' · ')+'</p>';
   html+='<p class="hint">Published values and model interpretations remain separate. Missing values are unknown. A shared profile does not establish equivalent attack paths or reusable asset answers.</p>';
   for(const f of cp.facts||[])html+='<details><summary>'+esc(f.condition)+'</summary><p>'+esc(f.kind)+' · '+esc(f.necessity)+' · '+esc(f.polarity)+'</p><blockquote>'+esc(f.evidence_quote)+'</blockquote><p>'+ocSourceLink(f.source_origin)+'</p></details>';
  }
  const weakness=data.weakness_review;
  if(weakness?.status==='available'){
    html+='<p><strong>Original taxonomy: '+esc(String(weakness.family_count))+' weakness families</strong></p>';
    html+=(weakness.memberships||[]).length?'<ul>'+weakness.memberships.map(m=>'<li>'+esc(m.name)+' · '+esc(m.basis)+'<br><span class="hint">'+m.required_operational_evidence.map(esc).join(' · ')+'</span></li>').join('')+'</ul>':'<p class="hint">No family assigned in the original taxonomy. Operational and CVE-specific review continues.</p>';
  }
  html+='<h4>Operational review types</h4><p class="hint">11 source-based operating workflows complement the 17 weakness families. Neither is a VEX verdict.</p><p class="hint">'+esc(data.specificity==='cvss_coarse'?'Only a broad CVSS-scored path is known.':data.specificity==='unresolved'?'Operational path or CVE identity requires investigation.':'Source-based workflow candidates; semantic review is still required.')+'</p>';
 for(const member of data.memberships||[]){
  html+='<details class="classification-type"><summary>'+esc(member.name)+(member.is_primary?' <span class="pill">Primary display label</span>':' <span class="pill">Additional candidate</span>')+'</summary><p>'+esc(member.definition)+'</p><p><strong>Selection criterion:</strong> '+esc(member.selection_criteria)+'</p>';
  if(member.scored_vector)html+='<p><strong>Scored source:</strong> <code>'+esc(member.scored_vector)+'</code><br><span class="hint">'+esc(member.scored_source_field)+'</span></p>';
  const evidence=member.evidence||[];
  if(evidence.length){
   html+='<p><strong>Literal source matches</strong></p>';
   for(const e of evidence.slice(0,4))html+='<blockquote class="classification-quote">'+ocContext(e)+'</blockquote><p class="hint">'+ocSourceLink(e.origin)+' · characters '+esc(String(e.span[0]))+'–'+esc(String(e.span[1]))+'<br>Source ID: <code>'+esc(e.source_id)+'</code></p>';
   if(evidence.length>4)html+='<p class="hint">Showing 4 of '+evidence.length+' matches. All source references are retained in the review JSON.</p>';
  }else html+='<p class="hint">No literal interface match. This label follows scored-path or discovery rules.</p>';
  html+='<p><strong>What this does not establish:</strong> '+esc(member.does_not_establish)+'</p><p class="hint">'+esc(member.invalid_shortcut)+'</p><details><summary>Exact matching rules</summary><pre>'+esc(JSON.stringify(member.patterns||[],null,2))+'</pre></details></details>';
 }
 if(data.review_notes?.length)html+='<div class="classification-notes"><strong>Review notes</strong><ul>'+data.review_notes.map(n=>'<li>'+esc(n)+'</li>').join('')+'</ul></div>';
 html+='<details class="classification-policy"><summary>How types and questions are selected</summary><p>'+esc(data.criteria.principle)+'</p><p>'+esc(data.criteria.method)+'</p><p>'+esc(data.criteria.cwe_role)+'</p><p>'+esc(data.criteria.primary_policy)+'</p><p>'+esc(data.criteria.multi_label)+'</p><p>'+esc(data.criteria.question_method)+'</p><p>'+esc(data.criteria.question_purposes)+'</p></details><p class="hint">Classification selects checks; it does not determine VEX status. Dataset: '+esc(data.dataset_version)+' · Source snapshot: '+esc(data.snapshot_completed_at||'unknown')+'</p></section>';
 return html;
}
function renderOperationalQuestionRationale(q){
 const origin=q.origin==='fixed_template'?'Fixed workflow template':q.origin==='system'?'Fixed installation check':q.origin==='llm'?'Historical model-generated question':'Historical rule question';
  const selected={source_workflow_candidate:'A literal source match selected this workflow',cvss_coarse:'A broad CVSS-scored path selected this discovery check',unresolved:'Insufficient detail; use a fixed discovery check',weakness_family_hint:'An original weakness-family assignment selected this investigation topic; no prerequisite is inferred'};
 const purposes={applicability:'Affected product or feature',access:'Actors and access',input_path:'Input origin and handling',trigger:'CVE-described trigger',scope:'Assessment coverage',configuration:'Actual configuration',privileges:'Actual execution rights',mitigation:'Operational protection or remediation',operational_impact:'Outage, dependency and recovery planning',discovery:'Missing source details'};
 let h='<p><strong>Question method:</strong> '+esc(origin)+'</p>';
 if(q.template_id)h+='<p><strong>Template:</strong> <code>'+esc(q.template_id)+'</code><br><strong>Purpose:</strong> '+esc(purposes[q.purpose_category]||q.purpose_category||'review')+'<br><strong>Selected by:</strong> '+esc(selected[q.selection_basis]||q.selection_basis||'fixed policy')+'</p>';
 h+='<p>'+esc(q.purpose||'Record observable operating facts.')+'</p>';
 if(q.purpose_category==='operational_impact')h+='<p><strong>Dependency and recovery answers are for outage planning. They cannot establish not_affected.</strong></p>';
 if(q.evidence)h+='<blockquote>'+esc(q.evidence)+'</blockquote>';
 if(q.source_provenance?.length)h+='<p>'+q.source_provenance.map(ocSourceLink).join(' · ')+'</p>';
 if(q.required_records?.length)h+='<p><strong>Records to check:</strong> '+q.required_records.map(esc).join(' · ')+'</p>';
 if(q.cvss40)h+='<p><strong>Source interpretation:</strong> '+esc(q.cvss40.metric||'Detail outside CVSS')+'='+esc(q.cvss40.value)+' · '+esc(q.necessity)+' · '+esc(q.polarity||'present')+'</p>';
 return h+'<p class="hint">A type or source mention is not a proven necessary condition. Yes/no/unknown answers alone do not clear this CVE.</p>';
}
async function showOperationalClassification(cve){
 const box=document.getElementById('classification-search-detail');if(!box)return;
 const request=cve;box.dataset.cve=request;box.innerHTML='<p class="hint">Loading classification evidence…</p>';
 try{const response=await fetch('/api/operational-classification/'+encodeURIComponent(cve));if(!response.ok)throw new Error('Classification requires the local backend.');const data=await response.json();if(box.dataset.cve!==request)return;box.innerHTML='<h3>'+esc(cve)+'</h3>'+renderOperationalClassification(data)}catch(error){if(box.dataset.cve===request)box.innerHTML='<p class="hint">'+esc(error.message)+'</p>'}
}
async function loadOperationalClassificationCatalog(){
 const box=document.getElementById('classification-catalog');if(!box)return;
 try{
  const response=await fetch('/api/operational-classification/catalog');if(!response.ok)throw new Error('Connect the local backend to view the saved classification criteria.');
  const data=await response.json();if(data.status!=='available')throw new Error(data.reason||'Classification snapshot unavailable.');
    const weakness=data.weakness_taxonomy;
    const cp=data.cvss_condition_taxonomy;
    box.innerHTML=(weakness?.status==='available'?'<h3>Original 17 weakness families</h3><p>'+esc(weakness.boundary)+'</p>'+weakness.profiles.map(p=>'<details class="classification-type"><summary>'+esc(p.name)+'</summary><p>'+esc(p.review_question)+'</p><p>'+p.required_operational_evidence.map(esc).join(' · ')+'</p></details>').join(''):'')+'<h3>Operating review workflows</h3><p>'+esc(data.criteria.principle)+'</p><p>'+esc(data.criteria.question_method)+'</p><p class="hint">'+esc(data.criteria.boundary)+'</p>'+data.profiles.map(p=>'<details class="classification-type"><summary>'+esc(p.name)+'</summary><p>'+esc(p.definition)+'</p><p><strong>Selection criterion:</strong> '+esc(p.selection_criteria)+'</p><p><strong>Boundary:</strong> '+esc(p.does_not_establish)+'</p><details><summary>Exact matching rules</summary><pre>'+esc(JSON.stringify(p.patterns,null,2))+'</pre></details></details>').join('');
    if(cp?.status==='available')box.innerHTML='<h3>CVSS condition profiles</h3><p>'+esc(cp.method)+'</p><p>'+esc(String(cp.population))+' CVEs · '+esc(String(cp.profile_groups))+' profiles · '+esc(String(cp.extraction_complete_cves))+' source readings complete. Source interpretation and asset evidence still require review.</p>'+box.innerHTML;
 }catch(error){box.textContent=error.message}
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',loadOperationalClassificationCatalog);else loadOperationalClassificationCatalog();
