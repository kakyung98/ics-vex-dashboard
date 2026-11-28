(function(){
'use strict';
const $=id=>document.getElementById('ov-'+id),root=$('panel');if(!root)return;
const clone=x=>JSON.parse(JSON.stringify(x)),el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
let selectedCve='',plan=null,profile=null,answers={},result=null,stale=true,sequence=0;
const labels={affected:'Affected',fixed:'Fixed',not_affected:'Not affected',under_investigation:'Under investigation'};
function message(text){$('message').textContent=text;}
function invalidate(){sequence++;result=null;$('result').hidden=true;if(plan)drawGraph();}
function profileChanged(){stale=true;invalidate();$('evaluate').disabled=true;summary();message('The component scope or evidence changed. Relink to rebuild the source-bound questions.');}
function summary(){const p=window.icsOperatingProfile?.snapshot();$('profile-summary').textContent=p?['Asset type: '+p.asset_type_id,'Asset: '+(p.scope.asset_ref||'Not provided'),'Component: '+(p.scope.product||'Not provided'),'BOM version: '+(p.scope.build||'Not provided')].join(' · '):'Select an operating asset and component.';}
async function api(path,payload){const r=await fetch('/api/operational-vex/'+path,payload===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}),v=await r.json();if(!r.ok)throw Error(typeof v.detail==='string'?v.detail:JSON.stringify(v.detail));return v;}
function select(parent,label,id,options,value,onchange,multiple=false){const l=el('label',label),s=el('select');s.setAttribute('aria-label',id);s.multiple=multiple;if(multiple)s.size=4;for(const[v,t]of Object.entries(options)){const o=el('option',t);o.value=v;o.selected=multiple?value.includes(v):value===v;s.append(o);}s.onchange=()=>{onchange(multiple?[...s.selectedOptions].map(o=>o.value):s.value);if(!s.closest('[data-mitigation]'))clearMitigations();invalidate();};l.append(s);parent.append(l);return s;}
function reference(parent,r){if(!r||/nist\.gov|NIST|SP[ .-]*800[ -]*82/i.test((r.url||'')+' '+(r.quote||'')))return;const b=el('blockquote',r.quote);parent.append(b);const a=el('a','English source · characters '+r.span.join('–'));a.href=r.url;a.target='_blank';a.rel='noopener';parent.append(a);}
function recordComparisonHint(card,q){if(!q.record_review?.supported)return;card.append(el('p','Choose record comparison to evaluate the selected original excerpts against this condition. A generative LLM reviews original records; unresolved, conflicting or insufficient evidence stays unknown.'));const d=el('details');d.append(el('summary','Condition checked against the operating records'),el('p',q.record_review.question),el('p','Check the current applied state within the assessed component scope.'));card.append(d);}
function clearMitigations(){if(!plan)return;for(const q of plan.mitigation_questions||[])answers[q.id]={value:'unknown',evidence_ids:[],coverage:'partial',scope_sha256:plan.scope_sha256};drawMitigations();$('mitigation-panel').hidden=true;}
function drawGraph(assessment){
 const graph=plan.attack_graph,box=$('attack-graph');box.replaceChildren();if(!graph)return;
 if(!graph.nodes.length){box.append(el('p','Attack graph generation is unavailable. Path-dependent conclusions remain unknown.'));$('graph-summary').textContent='MulVAL/XSB · '+(graph.generation_status||'unavailable');return;}
 const states=assessment?.node_states||{},byId=new Map(graph.nodes.map(n=>[n.id,n])),depths=new Map();
 function depth(id){if(depths.has(id))return depths.get(id);const n=byId.get(id),d=n.inputs.length?1+Math.max(...n.inputs.map(depth)):0;depths.set(id,d);return d;}
 const layers=new Map();for(const n of graph.nodes){const d=depth(n.id);if(!layers.has(d))layers.set(d,[]);layers.get(d).push(n);}
 const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg'),positions=new Map(),width=layers.size*245,height=Math.max(...[...layers.values()].map(a=>a.length))*92+30;
 svg.setAttribute('width',width);svg.setAttribute('height',height);svg.setAttribute('role','img');svg.setAttribute('aria-label','Source-bound attack graph. AND gates require every incoming condition.');
 for(const[d,list]of layers)list.forEach((n,i)=>positions.set(n.id,{x:d*245+10,y:i*92+15}));
 for(const e of graph.edges){const a=positions.get(e.source),b=positions.get(e.target),line=document.createElementNS(ns,'path');line.setAttribute('d','M '+(a.x+215)+' '+(a.y+30)+' L '+b.x+' '+(b.y+30));line.setAttribute('fill','none');line.setAttribute('stroke','#9b93ac');svg.append(line);}
 for(const n of graph.nodes){const p=positions.get(n.id),g=document.createElementNS(ns,'g'),r=document.createElementNS(ns,'rect'),t=document.createElementNS(ns,'text'),s=document.createElementNS(ns,'text'),title=document.createElementNS(ns,'title');g.setAttribute('transform','translate('+p.x+','+p.y+')');r.setAttribute('width',215);r.setAttribute('height',62);r.setAttribute('rx',8);r.setAttribute('fill',({true:'#d7f1df',false:'#f6dddd',unknown:'#fff0c7'})[states[n.id]||'unknown']);r.setAttribute('stroke','#8e839f');t.setAttribute('x',8);t.setAttribute('y',22);t.setAttribute('font-size',12);t.textContent=(n.kind==='predicate'?n.question_id:n.label).slice(0,29);s.setAttribute('x',8);s.setAttribute('y',45);s.setAttribute('font-size',11);s.textContent=n.kind+' / '+(states[n.id]||'unobserved');title.textContent=n.label;g.append(title,r,t,s);svg.append(g);}
 box.append(svg);$('graph-summary').textContent=(graph.generator||'MulVAL/XSB')+' / Origin: '+graph.scope.origin+' / '+graph.nodes.length+' nodes / '+graph.operational_field_ids.length+' operating observations / Coverage: '+(graph.coverage_complete?'complete':'partial')+' / '+(assessment?('Prerequisite goal: '+assessment.value):'Built before operating answers. No path is assumed absent.');
}
function drawMitigations(){
 const box=$('mitigation-questions');box.replaceChildren();
 for(const q of plan.mitigation_questions||[]){const card=el('section');card.className='auto-question';card.dataset.mitigation='true';card.append(el('h3',q.label));const a=answers[q.id];
 recordComparisonHint(card,q);
 select(card,'Observed condition after mitigation',q.id+' value',q.options,a.value,v=>a.value=v);
 const evidence=Object.fromEntries(Object.entries(profile.evidence).filter(([id,e])=>q.evidence_kinds.includes(e.kind)).map(([id,e])=>[id,id+' / '+e.kind+' / '+e.source]));
 select(card,'Applied-control and effectiveness records',q.id+' evidence',evidence,a.evidence_ids,v=>a.evidence_ids=v,true);
 select(card,'Verified coverage after mitigation',q.id+' coverage',{partial:'Partial / not verified',complete:'Complete assessed scope'},a.coverage,v=>a.coverage=v);reference(card,q.source);box.append(card);}
}
function draw(){
 drawGraph();drawMitigations();$('mitigation-panel').hidden=true;
 const box=$('auto-questions');box.replaceChildren();
 if(!plan.supported)box.append(el('p','No executable source-bound operating rule is registered for this CVE, or its identity is unresolved. No operational answers are guessed. The result remains under investigation.'));
 for(const q of plan.questions){const card=el('section');card.className='auto-question';card.dataset.questionId=q.id;card.append(el('h3',q.label));const a=answers[q.id];
 recordComparisonHint(card,q);
 select(card,'Observed asset operational information','auto-'+q.id+' value',q.options,a.value,v=>{a.value=v;if(q.id==='runtime_version')refreshRelevance();});
 const grid=el('div');grid.className='auto-grid';card.append(grid);
 const evidence=Object.fromEntries(Object.entries(profile.evidence).filter(([id,e])=>q.evidence_kinds.includes(e.kind)).map(([id,e])=>[id,id+' · '+e.source+(e.reviewed?' · reviewed':' · review required')]));
 select(grid,'Original records supporting this observation','auto-'+q.id+' evidence',evidence,a.evidence_ids,v=>a.evidence_ids=v,true);
 select(grid,'Coverage of this exact component instance and configuration','auto-'+q.id+' coverage',{partial:'Partial / remaining gaps',complete:'Complete scope verified from records'},a.coverage,v=>a.coverage=v);
 if(!Object.keys(evidence).length)card.append(el('p','Register actual inventory/configuration/vendor records in the Evidence library above. Leave this answer unknown until records are available.'));
 const d=el('details');d.append(el('summary','English source supporting this question'));reference(d,q.source);card.append(d);box.append(card);
 }
 $('source-info').textContent=plan.cve+' · '+plan.product.name+' · '+plan.questions.length+' operating questions';
 if(plan.untranslated_conditions?.length)$('source-info').append(el('p','Some required conditions could not be resolved. The assessment retains these as unknown.'));
 refreshRelevance();
}
async function refreshRelevance(){if(!plan)return;const cve=plan.cve,choice=answers.runtime_version?.value,q=plan.questions.find(q=>q.id==='runtime_version'),version=q?.version_values?.[choice]||'';try{const data=await api('question-relevance?cve='+encodeURIComponent(cve)+'&version='+encodeURIComponent(version)+'&product='+encodeURIComponent(profile.scope.product));if(plan?.cve!==cve||answers.runtime_version?.value!==choice)return;for(const n of $('auto-questions').children)n.hidden=!data.conditional_settings_required&&!['deployment','runtime_version','product_family'].includes(n.dataset.questionId);}catch{for(const n of $('auto-questions').children)n.hidden=false;}}
async function load(){
 const cve=selectedCve.trim().toUpperCase();if(!/^CVE-\d{4}-\d{4,}$/.test(cve))throw Error('Select a component and CVE from the BOM list.');
 if(window.icsBomVexContext&&!window.icsBomVexContext.acceptsCve(cve))throw Error('Select the component and CVE from the BOM cases.');
 invalidate();const seq=sequence,snap=window.icsOperatingProfile.snapshot();message('Compiling required operating questions from the pinned vendor rule.');
 const p=await api('plan',{cve,profile:snap});if(seq!==sequence||JSON.stringify(snap)!==JSON.stringify(window.icsOperatingProfile.snapshot()))throw Error('The scope changed while loading. Relink it.');
 profile=snap;plan=p;answers=Object.fromEntries([...p.questions,...(p.mitigation_questions||[])].map(q=>[q.id,{value:q.record_review?.supported&&!q.id.startsWith('mitigation:')?'from_evidence':'unknown',evidence_ids:[],coverage:'partial',scope_sha256:p.scope_sha256}]));stale=false;draw();$('work').hidden=false;$('evaluate').disabled=false;summary();message('The graph is ready. Select scoped operating records for generative LLM review or provide structured observations, then verify mitigation if a route is found.');return true;
}
function payload(){if(stale||!plan||JSON.stringify(profile)!==JSON.stringify(window.icsOperatingProfile.snapshot()))throw Error('Relink the latest component scope and evidence first.');return {cve:plan.cve,product_key:plan.product.key,profile:clone(profile),plan_sha256:plan.plan_sha256,auto_observations:clone(answers)};}
function render(r){const b=$('result-body');b.replaceChildren();drawGraph(r.mitigation_review?.all_paths_blocked?r.mitigation_review.post_graph:r.attack_graph_evaluation);$('mitigation-panel').hidden=!r.mitigation_review?.required;const h=el('p',labels[r.decision.status]+' · '+r.decision.status);h.className='auto-status';const expressionNote=r.decision.resolution_basis==='verified_path_mitigation'?'All assessed routes blocked by verified controls in this scope; the software version remains vulnerable.':r.decision.status==='fixed'?'Manufacturer-documented fixed running release.':'Attack graph goal: '+(r.attack_graph_evaluation?.value||'unknown');b.append(h,el('p',r.decision.reason),el('p',expressionNote+' · Operating conditions reviewed by the LLM: '+(r.operational_record_review?.executed||0)+' · Valid until: '+r.valid_until));
 const d=el('details');d.open=true;d.append(el('summary','Answers used in this assessment'));const table=el('table'),head=el('tr');for(const t of ['Operating question','Selected fact','Computed value','Evidence / unresolved reason'])head.append(el('th',t));table.append(head);
 for(const t of r.question_trace){const tr=el('tr');tr.append(el('td',[...plan.questions,...(plan.mitigation_questions||[])].find(q=>q.id===t.question_id)?.label||t.question_id),el('td',t.operational_choice),el('td',t.actual_version||t.computed_value),el('td',t.reasons.join(' · ')||t.evidence_ids.join(', ')));table.append(tr);}d.append(table);b.append(d);
 if(r.operational_record_review?.requested){const comparisons=el('details');comparisons.append(el('summary','Operating records → generative LLM review → graph condition'));for(const c of r.operational_record_review.comparisons){comparisons.append(el('h3',c.question_id+' · '+c.value),el('p',c.reasons.join(' · ')));for(const record of c.records||[]){comparisons.append(el('blockquote',record.premise),el('p','Record '+record.evidence_id+' · Value: '+record.value+' · '+record.reason));}}b.append(comparisons);}
 if(r.review_id){b.append(el('p','Saved assessment: '+r.review_id));}
 $('result').hidden=false;$('export-openvex').disabled=!r.export_ready;
 $('export-cyclonedx').disabled=!r.export_ready||!window.icsBomVexContext;
}
function task(id,fn){$(id).onclick=async()=>{const button=$(id);button.disabled=true;try{await fn();}catch(e){message(e.message);}finally{button.disabled=id==='evaluate'?stale:id==='export-cyclonedx'?!result?.export_ready||!window.icsBomVexContext:false;}};}
task('reload',load);
task('evaluate',async()=>{const p=payload(),seq=sequence;message('Evaluating attack routes and verified mitigation effects.');const r=await(window.icsBomVexContext?window.icsBomVexContext.assess(p):api('assess',p));if(seq!==sequence||JSON.stringify(p)!==JSON.stringify(payload()))throw Error('Answers changed during assessment. Calculate the latest inputs again.');result=r;render(r);message('VEX was calculated by the server and saved locally.');});
function download(data,name){const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'})),a=el('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
for(const kind of ['review','openvex','cyclonedx'])task('export-'+kind,async()=>{if(!result)throw Error('Calculate VEX first.');if(kind==='cyclonedx'&&!window.icsBomVexContext)throw Error('Load a BOM component to export CycloneDX VEX with its actual component reference.');const saved=result,seq=sequence;const out=await(window.icsBomVexContext?window.icsBomVexContext.export(kind,saved):api('reviews/'+saved.review_id+'/export/'+kind));if(saved!==result||seq!==sequence)throw Error('Inputs changed; export cancelled.');download(out,plan.cve+'-'+kind+(kind==='cyclonedx'?'-vex':'')+'.json');message('Re-evaluated current vendor rules and evidence before export.');});
async function reopen(rid){const initialSequence=sequence,initialProfile=JSON.stringify(window.icsOperatingProfile.snapshot()),initialCve=selectedCve;const p=await api('reviews/'+encodeURIComponent(rid)+'/input');if(sequence!==initialSequence||JSON.stringify(window.icsOperatingProfile.snapshot())!==initialProfile||selectedCve!==initialCve)throw Error('Inputs changed while loading; restoration cancelled.');if(!p.auto_observations)throw Error('This is a historical manual-proof assessment. It cannot be reused as an automatic result. Re-enter asset operational information.');if(window.icsBomVexContext)window.icsBomVexContext.validateReopen(rid,p);await window.icsOperatingProfile.restore(p.profile);selectedCve=p.cve;await load();if(plan.plan_sha256!==p.plan_sha256)throw Error('Source or scope changed. Previous answers were not adopted.');answers={...answers,...clone(p.auto_observations)};draw();const seq=sequence,expected=JSON.stringify(payload()),r=await api('reviews/'+encodeURIComponent(rid));if(sequence!==seq||JSON.stringify(payload())!==expected)throw Error('Inputs changed during reassessment; previous result was not displayed.');result=window.icsBomVexContext?window.icsBomVexContext.decorate(r):r;render(result);message('Saved operational answers were re-evaluated; previous VEX conclusions were not adopted.');}

document.addEventListener('ics-profile-changed',profileChanged);
window.icsOperationalVex={open:async cve=>{selectedCve=cve;return load();},reopen,invalidate:profileChanged,payload};
summary();
})();
