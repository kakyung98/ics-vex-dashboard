(function(){
'use strict';
const $=id=>document.getElementById('ov-'+id),root=$('panel');if(!root)return;
const clone=x=>JSON.parse(JSON.stringify(x));
let plan=null,profile=null,bindings=new Map(),approved=new Set(),result=null,sequence=0,stale=true;
let typedReview={version:'nist-three-axis-vex/1',records:{},selected_ids:[]};
const labels={under_investigation:"Under investigation",affected:"Affected",not_affected:"Not affected",fixed:"Fixed"};
const exposure={unknown:"Operational conditions unknown",prerequisites_observed:"Prerequisites observed for one path",registered_paths_refuted:"Registered paths refuted — this does not establish absence of all relevant paths"};
const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
function message(text,error=false){$('message').textContent=text;$('message').className=error?'ov-error':'';}
function invalidate(){result=null;$('result').hidden=true;}
function profileSummary(){const p=window.icsOperatingProfile?.snapshot();$('profile-summary').textContent=p?"Type: "+p.asset_type_id+" · Actual asset: "+(p.scope.asset_ref||"Not provided")+" · Product: "+(p.scope.product||"Not provided")+" · Running version: "+(p.scope.build||"Not provided")+" · Recorded operating fields: "+Object.values(p.inventory.values).filter(v=>v.state==='recorded'||v.state==='recorded_empty').length+"":"Prepare the asset operational information above.";}
async function api(path,payload){const response=await fetch('/api/operational-vex/'+path,payload===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const value=await response.json();if(!response.ok)throw new Error(typeof value.detail==='string'?value.detail:JSON.stringify(value.detail));return value;}
function link(parent,url,label){try{const u=new URL(url);if(!['http:','https:'].includes(u.protocol))throw Error();const a=el('a',label);a.href=u.href;a.target='_blank';a.rel='noopener';parent.append(a);}catch{parent.append(el('span',label));}}
function textInput(parent,label,value,onchange,multi=false){const l=el('label',label),n=el(multi?'textarea':'input');n.value=value||'';n.oninput=()=>{onchange(n.value);invalidate();};l.append(n);parent.append(l);return n;}
function check(parent,label,checked,onchange){const l=el('label'),n=el('input');l.className='ov-check';n.type='checkbox';n.checked=checked;n.onchange=()=>{onchange(n.checked);invalidate();};l.append(n,el('span',label));parent.append(l);}
function ref(parent,reference){const source=plan.sources.find(s=>s.id===reference.source_id);parent.append(el('blockquote',reference.quote));if(source)link(parent,source.url,"CVE source · "+reference.source_id+" · Characters "+reference.span.join('–'));}
function formula(node,names){if(node.condition)return names[node.condition]||node.condition;if(node.op==='not')return 'NOT ('+formula(node.args[0],names)+')';return '('+node.args.map(n=>formula(n,names)).join(node.op==='and'?' AND ':node.op==='or'?' OR ':' NOT ')+')';}
function drawPaths(){
 const box=$('paths');box.replaceChildren();
 if(!plan.scenarios.length)box.append(el('p','No source-supported paths exist. Unknown conditions are not invented.'));
 for(const s of plan.scenarios){const d=el('details');d.open=plan.scenarios.length===1;d.append(el('summary','Source path · '+s.id));ref(d,s.source_ref);
 const qs=plan.questions.filter(q=>q.scenario_id===s.id);d.append(el('pre',formula(s.expression,Object.fromEntries(qs.map((q,i)=>[q.condition_id,'Condition '+(i+1)])))));
 if(s.approvable)check(d,'I checked that this quotation describes prerequisites for this exact product and reviewed its AND/OR relationships.',approved.has(s.id),v=>v?approved.add(s.id):approved.delete(s.id));
 else d.append(el('p','Ambiguous or invalid source paths remain unknown.'));
 for(const q of qs){d.append(el('h4',q.proposition));ref(d,q.source_refs[0]);d.append(el('p','Eligible operating fields: '+((q.typed_field_ids||[]).join(', ')||'No supported operational predicate domain; leave unknown.')));}
 box.append(d);}
 drawProofs();drawBuilder();
}
function drawProofs(){
 const box=$('proof-list');box.replaceChildren();$('proof-count').textContent=Object.keys(typedReview.records).length+' coded records · '+typedReview.selected_ids.length+' explicitly reviewed and selected';
 for(const[id,p]of Object.entries(typedReview.records)){const d=el('details');d.append(el('summary',id+' · '+p.kind+' · '+p.conclusion));d.append(el('pre',JSON.stringify(p,null,2)));
 for(const eid of p.evidence_ids||[]){const e=profile.evidence[eid];d.append(el('blockquote',e?eid+' · '+e.source+'\n'+e.excerpt:eid+' · Missing evidence — import it in the operating-profile evidence library first.'));}
 check(d,'I reviewed the original records, coded conclusion, CVE/product/source binding, and exact operating scope.',typedReview.selected_ids.includes(id),v=>{p.reviewed=v;typedReview.selected_ids=typedReview.selected_ids.filter(x=>x!==id);if(v)typedReview.selected_ids.push(id);$('proof-count').textContent=Object.keys(typedReview.records).length+' coded records · '+typedReview.selected_ids.length+' explicitly reviewed and selected';});box.append(d);}
}
function drawBuilder(){
 const box=$('proof-builder');box.replaceChildren();
 const pick=(id,title,options,multi=false)=>{const l=el('label',title),s=el('select');s.id='ov-'+id;s.setAttribute('aria-label',title);s.multiple=multi;if(multi)s.size=4;for(const[value,label]of Object.entries(options)){const o=el('option',label);o.value=value;s.append(o);}l.append(s);box.append(l);return s;};
 const kinds={product_identity:'Inventory match: actual manufacturer/model and running version',condition:'Observation of one exact CVE prerequisite',product_status:'CVE-specific supplier or qualified product finding',installation:'The CVE-fixed build is actually running',route_coverage:'Qualified review of every relevant alternative CVE path'};
 const kind=pick('new-kind','Type of original finding',kinds);
 const dynamic=el('div');box.append(dynamic);
 function update(){dynamic.replaceChildren();const saved=box;const before=[...box.children];
 const types={product_identity:{matches:'The records match this exact source product and running build'},condition:{true:'The scoped record demonstrates this exact condition',false:'The complete scoped record excludes this exact condition'},product_status:{affected:'The exact running product/build is affected',fixed:'The documented build fixes this CVE',not_affected:'The exact product/configuration has no impact from this CVE'},installation:{running_fixed_build:'The documented fixed build is currently executing'},route_coverage:{complete:'Qualified analysis covers all relevant alternative paths'}};
 const mechanisms={product_identity:{inventory_match:'Inventory and source product/version comparison'},condition:{direct_observation:'Scoped operational observation or test',structural_nonexecution:'Qualified CVE-specific structural non-execution analysis'},product_status:{supplier_statement:'Supplier statement',qualified_product_analysis:'Qualified product analysis'},installation:{runtime_installation:'Runtime or installation verification'},route_coverage:{exhaustive_route_analysis:'Qualified exhaustive route analysis'}};
 pick('new-conclusion','Coded conclusion',{'':'Choose the conclusion stated by the record',...types[kind.value]});
 pick('new-mechanism','Evidence mechanism',{'':'Choose the evidence mechanism',...mechanisms[kind.value]});
 let question=null;if(kind.value==='condition')question=pick('new-question','Exact CVE source condition',Object.fromEntries([['','Select one source condition'],...plan.questions.map(q=>[q.id,q.proposition])]));
 const fieldOptions=Object.fromEntries(plan.fields.map(f=>[f.id,f.label]));
 const fields=pick('new-fields','Recorded operating observations supporting this proof',fieldOptions,true);
 if(kind.value==='product_identity'){for(const o of fields.options){const relevant=['C13-01.01','C13-01.03'].includes(o.value);o.selected=relevant;o.hidden=!relevant;o.disabled=!relevant;}}
 if(!['product_identity','condition'].includes(kind.value))fields.parentElement.hidden=true;
 if(question){question.onchange=()=>{const ids=plan.questions.find(q=>q.id===question.value)?.typed_field_ids||[];for(const o of fields.options){o.hidden=!ids.includes(o.value);o.disabled=!ids.includes(o.value);o.selected=false;}};question.onchange();}
 pick('new-evidence','Registered original evidence records',Object.fromEntries(Object.entries(profile.evidence).map(([id,e])=>[id,id+' · '+e.kind+' · '+e.source])),true);
 pick('new-coverage','Coverage established by the original record',{partial:'Partial coverage / remaining gaps',complete:'Complete coverage of the explicitly pinned scope'});
 for(const n of [...box.children])if(!before.includes(n))dynamic.append(n);
 }
 kind.onchange=update;update();
}
function resetAssertions(){for(const id of ['match-source','match-quote','finding-status','finding-source','finding-quote','action','impact','fix-source','fix-quote','route-source','route-quote'])$(id).value='';for(const id of ['match','finding-reviewed','fix-running','route-reviewed'])$(id).checked=false;findingVisibility();}
function findingVisibility(){const status=$('finding-status').value;$('finding-fields').hidden=!status;$('fixed-fields').hidden=status!=='fixed';}
async function load(productKey){
 const cve=$('cve').value.trim().toUpperCase();if(!/^CVE-\d{4}-\d{4,}$/.test(cve))throw Error("Select a CVE ID from the search results.");
 if(window.icsBomVexContext&&!window.icsBomVexContext.acceptsCve(cve))throw Error("Select the component and CVE to assess from the enriched BOM list.");
 snapshotChanged();const seq=sequence;message("Linking the CVE source and current asset operational information.");
 const snap=window.icsOperatingProfile.snapshot();const data=await api('plan',{cve,profile:snap,...(productKey?{product_key:productKey}:{})});if(seq!==sequence)return false;
 if(JSON.stringify(snap)!==JSON.stringify(window.icsOperatingProfile.snapshot()))throw Error("The asset operational information changed while loading. Link it again.");
 profile=snap;plan=window.icsVexEnglish.plan(data);typedReview={version:'nist-three-axis-vex/1',records:{},selected_ids:[]};stale=false;bindings=new Map(data.questions.map(q=>[q.id,{question_id:q.id,field_ids:[],value:'unknown',review_confirmed:false,explanation:'',absence_scope:'',structural_analysis:{review_confirmed:false,source:'',quote:''}}]));approved=new Set();
 $('product').replaceChildren();for(const p of data.products){const o=el('option',p.name);o.value=p.key;$('product').append(o);}$('product').value=data.product.key;
 $('source-info').textContent=data.description+" · Asset-type relationship: "+(data.type_relation==='candidate'?"Source candidate association available":"Type relationship unconfirmed — retained for assessment");
 resetAssertions();drawPaths();$('work').hidden=false;$('evaluate').disabled=false;profileSummary();message("Review the meaning of source paths and operating records before assessment.");return true;
}
function snapshotChanged(){sequence++;stale=true;invalidate();$('evaluate').disabled=true;}
function payload(){if(stale||!plan)throw Error("Link the asset operational information again.");const actual=window.icsOperatingProfile.snapshot();if(JSON.stringify(actual)!==JSON.stringify(profile))throw Error("The asset operational information changed. Link it again and review the evidence.");
 return {cve:plan.cve,product_key:plan.product.key,profile:clone(profile),plan_sha256:plan.plan_sha256,approved_scenarios:[...approved],bindings:[],typed_review:clone(typedReview)};}

function renderResult(r){
 const box=$('result-body');box.replaceChildren();const h=el('p',labels[r.decision.status]+' · '+r.decision.status);h.className='ov-status';box.append(h,el('p',window.icsVexEnglish.text(r.decision.reason)),el('p',"Operational conditions: "+exposure[r.operational_exposure]),el('p',"Scope: "+[r.scope.asset_ref,r.scope.product,r.scope.build,r.scope.mode,r.scope.origin].map(v=>v||"Not provided").join(' / ')));
 if(r.review_id){box.append(el('p',"Saved assessment ID: "+r.review_id));$('review-id').value=r.review_id;}
 if(r.remaining_issues.length){box.append(el('h4',"Information requiring further review"));const ul=el('ul');for(const text of r.remaining_issues)ul.append(el('li',window.icsVexEnglish.text(text)));box.append(ul);}
 const trace=el('details');trace.append(el('summary',"Source condition → operating record → decision trace"));for(const m of r.mappings){const q=plan.questions.find(q=>q.id===m.question_id);trace.append(el('p',(q?.proposition||m.question_id)+' → '+m.accepted_value+" / Operating fields: "+(m.field_ids.join(', ')||"None")+" / Evidence: "+(m.profile_evidence_ids.join(', ')||"None")));if(m.reasons.length)trace.append(el('p',m.reasons.map(window.icsVexEnglish.text).join(' · ')));}trace.append(el('pre',JSON.stringify(r.decision.decision_trace,null,2)));box.append(trace);
 $('result').hidden=false;$('export-openvex').disabled=!r.export_ready;$('export-review').disabled=false;
}
function task(id,fn){$(id).onclick=async()=>{const button=$(id);button.disabled=true;try{await fn();}catch(e){message(window.icsVexEnglish.text(e.message),true);}finally{button.disabled=id==='evaluate'?stale:false;}};}
$('import-proofs').onclick=()=>$('proof-file').click();
$('add-proof').onclick=async()=>{try{if(stale||!plan)throw Error('Link the latest source and asset operational information first.');const get=id=>$(id)?.value||'',many=id=>[...$(id).selectedOptions].map(o=>o.value);const kind=get('new-kind'),q=plan.questions.find(q=>q.id===get('new-question'));const p={kind,conclusion:get('new-conclusion'),mechanism:get('new-mechanism'),cve:plan.cve,product_key:plan.product.key,asset_type_id:profile.asset_type_id,source_digest:plan.source_digest,scope:Object.fromEntries(['asset_ref','product','build','config_baseline','mode','origin'].map(k=>[k,profile.scope[k]])),evidence_ids:many('new-evidence'),field_ids:many('new-fields'),question_id:kind==='condition'?(q?.id||''):'',source_quote_sha256:kind==='condition'?(q?.source_quote_sha256||''):'',coverage:get('new-coverage'),reviewed:false};const next=clone(typedReview);next.records['proof-'+Date.now().toString(36)]=p;await api('validate-typed-review',next);typedReview=next;drawProofs();invalidate();message('Draft proof added without adopting it. Review the original records and select its review checkbox.');}catch(e){message(e.message,true);}};
$('proof-file').onchange=async()=>{try{const f=$('proof-file').files[0];if(!f)return;if(f.size>2*1024*1024)throw Error('Proof registry exceeds 2 MiB.');const p=JSON.parse(await f.text());if(p.version!=='nist-three-axis-vex/1'||!p.records||Array.isArray(p.records)||Object.keys(p).sort().join(',')!=='records,selected_ids,version')throw Error('Use the documented coded-proof schema.');const trial={...p,selected_ids:[]};for(const v of Object.values(trial.records))v.reviewed=false;await api('validate-typed-review',trial);typedReview=trial;invalidate();drawProofs();message('Imported without adopting any conclusions. Review and select each original coded record.');}catch(e){message(e.message,true);}finally{$('proof-file').value='';}};
$('proof-context').onclick=()=>{if(!plan||stale)return message('Link the current asset operational information first.',true);download({review:{version:'nist-three-axis-vex/1',records:{},selected_ids:[]},binding:{cve:plan.cve,product_key:plan.product.key,asset_type_id:profile.asset_type_id,source_digest:plan.source_digest,scope:Object.fromEntries(['asset_ref','product','build','config_baseline','mode','origin'].map(k=>[k,profile.scope[k]]))},questions:plan.questions.map(q=>({question_id:q.id,proposition:q.proposition,source_quote_sha256:q.source_quote_sha256,eligible_field_ids:q.typed_field_ids})),schema_url:'/nist-typed-review.schema.json',instructions:'The review property is the importable registry. Register original evidence in the asset operational information. Qualified reviewers encode actual findings using the published schema. No source text is interpreted by the engine.'},plan.cve+'-typed-review-context.json');};
task('search',async()=>{const data=await api('cves?q='+encodeURIComponent($('cve').value.trim())+'&limit=20');$('search-results').replaceChildren();for(const row of data.rows){const b=el('button',row.cve+' · '+row.product_search.slice(0,100));b.type='button';b.onclick=()=>{$('cve').value=row.cve;load().catch(e=>message(window.icsVexEnglish.text(e.message),true));};const p=el('p');p.append(b);$('search-results').append(p);}message(data.total+" search results; displaying "+data.rows.length+" results");});
task('load',()=>load());task('reload',()=>load($('product').value));
$('product').onchange=()=>load($('product').value).catch(e=>message(window.icsVexEnglish.text(e.message),true));
$('finding-status').onchange=()=>{findingVisibility();invalidate();};
task('evaluate',async()=>{const p=payload(),seq=sequence;message("Checking evidence and current validity periods.");const r=await (window.icsBomVexContext?window.icsBomVexContext.assess(p):api('assess',p));if(seq!==sequence||stale||JSON.stringify(p)!==JSON.stringify(payload())){message("Inputs changed during assessment. Assess the latest inputs again.");return;}result=r;renderResult(r);message("Assessment saved on this computer.");});
function download(data,name){const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json;charset=utf-8'})),a=el('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
for(const kind of ['review','openvex'])task('export-'+kind,async()=>{
 if(!result)throw Error("Assess the current inputs again.");
 const saved=result,seq=sequence,cve=plan.cve,asset=profile.scope.asset_ref;
 const r=await (window.icsBomVexContext?window.icsBomVexContext.export(kind,saved):api('reviews/'+saved.review_id+'/export/'+kind));
 if(result!==saved||seq!==sequence||stale)throw Error("Inputs changed during download; the previous result download was canceled.");
 download(r,cve+'-'+asset.replace(/[^a-z0-9_-]/gi,'_')+'-'+kind+'.json');
 message("Downloaded after rechecking the current source and evidence validity.");
});
task('batch',async()=>{const ids=[...new Set($('batch-cves').value.toUpperCase().split(/[\s,;]+/).filter(Boolean))];if(!ids.length||ids.length>100||ids.some(x=>!/^CVE-\d{4}-\d{4,}$/.test(x)))throw Error("Enter between 1 and 100 valid CVE IDs.");
 const r=await api('batch',{profile:window.icsOperatingProfile.snapshot(),cases:ids.map(cve=>({cve}))});const table=el('table'),head=el('tr');for(const t of ['CVE',"Status","Next step"])head.append(el('th',t));table.append(head);for(const row of r.results){const tr=el('tr'),c=el('td'),b=el('button',row.cve);b.onclick=()=>{$('cve').value=row.cve;load().catch(e=>message(window.icsVexEnglish.text(e.message),true));};c.append(b);tr.append(c,el('td',row.error||labels[row.status]),el('td',row.error?"Check input/target":"Click to link product, conditions, and operating evidence"));table.append(tr);}$('batch-results').replaceChildren(table);message(r.total+" initial assessments completed — product applicability was not assumed.");});
root.addEventListener('input',e=>{if(e.target.closest('#ov-work'))invalidate();if(e.target===$('cve'))snapshotChanged();});
root.addEventListener('change',e=>{if(e.target.closest('#ov-work'))invalidate();});
document.addEventListener('ics-profile-changed',()=>{snapshotChanged();profileSummary();message("The asset operational information changed. Link the source and asset operational information again.");});
document.addEventListener('click',e=>{const b=e.target.closest?.('#av-cves [data-cve]');if(b){$('cve').value=b.dataset.cve;snapshotChanged();message("Selected CVE linked. Use the button above to connect the current asset operational information.");}});
async function reopen(rid){
 const initialSequence=sequence,initialProfile=JSON.stringify(window.icsOperatingProfile.snapshot()),initialCve=$('cve').value;
 const p=await api('reviews/'+encodeURIComponent(rid)+'/input');
 if(window.icsBomVexContext)window.icsBomVexContext.validateReopen(rid,p);
 if(sequence!==initialSequence||$('cve').value!==initialCve||JSON.stringify(window.icsOperatingProfile.snapshot())!==initialProfile)throw Error("Inputs changed while loading; saved assessment restoration was canceled.");
 await window.icsOperatingProfile.restore(p.profile);$('cve').value=p.cve;if(!await load(p.product_key))throw Error("Assessment restoration canceled because inputs changed.");
 if(plan.plan_sha256!==p.plan_sha256)throw Error("The source or template changed since saving. Previous mappings were not applied. Review the current source.");
 bindings=new Map(plan.questions.map(q=>[q.id,clone(p.bindings?.find(b=>b.question_id===q.id)||bindings.get(q.id))]));
 for(const b of bindings.values())b.structural_analysis||={review_confirmed:false,source:'',quote:''};
 typedReview=clone(p.typed_review||{version:'nist-three-axis-vex/1',records:{},selected_ids:[]});approved=new Set(p.approved_scenarios||[]);drawPaths();
 const match=p.product_binding||{};$('match').checked=match.review_confirmed===true;$('match-source').value=match.source||'';$('match-quote').value=match.quote||'';
 const f=p.product_finding||{};$('finding-status').value=f.status||'';$('finding-source').value=f.source||'';$('finding-quote').value=f.quote||'';$('action').value=f.action_statement||'';$('impact').value=f.impact_statement||'';$('finding-reviewed').checked=f.review_confirmed===true;
 $('fix-source').value=f.installation?.source||'';$('fix-quote').value=f.installation?.quote||'';$('fix-running').checked=f.installation?.execution_verified===true;
 const route=p.complete_route_analysis||{};$('route-reviewed').checked=route.review_confirmed===true;$('route-source').value=route.source||'';$('route-quote').value=route.quote||'';findingVisibility();
 const expected=JSON.stringify(payload()),seq=sequence;
 const restored=await api('reviews/'+encodeURIComponent(rid));
 if(seq!==sequence||stale||JSON.stringify(payload())!==expected)throw Error("Inputs changed during reassessment; the previous result was not displayed.");
 result=window.icsBomVexContext?window.icsBomVexContext.decorate(restored):restored;renderResult(result);message("Saved inputs restored and current evidence validity rechecked.");
}
window.icsOperationalVex={open:async cve=>{$('cve').value=cve;return load();},reopen,invalidate:snapshotChanged,payload};
task('open-review',()=>reopen($('review-id').value.trim()));
profileSummary();api('summary').then(s=>$('coverage').textContent=s.cves.toLocaleString()+" CVEs · "+s.asset_types+" asset types · With source-path candidates: "+s.with_scenario_candidates.toLocaleString()+" / Without: "+s.without_scenario_candidates.toLocaleString()+". Candidate counts do not measure semantic accuracy.").catch(e=>message(window.icsVexEnglish.text(e.message),true));
})();
