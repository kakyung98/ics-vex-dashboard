(function(){
'use strict';
const root=document.getElementById('op-panel');if(!root)return;
const catalog=JSON.parse(document.getElementById('op-template-data').textContent);
const englishPresentation=/* NIST_ENGLISH_PRESENTATION */;
catalog.rows=englishPresentation.rows;catalog.scope_fields=englishPresentation.scope;
if(window.icsVexEnglish){const oldPlan=window.icsVexEnglish.plan;window.icsVexEnglish.plan=p=>{p=oldPlan(p);for(const f of p.fields||[])if(englishPresentation.details[f.id])f.label=f.id+' · '+englishPresentation.details[f.id];return p;};}
const $=id=>document.getElementById(id),clone=x=>JSON.parse(JSON.stringify(x)),drafts=new Map();let selected,draft;
const states={unknown:'Unknown',recorded:'Evidence-supported selection',not_applicable:'Not applicable, confirmed',conflicting:'Conflicting evidence'};
const reasons={not_surveyed:'Not surveyed',evidence_missing:'Supporting evidence is unavailable',outside_inventory:'Required subject is not in the registered inventory',value_not_represented:'Actual finding is not represented by the offered options',scope_mismatch:'Available evidence concerns another subject or scope'};
const gateStates={unknown:'Applicability unknown',present:'Relevant to this assessment',absent:'Not applicable, supported by evidence'};
const scopes={'':'Select assessed scope',assessed_asset:'Current assessed asset',assessed_component:'Current BOM component',system_context:'Explicitly assessed site/system context'};
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function changed(){document.dispatchEvent(new CustomEvent('ics-profile-changed'));}
function select(options,value,name,change,multiple=false){const n=el('select');n.setAttribute('aria-label',name);n.multiple=multiple;if(multiple)n.size=4;for(const[v,label]of Object.entries(options)){const o=el('option',label);o.value=v;o.selected=multiple?value.includes(v):v===value;n.append(o)}if(!multiple)n.value=value;n.onchange=()=>{change(multiple?[...n.selectedOptions].map(o=>o.value):n.value);changed()};return n;}
function control(parent,title,node){const l=el('label',title);l.append(node);parent.append(l);}
function renderScope(){const box=$('op-scope');box.replaceChildren();for(const[k,title]of Object.entries(catalog.scope_fields)){const options={'':'Select from registered records'};if(draft.scope[k])options[draft.scope[k]]=draft.scope[k];for(const record of Object.values(draft.evidence)){if(record[k])options[record[k]]=record[k];}control(box,title,select(options,draft.scope[k],title,v=>{draft.scope[k]=v;renderFields()}));}}
function reset(record,state,field){record.state=state;record.evidence_ids=[];record.coverage_scope='';if(field){record.unknown_reason=state==='unknown'?'not_surveyed':'';record.data=state==='recorded'?{choice:'',coverage:'partial',value_refs:[]}:null;}}
function evidence(parent,record,id){
 if(record.state==='unknown')return;
 const options=Object.fromEntries(Object.entries(draft.evidence).map(([key,e])=>[key,key+' · '+e.source+(e.reviewed?' · reviewed':' · review required')]));
 control(parent,'Referenced evidence (multiple selections allowed)',select(options,record.evidence_ids,id+' evidence',ids=>{record.evidence_ids=ids},true));
 if(!Object.keys(options).length)parent.append(el('p','No evidence registered. Import source records in the Evidence library; leave the observation unknown until evidence is available.','op-muted'));
 control(parent,'Assessed scope',select(scopes,record.coverage_scope,id+' assessed scope',v=>record.coverage_scope=v));
}
function drawObservation(box,item){
 box.replaceChildren();const v=draft.inventory.values[item.id],spec=catalog.answer_specs[item.id];
 control(box,'Observation state',select(states,v.state,item.id+' state',state=>{reset(v,state,true);drawObservation(box,item)}));
 if(v.state==='unknown'){control(box,'Reason for unknown',select(reasons,v.unknown_reason,item.id+' unknown reason',x=>v.unknown_reason=x));return;}
 if(v.state==='recorded'){
  const options={'':'Select a finding supported by the selected records'};for(const o of spec.options)options[o.code]=o.label;
  control(box,'Finding',select(options,v.data.choice,item.id+' finding',choice=>{v.data.choice=choice;v.data.value_refs=[];drawObservation(box,item)}));
  control(box,'Survey coverage',select({partial:'Partial coverage / remaining gaps',complete:'Complete coverage of the explicitly assessed scope'},v.data.coverage,item.id+' coverage',x=>v.data.coverage=x));
  const option=spec.options.find(o=>o.code===v.data.choice);
  if(option?.requires_complete_scope)box.append(el('p','This negative or exhaustive finding requires complete surveyed coverage. Partial evidence cannot establish absence.','op-note'));
  if(option?.requires_value_reference){
   const values=Object.fromEntries(Object.entries(draft.reference_values).filter(([k,r])=>r.kind===spec.reference_kind&&r.asset_ref===draft.scope.asset_ref).map(([key,r])=>[key,key+' · '+r.label]));
   control(box,'Actual values from registered inventory ('+spec.reference_kind+')',select(values,v.data.value_refs,item.id+' registered values',x=>{v.data.value_refs=x},true));
   if(!Object.keys(values).length)box.append(el('p','No matching values for this assessed asset. Import the actual inventory/source records or retain Unknown → Required subject is not in the registered inventory.','op-muted'));
  }
 }
 if(v.state==='not_applicable')box.append(el('p','Non-applicability requires an evidenced absent applicability finding for the parent source item. Asset type alone is insufficient.','op-muted'));
 if(v.state==='conflicting')box.append(el('p','Select at least two reviewed, conflicting source records. No single truth is asserted.','op-muted'));
 evidence(box,v,item.id);
 box.append(el('p','If no option represents the actual finding, select Unknown → Actual finding is not represented. Do not choose the nearest answer.','op-muted'));
}
function drawGate(box,row){box.replaceChildren();const v=draft.gates[row.source_id];control(box,'Does this topic apply to the assessed asset?',select(gateStates,v.state,row.label+' applicability',state=>{reset(v,state,false);drawGate(box,row)}));evidence(box,v,row.source_id+' applicability');}
function renderLibrary(){
 const box=$('op-evidence-list');box.replaceChildren();
 for(const[id,e]of Object.entries(draft.evidence)){
  const wrap=el('div',undefined,'op-source');wrap.append(el('strong',id+' · '+e.kind),el('p',e.source),el('blockquote',e.excerpt));
  const label=el('label'),check=el('input');check.type='checkbox';check.checked=e.reviewed;check.setAttribute('aria-label','Review evidence '+id);check.onchange=()=>{e.reviewed=check.checked;renderFields();changed()};label.append(check,document.createTextNode(' I reviewed this original record and its relevance to the assessed subject.'));wrap.append(label);box.append(wrap);
 }
 if(!Object.keys(draft.evidence).length)box.append(el('p','No registered evidence. No example or synthetic observation is preloaded.','op-muted'));
 $('op-registry-count').textContent=Object.keys(draft.evidence).length+' evidence records · '+Object.keys(draft.reference_values).length+' registered values. Registration does not independently verify their contents.';
}
function renderFields(){
 const box=$('op-fields'),query=$('op-search').value.trim().toLowerCase(),table=$('op-filter').value;box.replaceChildren();let rows=0,details=0;
 for(const row of catalog.rows){if(table!=='all'&&String(row.table)!==table)continue;if(query&&!JSON.stringify(row).toLowerCase().includes(query))continue;rows++;details+=row.collection_elements.length;
  const wrap=el('section',undefined,'op-row');wrap.dataset.row=row.source_id;wrap.append(el('h3',row.label));
  const gate=el('div');drawGate(gate,row);wrap.append(gate);
  for(const item of row.collection_elements){const d=el('div',undefined,'op-detail');d.id='op-detail-'+item.id;d.dataset.detail=item.id;d.append(el('h4',item.label));const editor=el('div');drawObservation(editor,item);d.append(editor);wrap.append(d)}
  box.append(wrap);
 }
 $('op-counts').textContent='Displayed: '+rows+' topics · '+details+' questions';
}
function choose(id){selected=catalog.profiles.find(p=>p.asset.id===id)||catalog.profiles[0];if(!drafts.has(selected.asset.id))drafts.set(selected.asset.id,clone(selected.blank));draft=drafts.get(selected.asset.id);$('op-type').value=selected.asset.id;renderScope();renderLibrary();renderFields();}
async function validate(p){const r=await fetch('/api/asset-vulntology/operating-profiles/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});const d=await r.json();if(!r.ok)throw Error(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail));return d;}
function result(d){$('op-result').textContent='Selectable-answer structure checks passed\nRecorded: '+d.recorded_fields+' · Unknown: '+d.unknown_fields+' · Not applicable: '+d.not_applicable_fields+' · Conflicting: '+d.conflicting_fields+'\nMissing assessment scope: '+(d.missing_scope.join(', ')||'None')+'\nNo LLM used. Facts and answer-domain validity have not been independently expert-validated. No CVE/VEX verdict was generated.';}
function error(e){$('op-result').textContent='Validation/import failed: '+e.message;}
function download(p,name){const url=URL.createObjectURL(new Blob([JSON.stringify(p,null,2)],{type:'application/json'})),a=el('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
for(const p of catalog.profiles){const o=el('option',p.asset.id+' · '+p.asset.name);o.value=p.asset.id;$('op-type').append(o)}
$('op-type').onchange=()=>{choose($('op-type').value);changed()};$('op-filter').onchange=renderFields;$('op-search').oninput=renderFields;
$('op-check').onclick=async()=>{try{result(await validate(draft))}catch(e){error(e)}};
$('op-save').onclick=async()=>{try{result(await validate(draft));download(draft,'nist-selectable-'+draft.asset_type_id+'.json')}catch(e){error(e)}};
$('op-blank').onclick=()=>download(selected.blank,'nist-selectable-blank-'+selected.asset.id+'.json');
$('op-import-button').onclick=()=>$('op-import').click();
$('op-import').onchange=async()=>{try{const f=$('op-import').files[0];if(!f)return;if(f.size>2*1024*1024)throw Error('JSON must be no larger than 2 MiB.');const p=JSON.parse(await f.text()),d=await validate(p);drafts.set(p.asset_type_id,p);choose(p.asset_type_id);changed();result(d);$('op-import-name').textContent=f.name}catch(e){error(e)}finally{$('op-import').value=''}};
$('op-register-button').onclick=()=>$('op-register').click();
$('op-register').onchange=async()=>{try{
 const f=$('op-register').files[0];if(!f)return;if(f.size>2*1024*1024)throw Error('Evidence registry must be no larger than 2 MiB.');const data=JSON.parse(await f.text());
 if(data.version!=='nist-evidence-registry/1'||Object.keys(data).sort().join(',')!=='evidence,values,version'||!data.evidence||Array.isArray(data.evidence)||!data.values||Array.isArray(data.values))throw Error('Use the documented evidence registry format.');
 const p=clone(draft);
 for(const[id,e]of Object.entries(data.evidence)){if(Object.hasOwn(p.evidence,id))throw Error('Evidence ID already registered: '+id);p.evidence[id]={...e,reviewed:false}}
 for(const[id,v]of Object.entries(data.values)){if(Object.hasOwn(p.reference_values,id))throw Error('Value ID already registered: '+id);p.reference_values[id]=v}
 await validate(p);drafts.set(p.asset_type_id,p);draft=p;renderScope();renderLibrary();renderFields();changed();$('op-result').textContent='Records registered. Review each record before selecting it.';
 }catch(e){error(e)}finally{$('op-register').value=''}};
$('op-registry-template').onclick=()=>download({version:'nist-evidence-registry/1',evidence:{},values:{}},'nist-evidence-registry-blank.json');
window.icsOperatingProfile={snapshot:()=>clone(draft),select:id=>choose(id),restore:async p=>{const before=JSON.stringify(draft);await validate(p);if(before!==JSON.stringify(draft))throw Error('Draft changed during restoration.');drafts.set(p.asset_type_id,clone(p));choose(p.asset_type_id);changed()}};
choose(catalog.profiles[0].asset.id);
})();
