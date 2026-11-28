(function(){
'use strict';
const $=id=>document.getElementById('bw-'+id),node=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e;};
let w=null,selected=null,token=0,dirty=false,restoring=false;
const labels={under_investigation:"Under investigation",affected:"Affected",not_affected:"Not affected",fixed:"Fixed"};
const templates=JSON.parse(document.getElementById('op-template-data').textContent);
for(const p of templates.profiles){const o=node('option',p.asset.id+' · '+p.asset.name);o.value=p.asset.id;$('type').append(o);}
function message(t,error=false){$('message').textContent=t;$('message').className=error?'bw-status bw-error':'bw-status';}
async function api(path,payload){const r=await fetch('/api/bom-vex/'+path,payload===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();if(!r.ok)throw Error(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail));return d;}
function route(){return 'workflows/'+w.id;}
function guard(){if(!w||!selected)throw Error("Select a CVE and component from the BOM.");}
function revision(){return {revision:w.revision,bom_sha256:w.bom_sha256};}
const recordOptions={binding:{},mapping:{}};
function recordValues(kind){const record=recordOptions[kind][$(kind+'-record').value];return {source:record?.source||'',quote:record?.quote||'',review_confirmed:$(kind+'-reviewed').checked};}
function bindValues(){return recordValues('binding');}
function mappingValues(){return recordValues('mapping');}
function recordPicker(kind,saved){
 const picker=$(kind+'-record');picker.replaceChildren();recordOptions[kind]={};
 const blank=node('option','Select a reviewed record');blank.value='';picker.append(blank);
 for(const[id,e]of Object.entries(window.icsOperatingProfile.snapshot().evidence)){
  if(!e.reviewed)continue;recordOptions[kind][id]={source:e.source,quote:e.excerpt};
  const option=node('option',id+' · '+e.source);option.value=id;picker.append(option);
 }
 if(saved?.source&&saved?.quote){let id=Object.keys(recordOptions[kind]).find(id=>recordOptions[kind][id].source===saved.source&&recordOptions[kind][id].quote===saved.quote);
  if(!id){id='saved-record';while(Object.hasOwn(recordOptions[kind],id))id+='-old';recordOptions[kind][id]={source:saved.source,quote:saved.quote};const option=node('option','Saved record · '+saved.source);option.value=id;picker.append(option);}picker.value=id;
 }else picker.value='';
}
function render(){
 $('content').hidden=false;
 const cls=w.asset_classification,box=$('classification');box.replaceChildren();
 const title=node('strong','Asset classification');box.append(title);
 const profile=templates.profiles.find(p=>p.asset.id===cls?.asset_type_id);
 const label=cls?.status==='classified'&&profile ? profile.asset.name+' ('+profile.asset.id+') · provisional model classification · '+(cls.prediction?.input_basis||'advisory context') : cls?.status==='conflicting' ? 'Unresolved · advisory classifications conflict' : 'Unresolved · no matching product and vendor evidence';
 box.append(node('p',label));
 if(cls?.representative?.name)box.append(node('p','BOM representative: '+cls.representative.name+(cls.representative.vendor?' · '+cls.representative.vendor:'')));
 if(cls?.evidence?.length){const details=node('details'),summary=node('summary','Classification sources');details.append(summary);for(const evidence of cls.evidence){const p=node('p'),a=node('a',evidence.advisory_id);a.href=evidence.url;a.target='_blank';a.rel='noopener noreferrer';p.append(a,document.createTextNode(' · '+evidence.matched_product+' · '+evidence.classification_status));details.append(p)}box.append(details)}
 $('summary').textContent=w.components.length+" components · "+w.unique_cves+" unique CVEs · "+w.cases.length+" component–CVE assessments · Enriched BOM "+w.bom_sha256.slice(0,16)+'…';
 $('coverage').replaceChildren();
 if(w.unanalysed_components.length)$('coverage').append(node('p',"Components not analyzed during identification: "+w.unanalysed_components.join(', ')+" — this does not establish that no CVEs exist."));
 if(!w.cases.length)$('coverage').append(node('p',"No CVE associations. Check unidentified components and lookup failures in the identification results."));
 for(const warning of w.warnings)$('coverage').append(node('p',warning));
 const table=$('cases');table.replaceChildren();
 for(const c of w.cases){
  const tr=node('tr');tr.dataset.componentRef=c.component_ref||'';if(c.id===selected?.id)tr.className='bw-selected';
  const component=node('td',c.component_name+' / '+(c.component_version||"Version unknown"));component.append(node('br'),node('code',c.component_ref||"Unbound component"));
  tr.append(component,node('td',c.cve),
   node('td',c.match_status==='match'?"Product/version match":"Unconfirmed candidate"),node('td',labels[c.status]+' · '+c.status));
  const td=node('td'),b=node('button',"Review");b.disabled=!c.component_ref;b.onclick=()=>select(c.id).catch(e=>message(window.icsVexEnglish.text(e.message),true));td.append(b);
  if(c.review_id){const detail=node('span'," · Saved");td.append(detail);}tr.append(td);table.append(tr);
 }
}
async function restore(p){restoring=true;try{await window.icsOperatingProfile.restore(p);}finally{restoring=false;}}
async function select(cid){
 const seq=++token;selected=w.cases.find(c=>c.id===cid);if(!selected)throw Error("The selected assessment was not found.");
 window.icsBomVexContext=null;window.icsOperationalVex.invalidate();document.getElementById('ov-work').hidden=true;
 document.getElementById('ov-panel').hidden=true;document.getElementById('op-panel').hidden=true;
 $('selection').hidden=false;$('selected-title').textContent=selected.component_name+' / '+selected.component_version+' ['+selected.component_ref+'] · '+selected.cve;
 $('mapping').hidden=selected.match_status==='match';
 const mapping=selected.mapping_review||{};
 $('mapping-reviewed').checked=mapping.review_confirmed===true;
 const saved=w.profiles[selected.component_ref];
 const classification=w.asset_classification;
 const matched=templates.profiles.find(p=>p.asset.id===classification?.asset_type_id);
 if(!saved&&!matched){$('selection').hidden=true;message('Asset classification is unresolved. The model could not establish a supported asset type from the available product information.',true);return;}
 const profile=saved?.profile||JSON.parse(JSON.stringify(matched.blank));
 if(!saved){profile.scope.product=selected.component_name;profile.scope.build=selected.component_version;}
 await restore(profile);if(seq!==token)return;
 document.getElementById('ov-panel').hidden=false;document.getElementById('op-panel').hidden=false;
 $('type').value=profile.asset_type_id;
 for(const o of $('type').children){
  const t=templates.profiles.find(p=>p.asset.id===o.value);if(!t)continue;
  const suggested=(selected.source_context?.asset_type_suggestions||[]).filter(s=>s.asset_type_id===o.value);
  o.textContent=t.asset.id+' · '+t.asset.name+(suggested.length?' · ICSA suggestion (confirm actual type)':'');
 }
 recordPicker('binding',saved?.component_binding);recordPicker('mapping',mapping);$('binding-reviewed').checked=saved?.component_binding.review_confirmed===true;
 dirty=false;render();message(saved?'Saved operating scope loaded. The CVE-specific questions are displayed below.':'Enter the actual component scope and register evidence. Only questions required by this CVE are displayed below.');
 window.icsBomVexContext=context();
 if(!saved){message('The asset type was classified from advisory evidence. Complete the operating scope and save the profile to build this component’s exploit condition graph.');return;}
 if(selected.review_id){restoring=true;try{await window.icsOperationalVex.reopen(selected.review_id);}finally{restoring=false;}}
 else await window.icsOperationalVex.open(selected.cve);

}
function context(){
 const cid=selected.id,wid=w.id,ref=selected.component_ref;
 return {acceptsCve:cve=>cve===selected?.cve&&selected?.id===cid,
  validateReopen(rid,p){if(w.id!==wid||selected?.id!==cid||selected.review_id!==rid||p.cve!==selected.cve||JSON.stringify(p.profile)!==JSON.stringify(w.profiles[ref].profile))throw Error("The saved review does not match the current BOM component.");},
  decorate:r=>({...r,workflow_id:wid,case_id:cid}),
  async assess(assessment){
   if(dirty)throw Error("Save the changed asset operational information first.");
   if(selected?.id!==cid||w.id!==wid)throw Error("The BOM assessment target changed.");
   const result=await api(route()+'/cases/'+cid+'/assess',{...revision(),assessment,mapping_review:mappingValues()});
   if(selected?.id!==cid||w.id!==wid)throw Error("The target changed during assessment. Reload the saved result.");
   const updated=await api('workflows/'+wid);
   if(selected?.id!==cid||w.id!==wid)throw Error("The target changed while loading the result. Reload it.");
   w=updated;selected=w.cases.find(c=>c.id===cid);render();return result;
  },
  async export(kind,result){
   if(dirty||w.id!==wid||selected?.id!==cid||result.case_id!==cid)throw Error("Reload the saved assessment for the current component.");
   return api(route()+'/cases/'+cid+'/export/'+kind);
  }
 };
}
async function openCase(){
 guard();if(dirty)throw Error("Save the changed asset operational information first.");
 const saved=w.profiles[selected.component_ref];if(!saved)throw Error("Save the asset operational information.");
 if(JSON.stringify(window.icsOperatingProfile.snapshot())!==JSON.stringify(saved.profile))throw Error("The profile changed. Save it again.");
 window.icsBomVexContext=context();
 if(selected.review_id){restoring=true;try{await window.icsOperationalVex.reopen(selected.review_id);}finally{restoring=false;}}
 else await window.icsOperationalVex.open(selected.cve);
 message("Answer the required operational questions below. The server calculates VEX; no verdict is selected.");
}
$('type').onchange=async()=>{try{
 guard();if(!$('type').value)return;const t=templates.profiles.find(p=>p.asset.id===$('type').value);
 const p=JSON.parse(JSON.stringify(t.blank));p.scope.product=selected.component_name;p.scope.build=selected.component_version;
 await restore(p);dirty=true;window.icsOperationalVex.invalidate();message("A blank profile for the selected type is ready. Enter the actual operating scope and evidence.");
}catch(e){message(window.icsVexEnglish.text(e.message),true);}};
function task(id,fn){$(id).onclick=async()=>{const b=$(id);b.disabled=true;try{await fn();}catch(e){message(window.icsVexEnglish.text(e.message),true);}finally{b.disabled=false;}};}
task('save-profile',async()=>{
 guard();if(!$('type').value)throw Error("Select the actual asset type.");
 const p=window.icsOperatingProfile.snapshot();if(p.asset_type_id!==$('type').value)throw Error("The selected asset type and asset operational information type differ.");
 const seq=token,ref=selected.component_ref;
 const updated=await api(route()+'/profiles',{...revision(),component_ref:ref,profile:p,component_binding:bindValues()});
 if(seq!==token)return;w=updated;selected=w.cases.find(c=>c.id===selected.id);dirty=false;render();message("Asset operational information saved for this component. Review the evidence for each CVE.");
});
task('open-case',openCase);
async function loadResult(path,payload){
 const seq=++token;
 const result=await api(path,payload);if(seq!==token)return;
 window.icsBomVexContext=null;window.icsOperationalVex.invalidate();
 w=result;selected=null;dirty=false;$('selection').hidden=true;document.getElementById('ov-panel').hidden=true;document.getElementById('op-panel').hidden=true;document.getElementById('ov-work').hidden=true;render();
 const u=new URL(location.href);u.searchParams.set('workflow',w.id);u.searchParams.delete('job');u.searchParams.delete('identification_job');history.replaceState(null,'',u);
 message("JSON results opened. Review individual CVEs or generate the initial VEX.");
}
async function uploadFile(file){
 if($('load-job').disabled)return;
 const button=$('load-job');button.disabled=true;
 try{
  if(!file)throw Error("Choose a JSON file first.");
  if(!/\.json$/i.test(file.name))throw Error("Choose a .json file.");
  if(file.size>4*1024*1024)throw Error("JSON file exceeds 4 MiB.");
  message("Opening "+file.name+"…");
  let value;try{value=JSON.parse((await file.text()).replace(/^\uFEFF/,''));}catch(e){throw Error("Invalid JSON file. Check the file and try again.");}
  if(!value||typeof value!=='object'||Array.isArray(value))throw Error("The JSON file must contain an object.");
  if(value.bomFormat==='CycloneDX'||value.spdxVersion){
   const hasDeclaredCve=doc=>{
    const entries=[...(Array.isArray(doc.vulnerabilities)?doc.vulnerabilities:[]),...(Array.isArray(doc.cves)?doc.cves:[])];
    if(entries.some(row=>/^CVE-\d{4}-\d{4,}$/i.test(typeof row==='string'?row:row?.id||row?.cve||row?.cve_id||'')))return true;
    return (Array.isArray(doc.components)?doc.components:[]).some(hasDeclaredCve)||(Array.isArray(doc.packages)?doc.packages:[]).some(hasDeclaredCve)||(doc.metadata?.component?hasDeclaredCve(doc.metadata.component):false);
   };
   if(hasDeclaredCve(value)){
    sessionStorage.setItem('icsvex:item4:pending-bom',JSON.stringify(value));
    sessionStorage.setItem('icsvex:item4:pending-bom-name',file.name);
    location.assign('/item4.html');return;
   }
   throw Error('Operational VEX requires a BOM with identified CVEs. Run SBOM → CVE first, then upload the enriched BOM here.');
  }else await loadResult('from-json',value);
 }catch(e){message(window.icsVexEnglish.text(e.message),true);}finally{button.disabled=false;}
}
async function awaitIdentification(id){
 for(;;){
  const job=await api('identification-jobs/'+encodeURIComponent(id));
  if(job.status==='failed')throw Error(job.error||'Identification failed.');
  if(job.status==='completed'){await loadResult('from-job',{job_id:id});return;}
  const p=job.progress||{};const stage=p.stage==='i1_agent'?'Preparing or running the I1 model (first load checks model files)':(p.stage||job.status);message('Identifying BOM components · '+(p.done||0)+' / '+(p.total||'?')+' · '+stage+(p.component?' · '+p.component:''));
  await new Promise(resolve=>setTimeout(resolve,2000));
 }
}
$('load-job').onclick=()=>uploadFile($('file').files[0]);
function showFile(file){$('file-name').textContent=file?file.name:'CycloneDX · SPDX · Identification results / Up to 4 MiB';}
$('file').onchange=()=>{const file=$('file').files[0];showFile(file);message(file?file.name+' selected. Select Open VEX review to continue.':'Choose a JSON file above.');};
const dropzone=$('dropzone');
let dragDepth=0;
dropzone.addEventListener('dragenter',event=>{event.preventDefault();dragDepth++;dropzone.classList.add('bw-dragover');});
dropzone.addEventListener('dragover',event=>{event.preventDefault();if(event.dataTransfer)event.dataTransfer.dropEffect='copy';});
dropzone.addEventListener('dragleave',event=>{event.preventDefault();if(--dragDepth<=0){dragDepth=0;dropzone.classList.remove('bw-dragover');}});
dropzone.addEventListener('drop',event=>{
 event.preventDefault();dragDepth=0;dropzone.classList.remove('bw-dragover');
 if($('load-job').disabled)return;
 const files=event.dataTransfer?.files;
 if(!files||files.length!==1){message("Drop one JSON file at a time.",true);return;}
 $('file').files=files;showFile(files[0]);
 return uploadFile(files[0]);
});

task('refresh',async()=>{if(!w)throw Error("Open an enriched BOM first.");const wid=w.id,seq=token,updated=await api(route());if(w.id!==wid||seq!==token)return;w=updated;if(selected)selected=w.cases.find(c=>c.id===selected.id);render();message("Saved assessments rechecked against current evidence.");});
for(const b of document.querySelectorAll('[data-bw-export]'))b.onclick=async()=>{
 b.disabled=true;try{
  if(!w)throw Error("Open an enriched BOM first.");
  if(dirty&&!['original','bom'].includes(b.dataset.bwExport))throw Error("Save or reload the profile being edited before generating VEX.");
  const wid=w.id,kind=b.dataset.bwExport,value=await api(route()+'/export/'+kind);
  if(w.id!==wid)throw Error("The BOM changed during download.");
  const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json;charset=utf-8'}));
  const a=node('a');a.href=url;a.download='ics-vex-'+wid.slice(0,8)+'-'+kind+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  message("Checked the saved evidence and generated "+kind+" output.");
 }catch(e){message(window.icsVexEnglish.text(e.message),true);}finally{b.disabled=false;}
};
document.addEventListener('ics-profile-changed',()=>{if(selected&&!restoring){recordPicker('binding',bindValues());recordPicker('mapping',mappingValues());$('type').value=window.icsOperatingProfile.snapshot().asset_type_id;dirty=true;window.icsOperationalVex.invalidate();}});
for(const id of ['binding-record','binding-reviewed'])$(id).addEventListener('input',()=>{if(id==='binding-record')$('binding-reviewed').checked=false;dirty=true;window.icsOperationalVex.invalidate();});
for(const id of ['mapping-record','mapping-reviewed'])$(id).addEventListener('input',()=>{if(id==='mapping-record')$('mapping-reviewed').checked=false;window.icsOperationalVex.invalidate();});


const params=new URLSearchParams(location.search),wid=params.get('workflow'),job=params.get('job'),identificationJob=params.get('identification_job');
if(wid){const seq=++token;api('workflows/'+encodeURIComponent(wid)).then(value=>{if(seq!==token)return;w=value;render();message("Enriched BOM and saved CVE assessments loaded.");}).catch(e=>message(window.icsVexEnglish.text(e.message),true));}
else if(job){loadResult('from-job',{job_id:job}).catch(e=>message(window.icsVexEnglish.text(e.message),true));}
else if(identificationJob){$('load-job').disabled=true;awaitIdentification(identificationJob).catch(e=>message(window.icsVexEnglish.text(e.message),true)).finally(()=>$('load-job').disabled=false);}
})();
