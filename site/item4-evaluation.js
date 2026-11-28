(()=>{
'use strict';
const panel=document.getElementById('source-evaluation');if(!panel)return;
const status=document.getElementById('source-evaluation-status'),output=document.getElementById('source-evaluation-result');
const run=document.getElementById('source-evaluation-run'),download=document.getElementById('source-evaluation-download');
let report=null;
let llmReport=null;
async function showLLM(){
 const value=await request('/llm');if(value.report){llmReport=value.report;
 const section=document.createElement('section');
 const title=document.createElement('h3');title.textContent='V2 / V3 LLM validity audit';section.append(title);
 const text=document.createElement('p');text.textContent=llmReport.web_summary+(value.current_prompts?'':' This report uses earlier prompts.');section.append(text);
 const limit=document.createElement('p');limit.textContent=llmReport.web_limit||'Development source audit with Nemotron on H200. The deployed Qwen models, independent semantic accuracy and field exploitability were not measured.';section.append(limit);
 const button=document.createElement('button');button.type='button';button.className='secondary';button.textContent='Download LLM audit JSON';button.onclick=()=>saveJSON(llmReport,'item4-llm-validity-audit.json');section.append(button);output.append(section);
 }
 const labels=await request('/reference-labels');if(labels.manifest){
  const section=document.createElement('section'),heading=document.createElement('h3');heading.textContent='Reference labels and review status';section.append(heading);output.append(section);
  const m=labels.manifest,p=document.createElement('p');p.textContent=m.label_count+' assistant-reference cases ('+m.real_descriptions+' real descriptions, '+m.synthetic_cases+' synthetic cases). Independent expert labels: '+m.independent_expert_labels+'. Actual exploitability labels: '+m.actual_exploitability_labels+'.';section.append(p);
  for(const [path,label]of [['labels','Download reference labels (JSONL)'],['review-queue','Download expert review queue (JSONL)']]){const a=document.createElement('a');a.href='/api/item4/analyses/evaluation/reference-labels/'+path;a.textContent=label;a.style.marginRight='1rem';section.append(a);}
 }
}
function show(value){
 report=value;output.replaceChildren();download.disabled=!value;
 if(!value){status.textContent='No current contract-check report is available. Select Run logic checks.';return;}
 status.textContent=value.correct+' / '+value.cases+' synthetic logic checks passed.';
 const text=document.createElement('p');text.textContent='Model calls: '+(value.llm_called?'Yes':'None')+'. Independent extraction and field accuracy were not measured.';output.append(text);
 if(value.population_index){const p=document.createElement('p'),counts=value.population_index;p.textContent='Population index: '+counts.cves+' target CVEs; '+counts.with_supported_cvss+' have verified supported CVSS assessments. Indexing does not mean model extraction was run.';output.append(p);}
}
async function request(path,method='GET'){
 const response=await fetch('/api/item4/analyses/evaluation'+path,{method});
 if(!response.ok)throw Error('Evaluation service unavailable (HTTP '+response.status+').');return response.json();
}
panel.addEventListener('toggle',async()=>{if(!panel.open)return;try{const value=await request('');show(value.latest);await showLLM();}catch(error){status.textContent=error.message;}});
run.onclick=async()=>{run.disabled=true;status.textContent='Running synthetic question-selection and logic checks…';try{show(await request('/run','POST'));await showLLM();}catch(error){status.textContent=error.message;}finally{run.disabled=false;}};
function saveJSON(value,name){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
download.onclick=()=>{if(report)saveJSON(report,'item4-source-question-contract-report.json');};
})();
