// DOM-adapter interaction check, not a browser rendering/screenshot test.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Element{
 constructor(tag){this.tagName=tag;this.children=[];this.dataset={};this.hidden=false;this.disabled=false;this.textContent='';this.files=[];}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=[];this.append(...nodes);}
 get value(){return this._value??this.children[0]?.value??'';}
 set value(value){this._value=value;}
 setAttribute(k,v){(this.attrs??={})[k]=String(v);}
 addEventListener(type,listener){(this.listeners??={})[type]=listener;}
 classList={add(){},remove(){}};
 set innerHTML(_){throw Error('Untrusted content must use textContent');}
 click(){}
}
const dom={};for(const [,id]of fs.readFileSync('src/item4_questionnaire.html','utf8').matchAll(/id="([^"]+)"/g))dom[id]=new Element(id==='representative'?'select':'div');
const bom={bomFormat:'CycloneDX',metadata:{component:{name:'Controller','bom-ref':'root'}},vulnerabilities:[{id:'CVE-2026-12345'}]};
let stored={id:'job',status:'completed',revision:1,plan_sha256:'plan',answers:{},context_answers:{},asset_state:'completed',condition_state:'completed',cves_done:1,cves_total:1,
 representative:{name:'Controller'},asset_classification:{asset_type_id:'A0003',asset:{name:'PLC'},
 evidence:Array.from({length:21},(_,i)=>({advisory_id:'icsa-26-281-01',url:'https://example.invalid/icsa-26-281-01',cve:'CVE-2026-'+(12345+i%7),component_ref:'root'}))},
 assessment_state:'awaiting_inputs',unresolved:[],conditions:[{cve:'CVE-2026-12345',status:'extracted',source_kind:'CVE description',
 prerequisite:{draft:{prerequisites:[{id:'p',statement:'FTP is enabled',operational_quote:'FTP enabled <untrusted>',observation:{record_type:'configuration_export',check:'Check service configuration'}}],scenarios:[{expression:{op:'not',args:[{condition:'p'}]}}],unknowns:[],excluded_facts:[{reason:'implementation_defect',statement:'Defect <untrusted>'}]}},sources:[]}]};
stored.context_questions=[{id:'scope',label:'Scope',options:[{code:'unknown',label:'Unknown'},{code:'current_single',label:'Current asset'}]}];
stored.asset_questions=[{id:'source-http',key:'http_listener_enabled',label:'HTTP enabled <untrusted>',component_ref:'root',cve:'CVE-2026-12345',scope_kind:'HTTP',binding:'exact_positive_feature_target',yes_criterion:'HTTP enabled',no_criterion:'HTTP disabled',options:[{code:'unknown',label:'Unknown'},{code:'o',label:'o · Yes'},{code:'x',label:'x · No'}]}];
stored.questions=structuredClone(stored.asset_questions);
stored.asset_questions[0].label_ko='HTTP 수신 기능';
stored.asset_questions[0].catalogue_definition={asset_type_id:'A0003',key:'http_listener_enabled',label:'http listener enabled',label_ko:'HTTP 수신 기능',evidence_guidance:'HTTP 서비스 설정'};
const requests=[];
let interruptedStart=false,interruptedPoll=false;
let pending=JSON.stringify(bom);
const context={document:{getElementById:id=>dom[id],createElement:tag=>new Element(tag)},URL,URLSearchParams,Blob,console,
 sessionStorage:{getItem:key=>key==='icsvex:item4:pending-bom'?pending:null,removeItem:()=>{pending=null;}},
 location:{href:'http://127.0.0.1:8100/item4.html',search:''},history:{replaceState(){}},setTimeout:(fn)=>setTimeout(fn,0),clearTimeout,crypto:require('crypto').webcrypto,
 fetch:async(path,options)=>{
  requests.push({path,payload:options?.body?JSON.parse(options.body):undefined});
  if(path.endsWith('/start')){assert.deepEqual(JSON.parse(options.body).bom,bom);if(!interruptedStart){interruptedStart=true;throw new TypeError('Failed to fetch');}return {ok:true,json:async()=>({id:'job'})};}
  if(path.endsWith('/answers')){const p=JSON.parse(options.body);assert.equal(p.revision,stored.revision);stored={...stored,revision:stored.revision+1,answers:p.answers,context_answers:p.context_answers,assessment:null,assessment_state:'inputs_saved'};return {ok:true,json:async()=>structuredClone(stored)};}
  if(path.endsWith('/assess')){assert.equal(JSON.parse(options.body).revision,stored.revision);stored.assessment_state='completed';stored.assessment={input_revision:stored.revision,plan_sha256:stored.plan_sha256,provenance:'Operator attestation',decisions:[{cve:'CVE-2026-12345',component:{name:'Controller'},product_vex_status:'under_investigation',deployment_exploitability:'known_paths_blocked',prerequisite_status:'unsatisfied',condition_values:{'source-http':'false'},reason:'Known path blocked'}]};return {ok:true,json:async()=>structuredClone(stored)};}
  if(path.includes('/export/'))return {ok:true,json:async()=>({statements:[]})};
  assert.equal(path,'/api/item4/analyses/jobs/job');if(!interruptedPoll){interruptedPoll=true;return {ok:false,status:503};}return {ok:true,json:async()=>structuredClone(stored)};
 }};
vm.runInNewContext(fs.readFileSync('src/item4_questionnaire_ui.js','utf8'),context);
function all(element){return [element,...element.children.flatMap(all)];}
(async()=>{
 assert(!dom.start.disabled,'BOM handoff should populate the choice screen');assert.equal(pending,null);
 assert(dom['bom-upload-controls'].hidden,'A handed-off BOM must not request another upload');
 assert(!dom['bom-handoff-note'].hidden);assert(!dom['replace-bom'].hidden);
 assert.equal(dom['bom-heading'].textContent,'Load SBOM');
 dom['replace-bom'].onclick();assert(!dom['bom-upload-controls'].hidden);
 dom['bom-file'].files=[{name:'input.json',size:100,text:async()=>JSON.stringify(bom)}];
 await dom['bom-file'].onchange();assert(!dom.start.disabled);assert.equal(dom.representative.value,'root');
 assert(!dom.branches.hidden,'All four agents must remain visible before analysis starts');
 assert.equal(dom['asset-state'].textContent,'Waiting for SBOM analysis');
 assert(!dom['bom-upload-controls'].hidden,'Direct uploads must remain available');
 await dom['bom-dropzone'].listeners.drop({preventDefault(){},dataTransfer:{files:dom['bom-file'].files}});
 assert(!dom.start.disabled,'A dropped BOM should be ready without another upload');
 await dom.start.onclick();assert(!dom.sources.hidden);
 const submissions=requests.filter(r=>r.path.endsWith('/start'));assert.equal(submissions.length,2);assert.equal(new Set(submissions.map(r=>r.payload.request_id)).size,1,'A lost start response must retry the same request ID');
 assert(requests.filter(r=>r.path.endsWith('/jobs/job')).length===2,'A failed poll must reconnect to the same job');
 assert(!dom['questions-section'].hidden);assert(dom.assess);assert(dom['save-inputs']);
 assert(!all(dom['asset-questions']).some(n=>/[가-힣]/.test(n.textContent)),'Legacy catalogue labels and evidence guidance must render in English');
 assert(all(dom['asset-questions']).some(n=>n.textContent==='HTTP listener enabled'));
 assert.equal(stored.asset_questions[0].catalogue_definition.label_ko,'HTTP 수신 기능','Presentation must preserve original stored evidence');
 assert.equal(all(dom['asset-result']).filter(n=>n.tagName==='a').length,1,'Repeated advisory evidence must render one link');
 const evidence=all(dom['asset-result']).find(n=>n.tagName==='details');assert(!evidence.open,'Evidence should be collapsed');
 assert(all(dom['asset-result']).some(n=>n.textContent==='7 CVEs · 1 component'));
 assert.equal(dom['assessment-state'].textContent,'Waiting for operating values');
 assert(all(dom['condition-details']).some(n=>n.textContent==='Source prerequisite logic: NOT (FTP is enabled)'));
 assert(!all(dom['condition-details']).some(n=>n.tagName==='input'));
 const input=all(dom['asset-questions']).find(n=>n.tagName==='select');input.value='x';input.onchange();
 assert(dom['download-openvex'].disabled,'Editing must invalidate downloads immediately');
 await dom.assess.onclick();assert.equal(stored.answers['source-http'],'x');
 assert(!dom['assessment-result'].hidden);assert(!dom['download-openvex'].disabled);
 assert(all(dom['assessment-decisions']).some(n=>n.textContent==='Deployment exploitability: known_paths_blocked'));
 await dom['download-openvex'].onclick();assert(requests.some(r=>r.path.endsWith('/export/openvex')));
 const changed=all(dom['asset-questions']).find(n=>n.tagName==='select');changed.value='o';changed.onchange();
 assert(dom['assessment-result'].hidden);assert(dom['download-openvex'].disabled);
 const scopeInput=all(dom['context-questions']).find(n=>n.tagName==='select');scopeInput.value='current_single';scopeInput.onchange();
 assert(all(dom['asset-questions']).filter(n=>n.tagName==='select').every(n=>n.value==='unknown'),'Scope changes must clear previously displayed values');
 assert(requests.every(r=>r.path.startsWith('/api/item4/analyses/')));
 console.log('Upload recovery, safe source display, asset input, assessment, export and invalidation passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
