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
const dom={};for(const [,id]of fs.readFileSync('src/item4/web/asset_vex_questionnaire.html','utf8').matchAll(/id="([^"]+)"/g))dom[id]=new Element(id==='representative'?'select':'div');
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
stored.special_questions=[...stored.asset_questions];
stored.asset_questions[0].llm_confidence=92;
stored.asset_questions[0].extraction_confidence=0.95;stored.asset_questions[0].category='C1';
stored.asset_questions[0].condition_id='http';stored.asset_questions[0].positive_fact='HTTP is enabled';
stored.asset_questions[0].information_requirement={label:'Current HTTP configuration state',verification:{instruction:'Verify the exact HTTP state on this component using current applied settings.',record_sources:[{label:'Applied HTTP configuration export',use:'verify_same_source_fact'}],limitations:['A default does not establish the current state.']}};
stored.special_questions=[...stored.asset_questions];
stored.question_policy={threshold:80,comparison:'>',confidence_kind:'llm_reported_uncalibrated'};
stored.context_questions.push(
 {id:'mode',label:'Operating mode for this assessment',optional:true,options:[{code:'unknown',label:'Unknown'},{code:'normal',label:'Normal operation'}]},
 {id:'component:deployment',label:'Is this component installed?',options:[{code:'unknown',label:'Unknown'},{code:'running',label:'Installed'},{code:'not_deployed',label:'Not installed'}]},
 {id:'component:runtime',label:'Installed version confirmation',visible_when:{question_id:'component:deployment',value:'running'},options:[{code:'unknown',label:'Unknown'},{code:'bom',label:'Matches BOM'}]},
 {id:'component:inventory_coverage',label:'Inventory completeness',visible_when:{question_id:'component:deployment',value:'not_deployed'},options:[{code:'unknown',label:'Unknown'},{code:'complete',label:'Complete'}]});
const requests=[];
let interruptedStart=false,interruptedPoll=false;
let pending=JSON.stringify(bom);
const context={document:{getElementById:id=>dom[id],createElement:tag=>new Element(tag),createElementNS:(_,tag)=>new Element(tag)},URL,URLSearchParams,Blob,console,
 sessionStorage:{getItem:key=>key==='icsvex:item4:pending-bom'?pending:null,removeItem:()=>{pending=null;}},
 location:{href:'http://127.0.0.1:8100/item4.html',search:''},history:{replaceState(){}},setTimeout:(fn)=>setTimeout(fn,0),clearTimeout,crypto:require('crypto').webcrypto,
 fetch:async(path,options)=>{
  requests.push({path,payload:options?.body?JSON.parse(options.body):undefined});
  if(path.endsWith('/start')){assert.deepEqual(JSON.parse(options.body).bom,bom);if(!interruptedStart){interruptedStart=true;throw new TypeError('Failed to fetch');}return {ok:true,json:async()=>({id:'job'})};}
  if(path.endsWith('/answers')){const p=JSON.parse(options.body);assert.equal(p.revision,stored.revision);stored={...stored,revision:stored.revision+1,answers:p.answers,context_answers:p.context_answers,assessment:null,assessment_state:'inputs_saved'};return {ok:true,json:async()=>structuredClone(stored)};}
  if(path.endsWith('/assess')){assert.equal(JSON.parse(options.body).revision,stored.revision);stored.assessment_state='completed';stored.assessment={input_revision:stored.revision,plan_sha256:stored.plan_sha256,provenance:'Operator attestation',decisions:[{cve:'CVE-2026-12345',component:{name:'Controller'},product_vex_status:'under_investigation',deployment_exploitability:'known_paths_blocked',prerequisite_status:'unsatisfied',condition_values:{'source-http':'false'},reason:'Known path blocked'}]};return {ok:true,json:async()=>structuredClone(stored)};}
  if(path.includes('/export/'))return {ok:true,json:async()=>({statements:[]})};
  if(path.endsWith('/retry')){const p=JSON.parse(options.body);assert.equal(p.revision,stored.revision);assert.equal(p.plan_sha256,stored.plan_sha256);stored={...stored,revision:stored.revision+1,plan_sha256:'retry-plan',answers:{},context_answers:{},assessment:null,assessment_state:'awaiting_inputs'};return {ok:true,json:async()=>structuredClone(stored)};}
  assert.equal(path,'/api/item4/analyses/jobs/job');if(!interruptedPoll){interruptedPoll=true;return {ok:false,status:503};}return {ok:true,json:async()=>structuredClone(stored)};
 }};
vm.createContext(context);
vm.runInContext(fs.readFileSync('src/item4/web/operating_question_tree.js','utf8'),context);
const uiSource=fs.readFileSync('src/item4/web/asset_vex_questionnaire_ui.js','utf8').replace(/\}\)\(\);\s*$/,'globalThis.__drawQuestionFixture=value=>{job=value;drawInputs(value);};})();');
vm.runInContext(uiSource,context);
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
 assert.equal(stored.special_questions[0].catalogue_definition.label_ko,'HTTP 수신 기능','Presentation must preserve original stored evidence');
 assert.equal(all(dom['asset-result']).filter(n=>n.tagName==='a').length,1,'Repeated advisory evidence must render one link');
 const evidence=all(dom['asset-result']).find(n=>n.tagName==='details');assert(!evidence.open,'Evidence should be collapsed');
 assert(all(dom['asset-result']).some(n=>n.textContent==='7 CVEs · 1 component'));
 assert.equal(dom['assessment-state'].textContent,'Waiting for asset operational information');
 assert(all(dom['condition-details']).some(n=>n.textContent==='Source prerequisite logic: NOT (FTP is enabled)'));
 assert(!all(dom['condition-details']).some(n=>n.tagName==='input'));
 assert(all(dom['asset-questions']).some(n=>n.textContent==='2. CVE-specific operating questions'));
 assert(all(dom['asset-questions']).some(n=>n.textContent==='LLM Confidence 92/100 · self-reported'));
 assert(all(dom['asset-questions']).some(n=>n.textContent==='Information to verify: Current HTTP configuration state'));
 assert(all(dom['asset-questions']).some(n=>n.textContent==='Applied HTTP configuration export'));
 assert(all(dom['asset-questions']).some(n=>n.textContent==='A default does not establish the current state.'));
 assert(!all(dom['asset-questions']).some(n=>/COMMON ·|CVSS common requirements/.test(n.textContent)));
 const contextRows=all(dom['context-questions']).filter(n=>n.className==='context-field');
 const runtimeRow=contextRows.find(n=>all(n).some(c=>c.id==='input-component:runtime'));
 const inventoryRow=contextRows.find(n=>all(n).some(c=>c.id==='input-component:inventory_coverage'));
 assert(runtimeRow.hidden&&inventoryRow.hidden);
 const deployment=all(dom['context-questions']).find(n=>n.id==='input-component:deployment');
 deployment.value='running';deployment.onchange();assert(!runtimeRow.hidden&&inventoryRow.hidden);
 const runtime=all(runtimeRow).find(n=>n.tagName==='select');runtime.value='bom';runtime.onchange();
 deployment.value='not_deployed';deployment.onchange();assert(runtimeRow.hidden&&!inventoryRow.hidden);assert.equal(runtime.value,'unknown');
 deployment.value='running';deployment.onchange();
 const input=all(dom['asset-questions']).find(n=>n.id==='input-source-http');input.value='x';input.onchange();
 const recordRef=all(dom['asset-questions']).find(n=>n.id==='record-source-http-references');
 const recordTime=all(dom['asset-questions']).find(n=>n.id==='record-source-http-observed_at');
 recordRef.value='configuration export <untrusted>';recordRef.oninput();recordTime.value='2026-11-26T09:00:00+09:00';recordTime.oninput();
 assert(dom['download-openvex'].disabled,'Editing must invalidate downloads immediately');
 await dom.assess.onclick();assert.equal(stored.answers['source-http'],'x');
 const recordSubmission=requests.filter(r=>r.path.endsWith('/answers')).at(-1).payload.answer_records['source-http'];
 assert.deepEqual(recordSubmission.references,['configuration export <untrusted>']);
 assert.equal(recordSubmission.observed_at,'2026-11-26T09:00:00+09:00');
 assert(!dom['assessment-result'].hidden);assert(!dom['download-openvex'].disabled);
 assert(all(dom['assessment-decisions']).some(n=>n.textContent==='Deployment exploitability: known_paths_blocked'));
 await dom['download-openvex'].onclick();assert(requests.some(r=>r.path.endsWith('/export/openvex')));
 const changed=all(dom['asset-questions']).find(n=>n.id==='input-source-http');changed.value='o';changed.onchange();
 assert(dom['assessment-result'].hidden);assert(dom['download-openvex'].disabled);
 const scopeInput=all(dom['context-questions']).find(n=>n.tagName==='select');scopeInput.value='current_single';scopeInput.onchange();
 assert(all(dom['asset-questions']).filter(n=>n.tagName==='select').every(n=>n.value==='unknown'),'Scope changes must clear previously displayed values');
 await dom['retry-analysis'].onclick();
 const retried=requests.find(r=>r.path.endsWith('/retry'));
 assert(retried,'Retry must use the current analysis job');
 assert.equal(stored.plan_sha256,'retry-plan');
 assert(dom['assessment-result'].hidden&&dom['download-openvex'].disabled,'A retry must retire the prior assessment');
 assert(!dom['questions-section'].hidden,'The refreshed plan must render after retry');
 stored.asset_questions[0].asset_record_context={mode:'profile_record_candidates',fields:[{label:'web management',evidence_guidance:'Current applied listener configuration'}]};
 await dom['retry-analysis'].onclick();
 assert(!all(dom['asset-questions']).some(n=>n.textContent==='web management: Current applied listener configuration'),'Unbound asset profile fields must not appear as condition checks');
 stored.asset_questions[0].condition_mapping={scenario_ids:['source-path'],catalogue_keys:['http_listener_enabled']};
 stored.unmapped_source_conditions=[{cve:'CVE-2026-12345',condition_id:'unplaced'}];
 stored.asset_questions[0].asset_record_context={mode:'source_only',fields:[]};
 await dom['retry-analysis'].onclick();
 assert(all(dom['asset-questions']).some(n=>n.id==='input-source-http'),'An unresolved asset must keep the V2 question visible');
 assert(all(dom['asset-questions']).some(n=>n.textContent==='Mapped source scenarios: source-path · Asset record mapping: http_listener_enabled'));
 assert(all(dom['asset-questions']).some(n=>n.textContent.includes('No source scenario binds this extracted condition.')));
 assert(all(dom['asset-questions']).some(n=>n.textContent.startsWith('No asset-specific record match.')));
 stored.asset_questions=[{...stored.special_questions[0],id:'low-score',llm_confidence:80}];stored.special_questions=[];
 stored.conditions[0].prerequisite.draft.prerequisites=[];stored.conditions[0].prerequisite.draft.scenarios=[];
 stored.conditions[0].sources=[{id:'nvd:CVE-2026-12345',url:'https://nvd.nist.gov/vuln/detail/CVE-2026-12345',text:'Original description <untrusted>'}];
 await dom['retry-analysis'].onclick();
 assert(!all(dom['asset-questions']).some(n=>n.id==='input-low-score'),'Confidence 80 is not above the threshold');
 assert(all(dom['asset-questions']).some(n=>n.textContent==='No operating questions passed the source and Confidence checks'));
 assert(all(dom['asset-questions']).some(n=>n.textContent.includes('does not establish that no prerequisites exist')));
 assert(all(dom['condition-details']).some(n=>n.textContent.includes('No executable conditions · review needed')));
 assert(all(dom['condition-details']).some(n=>n.textContent==='Original description <untrusted>'));
 assert(requests.every(r=>r.path.startsWith('/api/item4/analyses/')));
 // Actual DOM visibility follows the immutable source expression.
 const treeQuestions=['a','b'].map(c=>({...stored.questions[0],id:'q-'+c,condition_id:c,case_id:'branch-case',
  component_ref:'root',label:'For this asset, is '+c+' enabled?',positive_fact:c+' is enabled',
  llm_confidence:95,extraction_confidence:0.95,catalogue_definition:undefined,condition_mapping:undefined}));
 const plan={case_id:'branch-case',cve:'CVE-2026-12345',expression:{op:'and',args:[{condition:'a'},{condition:'b'}]},
  condition_order:['a','b'],questions:Object.fromEntries(treeQuestions.map(q=>[q.condition_id,{id:q.id,label:q.label,positive_fact:q.positive_fact}])),
  standalone_condition_ids:[],unavailable_condition_ids:[],source_unknowns:[]};
 context.treeFixture={...structuredClone(stored),asset_questions:treeQuestions,operating_question_trees:[plan],asked_question_ids:[],answers:{},answer_provenance:{}};
 function drawTree(){context.__drawQuestionFixture(context.treeFixture);}
 function current(){return all(dom['asset-questions']).filter(n=>n.className==='asset-key-row'&&!n.hidden&&n.dataset.treeState==='current').flatMap(n=>all(n).filter(c=>c.tagName==='select').map(c=>c.id));}
 function selectTree(id,value){const s=all(dom['asset-questions']).find(n=>n.id==='input-q-'+id);s.value=value;s.onchange();}
 drawTree();assert.deepEqual(current(),['input-q-a']);
 assert(all(dom['asset-questions']).some(n=>n.tagName==='svg'),'The branching diagram must render');
 selectTree('a','x');assert.deepEqual(current(),[],'AND false must skip the remaining question');
 const recording=all(dom['asset-questions']).find(n=>n.dataset.treeState==='recording');
 assert(recording&&!recording.hidden,'Keep the answered card available while the operator records evidence');
 all(recording).find(n=>n.textContent==='Finish recording this answer').onclick();assert(recording.hidden);
 assert.equal(all(dom['asset-questions']).find(n=>n.id==='input-q-b').value,'unknown','Skipped questions must not receive a fabricated answer');
 selectTree('a','o');assert.deepEqual(current(),['input-q-b'],'Editing an earlier branch must reopen the needed question');
 all(dom['asset-questions']).find(n=>n.textContent==='Reset this path').onclick();assert.deepEqual(current(),['input-q-a']);
 const aRow=all(dom['asset-questions']).find(n=>n.className==='asset-key-row'&&all(n).some(c=>c.id==='input-q-a'));
 all(aRow).find(n=>n.textContent==='Keep Unknown and continue').onclick();assert.deepEqual(current(),['input-q-b']);
 selectTree('b','o');assert.deepEqual(current(),[]);
 assert(all(dom['asset-questions']).some(n=>n.className==='tree-status'&&n.textContent.includes('unresolved')),'Unknown AND true must remain unresolved');
 context.treeFixture.answers={'q-a':'unknown','q-b':'o'};context.treeFixture.asked_question_ids=['q-a','q-b'];drawTree();
 assert.deepEqual(current(),[],'Explicit Unknown progress must survive reload');
 context.treeFixture.operating_question_trees[0].expression.op='or';context.treeFixture.answers={};context.treeFixture.asked_question_ids=[];drawTree();
 selectTree('a','o');assert.deepEqual(current(),[],'OR true must skip the remaining question');
 const productBom={bomFormat:'CycloneDX',metadata:{component:{'bom-ref':'collection:fixture',name:'Product collection',type:'data'}},
  components:[{'bom-ref':'product-very-long-private-id-a',name:'GENESIS64',version:'>=10.97|<=10.97.2',type:'application'},
              {'bom-ref':'product-very-long-private-id-b',name:'GENESIS64',version:'<=10.97.3',type:'application'}],
  vulnerabilities:[{id:'CVE-2099-12345',affects:[{ref:'product-very-long-private-id-a'}]}]};
 dom['bom-file'].files=[{name:'products.json',size:100,text:async()=>JSON.stringify(productBom)}];await dom['bom-file'].onchange();
 const productOptions=dom.representative.children.filter(n=>n.value);
 assert.deepEqual(productOptions.map(n=>n.textContent),['GENESIS64 · ≥10.97 & ≤10.97.2','GENESIS64 · ≤10.97.3']);
 assert(productOptions.every(n=>!n.textContent.includes('product-very-long')),'Internal IDs must not be visible in product choices');
 assert.equal(productOptions[0].value,'product-very-long-private-id-a','Submission must preserve the exact internal reference');
 assert(dom.start.disabled,'A product choice is required for an advisory collection');
 dom.representative.value=productOptions[1].value;dom.representative.onchange();assert(!dom.start.disabled);
 console.log('Upload recovery, source display, asset input, assessment, exports, invalidation and retry passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
