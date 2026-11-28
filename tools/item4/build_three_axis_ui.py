"""Produce the English coded-proof UI from the existing operational workspace."""
from pathlib import Path
from bs4 import BeautifulSoup
ROOT=Path(__file__).resolve().parents[2]
EN=Path('D:/ICS-VEX/local-service/sbom-vex/vex_operational_logic_20261117/english_ui')
markup=(EN/'operational_vex.html').read_text(encoding='utf-8')
# Preserve hidden legacy elements for existing saved-review compatibility; they
# are not submitted as assertions by the new form.
soup=BeautifulSoup(markup,'html.parser')
soup.find('a',href='/operational-vex-logic.en.html')['href']='/nist-three-axis-method.html'
soup.find('a',href='/nist-three-axis-method.html').string='Decision rules and synthetic experiment ↗'
soup.find('a',href='/operational-vex-verification.en.html')['href']='/nist-three-axis-experiment.json'
soup.find('a',href='/nist-three-axis-experiment.json').string='Full experiment metrics ↗'
soup.find('style').string=soup.find('style').text+'\n#ov-panel [hidden]{display:none!important}\n'
for prefix in ('2.','4.'):
    heading=next(h for h in soup.find_all('h3') if h.text.startswith(prefix))
    wrapper=soup.new_tag('div',hidden='')
    heading.insert_before(wrapper)
    nodes=[heading]
    for n in heading.next_siblings:
        if getattr(n,'name',None)=='h3' or (getattr(n,'name',None) and n.find(id='ov-evaluate')):break
        nodes.append(n)
    for n in nodes:wrapper.append(n.extract())
for id in ['ov-match','ov-match-source','ov-match-quote','ov-finding-status','ov-route-reviewed']:
    node=soup.find(id=id)
    if node:
        parent=node.find_parent('details') if id=='ov-route-reviewed' else node.find_parent('label')
        parent['hidden']=''
for id in ['ov-match-source','ov-finding-status']:
    soup.find(id=id)['disabled']=''
for heading in soup.find_all('h3'):
    if heading.text.startswith(('2.','4.')):heading['hidden']=''
proofs=BeautifulSoup('''<section id="ov-typed-panel"><h3>2. Select CVE-specific coded proof records</h3>
<p>Use reviewed inventory, supplier, test, or qualified analysis records for this exact asset/build and CVE source. Select records below; the engine calculates the verdict. Excerpts are retained for audit and never interpreted by an LLM. A control's presence or a blocked network path alone cannot establish non-impact.</p>
<div class="ov-toolbar"><button type="button" id="ov-import-proofs">Import coded proof registry</button><input id="ov-proof-file" hidden type="file" accept=".json,application/json"><button type="button" id="ov-proof-context">Download source-bound review template</button><a href="/nist-typed-review.schema.json" target="_blank" rel="noopener">Proof schema ↗</a><a href="/nist-three-axis-method.html" target="_blank" rel="noopener">Decision method and experiment ↗</a></div>
<details open><summary>Create a coded proof from registered records</summary><p>Choose the original record's conclusion. This records a human-checked finding; selecting a desired VEX status is not evidence. Scope and source bindings are pinned automatically.</p><div id="ov-proof-builder"></div><button id="ov-add-proof" type="button">Add draft proof for review</button></details>
<p id="ov-proof-count" class="ov-muted"></p><div id="ov-proof-list"></div></section>''','html.parser')
soup.find(id='ov-source-info').insert_after(proofs)
(ROOT/'src/research/ui/operational_vex_choices.html').write_text(str(soup),encoding='utf-8')
script=(ROOT/'results/nist_information_20261118/before_selectable/operational_vex_ui.js').read_text(encoding='utf-8')
start=script.index('function drawPaths(){');end=script.index('function resetAssertions()',start)
script=script[:start]+'''function drawPaths(){
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
 for(const eid of p.evidence_ids||[]){const e=profile.evidence[eid];d.append(el('blockquote',e?eid+' · '+e.source+'\\n'+e.excerpt:eid+' · Missing evidence — import it in the operating-profile evidence library first.'));}
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
''' +script[end:]
script=script.replace("const labels={", "let typedReview={version:'nist-three-axis-vex/1',records:{},selected_ids:[]};\nconst labels={",1)
script=script.replace("profile=snap;plan=window.icsVexEnglish.plan(data);", "profile=snap;plan=window.icsVexEnglish.plan(data);typedReview={version:'nist-three-axis-vex/1',records:{},selected_ids:[]};",1)
start=script.index(' const p={cve:plan.cve',script.index('function payload()'));end=script.index('\nfunction renderResult',start)
script=script[:start]+''' return {cve:plan.cve,product_key:plan.product.key,profile:clone(profile),plan_sha256:plan.plan_sha256,approved_scenarios:[...approved],bindings:[],typed_review:clone(typedReview)};}
''' +script[end:]
script=script.replace('approved=new Set(p.approved_scenarios||[]);drawPaths();',"typedReview=clone(p.typed_review||{version:'nist-three-axis-vex/1',records:{},selected_ids:[]});approved=new Set(p.approved_scenarios||[]);drawPaths();")
anchor="task('search',async()=>"
extra='''$('import-proofs').onclick=()=>$('proof-file').click();
$('add-proof').onclick=async()=>{try{if(stale||!plan)throw Error('Link the latest source and asset operational information first.');const get=id=>$(id)?.value||'',many=id=>[...$(id).selectedOptions].map(o=>o.value);const kind=get('new-kind'),q=plan.questions.find(q=>q.id===get('new-question'));const p={kind,conclusion:get('new-conclusion'),mechanism:get('new-mechanism'),cve:plan.cve,product_key:plan.product.key,asset_type_id:profile.asset_type_id,source_digest:plan.source_digest,scope:Object.fromEntries(['asset_ref','product','build','config_baseline','mode','origin'].map(k=>[k,profile.scope[k]])),evidence_ids:many('new-evidence'),field_ids:many('new-fields'),question_id:kind==='condition'?(q?.id||''):'',source_quote_sha256:kind==='condition'?(q?.source_quote_sha256||''):'',coverage:get('new-coverage'),reviewed:false};const next=clone(typedReview);next.records['proof-'+Date.now().toString(36)]=p;await api('validate-typed-review',next);typedReview=next;drawProofs();invalidate();message('Draft proof added without adopting it. Review the original records and select its review checkbox.');}catch(e){message(e.message,true);}};
$('proof-file').onchange=async()=>{try{const f=$('proof-file').files[0];if(!f)return;if(f.size>2*1024*1024)throw Error('Proof registry exceeds 2 MiB.');const p=JSON.parse(await f.text());if(p.version!=='nist-three-axis-vex/1'||!p.records||Array.isArray(p.records)||Object.keys(p).sort().join(',')!=='records,selected_ids,version')throw Error('Use the documented coded-proof schema.');const trial={...p,selected_ids:[]};for(const v of Object.values(trial.records))v.reviewed=false;await api('validate-typed-review',trial);typedReview=trial;invalidate();drawProofs();message('Imported without adopting any conclusions. Review and select each original coded record.');}catch(e){message(e.message,true);}finally{$('proof-file').value='';}};
$('proof-context').onclick=()=>{if(!plan||stale)return message('Link the current asset operational information first.',true);download({review:{version:'nist-three-axis-vex/1',records:{},selected_ids:[]},binding:{cve:plan.cve,product_key:plan.product.key,asset_type_id:profile.asset_type_id,source_digest:plan.source_digest,scope:Object.fromEntries(['asset_ref','product','build','config_baseline','mode','origin'].map(k=>[k,profile.scope[k]]))},questions:plan.questions.map(q=>({question_id:q.id,proposition:q.proposition,source_quote_sha256:q.source_quote_sha256,eligible_field_ids:q.typed_field_ids})),schema_url:'/nist-typed-review.schema.json',instructions:'The review property is the importable registry. Register original evidence in the asset operational information. Qualified reviewers encode actual findings using the published schema. No source text is interpreted by the engine.'},plan.cve+'-typed-review-context.json');};
'''
script=script.replace(anchor,extra+anchor,1)
(ROOT/'src/research/ui/operational_vex_choices_ui.js').write_text(script,encoding='utf-8')
(EN/'operational_vex_ui.js').write_text(script,encoding='utf-8')
print('Built source-bound, selectable proof registry UI')
