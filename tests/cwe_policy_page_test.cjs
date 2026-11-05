const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const html=fs.readFileSync('site/vex-decision.html','utf8');
const scripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const script=scripts.find(s=>s.includes("getElementById('cwe-policy-explorer')"));
assert(script,'Policy explorer script must be present in the generated method page');
const data=JSON.parse(fs.readFileSync('data/cwe_routing/v2/profiles.json','utf8'));
const controls={};let downloads=0,fetches=0;
for(const name of ['cwe-policy-explorer','cwe-policy-query','cwe-policy-source','cwe-policy-pillar','cwe-policy-summary','cwe-pillar-results','cwe-policy-count','cwe-policy-rows','cwe-policy-download']){
 controls[name]={value:'',open:false,handlers:{},children:[],addEventListener(type,fn){this.handlers[type]=fn;},appendChild(v){this.children.push(v);}};
}
const document={getElementById:id=>controls[id],createElement:tag=>({click(){if(tag==='a')downloads++;}})};
const fetch=async url=>{assert.equal(url,'/api/item4/cwe-policy');fetches++;return {ok:true,json:async()=>data};};
vm.runInNewContext(script,{document,fetch,URL,Blob,setTimeout:fn=>fn()});
(async()=>{
 const root=controls['cwe-policy-explorer'];root.open=true;await root.handlers.toggle();
 assert(controls['cwe-policy-summary'].textContent.includes('944'));
 assert.equal(controls['cwe-policy-pillar'].children.length,10);
 const pillarTable=controls['cwe-pillar-results'].innerHTML;
 assert.equal((pillarTable.match(/<tr>/g)||[]).length,11);
 for(const [id,p] of Object.entries(data.summary.per_pillar)){
  assert(pillarTable.includes(id));assert(pillarTable.includes(p.name));
 }
 assert(pillarTable.includes('Membership counts overlap'));
 assert.equal(controls['cwe-policy-download'].disabled,false);
 const query=controls['cwe-policy-query'];query.value='CWE-493';query.handlers.input();
 assert(controls['cwe-policy-rows'].innerHTML.includes('language-access-modifiers'));
 assert(controls['cwe-policy-rows'].innerHTML.includes('Source baseline: required'));
 query.value='CWE-327';query.handlers.input();
 assert(controls['cwe-policy-rows'].innerHTML.includes('Source baseline: undetermined'));
 assert(controls['cwe-policy-rows'].innerHTML.includes('Allowed-with-Review'));
 query.value='CWE-862';controls['cwe-policy-pillar'].value='CWE-284';query.handlers.input();
 assert(controls['cwe-policy-count'].textContent.startsWith('1 matching'));
 controls['cwe-policy-source'].value='not_required';controls['cwe-policy-source'].handlers.input();
 assert(controls['cwe-policy-count'].textContent.startsWith('0 matching'));
 await root.handlers.toggle();assert.equal(fetches,1,'Do not download the matrix again on reopening');
 controls['cwe-policy-download'].handlers.click();assert.equal(downloads,1);
 console.log('944-CWE policy viewer loading, filtering, mapping cautions and editable JSON download: PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
