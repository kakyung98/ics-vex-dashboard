const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const script=fs.readFileSync('src/pages_bridge.js','utf8');
function setup(saved){
 const store=saved||new Map();const calls=[];const callbacks=[];
 const els={};for(const id of ['pages-backend-url','pages-backend-status','pages-backend-connect','pages-backend-disconnect','pages-open-local','cm-run'])els[id]={};
 const location=new URL('https://kakyung98.github.io/ics-vex-dashboard/index.html');location.reload=()=>{location.reloaded=true};
 const net=async(input,options)=>{
  const url=String(input);calls.push({url,options});
  if(url.endsWith('/api/health'))return new Response('{"ok":true}');
  if(url.endsWith('cve_index.json'))return new Response(JSON.stringify([{cve:'CVE-2024-1234',year:2024,vendors:['Acme']}]));
  if(url.endsWith('operational_corpus_cves.json'))return new Response(JSON.stringify([
   {cve:'CVE-2026-10000',state:'source_reading_pending',cluster_ids:[]},
   {cve:'CVE-2026-10001',state:'conditions_pending_review',cluster_ids:['C1']},
   {cve:'CVE-2026-10002',state:'conditions_pending_review',cluster_ids:['C1','C2']}
  ]));
  if(url.endsWith('operational_corpus_summary.json'))return new Response('{"population":12418,"snapshot_only":true}');
  if(url.endsWith('advisory_details_26.json'))return new Response(JSON.stringify({'icsa-26-302-03':{id:'icsa-26-302-03',title:'Latest advisory'}}));
  if(url.endsWith('sbom_index.json'))return new Response(JSON.stringify({assets:[{file:'sample.json',public_bundle:'sbom_bundle_000.json'}]}));
  if(url.endsWith('sbom_bundle_000.json'))return new Response(JSON.stringify({'sample.json':{bomFormat:'CycloneDX',components:[]}}));
  return new Response('{}');
 };
 const window={fetch:net};
 const document={readyState:'loading',getElementById:id=>els[id],addEventListener:(event,fn)=>callbacks.push(fn)};
 const sessionStorage={getItem:k=>store.get(k)||null,setItem:(k,v)=>store.set(k,v),removeItem:k=>store.delete(k)};
 const context={window,document,sessionStorage,location,URL,Request,Response,AbortSignal};
 vm.runInNewContext(script,context);callbacks.forEach(fn=>fn());return {window,els,calls,location,store};
}
(async()=>{
 const first=setup();assert.equal(first.els['cm-run'].disabled,true);
 await first.window.fetch('/api/summary');assert.equal(first.calls[0].url,'https://kakyung98.github.io/ics-vex-dashboard/cve_level.json');
 assert.equal((await first.window.fetch('/api/item4/cwe-policy')).status,503);
 assert(!first.calls.some(c=>c.url.endsWith('cwe_routing_profiles.json')));
 const blocked=await first.window.fetch('/api/cve-match/jobs',{method:'POST',body:'{}'});assert.equal(blocked.status,503);
 assert(!first.calls.some(c=>c.url.startsWith('http://127.')));
 const detail=await first.window.fetch('/api/advisory/icsa-26-302-03');assert.equal((await detail.json()).title,'Latest advisory');
 assert(first.calls.at(-1).url.endsWith('/ics-vex-dashboard/advisory_details_26.json'));
 const sbom=await first.window.fetch('reverse_sbom/sample.json');assert.equal((await sbom.json()).bomFormat,'CycloneDX');
 assert(first.calls.at(-1).url.endsWith('/ics-vex-dashboard/sbom_bundle_000.json'));
 const corpus=await (await first.window.fetch('/api/operational-workflow/corpus/cves?cluster=C1&offset=1&limit=1')).json();
 assert.equal(corpus.total,2);assert.equal(corpus.rows[0].cve,'CVE-2026-10002');
 const unknown=await (await first.window.fetch('/api/operational-workflow/corpus/cves?state=source_reading_pending')).json();
 assert.equal(unknown.total,1);assert.equal(unknown.rows[0].cluster_ids.length,0);
 assert.equal((await first.window.fetch('/api/operational-workflow/corpus/cves?limit=201')).status,422);
 assert.equal((await (await first.window.fetch('/api/operational-workflow/corpus/summary')).json()).population,12418);
 assert(!first.calls.some(c=>c.url.startsWith('http://127.')));
 await first.els['pages-backend-connect'].onclick();assert(first.location.reloaded);
 const connected=setup(first.store);assert.equal(connected.els['cm-run'].disabled,false);
 await connected.window.fetch('/api/item4/start',{method:'POST',body:'{}'});
 assert.equal(connected.calls.at(-1).url,'http://127.0.0.1:8100/api/item4/start');
 assert.equal(connected.calls.at(-1).options.credentials,'omit');
 await connected.window.fetch('reverse_sbom/sample.json');assert.equal(connected.calls.at(-1).url,'http://127.0.0.1:8100/reverse_sbom/sample.json');
 const invalid=setup();invalid.els['pages-backend-url'].value='http://external.example';await invalid.els['pages-backend-connect'].onclick();assert.equal(invalid.calls.length,0);
 console.log('Pages static fallback, opt-in connection, API/asset routing and URL restrictions: PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
