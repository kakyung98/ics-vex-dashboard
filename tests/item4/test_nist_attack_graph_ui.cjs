// DOM-adapter interaction tests, not a browser rendering test.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),cp=require('child_process');
const code=`import sys,json
sys.path.append(r'C:/Users/user/AppData/Local/Programs/Python/Python310/Lib/site-packages')
from tools.item4.auto_vex_fixture_support import profile,request
from src.item4 import nist_auto_vex as E
p=profile(); a=request('CVE-2014-0198',p,{'release_buffers':'enabled'})
before=E.evaluate(a)
a['auto_observations']['mitigation:release_buffers']={'value':'disabled','evidence_ids':['analysis'],'coverage':'complete','scope_sha256':E.scope_hash(p)}
print(json.dumps(dict(profile=p,plan=E.plan(a['cve'],p),affected=before,mitigated=E.evaluate(a))))`;
const fixture=JSON.parse(cp.execFileSync('python',['-S','-B','-X','utf8','-c',code],{encoding:'utf8',timeout:120000}));
class Node{
 constructor(tag){this.tagName=tag;this.children=[];this.dataset={};this.value='';this.disabled=false;this.hidden=false;this.textContent='';this.attrs={};}
 append(...nodes){for(const n of nodes){this.children.push(n);if(n&&typeof n==='object')n.parent=this;}}
 replaceChildren(...nodes){this.children=[];this.append(...nodes);}
 setAttribute(k,v){this.attrs[k]=String(v);}
 closest(selector){for(let n=this;n;n=n.parent)if(selector==='[data-mitigation]'&&n.dataset.mitigation)return n;return null;}
 get selectedOptions(){return this.children.filter(n=>n.selected);}
 click(){}
}
const dom={},html=fs.readFileSync('src/item4/web/evidence_based_vex_page.html','utf8');
for(const m of html.matchAll(/id="([^"]+)"/g)){assert(!dom[m[1]],'duplicate UI id');dom[m[1]]=new Node('div');}
const events={},requests=[];let active=structuredClone(fixture.profile);
const response=v=>({ok:true,json:async()=>structuredClone(v)});
const ctx={document:{getElementById:id=>dom[id],createElement:t=>new Node(t),createElementNS:(ns,t)=>new Node(t),addEventListener:(n,f)=>(events[n]??=[]).push(f)},window:{icsOperatingProfile:{snapshot:()=>structuredClone(active)}},fetch:async(url,options)=>{
 if(url==='/nist-auto-vex-rules.json')return response({population:{population_count:12418}});
 if(url.includes('question-relevance'))return response({conditional_settings_required:true});
 if(url.endsWith('/plan'))return response(fixture.plan);
 if(url.endsWith('/assess')){const p=JSON.parse(options.body);requests.push(p);if(p.auto_observations.release_buffers.value==='from_evidence'){const r=structuredClone(fixture.affected);r.operational_nli={requested:1,executed:1,comparisons:[{question_id:'release_buffers',value:'true',reasons:[],records:[{evidence_id:'configuration',premise:'SSL_MODE_RELEASE_BUFFERS is enabled.',positive:{label:'entailment'},negative:{label:'contradiction'}}]}]};return response(r);}return response(p.auto_observations['mitigation:release_buffers']?.value==='disabled'?fixture.mitigated:fixture.affected);}
 throw Error('Unexpected endpoint '+url);
},URL,Blob,Map,Set,JSON,console,setTimeout};
vm.runInNewContext(fs.readFileSync('src/item4/web/evidence_based_vex_ui.js','utf8'),ctx);
function all(n,predicate){return [...(predicate(n)?[n]:[]),...n.children.flatMap(c=>all(c,predicate))];}
function select(label){return all(dom['ov-mitigation-questions'],n=>n.attrs?.['aria-label']===label)[0];}
async function change(n,value){for(const o of n.children)o.selected=Array.isArray(value)?value.includes(o.value):o.value===value;n.value=value;await n.onchange();}
(async()=>{
 await ctx.window.icsOperationalVex.open('CVE-2014-0198');
 assert.equal(ctx.window.icsOperationalVex.payload().auto_observations.release_buffers.value,'from_evidence');
 assert.equal(dom['ov-attack-graph'].children[0].tagName,'svg');
 assert(dom['ov-mitigation-panel'].hidden,'mitigations must be hidden before affected');
 // Changing a base observation clears and rebuilds post-control inputs.
 const base=all(dom['ov-auto-questions'],n=>n.attrs?.['aria-label']==='auto-release_buffers value')[0];
 await change(base,'enabled');
 await dom['ov-evaluate'].onclick();assert(!dom['ov-mitigation-panel'].hidden);
 await change(select('mitigation:release_buffers value'),'disabled');
 await change(select('mitigation:release_buffers evidence'),['analysis']);
 await change(select('mitigation:release_buffers coverage'),'complete');
 assert(dom['ov-result'].hidden,'changed controls invalidate prior verdict');
 await dom['ov-evaluate'].onclick();
 const sent=requests.at(-1).auto_observations['mitigation:release_buffers'];
 assert.equal(sent.value,'disabled');assert.equal(sent.coverage,'complete');assert.deepEqual(sent.evidence_ids,['analysis']);
 assert(dom['ov-result-body'].children[0].textContent.includes('not_affected'));
 await change(base,'unknown');
 assert(dom['ov-mitigation-panel'].hidden);assert.equal(ctx.window.icsOperationalVex.payload().auto_observations['mitigation:release_buffers'].value,'unknown');
 await change(base,'from_evidence');
 const records=all(dom['ov-auto-questions'],n=>n.attrs?.['aria-label']==='auto-release_buffers evidence')[0];
 await change(records,['configuration']);await dom['ov-evaluate'].onclick();
 assert.equal(requests.at(-1).auto_observations.release_buffers.value,'from_evidence');
 assert(requests.at(-1).auto_observations.release_buffers.evidence_ids.includes('configuration'));
 const content=n=>n.textContent+n.children.map(content).join('');
 assert(content(dom['ov-result-body']).includes('Operating records → NLI comparison → graph condition'));
 assert(content(dom['ov-result-body']).includes('SSL_MODE_RELEASE_BUFFERS is enabled.'));
 console.log('Passed graph rendering, mitigation, NLI record selection and trace display, submission and stale-input checks.');
})().catch(e=>{console.error(e);process.exitCode=1;});
