const assert=require('assert');
const T=require('../../src/item4/web/operating_question_tree.js');
const conditions=Array.from({length:25},(_,i)=>'c'+i);
const plan={cve:'CVE-2099-12345',condition_order:conditions,questions:Object.fromEntries(conditions.map(c=>[c,{id:'q-'+c,positive_fact:c+' is enabled'}])),
 expression:{op:'and',args:conditions.map(condition=>({condition}))},standalone_condition_ids:[],source_unknowns:[],unavailable_condition_ids:[]};
const original=JSON.stringify(plan);
let g=T.graph(plan,{},[],true);
assert.equal(g.nodes[0].kind,'cve');assert.equal(g.nodes[0].label,plan.cve);
assert(g.edges.some(e=>e.from===0&&g.nodes[e.to].cid==='c0'),'CVE root must lead into the first condition without changing it');
assert(g.nodes.length<=160,'Full preview must remain bounded');assert(g.truncated);
assert.equal(T.snapshot(plan,{},[]).next_question_id,'q-c0');
const answers=Object.fromEntries(conditions.slice(0,24).map(c=>['q-'+c,'o']));
assert.equal(T.snapshot(plan,answers,Object.keys(answers)).next_question_id,'q-c24','Preview truncation must not drop later questions');
const active=T.graph(plan,{'q-c0':'x'},['q-c0']);
assert(active.edges.some(e=>e.active&&e.label==='No'));
assert.equal(JSON.stringify(plan),original,'Graph rendering must never mutate source logic');
const htmlPlan={...plan,expression:{condition:'c0'},questions:{c0:{id:'q-c0',positive_fact:'<script>untrusted()</script>'}}};
assert(T.graph(htmlPlan).nodes.some(n=>n.label.includes('<script>')),'Labels are plain data for textContent, never parsed HTML');
console.log('Adaptive tree bounds, selected branches, source immutability and complete navigation passed');
