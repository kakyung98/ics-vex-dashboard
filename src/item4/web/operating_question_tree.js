/* Adaptive question navigation and SVG presentation. No VEX verdicts. */
(function(root){
 'use strict';
 const truth=answer=>answer==='o'?'true':answer==='x'?'false':'unknown';
 function evaluate(expression,facts){
  if(!expression)return 'unknown';
  if('condition' in expression)return facts[expression.condition]||'unknown';
  const values=expression.args.map(a=>evaluate(a,facts));
  if(expression.op==='not')return {true:'false',false:'true',unknown:'unknown'}[values[0]];
  const [decisive,neutral]=expression.op==='and'?['false','true']:['true','false'];
  return values.includes(decisive)?decisive:values.every(v=>v===neutral)?neutral:'unknown';
 }
 function needed(expression,facts){
  if(!expression||evaluate(expression,facts)!=='unknown')return new Set();
  if('condition' in expression)return new Set([expression.condition]);
  return new Set(expression.args.flatMap(a=>[...needed(a,facts)]));
 }
 function snapshot(plan,answers={},asked=[]){
  const facts=Object.fromEntries(Object.entries(plan.questions).map(([cid,q])=>[cid,truth(answers[q.id])])),pending=needed(plan.expression,facts),visited=new Set(asked);
  const next=plan.condition_order.find(cid=>pending.has(cid)&&plan.questions[cid]&&!visited.has(plan.questions[cid].id)&&facts[cid]==='unknown')||
   plan.standalone_condition_ids.find(cid=>!visited.has(plan.questions[cid].id)&&facts[cid]==='unknown');
  return {value:evaluate(plan.expression,facts),next_question_id:next?plan.questions[next].id:null,
   needed_condition_ids:plan.condition_order.filter(cid=>pending.has(cid)),
   skipped_condition_ids:plan.condition_order.filter(cid=>!pending.has(cid)&&!plan.standalone_condition_ids.includes(cid)&&plan.questions[cid]&&facts[cid]==='unknown'),
   relationship_unresolved:!!plan.standalone_condition_ids.length||!plan.expression,source_unknowns:plan.source_unknowns,final_vex_decision:false};
 }
 function fallback(value,questions){
  const q=questions[0],draft=(value.conditions||[]).find(r=>r.cve===q.cve)?.prerequisite?.draft||{},scenarios=draft.scenarios||[],expressions=scenarios.map(s=>s.expression);
  const expression=expressions.length===1?expressions[0]:expressions.length?{op:'or',args:expressions}:null;
  function leaves(e){return !e?[]:'condition'in e?[e.condition]:e.args.flatMap(leaves);}
  const referenced=new Set(leaves(expression)),available=Object.fromEntries(questions.map(q=>[q.condition_id,{id:q.id,label:q.label,positive_fact:q.positive_fact||q.label}]));
  return {case_id:q.case_id||q.component_ref+'|'+q.cve,cve:q.cve,expression,questions:available,
   condition_order:[...new Set([...(draft.prerequisites||[]).map(a=>a.id),...questions.map(q=>q.condition_id)])],
   standalone_condition_ids:questions.map(q=>q.condition_id).filter(cid=>!referenced.has(cid)),
   unavailable_condition_ids:[...referenced].filter(cid=>!available[cid]),source_unknowns:draft.unknowns||[]};
 }
 // Expand the selected path; optional bounded full preview never limits navigation.
 function graph(plan,answers={},asked=[],full=false,limit=160){
  const nodes=[{id:0,depth:0,onPath:true,kind:'cve',label:plan.cve||'CVE'}],edges=[],visited=new Set(asked);let truncated=false;
  function add(facts,attempted,depth,onPath,expand,budget){
   const state=snapshot(plan,Object.fromEntries(Object.entries(facts).map(([cid,v])=>[plan.questions[cid]?.id,v==='true'?'o':v==='false'?'x':'unknown'])),[...attempted].map(cid=>plan.questions[cid]?.id));
   const cid=Object.keys(plan.questions).find(cid=>plan.questions[cid].id===state.next_question_id);
   const index=nodes.length,node={id:index,depth,onPath,kind:cid?'question':'outcome',cid,label:cid?plan.questions[cid].positive_fact:state.value,value:state.value};nodes.push(node);
   if(!cid)return index;
   if(!expand||budget<4||depth>=41){node.kind='collapsed';truncated=truncated||expand||full;return index;}
   const qid=plan.questions[cid].id,selected=truth(answers[qid]),hasAnswer=selected!=='unknown'||visited.has(qid);
   for(const [answer,label]of [['true','Yes'],['false','No'],['unknown','Unknown']]){
    const nextAttempted=new Set(attempted);nextAttempted.add(cid);
    const active=onPath&&hasAnswer&&selected===answer;
    const childBudget=full?Math.max(1,Math.floor((budget-1)/3)):active?budget-3:1;
    const child=add({...facts,[cid]:answer},nextAttempted,depth+1,active,full||active,childBudget);
    edges.push({from:index,to:child,label,active});
   }
   return index;
  }
  const first=add({},new Set(),1,true,true,limit-1);
  edges.push({from:0,to:first,label:'',active:true});
  let row=0;
  function position(id){const children=edges.filter(e=>e.from===id);if(!children.length)nodes[id].y=++row*94;
   else{children.forEach(e=>position(e.to));nodes[id].y=children.reduce((s,e)=>s+nodes[e.to].y,0)/children.length;}}
  position(0);return {nodes,edges,truncated,width:(Math.max(...nodes.map(n=>n.depth))+1)*290+70,height:Math.max(330,(row+1)*94)};
 }
 function draw(host,plan,answers,asked,full){
  const doc=host.ownerDocument||document,ns='http://www.w3.org/2000/svg',data=graph(plan,answers,asked,full);
  const el=(tag,attrs={},text)=>{const n=doc.createElementNS(ns,tag);for(const[k,v]of Object.entries(attrs))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=text;return n;};
  const svg=el('svg',{viewBox:`0 0 ${data.width} ${data.height}`,width:data.width,height:data.height,role:'img','aria-label':`${plan.cve||'CVE'} operating condition question tree. Yes, No and Unknown branches.`});
  for(const edge of data.edges){const a=data.nodes[edge.from],b=data.nodes[edge.to],x1=a.depth*290+36,x2=b.depth*290+36,mid=(x1+x2)/2;
   svg.append(el('path',{d:`M${x1},${a.y} C${mid},${a.y} ${mid},${b.y} ${x2},${b.y}`,class:edge.active?'tree-edge active':'tree-edge'}),
    el('text',{x:x2-76,y:b.y-9,class:edge.active?'tree-edge-label active':'tree-edge-label'},edge.label));}
  const titles={true:'Known expression: true',false:'Known expression: false',unknown:'Known expression: unknown'};
  for(const n of data.nodes){const x=n.depth*290+36,g=el('g',{class:`tree-node ${n.kind} ${n.onPath?'selected':''}`});
   g.append(el('title',{},n.kind==='outcome'?titles[n.value]:n.label),el('circle',{cx:x,cy:n.y,r:n.kind==='cve'?11:n.kind==='outcome'?9:8}));
   const label=n.kind==='outcome'?titles[n.value]:n.label,words=label.match(/.{1,31}(?:\s|$)|\S{1,31}/g)||[label];
   const text=el('text',{x:x+15,y:n.y-10,class:'tree-node-label'});
   words.slice(0,4).forEach((word,i)=>text.append(el('tspan',{x:x+15,dy:i?'1.2em':'0'},word.trim()+(i===3&&words.length>4?'…':''))));
   if(n.kind==='collapsed')text.append(el('tspan',{x:x+15,dy:'1.3em',class:'tree-preview-label'},'Next question preview'));
   g.append(text);svg.append(g);}
  host.replaceChildren(svg);return data;
 }
 const api={truth,evaluate,needed,snapshot,fallback,graph,draw};
 if(typeof module!=='undefined'&&module.exports)module.exports=api;
 root.Item4QuestionTree=api;
})(globalThis);
