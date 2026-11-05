const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const code=fs.readFileSync('results/shared_vex_ui_scripts.js','utf8');
const take=(start,end)=>code.slice(code.indexOf(start),code.indexOf(end,code.indexOf(start)));
const functions=take('function _applyGroundedVex(', 'function _vexRows(')
 +take('function exportOpenVex(', 'function exportCsaf(')
 +take('function exportCsaf(', 'function renderTreeList(');
for(const status of ['under_investigation','not_affected']){
 const captured=[];
 const context={_armResult:{statements:[{cve:'CVE-2099-12345',status,justification:status==='not_affected'?'vulnerable_code_not_present':null,
   reason:'rule reason',authoring:{status:'validated_draft'},document_draft:{impact_statement:'Generated explanation from supplied facts.',
   action_statement:null,evidence_refs:['case:decision']}}]},
  _sbomProduct:()=>({name:'Fixture',ref:'PRODUCT-1',purl:'pkg:generic/fixture'}),_isoNow:()=> '2026-11-01T00:00:00Z',_docId:()=> 'fixture',
  _pidFor:()=>null,_effStatus:r=>r.status,_justOrNull:r=>r.justification,_componentPids:()=>({list:[]}),
  _remedCsaf:()=> 'vendor_fix',_dl:(name,doc)=>captured.push({name,doc}),alert:()=>{throw Error('unexpected alert')}};
 vm.createContext(context);vm.runInContext(functions,context);
 context._vexRows=()=>[context._applyGroundedVex({cve:'CVE-2099-12345',component:'Fixture',status:'affected'})];
 vm.runInContext('exportOpenVex();exportCsaf();',context);
 assert.equal(captured[0].doc.statements[0].status,status);
 assert(JSON.stringify(captured[0].doc).includes('Generated explanation from supplied facts.'));
 assert(JSON.stringify(captured[0].doc).includes('case:decision'));
 assert.equal(captured[1].doc.document.tracking.status,'draft');
 assert(JSON.stringify(captured[1].doc).includes('Generated explanation from supplied facts.'));
 assert(JSON.stringify(captured[1].doc).includes('case:decision'));
 context._armResult.statements[0].document_draft=null;
 context._armResult.statements[0].authoring.status='rejected';
 const row=context._applyGroundedVex({cve:'CVE-2099-12345'});
 assert.equal(row.impact_statement,'rule reason');assert.equal(row.model_authoring_status,'rejected');
}
console.log('Generated draft text, locked VEX status and evidence IDs reach OpenVEX/CSAF; rejected text excluded: PASS');
