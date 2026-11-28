// Identification mappings only; this export does not assign VEX verdicts.
function exportIdentificationBom(input, result) {
 const copy=value=>JSON.parse(JSON.stringify(value));
 if(!input||!result||!Array.isArray(result.components))throw Error('The original BOM and completed identification results are required.');
 const property=(target,name,value)=>{
  if(target===bom&&bom.specVersion==='1.4')target=(bom.metadata??={});
  (target.properties??=[]).push({name,value:typeof value==='string'?value:JSON.stringify(value)});
 };
 let bom;
 if(input.bomFormat==='CycloneDX'){
  bom=copy(input);
  // Keep the input schema version: upgrading a BOM can invalidate native fields.
  bom.components??=[];
 }else if(/^SPDX-2\./.test(input.spdxVersion||'')){
  bom={bomFormat:'CycloneDX',specVersion:'1.7',version:1,components:(input.packages||[]).map((item,index)=>{
   const component={type:'library','bom-ref':item.SPDXID||String(index),name:item.name};
   if(item.versionInfo)component.version=item.versionInfo;
   if(item.description)component.description=item.description;
   for(const reference of item.externalRefs||[]){
    if(/cpe/i.test(reference.referenceType))component.cpe=reference.referenceLocator;
    if(/purl/i.test(reference.referenceType))component.purl=reference.referenceLocator;
   }
   property(component,'icsvex:spdx-package',item);
   return component;
  })};
  const dependencies=new Map(bom.components.map(c=>[c['bom-ref'],new Set()]));
  for(const relation of input.relationships||[]){
   const [from,to]=relation.relationshipType==='DEPENDS_ON'?[relation.spdxElementId,relation.relatedSpdxElement]:
    relation.relationshipType==='DEPENDENCY_OF'?[relation.relatedSpdxElement,relation.spdxElementId]:[];
   if(dependencies.has(from)&&dependencies.has(to))dependencies.get(from).add(to);
  }
  bom.dependencies=[...dependencies].map(([ref,items])=>({ref,dependsOn:[...items]}));
 }else throw Error('The input must be a CycloneDX or SPDX 2.x BOM.');
 property(bom,'icsvex:original-input-bom',input);
 property(bom,'icsvex:identification-result',result);
 property(bom,'icsvex:mapping-scope','Product/version identification only; deployment exploitability is not assessed. Unconfirmed candidates remain in icsvex:identification-result.');
 // A modified document cannot retain an input signature as its own signature.
 delete bom.signature;
 const byRef=new Map();
 function register(component,fallback){
  component['bom-ref']??=fallback;
  const ref=component['bom-ref'];
  if(byRef.has(ref))throw Error('Duplicate component reference in the exported BOM: '+ref);
  byRef.set(ref,component);
  (component.components||[]).forEach((child,index)=>register(child,ref+'/components/'+index));
 }
 bom.components.forEach((component,index)=>register(component,String(index)));
 if(bom.metadata?.component){
  const root=bom.metadata.component,ref=root['bom-ref'];
  // Some input inventories repeat their representative as a top-level component.
  // Retain its additional metadata on the single exported component; the complete
  // original document is also preserved above.
  if(ref&&byRef.has(ref)){
   const existing=byRef.get(ref);
   if(existing.name!==root.name||existing.version!==root.version)throw Error('Conflicting component identities share reference '+ref);
   for(const [key,value]of Object.entries(root))if(!(key in existing))existing[key]=copy(value);
   // Nested components must keep their references available to CVE mappings.
   (existing.components||[]).forEach((child,index)=>{if(!byRef.has(child['bom-ref']))register(child,ref+'/components/'+index);});
   delete bom.metadata.component;
  }else register(root,'metadata:component');
 }
 const findings=new Map((bom.vulnerabilities||[]).map(v=>[v.id,copy(v)]));
 const rows=[...result.components,...(result.asset_analysis?[result.asset_analysis]:[])];
 for(const row of rows){
  const ref=String(row.component.id),component=byRef.get(ref);
  if(!component)throw Error('Identification component is missing from the input BOM: '+ref);
  property(component,'icsvex:identification',row);
  for(const finding of row.cves||[]){
   if(finding.match_status!=='match'||!/^CVE-\d{4}-\d{4,}$/i.test(finding.cve_id||''))continue;
   const id=finding.cve_id.toUpperCase();
   if(!findings.has(id))findings.set(id,{id,source:{name:'NVD',url:'https://nvd.nist.gov/vuln/detail/'+id},affects:[]});
   const vulnerability=findings.get(id);vulnerability.affects??=[];
   if(!vulnerability.affects.some(item=>item.ref===ref))vulnerability.affects.push({ref});
  }
 }
 bom.vulnerabilities=[...findings.values()];
 return bom;
}
