/* Pages uses the same UI as the local app; analysis runs on an explicitly connected backend. */
(() => {
  'use strict';
  const net=window.fetch.bind(window);
  const key='icsvex-pages-backend:'+location.pathname.split('/')[1];
  const defaultBase='http://127.0.0.1:8100';
  let backend=sessionStorage.getItem(key)||'';
  const loopback=u=>['127.0.0.1','localhost','[::1]'].includes(u.hostname);
  function validated(value){
    const u=new URL(value);
    if(u.username||u.password||u.search||u.hash)throw new Error('Use a backend URL without credentials, query parameters or fragments.');
    if(u.protocol!=='https:'&&!(u.protocol==='http:'&&loopback(u)))throw new Error('Use HTTPS, or HTTP on localhost.');
    return u.href.replace(/\/$/,'');
  }
  try{if(backend)backend=validated(backend)}catch(_){backend='';sessionStorage.removeItem(key)}
  const files={
    '/api/summary':'cve_level.json','/api/source_available':'source_available.json',
    '/api/by_year':'by_year.json','/api/advisories':'advisories.json',
    '/api/advisories/list':'advisories_list.json','/api/sbom_index':'sbom_index.json',
    '/api/published_vex':'published_vex.json','/api/verify_results':'verify_results.json',
    '/api/verify_coverage':'verify_coverage.json',
    '/api/item4/cwe-policy':'cwe_routing_profiles.json'
  };
  const asJson=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});
  let index;
  let sboms;
  async function sbomDocument(path){
    if(!sboms)sboms=net(new URL('sbom_index.json',location.href)).then(r=>r.json());
    const name=decodeURIComponent(path.split('/').pop());
    const asset=((await sboms).assets||[]).find(a=>a.file===name);
    if(!asset)return asJson({detail:'SBOM not found'},404);
    if(!asset.public_bundle)return net(new URL('reverse_sbom/'+encodeURIComponent(name),location.href));
    const response=await net(new URL(asset.public_bundle,location.href));
    if(!response.ok)return response;
    const documents=await response.json();
    return documents[name]?asJson(documents[name]):asJson({detail:'SBOM not found'},404);
  }
  async function cves(){if(!index)index=net(new URL('cve_index.json',location.href)).then(r=>r.json());return index}
  function project(r){return {...r,vendor:(r.vendors||[]).slice(0,2).join(', ')}}
  async function snapshot(u){
    if(files[u.pathname])return net(new URL(files[u.pathname],location.href));
    if(u.pathname.startsWith('/api/advisory/')){
      const aid=decodeURIComponent(u.pathname.split('/').pop());
      if(!/^icsa?-\d{2}-\d{3}-\d{2}[a-z]?$/.test(aid))return asJson({detail:'Advisory not found'},404);
      const response=await net(new URL('advisory_details_'+aid.split('-')[1]+'.json',location.href));
      if(!response.ok)return response;
      const data=await response.json();
      return data[aid]?asJson(data[aid]):asJson({detail:'Advisory not found'},404);
    }
    if(u.pathname==='/api/cve_search'){
      const q=(u.searchParams.get('q')||'').toLowerCase();
      return asJson({cves:(await cves()).filter(r=>JSON.stringify([r.cve,r.component,r.vendors]).toLowerCase().includes(q)).slice(0,100).map(project)});
    }
    if(u.pathname==='/api/cves'){
      const dim=u.searchParams.get('dim'),value=u.searchParams.get('value'),scope=u.searchParams.get('scope')||'corpus';
      const selected=(await cves()).filter(r=>{
        if(scope==='source_available'&&!r.source_available)return false;
        if(dim==='vendor')return (r.vendors||[]).includes(value);
        if(dim==='device_type')return (r.device_types||[]).includes(value);
        return String(r[dim]??'')===value;
      });
      return asJson({dim,value,scope,count:selected.length,cves:selected.slice(0,400).map(project)});
    }
    return asJson({detail:'Connect your local backend to run analysis.'},503);
  }
  window.fetch=async function(input,options){
    const u=new URL(typeof input==='string'||input instanceof URL?input:input.url,location.href);
    const assetPath=u.pathname.match(/\/(reverse_sbom\/[^/]+|results\/verify_evidence\/.*)$/);
    if(u.origin!==location.origin||(!u.pathname.startsWith('/api/')&&!assetPath))return net(input,options);
    if(backend){
      const local=loopback(new URL(backend));
      const opts={credentials:'omit',mode:'cors',...(options||{}),...(local?{targetAddressSpace:'local'}:{})};
      const url=backend+(assetPath?'/'+assetPath[1]:u.pathname)+u.search;
      return net(input instanceof Request?new Request(url,input):url,opts);
    }
    if(assetPath)return assetPath[1].startsWith('reverse_sbom/')?sbomDocument(assetPath[1]):net(input,options);
    const method=(options?.method||(input instanceof Request?input.method:'GET')).toUpperCase();
    return method==='GET'?snapshot(u):asJson({detail:'Connect your local backend before submitting files or starting a job.'},503);
  };
  function ready(){
    const address=document.getElementById('pages-backend-url');
    const note=document.getElementById('pages-backend-status');
    const button=document.getElementById('pages-backend-connect');
    const disconnect=document.getElementById('pages-backend-disconnect');
    const localLink=document.getElementById('pages-open-local');
    const run=document.getElementById('cm-run');
    address.value=backend||defaultBase;localLink.href=backend||defaultBase;
    disconnect.hidden=!backend;
    note.textContent=backend?'Selected backend: '+backend:'Public data is available. Connect the backend running on this PC to identify CVEs and review VEX evidence.';
    if(run)run.disabled=!backend;
    button.onclick=async()=>{
      button.disabled=true;note.textContent='Connecting…';
      try{
        const value=validated(address.value.trim());
        const response=await net(value+'/api/health',{mode:'cors',credentials:'omit',...(loopback(new URL(value))?{targetAddressSpace:'local'}:{}),signal:AbortSignal.timeout(10000)});
        const data=await response.json();if(!response.ok||!data.ok)throw new Error('Backend health check failed.');
        if(value!==backend)sessionStorage.removeItem('cve-job');
        sessionStorage.setItem(key,value);location.reload();
      }catch(error){note.textContent='Connection failed. Keep the local server running and allow local-network access if your browser asks. You can also open the local app directly. '+error.message}
      finally{button.disabled=false}
    };
    disconnect.onclick=()=>{sessionStorage.removeItem(key);sessionStorage.removeItem('cve-job');location.reload()};
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',ready);else ready();
})();
