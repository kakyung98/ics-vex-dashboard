"""Conservative, auditable ICS SBOM -> NVD CVE matching pipeline.

It DOES NOT establish runtime exploitability, firmware patch state, or VEX.
Optional LLM is used for alias suggestions ONLY (never trusted as an identifier).
"""
from __future__ import annotations
import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any, TypedDict

import requests
from packaging.version import Version, InvalidVersion
from langgraph.graph import StateGraph, START, END

CPE_API = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
CVE_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
ALIAS = {'libssl':'openssl','libcrypto':'openssl','openssl-libs':'openssl',
         'libcurl':'curl','curl-libs':'curl','libxml2.so':'libxml2'}


def norm(s: Any) -> str:
    return re.sub(r'[^a-z0-9]+', '_', str(s or '').strip().lower()).strip('_')


def cpe_parts(s: str) -> list[str]:
    # This parser supports ordinary unescaped CPE 2.3 strings; escaped names are unresolved.
    if not isinstance(s,str) or not s.startswith('cpe:2.3:') or '\\' in s:
        return []
    p=s.split(':')
    return p if len(p)==13 else []


def extract(sbom: dict) -> list[dict]:
    if sbom.get('bomFormat') == 'CycloneDX':
        out=[]
        for i,c in enumerate(sbom.get('components',[])):
            supplier=c.get('supplier') or {}
            ids=[x.get('cpe') for x in [c] if x.get('cpe')]
            out.append({'id':c.get('bom-ref') or str(i),'name':c.get('name') or '',
                'version':c.get('version') or '', 'supplier':supplier.get('name','') if isinstance(supplier,dict) else str(supplier),
                'purl':c.get('purl'), 'cpes':ids,'description':c.get('description','')})
        return out
    if 'spdxVersion' in sbom:
        out=[]
        for i,p in enumerate(sbom.get('packages',[])):
            ids=[]; purl=None
            for r in p.get('externalRefs',[]):
                t=str(r.get('referenceType','')).lower(); x=r.get('referenceLocator','')
                if 'cpe' in t: ids.append(x)
                if 'purl' in t: purl=x
            out.append({'id':p.get('SPDXID') or str(i),'name':p.get('name') or '',
                'version':p.get('versionInfo') or '', 'supplier':p.get('supplier',''),
                'purl':purl,'cpes':ids,'description':p.get('description','')})
        return out
    raise ValueError('Expected CycloneDX JSON or SPDX JSON')


class NVD:
    def __init__(self, offline=False, fixtures=None):
        self.offline=offline
        self.fixtures=fixtures or {}
        self.session=requests.Session()
        self.key=os.getenv('NVD_API_KEY')
        self.last=0.0
        self.cache={}
    def get(self, path, params):
        key=json.dumps([path,params],sort_keys=True)
        if key in self.cache:return self.cache[key]
        if self.offline:
            # fixture keys are URL paths and JSON-encoded parameter maps
            value=self.fixtures.get(key, {})
            self.cache[key]=value
            return value
        headers={'apiKey':self.key} if self.key else {}
        # NVD rate limiting: conservative client-side spacing
        gap=0.7 if self.key else 6.1
        delta=time.monotonic()-self.last
        if delta<gap:time.sleep(gap-delta)
        for retry in range(3):
            self.last=time.monotonic()
            try:
                response=self.session.get(path,params=params,headers=headers,timeout=25)
                if response.status_code in (429,500,502,503,504):
                    time.sleep(2**retry * 2); continue
                response.raise_for_status()
                result=response.json()
                self.cache[key]=result
                return result
            except (requests.RequestException,ValueError) as ex:
                if retry==2:raise RuntimeError(f'NVD request failed: {ex}') from ex
                time.sleep(2**retry)
        raise RuntimeError('NVD retries exhausted')

    def get_all(self, path, params, field):
        """Read every NVD page, preserving its result metadata."""
        query=dict(params);start=int(query.get('startIndex',0));items=[]
        while True:
            page=self.get(path,{**query,'startIndex':start})
            rows=page.get(field,[])
            if not isinstance(rows,list):raise RuntimeError('Invalid NVD result list: '+field)
            items.extend(rows)
            total=int(page.get('totalResults',len(items)))
            if not rows or start+len(rows)>=total:return {**page,field:items}
            start+=len(rows)


class State(TypedDict, total=False):
    component:dict
    l2:dict
    l3:dict
    l4:dict
    validation:dict
    matches:list
    trace:list
    route:str


def llm_alias(name: str) -> list[str]:
    """Optional OpenAI-compatible local sLLM; suggestions untrusted by design."""
    url=os.getenv('SLLM_BASE_URL')
    model=os.getenv('SLLM_MODEL')
    if not url or not model:return []
    try:
        response=requests.post(url.rstrip('/')+'/chat/completions',json={
            'model':model,'temperature':0,'max_tokens':100,
            'messages':[{'role':'system','content':'Return JSON {"aliases":["..."]}. Suggest at most 3 known upstream software product names. Never invent IDs.'},
                        {'role':'user','content':f'Software component: {name}'}]},timeout=20)
        response.raise_for_status()
        content=response.json()['choices'][0]['message']['content']
        obj=json.loads(content)
        return [norm(x) for x in obj.get('aliases',[])[:3] if isinstance(x,str)]
    except (Exception):
        return []


def l2(state: State) -> dict:
    c=state['component']; raw=norm(c.get('name'))
    normalized=ALIAS.get(raw,raw)
    suggestions=llm_alias(c.get('name','')) if normalized else []
    return {'l2':{'raw':c.get('name'), 'normalized':normalized,
                  'aliases_suggested_unverified':suggestions,
                  'status':'resolved' if normalized else 'unresolved'}}


def l3(state: State) -> dict:
    raw=str(state['component'].get('version') or '').strip()
    v=re.sub(r'^[vV](?=\d)','',raw)
    # Preserve upstream, revision, epoch and custom suffix. DO NOT drop to base version.
    opaque=(not v or v.lower() in ('unknown','latest','unspecified','noassertion'))
    return {'l3':{'raw':raw,'normalized':v if not opaque else None,
                  'status':'unresolved' if opaque else 'present',
                  'note':'Original version retained; version scheme validated per CVE rule.'}}


def cpe_candidates(nvd:NVD, name:str) -> tuple[list[dict],str|None]:
    try:
        data=nvd.get(CPE_API,{'keywordSearch':name,'resultsPerPage':100})
    except RuntimeError as e:return [],str(e)
    out=[]
    for item in data.get('products',[]):
        p=item.get('cpe',{})
        s=p.get('cpeName',''); fields=cpe_parts(s)
        if not fields or p.get('deprecated'):continue
        # Exact product segment only; no fuzzy guessing.
        if norm(fields[4])==name:
            out.append({'cpe':s,'vendor':fields[3],'product':fields[4], 'version':fields[5]})
    return out,None


def make_l4(nvd:NVD):
    def l4(state:State)->dict:
        c=state['component']; valid=[]; errors=[]
        for s in c.get('cpes',[]):
            p=cpe_parts(s)
            if p and p[2]=='a':valid.append({'cpe':s,'vendor':p[3],'product':p[4], 'version':p[5], 'origin':'sbom_unverified'})
            else:errors.append('invalid_or_unsupported_input_cpe')
        if valid:
            return {'l4':{'candidates':valid,'lookup_error':None,'warnings':errors,'status':'input_cpe_requires_verification'}}
        name=state['l2']['normalized']
        if not name:return {'l4':{'candidates':[],'status':'unresolved','warnings':['missing_name']}}
        found,err=cpe_candidates(nvd,name)
        for item in found:item['origin']='nvd_dictionary'
        return {'l4':{'candidates':found,'lookup_error':err,'warnings':errors,
                       'status':'candidates_found' if found else 'unresolved'}}
    return l4


def validate(state:State)->dict:
    c=state['component']; l4r=state['l4']; name=state['l2']['normalized']
    candidates=l4r.get('candidates',[])
    # Accept only when exactly one distinct vendor/product exists; upstream supplier is not device maker.
    products={(x['vendor'],x['product']) for x in candidates if norm(x['product'])==name and x['vendor'] not in ('*','-')}
    reasons=[]
    if not name:reasons.append('component_name_missing')
    if not state['l3']['normalized']:reasons.append('version_missing')
    if l4r.get('lookup_error'):reasons.append('nvd_lookup_failure')
    if len(products)!=1:reasons.append('ambiguous_or_absent_product_identity')
    # Require source from NVD dictionary, not an unverified assertion from SBOM.
    if len(products)==1 and not any(x['origin']=='nvd_dictionary' for x in candidates):
        reasons.append('input_cpe_not_verified_in_dictionary')
    selected=next(iter(products)) if len(products)==1 and not reasons else None
    return {'validation':{'status':'validated' if selected else 'unresolved',
                          'vendor':selected[0] if selected else None,
                          'product':selected[1] if selected else None,
                          'reasons':reasons}}


def compare(v: str, bound: str) -> int|None:
    # Strict PEP440 only: other ecosystems need dedicated comparators, never lexicographic.
    try:
        a,b=Version(v),Version(bound)
        return (a>b)-(a<b)
    except InvalidVersion:return None


def criterion_state(m:dict, vendor:str, product:str, version:str)->str:
    p=cpe_parts(m.get('criteria',''))
    if not p or p[3]!=vendor or p[4]!=product:return 'false'
    if not m.get('vulnerable',False):return 'false'
    exact=p[5]
    if exact not in ('*','-'):
        return 'true' if exact==version else 'false'
    for field,op in [('versionStartIncluding','ge'),('versionStartExcluding','gt'),
                     ('versionEndIncluding','le'),('versionEndExcluding','lt')]:
        if field not in m:continue
        d=compare(version,str(m[field]))
        if d is None:return 'unknown'
        if not {'ge':d>=0,'gt':d>0,'le':d<=0,'lt':d<0}[op]:return 'false'
    return 'true'


def evaluate_nodes(nodes:list, vendor:str, product:str,version:str)->str:
    """CPE configurations: conservative 3-valued evaluation.
    Other platform prerequisites remain unknown: no fabricated vulnerability conclusions.
    """
    def NOT(v):return {'true':'false','false':'true','unknown':'unknown'}[v]
    def AND(values):return 'false' if 'false' in values else ('unknown' if 'unknown' in values else 'true')
    def OR(values):return 'true' if 'true' in values else ('unknown' if 'unknown' in values else 'false')
    def rec(node):
        vals=[]
        for item in node.get('cpeMatch',[]):
            p=cpe_parts(item.get('criteria',''))
            if p and (p[3],p[4])!=(vendor,product):
                # Other software/platform requirements are not observed by this matcher.
                vals.append('unknown')
            else:vals.append(criterion_state(item,vendor,product,version))
        vals.extend(rec(child) for child in node.get('children',[]))
        if not vals:return 'unknown'
        result=AND(vals) if node.get('operator','OR')=='AND' else OR(vals)
        return NOT(result) if node.get('negate',False) else result
    return OR([rec(x) for x in nodes]) if nodes else 'unknown'


def make_matcher(nvd:NVD):
    def match(state:State)->dict:
        valid=state['validation']; version=state['l3']['normalized']
        if valid['status']!='validated':return {'matches':[],'trace':['CVE query skipped: unresolved identity']}
        # NVD cpeName requires a full 13-part string. Use product/version CPE then inspect configurations.
        cpe=f"cpe:2.3:a:{valid['vendor']}:{valid['product']}:{version}:*:*:*:*:*:*:*"
        try:data=nvd.get(CVE_API,{'cpeName':cpe,'resultsPerPage':2000})
        except RuntimeError as e:return {'matches':[],'trace':[str(e)]}
        # If pagination incomplete do not assert exhaustiveness.
        incomplete=data.get('totalResults',0)>len(data.get('vulnerabilities',[]))
        found=[]
        for item in data.get('vulnerabilities',[]):
            cv=item.get('cve',{}); config=cv.get('configurations',[])
            status=evaluate_nodes(config,valid['vendor'],valid['product'],version)
            found.append({'cve_id':cv.get('id'),'match_status':{'true':'match','false':'no_match','unknown':'unknown'}[status],
                          'evidence':{'nvd_cve':cv.get('id'),'cpe_query':cpe},
                          'patch_status':'not_checked','runtime_exploitability':'not_assessed'})
        return {'matches':found,'trace':['NVD query completed' if not incomplete else 'WARNING: paginated results incomplete']}
    return match


def graph(nvd:NVD):
    g=StateGraph(State)
    g.add_node('orchestrator',lambda s:{'route':'process'})
    g.add_node('l2_name',l2)
    g.add_node('l3_version',l3)
    g.add_node('l4_identifier',make_l4(nvd))
    g.add_node('decision_validator',validate)
    g.add_node('cve_matching',make_matcher(nvd))
    g.add_edge(START,'orchestrator')
    g.add_conditional_edges('orchestrator',lambda s:'l2_name' if s['component'].get('name') else 'l3_version',
        {'l2_name':'l2_name','l3_version':'l3_version'})
    g.add_edge('l2_name','l3_version')
    g.add_conditional_edges('l3_version',lambda s:'l4_identifier' if s.get('l2',{}).get('normalized') else 'decision_validator',
         {'l4_identifier':'l4_identifier','decision_validator':'decision_validator'})
    g.add_edge('l4_identifier','decision_validator')
    g.add_conditional_edges('decision_validator',lambda s:'cve_matching' if s['validation']['status']=='validated' else 'end',
        {'cve_matching':'cve_matching','end':END})
    g.add_edge('cve_matching',END)
    return g.compile()


def run(sbom:dict,nvd:NVD)->dict:
    app=graph(nvd); results=[]
    for c in extract(sbom):
        try:
            out=app.invoke({'component':c})
            results.append({'component':c,'l2':out.get('l2'),'l3':out.get('l3'),
                            'l4':out.get('l4'),'validation':out.get('validation'),
                            'cves':out.get('matches',[]),'trace':out.get('trace',[])})
        except Exception as exc:
            results.append({'component':c,'error':str(exc),'status':'unknown'})
    return {'schema_version':'0.2','interpretation':'candidate CVE matches only; NOT a VEX decision',
            'components':results}


def main():
    parser=argparse.ArgumentParser(description='ICS SBOM NVD candidate CVE matcher')
    parser.add_argument('sbom');parser.add_argument('-o','--output',default='results.json')
    parser.add_argument('--offline',action='store_true',help='No NVD requests; unresolved results expected')
    args=parser.parse_args()
    sbom=json.loads(Path(args.sbom).read_text(encoding='utf-8'))
    result=run(sbom,NVD(offline=args.offline))
    Path(args.output).write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(f'Wrote {args.output}: {len(result["components"])} components')

if __name__=='__main__':main()

