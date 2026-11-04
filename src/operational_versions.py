"""Bind operator version facts to component refs and authoritative product scope."""
import re
from src.cve_source_evidence import documents

def norm(v):return re.sub(r'[^a-z0-9]+',' ',str(v or '').lower()).strip()
def version(v):return re.sub(r'^[vV](?=\d)','',str(v or '').strip())

def products(document):
    out={}
    def walk(branches,vendor='',family='',release=''):
        for b in branches:
            cat=b.get('category');v=b.get('name','')
            ve=v if cat=='vendor' else vendor;fa=v if cat=='product_name' else family
            ver=v if cat=='product_version' else release
            if b.get('product'):
                p=b['product'];out[p['product_id']]={'vendor':ve,'product':fa,'version':ver,
                    'name':p.get('name',''),'product_id':p['product_id']}
            walk(b.get('branches',[]),ve,fa,ver)
    walk(document.get('product_tree',{}).get('branches',[]))
    return out

def product_options(cases):
    return sorted({(p['vendor']+' '+p['product']).strip() for case in cases for d in documents(case['cve']) for p in products(d['record']).values() if p['product']})

def assets_for(cases,sbom=None):
    assets={};original={str(c.get('bom-ref') or i):c for i,c in enumerate((sbom or {}).get('components',[]))}
    for case in cases:
        mappings=case.get('mappings') or [{'component_id':'asset','component':case.get('component') or case['product'],'version':case.get('version','')}]
        for m in mappings:
            ref=str(m.get('component_id') or 'asset');raw=original.get(ref,{})
            assets.setdefault(ref,{'ref':ref,'name':m.get('component',''),'reported_sbom_version':m.get('version',''),
                'purl':raw.get('purl'),'product_options':product_options([case]),'installed_version':'',
                'present':'unknown','attested':False,'evidence':''})
    return list(assets.values())

def validate_facts(assets,facts):
    if not isinstance(facts,dict) or set(facts)-{a['ref'] for a in assets}:raise ValueError('Unknown component reference in version facts.')
    out={}
    for a in assets:
        f=facts.get(a['ref'],{})
        if not isinstance(f,dict) or set(f)-{'present','product_name','installed_version','evidence','attested'}:raise ValueError('Invalid component fact fields.')
        if any(not isinstance(f.get(k,''),str) for k in ['product_name','installed_version','evidence']):raise ValueError('Component fact values must be text.')
        v={'present':f.get('present') or 'unknown','product_name':f.get('product_name','').strip(),
            'installed_version':f.get('installed_version','').strip(),'evidence':f.get('evidence','').strip(),'attested':f.get('attested',False)}
        if v['present'] not in {'unknown','yes','no'} or type(v['attested']) is not bool:raise ValueError('Invalid component presence/attestation.')
        if any(not isinstance(v[k],str) or len(v[k])>limit for k,limit in [('product_name',500),('installed_version',160),('evidence',1500)]):raise ValueError('Invalid component fact length/type.')
        out[a['ref']]=v
    return out

def compare_case(case,assets,facts):
    refs={str(m.get('component_id') or 'asset') for m in case.get('mappings',[])} or {a['ref'] for a in assets}
    records=[]
    for asset in assets:
        ref=asset['ref']
        if ref not in refs:continue
        fact=facts[ref];states=[];evidence=[]
        if fact['present']=='no':state='not_selected'
        elif fact['present']!='yes' or not fact['product_name'] or not fact['installed_version']:state='unknown'
        else:
            for d in documents(case['cve']):
                ps=products(d['record']);v=d['vulnerability'];target=norm(fact['product_name'])
                scoped=[p for p in ps.values() if target==norm(p['vendor']+' '+p['product'])]
                if not scoped:continue
                for p in scoped:
                    if version(p['version'])!=version(fact['installed_version']):continue
                    for status,label in [('known_affected','listed_affected'),('fixed','listed_fixed'),('known_not_affected','listed_not_affected')]:
                        if p['product_id'] in v.get('product_status',{}).get(status,[]):
                            states.append(label);evidence.append({'state':label,'product':p,'source':d['url'],'sha256':d['sha256'],'method':'exact_CSAF_product_status'})
                families={p['product'] for p in ps.values() if p['product']}
                target_family=scoped[0]['product'];other_words=set().union(*(set(norm(f).split()) for f in families if f!=target_family)) if len(families)>1 else set()
                distinguishing=[w for w in norm(target_family).split() if w not in other_words and len(w)>=2]
                for remediation in v.get('remediations',[]):
                    text=remediation.get('details','')
                    if not re.search(r'(?i)\bfix(?:ed)?\b.*\b(?:available|version)|\bfixed in\b',text):continue
                    # Require explicit product scope of the remediation.
                    ids=set(remediation.get('product_ids',[]))
                    if ids and not any(p['product_id'] in ids for p in scoped):continue
                    fixed=[]
                    if len(families)>1:
                        for word in distinguishing:
                            fixed.extend(m.group(1) for m in re.finditer(r'(?i)(?:\b|(?<=and))'+re.escape(word)+r'\s+(?:firmware\s+|version\s+)?([vV]?\d[0-9A-Za-z.+~-]*)',text))
                    else:
                        fixed.extend(m.group(1) for m in re.finditer(r'(?i)(?:fixed\s+(?:in\s+)?(?:version\s+)?|fix is available in\s+)([vV]?\d[0-9A-Za-z.+~-]*)',text))
                    if version(fact['installed_version']) in {version(x.rstrip('.,;')) for x in fixed}:
                        states.append('listed_fixed');evidence.append({'state':'listed_fixed','source':d['url'],'sha256':d['sha256'],
                            'product':scoped[0]['vendor']+' '+target_family,'quote':text,'method':'exact_explicit_vendor_fix_version'})
            state=next(iter(set(states))) if len(set(states))==1 else 'conflict' if len(set(states))>1 else 'unknown'
        records.append({'component_ref':ref,'product_name':fact['product_name'],'installed_version':fact['installed_version'] or None,
            'state':state,'operator_attested':fact['attested'],'operator_evidence':fact['evidence'],'deployment_independently_verified':False,
            'source_evidence':evidence,'missing_evidence':[] if state.startswith('listed_') else ['Confirmed product/version applicability']})
    active=[r for r in records if r['state']!='not_selected']
    compared=bool(active) and all(r['state'].startswith('listed_') for r in active)
    decided=compared and all(r['operator_attested'] and r['operator_evidence'] for r in active)
    return {'components':records,'version_decided':bool(decided),'reported_versions_compared':compared,'source':'pinned_CISA_CSAF',
        'comparison_policy':'Exact scoped product statuses / explicit fix versions only; unlisted versions or unsupported ordering stay unknown. No lexical version guessing.'}

def formal_version_status(evaluation):
    active=[r for r in evaluation['components'] if r['state']!='not_selected']
    if not active or not all(r['operator_attested'] and r['operator_evidence'] and r['state'].startswith('listed_') for r in active):return 'under_investigation',None
    if all(r['state']=='listed_fixed' for r in active):return 'fixed',None
    # A negative VEX justification is not invented from a version status alone.
    # A vulnerable version is applicability evidence, not runtime exploitability proof.
    return 'under_investigation',None
