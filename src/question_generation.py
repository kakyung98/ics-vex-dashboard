"""CVE-keyed retrieval -> tuned question adapter -> source/schema checks."""
from copy import deepcopy
import hashlib
import re
from src import review_store as STORE
from src import operational_model_config as CONFIG
from src.vex_roles import fingerprint
from src.item4_questions import SYSTEM, topics, validate


def infer(packet):
    from src.identification_agents import get_runtime
    return get_runtime().grounded_role('item4-questions',packet)


def signature():
    spec=CONFIG.configured('item4-questions')
    return fingerprint([SYSTEM,spec['weights_sha256'] if spec else 'rules_v1'])


def retrieve(case, sources):
    # Only this CVE's pinned catalog participates, never neighbouring CVEs.
    ranks={'description':0,'summary':1,'cvss':2,'remediation':3}
    def score(s):
        text=s['text'].lower()
        relevant=len(re.findall(r'\b(?:attacker|malicious|untrusted|crafted|remote|requires|when|if|ftp|http|protocol|input|server|client)\b',text))
        boilerplate=bool(re.search(r'not aware of any exploit|introduced in commit|fixed in|version \d|parser always',text))
        return (ranks.get(s['source_kind'],4),boilerplate,-relevant)
    candidates=sorted((deepcopy(s) for s in sources if s['id'].startswith(case['cve']+':')),key=score)
    if case.get('vector') and not any(s['source_kind']=='cvss' for s in candidates):
        vector=case['vector']
        candidates.append({'id':case['cve']+':cvss:'+hashlib.sha256(vector.encode()).hexdigest()[:12],
            'text':vector,'source_kind':'cvss','condition_eligible':False,
            'source':{'source':'supplied_CVE_record','field':'vector'}})
    selected=[];size=0
    for s in candidates:
        if len(selected)>=7 or size+len(s['text'])>5500:continue
        s['text_sha256']=hashlib.sha256(s['text'].encode()).hexdigest()
        selected.append(s);size+=len(s['text'])
    return selected


def generate(case, sources, base_validator):
    spec=CONFIG.configured('item4-questions')
    if spec is None:return None
    selected=retrieve(case,sources)
    retrieval={'method':'cve_keyed_catalog_retrieval_v1','cve':case['cve'],
               'source_ids':[s['id'] for s in selected],
               'sources':selected,'vector_database_used':False}
    packet={'cve':case['cve'],'product':case.get('product'),
            'cwes':(case.get('analysis_route') or {}).get('cwes',case.get('cwe',[])),
            'common_topics':topics(case),'sources':selected,
            'scope':'Collect operator-observable facts. No source-code analysis or definitive VEX verdict.'}
    cache_key=fingerprint([packet,SYSTEM,spec['weights_sha256']])
    cached=STORE.get('tuned_question_draft',cache_key)
    if cached:
        cached=deepcopy(cached)
        accepted,rows,errors,norms=validate(cached['generation']['attempts'][-1],selected,case,base_validator)
        if accepted:
            cached['generation']['cache_hit']=True
            return cached['generation'],[{**q,'origin':'llm','necessity':'not_established',
                'can_refute':False,'semantic_review_required':True} for q in rows]
    attempts=[];errors=['no_retrieved_evidence'];normalizations=[];rows=[]
    if selected:
        for attempt in range(2):
            try:output=infer(packet)
            except Exception as e:
                output={'prediction':None,'raw':'','error':str(e),'role':'item4-questions'}
            attempts.append(deepcopy(output))
            accepted,rows,errors,normalizations=validate(output,selected,case,base_validator)
            if accepted:
                rows=[{**q,'origin':'llm','necessity':'not_established','can_refute':False,
                       'semantic_review_required':True} for q in rows]
                generation={'status':'validated','method':'tuned_adapter_cve_rag','llm_used':True,
                    'adapter':spec['folder'].name,'adapter_sha256':spec['weights_sha256'],
                    'retrieval':retrieval,'attempts':attempts,'errors':[],
                    'normalizations':normalizations,'cache_hit':False,
                    'independent_semantic_accuracy_established':False}
                STORE.put('tuned_question_draft',cache_key,{'generation':generation,'rows':rows},7*86400)
                return generation,rows
            if output.get('error') and output['error'] not in {'invalid_json_output','output_token_limit'}:break
            packet={**packet,'generation_feedback':{'failed_checks':errors,
                'instruction':'Generate new concise questions using the supplied source IDs. Do not repeat version/build questions or ask for code-level analysis.'}}
    return {'status':'model_rejected','method':'tuned_adapter_cve_rag','llm_used':False,
            'llm_attempted':bool(attempts),'adapter':spec['folder'].name,
            'adapter_sha256':spec['weights_sha256'],'retrieval':retrieval,'attempts':attempts,
            'errors':errors,'normalizations':normalizations},[]
