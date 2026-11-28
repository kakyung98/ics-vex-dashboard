"""Freeze three actual-engine inputs for every one of the 12,418 target IDs.

Oracle classes come from raw CSAF product-status pointers plus counterfactual
deployment presence. This is source-consistency testing, not independent real
exploitation ground truth. Unresolved references are retained, never relabelled.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from datetime import datetime,timezone
from itertools import product
import gzip,hashlib,json,re,time
from src.item4.decision import scoped_vex_review as A
from src.item4.decision import evidence_based_vex as E
from src.item4.decision import population_condition_rules as P
from tools.item4.auto_vex_fixture_support import profile
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'results/nist_population_vex_20261118/benchmark'
def pointer(d,p):
    for part in p.split('/')[1:]:d=d[int(part)] if isinstance(d,list) else d[part.replace('~1','/').replace('~0','~')]
    return d
def ref_check(raw,version):
    s=re.sub(r'(?i)\b(?:all\s+)?versions?\s*','',raw).strip()
    if raw.strip().lower() in ('all versions','all releases','*'):return True
    if '|' in s:return version in [p.strip() for p in s.split('|')]
    s=re.sub(r'(?i)prior to|before|earlier than','<',s)
    if re.search(r'(?i)and earlier|and prior',s):s='<='+re.split(r'(?i)and earlier|and prior',s)[0].strip()
    pairs=re.findall(r'(<=|>=|<|>)\s*([vVrR]?\d+(?:\.\d+)*)',s)
    if pairs:
        rest=re.sub(r'(<=|>=|<|>)\s*[vVrR]?\d+(?:\.\d+)*','',s)
        if re.sub(r'(?i)\band\b|[ ,;]','',rest):return None
        def n(v):
            m=re.fullmatch(r'([vVrR]?)(\d+(?:\.\d+)*)',v)
            return (m[1].lower().replace('v',''),tuple(map(int,m[2].split('.')))) if m else None
        actual=n(version)
        if actual is None:return None
        for op,bound in pairs:
            target=n(bound)
            if actual[0]!=target[0]:return None
            size=max(len(actual[1]),len(target[1]));a=actual[1]+(0,)*(size-len(actual[1]));b=target[1]+(0,)*(size-len(target[1]))
            if not {'<':a<b,'<=':a<=b,'>':a>b,'>=':a>=b}[op]:return False
        return True
    if re.search(r'(?i)prior|before|after|except|through|all|unknown|earlier|later|[<>*]',s):return None
    return bool(s) and s.casefold()==version.casefold()
def reference_witness(raw):
    if raw.strip().lower() in ('all versions','all releases','*'):return '1.0.0'
    tokens=re.findall(r'[vVrR]?\d+(?:\.\d+)*',raw);candidates=[raw.strip(),'1.0.0','0.0.1']
    for token in tokens:
        candidates.append(token);m=re.fullmatch(r'([vVrR]?)(\d+(?:\.\d+)*)',token);nums=list(map(int,m[2].split('.')))
        for offset in (-1,1):
            if nums[-1]+offset>=0:candidates.append(m[1]+'.'.join(map(str,nums[:-1]+[nums[-1]+offset])))
    return next((v for v in candidates if v and ref_check(raw,v) is True),None)
_docs={}
def referenced_sample(row):
    key=row['source_file']
    if key not in _docs:
        raw=(ROOT/key).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=row['document_sha256']:raise ValueError('Raw primary source changed')
        _docs[key]=json.loads(raw.decode('utf-8-sig'))
    d=_docs[key];name=pointer(d,row['product_pointer'])['name']
    if P.norm(row['model']) not in P.norm(name):return None
    version=reference_witness(row['version_text'])
    if not version:return None
    pid=pointer(d,row['status_pointer']);product=pointer(d,row['product_pointer'])
    if pid!=product['product_id']:raise ValueError('Raw product/status pointer mismatch')
    return version,pointer(d,row['cve_pointer'])
def bool_expr(n,assignment):
    if 'condition' in n:return assignment[n['condition']]
    values=[bool_expr(a,assignment) for a in n['args']]
    return not values[0] if n['op']=='not' else all(values) if n['op']=='and' else any(values)
def operational_assignment(plan):
    editable={q['id']:q for q in plan['questions'] if q.get('true_values') and q.get('false_values') and q['id']!='deployment'}
    if not plan['expression']:return {}
    names=sorted(P.leaves(plan['expression']));bounded=names[:14]
    chosen={n:True for n in names}
    for vector in product((True,False),repeat=len(bounded)):
        candidate=dict(chosen);candidate.update(zip(bounded,vector))
        if bool_expr(plan['expression'],candidate):chosen=candidate;break
    return {qid:(q['true_values'][0] if chosen.get(qid,True) else q['false_values'][0]) for qid,q in editable.items()}
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'protocol.json').exists():raise ValueError('Frozen full-population benchmark already exists')
    population=sorted(c['cve'] for c in A.catalogue()['cves']);stamp=datetime.now(timezone.utc);start=time.monotonic();count=0;resolved=0
    with gzip.open(OUT/'inputs.jsonl.gz','wt',encoding='utf-8',compresslevel=1) as out,(OUT/'references.jsonl').open('w',encoding='utf-8') as gold:
        for i,cve in enumerate(population):
            row=P.get(cve);selected=None;actual=None
            for status in ('known_affected','fixed','known_not_affected'):
                for p in row['products']:
                    if p['status']!=status:continue
                    probe=referenced_sample(p)
                    if probe and probe[1]==cve:selected=(p,probe[0]);actual={'known_affected':'affected','fixed':'fixed','known_not_affected':'not_affected'}[status];break
                if selected:break
            if selected:model=selected[0]['model'];version=selected[1];resolved+=1
            else:model=row['products'][0]['model'] if row['products'] else 'Unresolved source product '+cve;version='UNVERIFIED-BUILD'
            p=profile(model,version,i%18,stamp,'SYNTHETIC-'+cve);plan=E.plan(cve,p);values=operational_assignment(plan)
            base={}
            for q in plan['questions']:
                value='running' if q['id']=='deployment' else 'bom' if q['id']=='runtime_version' and 'bom' in q['options'] else values.get(q['id'],'unknown')
                base[q['id']]=dict(value=value,evidence_ids=[] if value=='unknown' else ['inventory' if q['id'] in ('deployment','runtime_version') else 'configuration'],coverage='complete',scope_sha256=plan['scope_sha256'])
            for kind in ('source_present','component_absent','evidence_missing'):
                answers=json.loads(json.dumps(base))
                if kind=='component_absent':answers['deployment']['value']='not_deployed'
                if kind=='evidence_missing':
                    for a in answers.values():a.update(value='unknown',evidence_ids=[])
                payload=dict(cve=cve,product_key=plan['product']['key'],profile=p,plan_sha256=plan['plan_sha256'],auto_observations=answers);cid=cve+':'+kind
                out.write(json.dumps(dict(case_id=cid,payload=payload),ensure_ascii=False,separators=(',',':'))+'\n')
                reference=dict(case_id=cid,cve=cve,scenario=kind,actual_status='not_affected' if kind=='component_absent' else actual,reference_quality='synthetic_complete_inventory_absence' if kind=='component_absent' else 'raw_csaf_status_with_assumed_satisfied_source_prerequisites' if actual else 'unresolved_source_reference',source_pointer=selected[0]['status_pointer'] if selected else None,source_file=selected[0]['source_file'] if selected else None,all_latent_prerequisites_assumed_present=kind!='component_absent')
                gold.write(json.dumps(reference,ensure_ascii=False)+'\n');count+=1
            if (i+1)%1000==0:print('Frozen CVEs:',i+1,'cases:',count,flush=True)
    (OUT/'population.json').write_text(json.dumps(population),encoding='utf-8')
    protocol=dict(version=1,population_count=12418,population_sha256=P.digest(population),cases=count,case_types=['source_present','component_absent','evidence_missing'],frozen_at=stamp.isoformat(),catalogue_sha256=P.manifest()['sha256'],raw_status_resolved_cves=resolved,all_cvEs_retained=True,excluded_cves=0,labels_from_engine_output=False,llm_used=False,training=False,reference_is_independent_expert_ground_truth=False,limitations=['This measures synthetic source-status consistency, not independent real-world exploitability accuracy.','Present-case references assume every latent source prerequisite holds; unobservable/untranslated facts are withheld from operator inputs and may therefore become false negatives/abstentions.','The source-status reference derives from raw machine-extracted CISA CSAF and can itself contain inaccuracies.','Every CVE, including unresolved source references, remains in the input, output and coverage ledger.','Three counterfactual scenarios share a CVE; they are not independent field samples.'],sha256={n:hashlib.sha256((OUT/n).read_bytes()).hexdigest() for n in ['inputs.jsonl.gz','references.jsonl','population.json']},elapsed_seconds=time.monotonic()-start)
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in protocol.items() if k!='sha256'}))
if __name__=='__main__':main()
