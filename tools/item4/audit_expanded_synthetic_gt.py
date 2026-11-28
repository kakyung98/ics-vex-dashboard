"""Audit corpus structure, split isolation and scorer attainability, not model accuracy."""
from pathlib import Path
from copy import deepcopy
from collections import Counter
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import metamorphic_synthetic as E
from src.item4.evaluation.sealed_source_gt import judge

def validate_case(c):
    errors=[];g=c['gold'];facts=g['facts'];fs={f['id']:f for f in facts}
    if len(fs)!=len(facts):errors.append('duplicate_fact_id')
    for f in facts:
        if f['kind'] not in {'C'+str(i) for i in range(1,8)}:errors.append('unknown_kind')
        if type(f['polarity']) is not bool:errors.append('invalid_polarity')
        if not f['aliases'] or not f['evidence']:errors.append('missing_annotation')
        if f['source'] not in c['passages']:errors.append('missing_fact_source');continue
        for span in f['evidence']:
            if span not in c['passages'][f['source']]:errors.append('noncontiguous_fact_evidence')
            if len(span.split())>25:errors.append('quote_budget')
    exprs=[]
    for b in g['branches']:
        if not b['facts'] or len(b['facts'])!=len(set(b['facts'])):errors.append('empty_or_duplicate_branch')
        valid=True
        for i in b['facts']:
            if i not in fs or fs[i]['necessity']!='required':errors.append('nonrequired_branch_reference');valid=False
        if any(span not in c['passages'].get(b['source'],'') for span in b['evidence']):errors.append('noncontiguous_relation_evidence')
        if valid:
            terms=[E.leaf(i) if fs[i]['polarity'] else E.node('not',E.leaf(i)) for i in b['facts']]
            exprs.append(terms[0] if len(terms)==1 else E.node('and',*terms))
    expected=exprs[0] if len(exprs)==1 else E.node('or',*exprs) if exprs else None
    if not E.equivalent(expected,g['expression'],sorted(fs)):errors.append('expression_branch_mismatch')
    if set(c['scopes'])!=set(c['passages']):errors.append('missing_scope')
    return errors

def reference_prediction(c):
    """GT-derived positive control, never an LLM output or an accuracy result."""
    states={'C1':'enabled','C2':'available','C3':'reachable','C4':'required','C5':'has required permission','C6':'opens','C7':'active'}
    negative={'C1':'disabled','C2':'unavailable','C3':'unreachable','C4':'not required','C5':'has no permission','C7':'inactive'}
    conditions=[]
    for f in c['gold']['facts']:
        state='not required' if f['necessity']=='nonrequirement' else states[f['kind']] if f['polarity'] else negative[f['kind']]
        conditions.append(dict(id=f['id'],source=f['source'],quote=f['evidence'][0],axis='OTHER',target=f['aliases'][0],state=state,actor=f.get('actor') or 'system',necessity=f['necessity']))
    scenarios=[dict(id='s'+str(i),conditions=b['facts'],source=b['source'],quote=b['evidence'][0]) for i,b in enumerate(c['gold']['branches'])]
    return dict(conditions=conditions,scenarios=scenarios,unknowns_ko=c['gold']['allowed_uncertainty'][0],complete=True)

def audit(root):
    read=lambda p:json.loads(p.read_text(encoding='utf-8'));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    m=read(root/'manifest.json');assert all(sha(root/p)==h for p,h in m['sha256'].items())
    cases=[];split_domains={};split_groups={};split_ids={};exact=set();failures=[];controls=Counter();split_patterns={}
    for split in m['splits']:
        inputs=read(root/split/'inputs.json');gold=read(root/split/'gold.json');byid={g['id']:g for g in gold}
        assert len(inputs)==len(byid) and {c['id'] for c in inputs}==set(byid)
        split_ids[split]={c['id'] for c in inputs};split_domains[split]={g['domain'] for g in gold};split_groups[split]={g['group_id'] for g in gold};split_patterns[split]={g['challenge'] for g in gold}
        for c in inputs:
            assert set(c)=={'id','cve','passages','cvss_version','scopes'},'Answer metadata in model input'
            case=dict(c,**{k:v for k,v in byid[c['id']].items() if k!='id'});cases.append(case)
            canonical=json.dumps(c['passages'],sort_keys=True)
            assert canonical not in exact,'Duplicate source document';exact.add(canonical)
            errors=validate_case(case)
            p=reference_prediction(case);j=judge(case,p)
            if errors or not j['correct']:failures.append(dict(id=c['id'],structural_errors=errors,reference_judgement=j))
            controls['reference_positive_pass']+=j['correct']
            if p['conditions']:
                bad=deepcopy(p);bad['conditions'][0]['quote']='A successful attack may interrupt telemetry'
                controls['unrelated_quote_rejected']+=not judge(case,bad)['correct']
            if case['challenge']=='and_negative_guard':
                bad=deepcopy(p);next(f for f in bad['conditions'] if f['id']=='b')['state']='enabled'
                controls['guard_polarity_flip_rejected']+=not judge(case,bad)['correct']
            if any(f['necessity']=='nonrequirement' for f in case['gold']['facts']):
                bad=deepcopy(p);next(f for f in bad['conditions'] if f['necessity']=='nonrequirement')['state']='required'
                controls['nonrequirement_flip_rejected']+=not judge(case,bad)['correct']
    overlaps=[]
    names=list(split_ids)
    for i,a in enumerate(names):
        for b in names[i+1:]:
            d=dict(a=a,b=b,id_overlap=len(split_ids[a]&split_ids[b]),domain_overlap=len(split_domains[a]&split_domains[b]),scenario_overlap=len(split_groups[a]&split_groups[b]),shared_construction_families=sorted(split_patterns[a]&split_patterns[b]))
            assert not (d['id_overlap'] or d['domain_overlap'] or d['scenario_overlap']);overlaps.append(d)
    original=ROOT/'results/sealed_recheck_20261127';seal=read(original/'freeze.json')
    original_unchanged=all(sha(ROOT/p)==h for p,h in seal['runtime_files'].items()) and sha(original/'item4/gold.json')==seal['private_answers_sha256']['item4'] and sha(original/'item4/inputs.json')==seal['input_sha256']['item4']
    assert original_unchanged
    assert len(cases)==320 and controls['reference_positive_pass']==320 and not failures,failures[:3]
    assert controls['guard_polarity_flip_rejected']==32 and controls['nonrequirement_flip_rejected']==64 and controls['unrelated_quote_rejected']==288,controls
    result=dict(passed=True,new_documents=len(cases),structural_failures=failures,split_overlap_checks=overlaps,controls=dict(controls),original_sealed_artifacts_unchanged=original_unchanged,
        qualification='Positive controls are synthesized from GT, not model predictions. This checks mechanical attainability and selected false-accept controls, not independent semantic correctness. Shared construction families remain across splits. No new model performance result.')
    (root/'audit_report.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=True))

if __name__=='__main__':audit(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'data/item4_synthetic_gt_expanded_v1')
