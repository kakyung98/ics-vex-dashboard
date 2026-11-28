"""Read-only audit of frozen examples, overlap, request content and oracle limits.

No model calls, new tuning, or replacement of original predictions/scores.
"""
from pathlib import Path
from collections import Counter,defaultdict
from copy import deepcopy
import hashlib,json,re,sys,tarfile
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import nemotron_source_synthetic as N
from src.item4.evaluation import metamorphic_synthetic as E

BASE=ROOT/'results/scoped_llm_evaluations_20261127'


def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()
def norm(v):return re.sub(r'[^a-z0-9]+','_',str(v or '').casefold()).strip('_')


def main():
    out=BASE/'audit';out.mkdir(exist_ok=True)
    names=['item3_metamorphic','item3_metamorphic_confirmatory','item3_metamorphic_version_stress']
    inputs={name:read(BASE/name/'inputs.json') for name in names};originals={n:[c for c in rows if c['variant']=='original'] for n,rows in inputs.items()}
    sources={n:{c['source'].replace('\\','/') for c in rows} for n,rows in originals.items()}
    hashes={n:{digest(c['sbom']) for c in rows} for n,rows in originals.items()}
    pairs={};model_same=defaultdict(Counter);alternatives=Counter();confirmed=Counter();product_sets={};sample3=[];subset_products={};subset_semantics={}
    selected_sources={Path(c['source']).stem for rows in originals.values() for c in rows}
    folds={};semantics={}
    with (ROOT/'benchmark/item3_evaluation/gold.jsonl').open(encoding='utf-8') as f:
        for line in f:
            r=json.loads(line)
            if r['id'] in selected_sources:folds[r['id']]=r.get('fold');semantics[r['id']]=r.get('source_semantic_sha256')
    training=read(out/'verified_training_metadata.json');training_ids={r['id'] for r in training['identification_training_rows']};train_products=set()
    for r in training['identification_training_rows']:
        c=r.get('component') or {}
        for cpe in c.get('cpes',[]):
            p=cpe.casefold().split(':')
            if len(p)>=5:train_products.add(tuple(p[2:5]))
    def model_hashes(row):
        return tuple((stage,a['generation']['model_packet_sha256']) for c in row.get('result',{}).get('components',[]) for stage in ('i1','i2','i3') for a in [c.get(stage,{}).get('agent') or {}] if (a.get('generation') or {}).get('model_packet_sha256'))
    for name in names:
        folder=BASE/name;rows={c['id']:read(folder/'predictions'/(c['id']+'.json')) for c in inputs[name]}
        product_sets[name]=set()
        for c in originals[name]:
            row=rows[c['id']]
            sig=row.get('signature',[{}])[0]
            if sig.get('identity',[None])[0]=='validated':product_sets[name].add(tuple(sig['identity'][1:]))
            key=name+'/'+c['split'];subset_products.setdefault(key,set());subset_semantics.setdefault(key,set()).add(semantics.get(Path(c['source']).stem))
            if sig.get('identity',[None])[0]=='validated':subset_products[key].add(tuple(sig['identity'][1:]))
            if name!=names[0] and c['split']=='test':
                confirmed['originals']+=1;confirmed['with_confirmed_cves']+=any(s=='match' for _,s in sig.get('cves',[]))
        if name==names[0]:continue
        for c in inputs[name]:
            if c['split']!='test':continue
            row=rows[c['id']]
            for comp in row.get('result',{}).get('components',[]):
                for stage in ('i1','i2','i3'):
                    a=comp.get(stage,{}).get('agent') or {};g=a.get('generation') or {}
                    if 'valid_alternatives' in g:alternatives[str(g['valid_alternatives'])]+=1
            if c['variant']=='original':continue
            original=next(x for x in inputs[name] if x['id']==c['base_id']+'__original')
            if json.dumps(c['sbom'])==json.dumps(original['sbom']):continue
            x=model_hashes(rows[original['id']]);y=model_hashes(row);counter=model_same[c['variant']]
            counter['pairs']+=1;counter['same_model_input']+=bool(x) and x==y;counter['no_model_input_hash']+=not bool(x) or not bool(y)
        if name==names[2]:
            c=next(c for c in originals[name] if c['id']=='vs1__original');v=next(x for x in inputs[name] if x['base_id']==c['base_id'] and x['variant']=='version_notation')
            sample3.append(dict(id=c['id'],cohort=name,original=c['sbom']['components'][0],variant=v['sbom']['components'][0],original_result=rows[c['id']]['signature'],variant_result=rows[v['id']]['signature']))
        elif name==names[1]:
            c=next(c for c in originals[name] if c['id']=='w1__original');v=next(x for x in inputs[name] if x['base_id']==c['base_id'] and x['variant']=='display_case')
            sample3.append(dict(id=c['id'],cohort=name,original=c['sbom']['components'][0],variant=v['sbom']['components'][0],original_result=rows[c['id']]['signature'],variant_result=rows[v['id']]['signature']))
    for i,a in enumerate(names):
        for b in names[i+1:]:
            pairs[a+' / '+b]=dict(shared_source_files=len(sources[a]&sources[b]),shared_exact_normalized_json=len(hashes[a]&hashes[b]),shared_validated_product_keys=len(product_sets[a]&product_sets[b]))
    train_overlap={name:dict(exact_training_case_ids=sorted({Path(c['source']).stem for c in rows}&training_ids),known_cpe_product_overlap=len(product_sets[name]&train_products)) for name,rows in originals.items()}
    n=BASE/'nemotron_evaluation';ninputs=read(n/'inputs.json');gold={r['id']:r['gold'] for r in read(n/'gold.json')};test=[c for c in ninputs if c['split']=='test'];dev=[c for c in ninputs if c['split']=='dev']
    def skeleton(c):return re.sub(r'Aster\d+','ENTITY',c['record']['sources'][0]['text'])
    shapes=Counter(skeleton(c) for c in test);samples=[]
    for id in ['f3-08__original','f6-08__original','f9-08__original']:
        c=next(c for c in test if c['id']==id)
        samples.append(dict(id=id,source=c['record']['sources'][0]['text'],gold=gold[id],baseline=read(n/'predictions/baseline'/(id+'.json'))['prediction'],tuned=read(n/'predictions/tune_r3'/(id+'.json'))['prediction']))
    raw_stats=Counter();request_keys=Counter();gold_keys=[];observed_cases=set()
    for p in (n/'native_cache/tune_r3/raw_calls').glob('*.json'):
        raw=read(p);body=raw['request'];u=json.loads(body['messages'][1]['content']);request_keys[','.join(sorted(u))]+=1
        def visit(x):
            if isinstance(x,dict):
                for k,v in x.items():
                    if k.casefold() in ('gold','gt','expected_atoms','correct_answer','labels'):gold_keys.append(dict(file=p.name,key=k))
                    visit(v)
            elif isinstance(x,list):
                for v in x:visit(v)
        visit(u);raw_stats['requests']+=1;raw_stats['cases']+=len(u.get('cases',{}));observed_cases.update(c['case_id'] for c in u.get('cases',{}).values())
    raw_stats['unique_cases']=len(observed_cases);raw_stats['test_cases_covered']=len(observed_cases&{c['id'] for c in test})
    mutation_tests=[]
    for kind,id in [('required_permission_negated','f9-08__original'),('nonrequirement_state_contradiction','f6-08__original'),('unrelated_relation_quote','f3-08__original'),('wrong_cvss_axis','f9-08__original')]:
        c=next(c for c in test if c['id']==id);case=dict(c,gold=gold[id]);pred=deepcopy(read(n/'predictions/tune_r3'/(id+'.json'))['prediction'])
        if kind=='required_permission_negated':
            pred['conditions'][0]['state']='assessed principal has no permission'
        elif kind=='nonrequirement_state_contradiction':
            for a in pred['conditions']:
                if a['necessity']=='nonrequirement':a['state']='required'
        elif kind=='unrelated_relation_quote':
            for s in pred['scenarios']:s['quote']='Affected component:'
        else:
            for a in pred['conditions']:a['axis']='UI'
        mutation_tests.append(dict(control=kind,id=id,mutated_prediction=pred,judge=N.judge(case,pred)))
    semantic_overlap=[]
    for i,a in enumerate(subset_semantics):
        for b in list(subset_semantics)[i+1:]:
            same=subset_semantics[a]&subset_semantics[b];products=subset_products[a]&subset_products[b]
            semantic_overlap.append(dict(a=a,b=b,semantic_hash_overlap=len(same-{None}),validated_product_overlap=[list(x) for x in sorted(products)]))
    with tarfile.open(BASE/'artifacts.tar.gz') as t:
        times={m.name:m.mtime for m in t.getmembers()};selected_time=times['nemotron_evaluation/selection.json']
        test_times=[v for k,v in times.items() if k.startswith('nemotron_evaluation/predictions/tune_r3/') and k.endswith('.json') and int(Path(k).stem.split('__')[0].split('-')[1])>=8]
    chronology=dict(selection_precedes_every_test_prediction=selected_time<min(test_times),seconds_to_first_test_prediction=min(test_times)-selected_time,test_predictions=len(test_times))
    report=dict(item3=dict(source_overlap=pairs,source_fold_counts=dict(Counter(folds.values())),source_fold_records_found=len(folds),selected_source_count=len(selected_sources),semantic_and_product_overlap=semantic_overlap,
        original_test_outcomes=dict(confirmed),same_llm_inputs_by_transformation={k:dict(v) for k,v in model_same.items()},model_valid_alternative_counts=dict(alternatives),training_overlap=train_overlap,
        training_manifest_verified=training['manifest_sha256']=='62f812642fbe00a92a8c310e738bd508da2613988a2842ac36ecb8370e401ba2',examples=sample3),
        item4=dict(dev_documents=len(dev),test_documents=len(test),unique_test_texts_after_entity_mask=len(shapes),template_multiplicities=sorted(shapes.values()),
            shared_exact_raw_source_texts=len({c['record']['sources'][0]['text'] for c in dev}&{c['record']['sources'][0]['text'] for c in test}),
            shared_families=sorted({c['family'] for c in dev}&{c['family'] for c in test}),raw_request_counts=dict(raw_stats),user_payload_keys=dict(request_keys),answer_key_hits=gold_keys,
            samples=samples,scorer_negative_controls=mutation_tests,scorer_unchanged=True,archive_chronology=chronology,
            current_oracle_sha256=hashlib.sha256(Path(N.__file__).read_bytes()).hexdigest(),recorded_oracle_sha256=read(n/'manifest.json')['oracle_sha256']),
        limits=['Exact file/ID non-overlap does not establish absence of product/semantic/pretraining overlap.','No independent expert labels or independent held-out generator were used.','Negative controls mutate copies only; original 100% scores and predictions were not changed.'])
    (out/'audit_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(item3={k:v for k,v in report['item3'].items() if k!='examples'},item4={k:v for k,v in report['item4'].items() if k not in ('samples','scorer_negative_controls')},negative_controls=[dict(control=x['control'],still_passes=x['judge']['case_correct']) for x in mutation_tests]),ensure_ascii=False))


if __name__=='__main__':main()
