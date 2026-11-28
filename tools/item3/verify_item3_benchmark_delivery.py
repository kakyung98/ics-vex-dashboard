"""Independently audit the frozen delivery and re-count every evaluation CVE edge."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from collections import Counter
import argparse,hashlib,json,sqlite3,time,zlib

ROOT=Path(__file__).resolve().parents[2]
DEFAULT=ROOT/'results/item3_benchmark_validation_h200_20261119'


from src.common.paths import source_path

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()


def verify(out):
    report=json.loads((out/'report.json').read_bytes())
    assert report['complete']
    artifacts=json.loads((out/'artifacts_manifest.json').read_bytes())
    assert all(sha(out/name)==expected for name,expected in artifacts.items())
    signature=json.loads((out/'run_signature.json').read_bytes())
    drift=[]
    metadata_binding='''        # The pinned bytes above were verified at the resolved snapshot. Bind
        # in-memory adapter metadata to that actual path after cache relocation.
        for adapter_config in self.model.peft_config.values():
            adapter_config.base_model_name_or_path=str(base_folder.resolve())
'''
    for name,expected in signature['code'].items():
        frozen=out/'source_snapshot/src'/name;current=source_path(name, root=ROOT)
        assert sha(frozen)==expected
        if sha(current)!=expected:
            assert name=='precision_role_runtime.py'
            assert current.read_text(encoding='utf-8').replace(metadata_binding,'')==frozen.read_text(encoding='utf-8')
            drift.append({'file':name,'change':'In-memory adapter base path metadata binding only; loaded weights and scoring forward pass unchanged.'})
    assert all(sha(ROOT/name)==expected for name,expected in signature['data'].items())
    assert sha(ROOT/'models/precision_roles_qwen25_14b_v1/adapter_model.safetensors')==signature['adapter']
    transferred=json.loads((out/'transfer_manifest.json').read_bytes())
    assert sha(ROOT/'tools/item3/item3_v6_metrics.py')==transferred['tools/item3/item3_v6_metrics.py']
    original=(out/'source_snapshot/run_item3_benchmark_validation.py').read_bytes()
    bounded=(out/'tools/summarize_item3_benchmark_bounded.py').read_bytes()
    assert bounded==original.replace(b'@lru_cache(maxsize=128)',b'@lru_cache(maxsize=2)')
    assert (ROOT/'tools/item3/run_item3_benchmark_validation.py').read_bytes() in (original,bounded)
    db=sqlite3.connect('file:'+str((out/'validation.sqlite3').resolve())+'?mode=ro',uri=True)
    assert db.execute('pragma quick_check').fetchone()[0]=='ok'
    n,a,r=db.execute('select count(*),count(agents),count(rules) from units').fetchone()
    assert n==a==r==report['units']
    checked=Counter()
    for table in ('inputs','units'):
        for key,blob in db.execute('select sha256,body from '+table):
            assert hashlib.sha256(zlib.decompress(blob)).hexdigest()==key
            checked[table]+=1
    labels={identity:json.loads(value) for identity,value in db.execute('select id,label from gold')}
    assert len(labels)==18608
    cases={identity:(key,family,gold) for identity,key,family,gold in db.execute('select * from cases')}
    empty_cases={identity for identity, in db.execute('select c.id from cases c join inputs i on i.sha256=c.input_sha256 where i.components<=0')}
    universe=set()
    for line in (ROOT/'data/item3_identification_sources_v11/cves.jsonl').open(encoding='utf-8'):
        universe.add(json.loads(line)['id'])
    for gold in labels.values():universe.update(gold['expected_cves']);universe.update(gold['unknown_cves'])
    counts={mode:Counter() for mode in ('agents','rules')};errors={mode:set() for mode in counts}
    seen=set();gold_seen=set();components=Counter();retrieved=Counter();positive_edges=0
    for line in (out/'case_results.jsonl').open(encoding='utf-8'):
        item=json.loads(line);identity=item['file'];assert identity not in seen;seen.add(identity)
        key,family,gold_id=cases[identity]
        assert (item['input_sha256'],item['benchmark_folder'],item['gold_id'])==(key,family,gold_id)
        if gold_id:
            assert gold_id not in gold_seen;gold_seen.add(gold_id)
            gold=labels[gold_id];positive_edges+=len(set(gold['expected_cves']))
        for mode,row in item['modes'].items():
            components[mode]+=row['components'];assert not row['agent_errors']
            if row['error']:errors[mode].add(identity)
            if not gold_id:continue
            output=set(row['confirmed_cves']);expected=set(gold['expected_cves']);unknown=set(gold['unknown_cves'])
            score={'TP':len(output&expected),'FP':len((output&universe)-expected-unknown),
                   'FN':len(expected-output),'unjudged':len(output&unknown&universe),'out_of_scope':len(output-universe)}
            assert score==row['gold_score']['mapping'];counts[mode].update(score)
            retrieved[mode]+=len((output|set(row['candidate_cves']))&expected)
    assert seen==set(cases);assert gold_seen==set(labels)
    assert db.execute('select count(*) from case_results').fetchone()[0]==len(seen)
    assert all(errors[mode]==empty_cases for mode in errors)
    assert all(components[mode]==report['inventory']['total_component_occurrences'] for mode in components)
    for mode,c in counts.items():
        observed=report['gold_evaluation'][mode]
        assert observed['completed_BOMs']==18608 and observed['execution_errors']==0
        assert all(c[k]==observed['all_BOMs_latent_asset_mapping_metrics'][k] for k in ('TP','FP','FN','unjudged','out_of_scope'))
    role_cases=Counter();model_backed_cases=0;gold_rows=0
    for blob, in db.execute('select u.agents from cases c join input_units i on i.input_sha256=c.input_sha256 join units u on u.sha256=i.unit_sha256 where c.gold_id is not null'):
        value=json.loads(zlib.decompress(blob));rows=value['components'];assert len(rows)==1;gold_rows+=1
        used={role:bool((rows[0].get(role,{}).get('agent') or {}).get('llm_used')) for role in ('i1','i2','i3')}
        model_backed_cases+=any(used.values());role_cases.update({k:int(v) for k,v in used.items()})
    assert gold_rows==18608 and model_backed_cases>0
    packets=sqlite3.connect('file:'+str((out/'packet_cache.sqlite3').resolve())+'?mode=ro',uri=True)
    assert packets.execute('pragma quick_check').fetchone()[0]=='ok'
    requests=Counter();cached_packets=0
    for task,blob in packets.execute('select task,response from packets'):
        response=json.loads(zlib.decompress(blob));cached_packets+=1
        requests[task]+=int(bool(response.get('llm_used')) and not (response.get('generation') or {}).get('model_input_cache_hit',False))
    progress=json.loads((out/'progress.json').read_bytes())['packet_cache']
    assert sum(requests.values())==progress['actual_llm_requests']>0
    assert cached_packets==progress['cached_packets']
    value={'verified_at':time.time(),'passed':True,'delivery_artifact_hashes_checked':len(artifacts),
           'frozen_classification_code_data_adapter_verified':True,'current_workspace_code_drift':drift,
           'aggregation_change':'Only cache capacity 128 to 2; scoring arithmetic and predictions unchanged.',
           'canonical_input_hashes_checked':dict(checked),'case_occurrences':len(seen),'gold_cases':len(gold_seen),
           'components_per_mode':dict(components),'empty_source_occurrences_per_mode':len(empty_cases),
           'independent_gold_mapping_counts':{m:dict(c) for m,c in counts.items()},
           'known_positive_retrieval_recall_including_unconfirmed_candidates':{m:retrieved[m]/positive_edges for m in retrieved},
           'formal_evaluation_model_backed_cases':model_backed_cases,
           'formal_evaluation_model_backed_decision_occurrences_by_role':dict(role_cases),
           'all_benchmark_distinct_gpu_requests':sum(requests.values()),
           'all_benchmark_distinct_gpu_requests_by_role':dict(requests),
           'interpretation':'Model-backed decision occurrence counts include cache reuse; GPU request counts exclude projected model-input cache hits. Primary precision scores confirmed mappings only. Candidate-inclusive recall is a separate retrieval diagnostic.'}
    (out/'independent_validation.json').write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(value,ensure_ascii=False),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=DEFAULT)
    verify(p.parse_args().output.resolve())
