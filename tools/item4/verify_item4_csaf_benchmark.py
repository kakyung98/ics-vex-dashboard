"""Audit full population, blind separation, frozen hashes and every CSAF draft."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter
import argparse
import json
from pathlib import Path
import jsonschema

from src.item4.evaluation.synthetic_vex_benchmark import VARIANTS; from src.item4.evaluation.synthetic_vex_benchmark import JUSTIFICATIONS; from src.item4.evaluation.synthetic_vex_benchmark import scenario
from tools.item4.build_item4_csaf_benchmark import DEFAULT, ROOT, sha, write


def audit(data,output):
    manifest=json.loads((data/'manifest.json').read_bytes())
    for name,expected in manifest['artifacts'].items():
        if sha(data/name)!=expected:raise ValueError('Frozen artifact changed: '+name)
    split=json.loads((data/'advisory_split.json').read_bytes())
    assert len(split['train'])==2717 and len(split['evaluation'])==1164
    assert not set(split['train']) & set(split['evaluation'])
    pop=json.loads((data/'population_index.json').read_bytes())
    assert len(pop)==len({r['cve'] for r in pop})==12418
    expected={key for r in pop for key in r['case_ids']}
    assert len(expected)==86926 and all(len(r['case_ids'])==7 for r in pop)
    candidate_ids=set();variants=Counter();counts=Counter()
    for r in map(json.loads,(data/'candidate_labels.jsonl').open(encoding='utf-8')):
        assert r['id'] not in candidate_ids
        candidate_ids.add(r['id']);variants[r['variant']]+=1
        oracle=scenario(r['variant'],r['source_relationship_available'])
        assert r['candidate_actual_affected'] is oracle['candidate_actual_affected']
        assert r['candidate_justifications']==oracle['candidate_justifications']
        assert r['expert_validated'] is False
    assert candidate_ids==expected and set(variants)==set(VARIANTS)
    assert set(variants.values())=={12418}
    for name in ['inputs.jsonl','gold.jsonl']:
        ids=set()
        for r in map(json.loads,(data/name).open(encoding='utf-8')):
            assert r['id'] not in ids;ids.add(r['id'])
            if name=='gold.jsonl':
                assert r['actual_affected'] is None and not r['expert_validated']
            else:
                assert not {'variant','candidate_actual_affected','candidate_status','fold','intended_justification','latent_state'} & r.keys()
                assert (data/r['sbom_file']).is_file()
        assert ids==expected
    training=list(map(json.loads,(data/'training/corpus.jsonl').open(encoding='utf-8')))
    assert {r['id'] for r in training}==set(split['train'])
    assert all(set(r)=={'id','text','source_sha256','source_url','label_supervision'} and
               r['label_supervision'] is False for r in training)
    packet_ids=set()
    for r in map(json.loads,(data/'review/packets.jsonl').open(encoding='utf-8')):
        assert r['id'] not in packet_ids;packet_ids.add(r['id'])
        assert r['advisory_id'] in split['evaluation']
        assert not {'variant','candidate_status','candidate_actual_affected','intended_justification'} & r.keys()
    evaluation_ids={key for r in pop if r['fold']=='evaluation' for key in r['case_ids']}
    assert packet_ids==evaluation_ids
    for name in ['rater_a','rater_b','adjudication']:
        rows=list(map(json.loads,(data/'review'/(name+'.jsonl')).open(encoding='utf-8')))
        assert {r['id'] for r in rows}==packet_ids
        assert len(rows)==len(packet_ids)
        assert all(r['reviewer_id'] is None and r['status'] is None for r in rows)
    schema=json.loads((ROOT/'data/standards/csaf-2.0-schema.json').read_bytes())
    validator=jsonschema.Draft7Validator(schema)
    ids=set()
    for i,row in enumerate(map(json.loads,(data/'candidate_csaf_vex.jsonl').open(encoding='utf-8')),1):
        assert row['id'] not in ids;ids.add(row['id'])
        doc=row['document'];validator.validate(doc)
        v=doc['vulnerabilities'][0]
        pids={p['product_id'] for p in doc['product_tree']['full_product_names']}
        assert doc['document']['tracking']['status']=='draft'
        for refs in v['product_status'].values():assert set(refs)<=pids
        for flag in v.get('flags',[]):
            assert flag['label'] in JUSTIFICATIONS
            assert set(flag['product_ids'])<=set(v['product_status']['known_not_affected'])
        counts['csaf_schema_valid']+=1
        if i%10000==0:print('CSAF validated',i,flush=True)
    assert ids==expected
    report=dict(status='passed',population_cves=12418,scenarios=86926,
        train_icsa=2717,evaluation_icsa=1164,expert_cases=len(packet_ids),
        checked_hashes=len(manifest['artifacts']),variants=dict(variants),
        csaf_schema_valid=counts['csaf_schema_valid'],csaf_schema_sha256=sha(ROOT/'data/standards/csaf-2.0-schema.json'),
        blind_inputs_and_blank_gold_verified=True,expert_review_complete=False,
        interpretation='Data integrity, schema and separation audit only; no independent semantic accuracy claim.')
    write(output,report);print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data',type=Path,default=DEFAULT)
    p.add_argument('--output',type=Path,default=ROOT/'results/item4_csaf_v2_20261120/data_audit.json')
    a=p.parse_args();audit(a.data,a.output)
