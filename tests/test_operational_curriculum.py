import json
from pathlib import Path
from collections import Counter,defaultdict
import pytest
from src.operational_role_tasks import check,evaluate
from src import gpu_lease

ROOT=Path(__file__).resolve().parents[1]

def test_curriculum_targets_and_split_isolation():
    from src.item4_role_tasks import check as current_check
    folder=ROOT/'data/operational_curriculum_v3'
    for role in ['item4-questions','operation-assessment']:
        groups={};ids={}
        for split,n in [('train',800),('validation',100),('test',100)]:
            rows=[json.loads(line) for line in (folder/role/(split+'.jsonl')).read_text(encoding='utf-8').splitlines()]
            assert len(rows)==n
            groups[split]={r['group_id'] for r in rows};ids[split]={r['packet']['cve'] for r in rows}
            for row in rows:
                assert row['simulation'] and row['packet']['cve'].startswith('SIM-')
                assert all(current_check(role,row['packet'],row['target']).values())
        for a,b in [('train','validation'),('train','test'),('validation','test')]:
            assert not groups[a]&groups[b] and not ids[a]&ids[b]
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    assert manifest['human_gold'] is False and manifest['heldout_test_created'] is True
    assert manifest['test_loaded_for_training'] is False


def test_no_unknown_answer_clearance():
    p={'questions_and_answers':[{'id':'q1','answer':{'value':'unknown','evidence':''}}],'question_generation_valid':True}
    pred={'assessment':'likely_not_affected','explanation':'Unsupported clearance','answer_refs':['q1'],'missing_evidence':[]}
    assert check('operation-assessment',p,pred)['unknown_safety'] is False
    pred['assessment']='likely_cannot_determine';assert all(check('operation-assessment',p,pred).values())
    pred['answer_refs']=['another-case'];assert not check('operation-assessment',p,pred)['answer_refs_valid']

def test_live_lease_blocks_inference_and_stale_lease_does_not(monkeypatch):
    monkeypatch.setattr(gpu_lease,'read_json',lambda path:{'active':True,'pid':123})
    monkeypatch.setattr(gpu_lease,'alive',lambda pid:True)
    with pytest.raises(RuntimeError):gpu_lease.assert_inference_available()
    monkeypatch.setattr(gpu_lease,'alive',lambda pid:False)
    gpu_lease.assert_inference_available()

def test_repaired_real_inputs_are_grouped_and_still_unlabelled():
    folder=ROOT/'data/operational_review_benchmark_v2';rows=[]
    for split in ['train','validation','test']:
        part=[json.loads(l) for l in (folder/(split+'.annotation.jsonl')).read_text(encoding='utf-8').splitlines()]
        assert len(part)==(800 if split=='train' else 100)
        rows.extend(part)
    groups=defaultdict(set);advisories=defaultdict(set)
    for r in rows:
        assert r['review_status']=='pending' and r['required_conditions'] is None
        groups[r['group_id']].add(r['split'])
        for aid in r['advisory_ids']:advisories[aid].add(r['split'])
    assert all(len(s)==1 for s in groups.values()) and all(len(s)==1 for s in advisories.values())
    assert sum(bool(r['cvss_vector']) for r in rows)==961
    assert sum(bool(r['cwes']) for r in rows)==930
