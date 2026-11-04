import json
import hashlib
from pathlib import Path
from src.item4_role_tasks import check, evaluate

ROOT=Path(__file__).resolve().parents[1]


def read(role,split):
    return [json.loads(line) for line in (ROOT/'data/operational_curriculum_v3'/role/(split+'.jsonl')).read_text(encoding='utf-8').splitlines()]


def test_new_curriculum_targets_and_split_provenance():
    manifest=json.loads((ROOT/'data/operational_curriculum_v3/manifest.json').read_text(encoding='utf-8'))
    assert manifest['human_gold'] is False and manifest['deployment_approved'] is False
    for role in ['item4-questions','operation-assessment']:
        groups=[];ids=[]
        for split,count in [('train',800),('validation',100),('test',100)]:
            rows=read(role,split);assert len(rows)==count
            groups.append({r['group_id'] for r in rows});ids.append({r['packet']['cve'] for r in rows})
            for row in rows:
                assert all(check(role,row['packet'],row['target']).values()),row['id']
                assert row['simulation'] and row['packet']['cve'].startswith('SIM-')
        assert not groups[0]&groups[1] and not groups[0]&groups[2] and not groups[1]&groups[2]
        assert not ids[0]&ids[1] and not ids[0]&ids[2]
    # Real #4 gold remains absent; synthetic preparation never rewrites it.
    real=json.loads((ROOT/'data/item4_v3/manifest.json').read_text(encoding='utf-8'))
    assert real['independent_gold_count']==0
    for name,digest in real['files'].items():
        assert hashlib.sha256((ROOT/'data/item4_v3'/name).read_bytes()).hexdigest()==digest


def test_empty_unknown_and_invented_questions_are_not_validated():
    q=read('item4-questions','validation')[0]
    metrics,records=evaluate('item4-questions',[q],['[]'])
    assert metrics['contract_valid']==0
    pred=json.loads(json.dumps(q['target']));pred['questions'][0]['evidence_ids']=['invented']
    assert not check('item4-questions',q['packet'],pred)['contract_valid']
    a=next(r for r in read('operation-assessment','validation') if r['scenario']==5)
    pred={**a['target'],'assessment':'likely_affected'}
    checked=check('operation-assessment',a['packet'],pred)
    assert not checked['unknown_answer_safety'] and not checked['unknown_safety']
    a=next(r for r in read('operation-assessment','validation') if r['scenario']==7)
    assert not check('operation-assessment',a['packet'],pred)['unknown_version_safety']
