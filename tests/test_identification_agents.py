import json
from pathlib import Path
import sys

import pytest

from src.identification_tasks import parse_output, valid_output, identity_gold, version_gold
from evaluation.identification_metrics import score, score_cve_pairs
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from eval_identification_agents import build_pipeline_fixture, evaluate_tasks
from audit_identification_agent_data import audit
from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD, run


def test_invalid_output_does_not_disappear_as_abstention():
    rows=[{'id':'a','gold':{'normalized':'curl','status':'resolved'}},
          {'id':'b','gold':{'normalized':None,'status':'unresolved'}}]
    result=score('L2',rows,[None,{'normalized':None,'status':'unresolved'}])
    assert result['exact_accuracy']==0.5
    assert result['coverage']==0
    assert result['abstention_rate']==0.5
    assert result['invalid_outputs']==1
    assert result['decision_precision'] is None
    assert result['decision_recall']==0


def test_revision_loss_is_counted_as_error():
    rows=[{'id':'v','gold':{'normalized':'1.2.3-vendor2','status':'present'}}]
    result=score('L3',rows,[{'normalized':'1.2.3','status':'present'}])
    assert result['revision_prefix_truncations']==1
    assert result['decision_precision']==0


def test_cve_partial_oracle_duplicates_and_missing_positives():
    result=score_cve_pairs({('a','CVE-1'):True,('b','CVE-2'):False,('c','CVE-3'):True},
                           [('a','CVE-1'),('a','CVE-1'),('b','CVE-2'),('d','CVE-4')])
    assert (result['TP'],result['FP'],result['FN'],result['unlabelled_predictions'])==(1,1,1,1)
    assert result['precision']==0.5
    assert result['recall_on_labelled_positives']==0.5


def test_schema_and_strict_json():
    assert parse_output('```json\n{"status":"unresolved"}\n```') is None
    assert not valid_output('L3',{'normalized':'1.2','status':'unresolved'})
    assert not valid_output('L4',{'vendor':None,'product':'curl','status':'validated'})


def test_product_groups_disjoint_and_hashes_match():
    import hashlib
    data=Path(__file__).resolve().parents[1]/'data/identification_agents'
    manifest=json.loads((data/'manifest.json').read_text())
    for task in ('L2','L3','L4'):
        groups=[]
        for split in ('train','val','test'):
            path=data/f'{split}.jsonl'
            assert hashlib.sha256(path.read_bytes()).hexdigest()==manifest['splits'][split]['sha256']
            rows=[json.loads(l) for l in path.read_text(encoding='utf-8').splitlines()]
            groups.append({json.dumps(r['group']) for r in rows if r['task']==task})
        assert not groups[0]&groups[1]
        assert not groups[0]&groups[2]
        assert not groups[1]&groups[2]


def test_model_cannot_erase_vendor_revision_or_invent_identity(monkeypatch):
    monkeypatch.delenv('SLLM_BASE_URL',raising=False)
    cases,fixtures,gold,_=build_pipeline_fixture()
    def good(task,payload):
        if task=='L2':pred={'normalized':payload['name'],'status':'resolved'}
        elif task=='L3':pred=version_gold(payload['raw_version'])
        else:pred=identity_gold(payload)
        return {'prediction':pred}
    sbom={'bomFormat':'CycloneDX','components':[c['component'] for c in cases]}
    result=run(sbom,NVD(offline=True,fixtures=fixtures),agents=good)
    pairs={(r['component']['id'],c['cve_id']) for r in result['components'] for c in r['cves'] if c['match_status']=='match'}
    assert score_cve_pairs(gold,pairs)['precision']==1
    assert score_cve_pairs(gold,pairs)['recall_on_labelled_positives']==1
    def invented(task,payload):
        if task=='L4':return {'prediction':{'vendor':'invented','product':'curl','status':'validated'}}
        return good(task,payload)
    result=run(sbom,NVD(offline=True,fixtures=fixtures),agents=invented)
    assert all(r['validation']['status']=='unresolved' for r in result['components'])
    def truncated(task,payload):
        if task=='L3':return {'prediction':{'normalized':'7.10','status':'present'}}
        return good(task,payload)
    result=run(sbom,NVD(offline=True,fixtures=fixtures),agents=truncated)
    assert all(r['l3']['normalized'] is None for r in result['components'])
    assert all(r['validation']['version_status']=='unknown' for r in result['components'])
    assert not any(c['match_status']=='match' for r in result['components'] for c in r['cves'])


def test_independent_evaluator_keeps_same_inputs_for_base_and_tuned(tmp_path,monkeypatch):
    import src.identification_agents as runtime
    seen=[]
    def provider(mode):
        def call(task,payload):
            seen.append((mode,task,payload.copy()))
            return {'prediction':{'normalized':'curl','status':'resolved'},'raw':'test'}
        return call
    monkeypatch.setattr(runtime,'get_agents',provider)
    row={'id':'one','task':'L2','input':{'name':'libcurl'},'gold':{'normalized':'curl','status':'resolved'}}
    path=tmp_path/'labels.jsonl'; path.write_text(json.dumps(row)+'\n',encoding='utf-8')
    result=evaluate_tasks(path)
    assert result['tasks']['L2']['base']['scores']['exact_accuracy']==1
    assert seen[0][2]==seen[1][2]
    path.write_text((json.dumps(row)+'\n')*2,encoding='utf-8')
    with pytest.raises(ValueError,match='Duplicate'):evaluate_tasks(path)


def test_expanded_dataset_is_thousands_of_unique_inputs_and_preserves_holdouts():
    root=Path(__file__).resolve().parents[1]
    result=audit(root/'data/identification_agents_v2',root/'data/identification_agents')
    assert result['status']=='passed'
    for split in ('train','val','test'):
        for task in ('L2','L3','L4'):
            assert result['splits'][split][task]['unique_inputs']>=1000
    assert result['preserved_previous_rows']=={'train':1536,'val':192,'test':192}
    grid=json.loads((root/'data/identification_agents_v2/learning_curve_subsets.json').read_text())
    for task in ('L2','L3','L4'):
        for small,large in ((512,1024),(1024,2048),(2048,4096)):
            assert grid[str(small)][task]==grid[str(large)][task][:small]
