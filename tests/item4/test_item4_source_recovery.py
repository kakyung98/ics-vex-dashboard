from copy import deepcopy
import hashlib
import json
import sqlite3
import pytest

from src.item4.decision.scoped_vex_review import digest
from src.research.item4_source_recovery import recover, unresolved_evidence, observable
from src.item4.evaluation.source_context_simulation import model_packet; from src.item4.evaluation.source_context_simulation import source_spec
from tools.item4.build_item4_source_context_gold import boundary
from tools.item4 import evaluate_item4_source_context as evaluation


def record(text, status='Modified'):
    value = dict(cve='CVE-2026-12345', original_nvd_status=status, scenarios=[],
        products=[dict(key='product', name='Example controller')],
        sources=[dict(id='nvd:CVE-2026-12345', url='https://example.test/advisory', text=text,
            text_sha256=hashlib.sha256(text.encode()).hexdigest(), product_keys=['product'])])
    value['record_digest'] = digest(value)
    return value


def test_access_after_consequence_is_recovered_without_changing_source():
    original = record('The service allows remote attackers to execute arbitrary code.')
    before = deepcopy(original)
    derived = recover(original)
    assert original == before
    assert derived['sources'] == original['sources']
    paths = [source_spec(derived, s) for s in derived['scenarios'] if s['id'].startswith('recovery:')]
    assert paths
    _, true_state, false_state, pivotal = boundary(paths[0])
    assert true_state[pivotal] != false_state[pivotal]
    assert derived['original_record_digest'] == original['record_digest']


def test_local_users_are_not_lost_by_attacker_only_descriptor():
    derived = recover(record('The utility allows local users to modify arbitrary files.'))
    paths = [source_spec(derived, s) for s in derived['scenarios'] if s['id'].startswith('recovery:')]
    assert any(c['kind'] == 'local_access' for s in paths for c in s['conditions'])


def test_descriptor_does_not_discard_explicit_configuration_requirement():
    derived = recover(record('When debug mode is enabled, the service allows remote attackers to execute code.'))
    assert not any(s['id'].startswith('recovery:') for s in derived['scenarios'])


def test_rejected_identity_is_not_given_an_invented_path():
    original = record('The service allows remote attackers to execute code.', 'Rejected')
    assert recover(original) == original


def test_observability_is_not_rejected_just_because_actor_is_mentioned():
    assert observable('The attacker has network access')
    assert not observable('The attacker must obtain valid credentials and network access')
    assert not observable('A heap pointer is configured incorrectly')
    assert not observable('An authenticated attacker has network access')


def test_authenticated_user_qualification_is_a_separate_unobserved_requirement():
    derived=recover(record('The service allows remote authenticated users to execute code.'))
    scenario=next(s for s in derived['scenarios'] if s['id'].startswith('recovery:'))
    spec=source_spec(derived,scenario)
    authentication=next(c for c in spec['conditions'] if c['kind']=='attacker_authentication')
    assert authentication['operator_observable'] is False
    assert authentication['id'] in spec['simulation_assumptions']['unobserved_requirements_satisfied']
    assert any(c['operator_observable'] and c['kind']=='network_access' for c in spec['conditions'])


def test_unknown_path_still_sends_original_source_to_model():
    original = record('An unspecified vulnerability exists in the product.')
    evidence = unresolved_evidence(original)
    packet = dict(mode='source_conditioned_simulation', synthetic=True, cve=original['cve'], spec=None,
        source_evidence=evidence, unknown_source_reasons=['No admissible source path'])
    projected = model_packet(packet)
    assert projected['source_evidence'][0]['text'] == original['sources'][0]['text']
    assert projected['source_path'] is None
    assert 'actual_affected' not in projected


def test_unknown_impact_is_not_scored_as_a_known_negative():
    labels={'case':dict(cve='CVE-2026-12345',actual_affected=None,expected_code='U')}
    result=evaluation.metric([dict(id='case',simulation_status='affected')],labels)
    assert result['FP']==0 and result['unjudged_positive']==1
    assert result['precision'] is None and result['precision_lower_bound']==0


def test_report_refuses_ledger_only_unknown_without_model_call(tmp_path,monkeypatch):
    for fold in ('train','evaluation'):
        directory=tmp_path/fold;directory.mkdir()
        labels=[] if fold=='train' else [dict(id='case',cve='CVE-2026-12345',actual_affected=None,expected_code='U')]
        (directory/'labels.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in labels),encoding='utf-8')
        (directory/'inputs.jsonl').write_text('' if fold=='train' else json.dumps(dict(id='case'))+'\n',encoding='utf-8')
    monkeypatch.setattr(evaluation,'DATA',tmp_path)
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE predictions(id TEXT,prediction TEXT)')
        db.execute('INSERT INTO predictions VALUES (?,?)',('case',json.dumps(dict(raw=dict(llm_used=False)))))
        with pytest.raises(ValueError,match='actual model inference'):
            evaluation.report(db)
