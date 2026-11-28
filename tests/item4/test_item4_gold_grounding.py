import hashlib
import json
from copy import deepcopy

import pytest

from src.item4.decision.scoped_vex_review import digest
from src.item4.evaluation.ground_truth_evidence import GroundingIndex; from src.item4.evaluation.ground_truth_evidence import typed_question; from src.item4.evaluation.ground_truth_evidence import title_products
from src.item4.evaluation.source_context_simulation import source_spec; from src.item4.evaluation.source_context_simulation import gate
from tools.item4.build_item4_source_context_gold import boundary


def fixture(tmp_path,notes=None,names=None):
    names=names or ['Example PLC Alpha','Example PLC Beta']
    notes=notes or [
        dict(category='summary',title='Summary',text="Exploitation is possible if network access (port 102/TCP) is available and the CPs' configuration was stored on their corresponding CPUs."),
        dict(category='summary',title='For Example PLC Alpha',text='Potential exploitation requires access to the PROFIBUS network.')]
    branches=[dict(category='product_name',name=name,branches=[dict(category='product_version_range',name='vers:all/*',
        product=dict(product_id=f'p{i}',name=name))]) for i,name in enumerate(names)]
    obj=dict(document=dict(tracking=dict(id='icsa-test')),product_tree=dict(branches=branches),
        vulnerabilities=[dict(cve='CVE-2026-12345',notes=notes,product_status=dict(known_affected=[f'p{i}' for i in range(len(names))]))])
    p=tmp_path/'icsa/csaf/icsa-test.json';p.parent.mkdir(parents=True);raw=json.dumps(obj).encode();p.write_bytes(raw)
    sha=hashlib.sha256(raw).hexdigest()
    record=dict(cve='CVE-2026-12345',original_nvd_status='Modified',scenarios=[],
        products=[dict(key=f'icsa-test:p{i}',name=name,advisory_id='icsa-test',source_product_id=f'p{i}') for i,name in enumerate(names)],
        sources=[dict(id=f'icsa-test:v0:n{i}',url='https://example.test/advisory',text=n['text'],
            text_sha256=hashlib.sha256(n['text'].encode()).hexdigest(),document_sha256=sha,
            pointer=f'/vulnerabilities/0/notes/{i}/text',product_keys=[f'icsa-test:p{j}' for j in range(len(names))]) for i,n in enumerate(notes)])
    record['record_digest']=digest(record)
    return record


def test_product_specific_profibus_does_not_leak_to_other_product(tmp_path):
    original=fixture(tmp_path);before=deepcopy(original)
    r=GroundingIndex(tmp_path).prepare(original)
    assert original==before
    general,specific=r['sources']
    assert general['product_keys']==['icsa-test:p1']
    assert specific['product_keys']==['icsa-test:p0']
    p=next(s for s in r['scenarios'] if s['source_ref']['source_id']==specific['id'])
    spec=source_spec(r,p)
    assert spec['product']['name']=='Example PLC Alpha'
    assert len(spec['conditions'])==1
    assert 'PROFIBUS' in spec['conditions'][0]['question']
    assert '102' not in spec['conditions'][0]['question']
    assert spec['asset_type']['taxonomy_id']=='A0003'
    assert spec['simulation_assumptions']['unobserved_requirements_satisfied']==[]
    _,true_state,false_state,pivotal=boundary(spec)
    assert true_state[pivotal] and not false_state[pivotal]


def test_unmatched_exception_title_blocks_general_transfer(tmp_path):
    r=fixture(tmp_path,notes=[dict(category='summary',title='Summary',text='Exploitation requires network access.'),
        dict(category='summary',title='For Unknown Product',text='Exploitation requires physical access.')])
    r=GroundingIndex(tmp_path).prepare(r)
    assert all(not s['product_keys'] for s in r['sources'])


def test_parenthetical_version_qualifier_is_not_discarded():
    products={'p':{'name':'Example PLC (SKU-123)'}}
    assert title_products('For Example PLC (versions before 2.0)',products)==set()
    assert title_products('For Example PLC (SKU-123)',products)=={'p'}


def test_unknown_asset_role_does_not_borrow_router_estimate(tmp_path):
    r=fixture(tmp_path,names=['Unclassified Device Alpha','Unclassified Device Beta'])
    r=GroundingIndex(tmp_path).prepare(r)
    assert all(p['asset_type']['status']=='unknown' for p in r['products'])
    for scenario in r['scenarios']:
        with pytest.raises(ValueError):source_spec(r,scenario)


def test_question_contract_rejects_exploit_internal_and_nonrequirements():
    assert typed_question('the attacker obtains valid credentials','PLC') is None
    assert typed_question('a buffer pointer is configured','PLC') is None
    assert typed_question('authentication is not required','PLC') is None
    q=typed_question('network access (port 102/TCP) is available','PLC')
    assert q['parameters']=={'port':102,'protocol':'TCP'}
    assert q['answers']=={'yes':'true','no':'false','unknown':'unknown'}


def test_question_or_scope_tampering_is_rejected(tmp_path):
    r=GroundingIndex(tmp_path).prepare(fixture(tmp_path))
    scenario=next(s for s in r['scenarios'] if s['source_ref']['source_id'].endswith(':n1'))
    scenario['conditions'][0]['question_contract']['answers']['unknown']='false'
    with pytest.raises(ValueError,match='contract mismatch'):source_spec(r,scenario)


def test_cannot_treat_plc_engineering_tool_as_the_plc(tmp_path):
    r=GroundingIndex(tmp_path).prepare(fixture(tmp_path,names=['PLC Engineering Tool','Example PLC Beta']))
    assert r['products'][0]['asset_type']['status']=='unknown'


@pytest.mark.parametrize('name',[
    'Ethernet Module (For DirectLogic Programmable Logic Controllers)',
    'Modbus RTU - TCP Gateway',
    'Communication adapter for HMI',
    'PLC firmware',
    'Modicon M340 PLC modules',
])
def test_host_and_protocol_names_do_not_become_the_component_type(tmp_path,name):
    r=GroundingIndex(tmp_path).prepare(fixture(tmp_path,names=[name,'Example PLC Beta']))
    assert r['products'][0]['asset_type']['status']=='unknown'


@pytest.mark.parametrize('operator',['and','or'])
def test_source_boolean_connectives_preserve_truth_table(tmp_path,operator):
    from tools.item4.build_item4_source_context_gold import dnf,plant
    text="Exploitation is possible if network access (port 102/TCP) is available "+operator+" the CPs' configuration was stored on their corresponding CPUs."
    r=GroundingIndex(tmp_path).prepare(fixture(tmp_path,notes=[dict(category='summary',title='Summary',text=text)]))
    spec=source_spec(r,r['scenarios'][0]);terms=dnf(spec['expression'])
    for a,b in [(False,False),(False,True),(True,False),(True,True)]:
        assert plant(terms,{'c1':a,'c2':b})==((a and b) if operator=='and' else (a or b))


def test_mixed_ambiguous_operators_stay_unknown(tmp_path):
    text="Exploitation is possible if network access and debug mode is enabled or logging is disabled."
    r=GroundingIndex(tmp_path).prepare(fixture(tmp_path,notes=[dict(category='summary',title='Summary',text=text)]))
    assert r['scenarios']
    for scenario in r['scenarios']:
        with pytest.raises(ValueError):source_spec(r,scenario)


def test_negated_condition_keeps_positive_question_and_not_formula(tmp_path):
    from tools.item4.build_item4_source_context_gold import dnf,plant
    text='The vulnerability is exploitable unless debug mode is enabled.'
    r=GroundingIndex(tmp_path).prepare(fixture(tmp_path,notes=[dict(category='summary',title='Summary',text=text)]))
    spec=source_spec(r,r['scenarios'][0]);terms=dnf(spec['expression'])
    assert 'enabled' in spec['conditions'][0]['question']
    assert plant(terms,{'c1':False}) is True
    assert plant(terms,{'c1':True}) is False
