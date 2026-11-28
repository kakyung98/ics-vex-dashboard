"""ICS extension admission, shared Boolean identity and question propagation."""
from copy import deepcopy
import pytest
from jsonschema import Draft202012Validator

from src.item4.analysis import exploitation_prerequisites as V
from src.item4.analysis import prerequisite_taxonomy as T
from src.item4.analysis import ics_operating_conditions as IC
from src.item4.analysis import asset_operating_question_generation as Q
from src.item4.analysis import condition_question_contract as CONTRACT
from src.item4.decision.condition_logic_evaluation import leaves
from tests.item4.test_empty_extraction_review import source, empty


def annotated(quote, kind='feature_configuration', predicate='feature_enabled'):
    return dict(predicate=predicate, operational_quote=quote,
                ics_context=[dict(kind=kind,quote=quote)])


def test_ic_absence_is_unknown_and_not_inferred_from_product_name():
    row=T.source_dimensions(dict(prerequisites=[dict(id='a',category='OTHER',
        target='PLC Modbus TCP',predicate='feature_enabled')]))['IC']
    assert row['status']=='unknown' and row['condition_ids']==[]
    assert row['metric_value'] is None


@pytest.mark.parametrize('quote',[
    'The HTTP input is enabled.', 'The PLC is an industrial controller.',
    'Users should disable Modbus TCP.', 'Avoid leaving the PLC in PROGRAM mode.',
])
def test_generic_surface_label_and_advice_do_not_supply_ic(quote):
    with pytest.raises(ValueError,match='ICS operating clause'):
        IC.validate(annotated(quote))


def test_literal_evidence_and_unique_kind_are_required():
    atom=annotated('Exploitation requires the Modbus TCP feature to be enabled.')
    IC.validate(atom)
    other=deepcopy(atom);other['ics_context'][0]['quote']='Modbus TCP is enabled'
    with pytest.raises(ValueError,match='literal'):IC.validate(other)
    other=deepcopy(atom);other['ics_context']*=2
    with pytest.raises(ValueError,match='duplicate'):IC.validate(other)


def test_generic_http_on_industrial_device_does_not_establish_ic_function():
    with pytest.raises(ValueError,match='industrial function clause'):
        IC.validate(annotated('Exploitation requires HTTP to be enabled on the PLC.'))


def test_two_operating_states_cannot_hide_inside_one_ic_atom():
    atom=annotated('If Modbus TCP is enabled and configured, the attack is possible.')
    atom['statement']='Modbus TCP is enabled and configured.'
    with pytest.raises(ValueError,match='separate atomic'):IC.validate(atom)


def test_engineering_workstation_alone_does_not_establish_control_link():
    with pytest.raises(ValueError,match='engineering link'):
        IC.validate(annotated('Exploitation requires a dedicated engineering workstation connection.',
                              'engineering_connection','configuration_required'))


def test_mode_and_engineering_link_require_distinct_source_clauses():
    IC.validate(annotated('Exploitation requires the PLC to be in PROGRAM mode.',
                          'operating_mode','configuration_required'))
    IC.validate(annotated('Exploitation requires a dedicated engineering connection to the controller.',
                          'engineering_connection','configuration_required'))
    with pytest.raises(ValueError,match='engineering link'):
        IC.validate(annotated('Exploitation requires a connection to the PLC.',
                              'engineering_connection','network_reachable'))


def test_impact_cannot_be_turned_into_ic():
    item=dict(statement='Modbus TCP is enabled.',reason='impact',
        source_refs=[dict(quote='Modbus TCP is enabled.')],
        ics_context=[dict(kind='feature_configuration',quote='Modbus TCP is enabled.')])
    with pytest.raises(ValueError,match='impacts'):IC.validate(item)


@pytest.mark.parametrize('primary_tagged',[True,False])
@pytest.mark.parametrize('aid',[None,'A0003','A0001'])
def test_shared_at_ic_atom_survives_real_pipeline_and_question_packet(primary_tagged,aid):
    text='Exploitation requires the Modbus TCP feature to be enabled.'
    record=source(text);calls=[]
    from src.item4.assets.question_record_context import extraction_context
    record['sources'][0].update(id='icsa-99-001-01:cve',url='https://example.invalid/icsa-99-001-01')
    record['asset_type_context']=extraction_context(dict(asset_classification=dict(
        status='classified' if aid else 'unresolved',asset_type_id=aid,component_ref='asset')),
        [dict(ref='asset')])
    def model(system,wire,role):
        assert IC.RULES in system
        assert wire['asset_type_context']==record['asset_type_context']
        assert wire['asset_type_context']['components'][0]['asset_type_id']==aid
        calls.append(role)
        item=wire['schema']['properties']['prerequisites']['items']
        assert 'ics_context' in item['required']
        assert 'IC' not in {c.split(':')[0] for c in item['properties']['condition_type']['enum']}
        op=next(r['id'] for r in wire['operational_evidence'] if r['quote']==text)
        atom=dict(id='p1',condition_type='AT:feature_enabled',target='Modbus TCP',value='enabled',
            statement='The Modbus TCP feature is enabled.',operator_observable=True,
            operational_evidence_id=op,source_refs=[dict(evidence_id='e1')],
            extraction_confidence=.95,operator='eq',expected=True,
            ics_context=[dict(kind='feature_configuration',quote=text)] if primary_tagged or wire.get('focus_ics_kind') else [],
            observation=dict(kind='configuration',record_type='configuration_export',
                check='Inspect the current applied Modbus TCP feature configuration.'))
        draft=empty(record);draft.update(prerequisites=[atom],unknowns=[],scenarios=[dict(
            id='path',product_keys=[],product_binding='unresolved',
            expression=dict(condition='p1'),source_refs=[dict(evidence_id='e1')])])
        Draft202012Validator(wire['schema']).validate(draft)
        return dict(prediction=draft,llm_used=True,model=dict(model='synthetic_contract_test'))
    artifact=V.extract(record,runner=model)
    assert len(calls)==(2 if primary_tagged else 3) and artifact['coverage_review']['status']=='recovered'
    draft=artifact['draft'];atom=draft['prerequisites'][0]
    assert len(draft['prerequisites'])==1
    assert leaves(draft['scenarios'][0]['expression'])=={'p1'}
    assert draft['prerequisites'][0]['source_refs'][0]['source_id']=='icsa-99-001-01:cve'
    assert artifact['source_dimensions']['AT']['condition_ids']==['p1']
    assert artifact['source_dimensions']['IC']['condition_ids']==['p1']
    question=dict(condition_id='p1',label=atom['statement'],scope_kind=atom['target'],
        predicate=atom['predicate'],category=atom['category'],ics_context=atom['ics_context'],
        extraction_confidence=.95,observation=atom['observation'],source_refs=atom['source_refs'],
        operational_quote=atom['operational_quote'])
    job=dict(components=[dict(ref='asset')],conditions=[dict(cve=record['cve'],
        sources=record['sources'],prerequisite=artifact)])
    packet=Q.packet(job,dict(cve=record['cve'],declared_ref='asset'),[question])
    assert packet['atoms']['p1']['ics_context']==atom['ics_context']
    assert packet['locked_scenarios']==draft['scenarios']


def test_mode_question_uses_current_state_guidance_without_new_logic():
    atom=annotated('Exploitation requires the controller to be in PROGRAM mode.',
                   'operating_mode','configuration_required')
    atom.update(category='OTHER',positive_fact='The controller is in PROGRAM mode.',
                observation=dict(record_type='configuration_export',kind='operating_mode',check='Inspect current mode.'))
    blueprint=CONTRACT.blueprint(atom)
    assert blueprint['question_type']=='operating_state'
    assert 'observation time' in blueprint['guidance']
    assert blueprint['answer_semantics']==dict(yes='true',no='false',unknown='unknown')


def test_uncovered_ic_cue_triggers_review_and_stays_unknown_without_invention():
    record=source('Exploitation requires the Modbus TCP feature to be enabled.')
    calls=[]
    def model(system,wire,role):
        calls.append(wire.get('focus_ics_kind'))
        return dict(prediction=empty(record),llm_used=True,model=dict(model='synthetic'))
    artifact=V.extract(record,runner=model)
    assert calls==[None,None,'feature_configuration']
    assert artifact['draft']['prerequisites']==[]
    assert artifact['source_dimensions']['IC']['status']=='unknown'
    assert artifact['coverage_review']['uncovered_hints'][0]['kind']=='ics_feature_configuration'
    assert any('ics_feature_configuration' in gap for gap in artifact['draft']['unknowns'])


def test_cue_in_other_cve_section_does_not_request_ic_review():
    text='Exploitation requires Modbus TCP to be enabled. An unrelated parser defect.'
    record=source(text);record['sources'][0]['cve_scope_span']=[text.index('An unrelated'),len(text)]
    assert IC.hints(record)==[]


@pytest.mark.parametrize('target',['HCI Modbus TCP','HCI Modbus TCP function'])
def test_real_rtu500_clause_admits_two_shared_ic_atoms_and_source_and(target):
    # Real source phrasing; this checks admission, not independent model accuracy.
    quote='If the HCI Modbus TCP is enabled and configured'
    text='A vulnerability exists in the HCI Modbus TCP function. '+quote+', an attacker could exploit the vulnerability by sending a specially crafted message to the RTU500.'
    record=source(text);record['cve']='CVE-2022-2081'
    def model(system,wire,role):
        op=next(r['id'] for r in wire['operational_evidence'] if r['quote']==text)
        atoms=[]
        for key,predicate,state in [('enabled','feature_enabled','enabled'),('configured','configuration_required','configured')]:
            atoms.append(dict(id=key,condition_type='OTHER:'+predicate,target=target,
                value=state,statement='The HCI Modbus TCP function is '+state+'.',
                operator_observable=True,operator='eq',expected=True,extraction_confidence=.95,
                operational_evidence_id=op,operational_quote=quote,
                source_refs=[dict(evidence_id='e1')],
                ics_context=[dict(kind='feature_configuration',quote=quote)],
                observation=dict(kind='configuration',record_type='configuration_export',
                    check='Inspect the current HCI Modbus TCP '+state+' setting.')))
        draft=empty(record);draft.update(prerequisites=atoms,unknowns=[],scenarios=[dict(
            id='rtu_path',product_keys=[],product_binding='unresolved',
            expression=dict(op='and',args=[dict(condition='enabled'),dict(condition='configured')]),
            source_refs=[dict(evidence_id='e1')])])
        Draft202012Validator(wire['schema']).validate(draft)
        return dict(prediction=draft,llm_used=True,model=dict(model='real_clause_contract_fixture'))
    artifact=V.extract(record,runner=model)
    assert artifact['coverage_review']['status']=='recovered'
    assert artifact['source_dimensions']['IC']['condition_ids']==['enabled','configured']
    assert artifact['source_dimensions']['AT']['status']=='unknown'
    assert artifact['draft']['scenarios'][0]['expression']['op']=='and'


def test_descriptor_ellipsis_requires_full_name_in_same_parent_quote():
    quote='If Modbus TCP is enabled, the attack is possible.'
    atom=annotated(quote);atom.update(target='Modbus TCP function',source_refs=[dict(quote=quote)])
    assert IC.polarity_target(atom)=='Modbus TCP function'
    atom['source_refs'][0]['quote']='The Modbus TCP function is affected. '+quote
    assert IC.polarity_target(atom)=='Modbus TCP'
    atom['ics_context']=[]
    assert IC.polarity_target(atom)=='Modbus TCP function'
