"""CVSS concept extraction contracts; synthetic responses are not accuracy gold."""
import pytest

from src.item4.analysis import exploitation_prerequisites as V
from src.item4.analysis import prerequisite_automation as AUTO
from src.item4.analysis import operational_evidence_catalogue as EVIDENCE
from src.item4.analysis import prerequisite_taxonomy as T
from src.item4.analysis import source_surface_review as REVIEW
from src.item4.web.asset_vex_questionnaire_api import condition_taxonomy
from tests.item4.test_empty_extraction_review import source, empty, recovered


def test_active_wire_has_four_primary_categories_and_retains_other():
    wire=T.bind_type_schema(EVIDENCE.bind(V.extraction_packet(source())))
    item=wire['schema']['properties']['prerequisites']['items']
    choices=item['properties']['condition_type']['enum']
    assert {choice.split(':')[0] for choice in choices}=={'AV','PR','UI','AT','OTHER'}
    assert 'OTHER:interface_available' in choices
    assert 'AV:interface_available' not in choices
    assert 'UI:input_processed' not in choices
    assert 'C2:interface_available' not in choices
    assert 'cvss_metrics' not in item['properties']
    for field in ('nonrequirements','excluded_facts'):
        assert 'category' in wire['schema']['properties'][field]['items']['required']
    api=condition_taxonomy()
    assert api['operating_conditions']==['AV','PR','UI','AT','IC']
    assert api['retained_categories']==['OTHER','AC']
    assert api['missing_source']=='unknown' and api['cvss_scoring'] is False


def test_silence_and_input_availability_do_not_imply_none_or_network_vector():
    draft=dict(prerequisites=[dict(id='http',predicate='interface_available',category='OTHER')])
    dimensions=T.source_dimensions(draft)
    assert all(row['status']=='unknown' and row['metric_value'] is None for row in dimensions.values())
    assert T.category(dict(predicate='authentication_required')) is None
    assert T.category(dict(predicate='network_reachable')) is None


def test_explicit_nonrequirement_and_unobservable_condition_remain_distinct():
    dimensions=T.source_dimensions(dict(prerequisites=[],
        nonrequirements=[dict(category='PR')],excluded_facts=[dict(category='AT')]))
    assert dimensions['PR']['status']=='stated'
    assert dimensions['PR']['condition_ids']==[]
    assert dimensions['PR']['nonrequirement_indices']==[0]
    assert dimensions['AT']['retained_fact_indices']==[0]
    assert dimensions['UI']['status']=='unknown'
    assert all(row['metric_value'] is None for row in dimensions.values())


def test_old_labels_are_readable_but_cannot_be_generated_or_relabelled():
    legacy=dict(id='old',category='C4',predicate='authentication_required')
    T.validate(legacy)
    assert T.category(legacy)=='C4'
    assert T.source_dimensions(dict(prerequisites=[legacy]))['PR']['status']=='unknown'
    with pytest.raises(ValueError,match='New extraction'):
        T.validate_generated(dict(prerequisites=[legacy]))
    with pytest.raises(ValueError,match='Unknown condition type'):
        T.resolve_type(dict(condition_type='C4:authentication_required'))


@pytest.mark.parametrize('reason',['impact','remediation','implementation_defect','internal_architecture'])
def test_nonconditions_cannot_establish_primary_categories(reason):
    with pytest.raises(ValueError,match='cannot establish'):
        T.validate_generated(dict(excluded_facts=[dict(category='PR',reason=reason)]))


def test_four_categories_run_through_real_extraction_review_and_logic():
    clauses=[
        'Exploitation requires network access to the diagnostic interface.',
        'The attacker must have permission to import projects.',
        'A legitimate user must open a project.',
        'Exploitation requires the application running in maintenance mode.',
        'Exploitation requires the HTTP request input to be available.',
    ]
    record=source(' '.join(clauses));calls=[]
    def model(system,wire,role):
        calls.append(role)
        assert T.EXTRACTION_RULES in system
        values=[
            ('AV:network_reachable','diagnostic interface','The assessed actor has network access to the diagnostic interface.','network_access','firewall_acl'),
            ('PR:privilege_required','import projects','The assessed actor has permission to import projects.','access_policy','access_control_record'),
            ('UI:user_performs_action','project','A legitimate user opens a project.','operating_workflow','operating_event_log'),
            ('AT:configuration_required','application operating mode','The application is running in maintenance mode.','operating_mode','configuration_export'),
            ('OTHER:interface_available','HTTP','The HTTP request input is available.','service_inventory','service_inventory'),
        ]
        atoms=[]
        for i,(kind,target,statement,observation,record_type) in enumerate(values):
            op=next(row['id'] for row in wire['operational_evidence'] if row['quote']==clauses[i])
            atoms.append(dict(id='a'+str(i),condition_type=kind,target=target,value='present',
                statement=statement,operator_observable=True,operator='eq',expected=True,
                extraction_confidence=.95,operational_evidence_id=op,source_refs=[dict(evidence_id='e1')],
                observation=dict(kind=observation,record_type=record_type,check='Inspect current scoped records for '+target+'.')))
        result=empty(record)
        result.update(prerequisites=atoms,unknowns=[],scenarios=[dict(id='p',product_keys=[],
            product_binding='unresolved',expression=dict(op='and',args=[dict(condition=a['id']) for a in atoms]),
            source_refs=[dict(evidence_id='e1')])])
        return dict(prediction=result,llm_used=True,model=dict(model='synthetic'))
    artifact=AUTO.extract(record,runner=model)
    assert calls==['exploitation-prerequisites',REVIEW.ROLE]
    assert artifact['coverage_review']['status']=='recovered'
    assert [p['category'] for p in artifact['draft']['prerequisites']]==['AV','PR','UI','AT','OTHER']
    assert all(artifact['source_dimensions'][key]['status']=='stated' for key in T.PRIMARY)
    assert artifact['source_dimensions']['IC']['status']=='unknown'
    assert artifact['draft']['scenarios'][0]['expression']['op']=='and'
    assert artifact['coverage_complete'] is False
    assert artifact['independent_semantic_accuracy_verified'] is False


def test_unobservable_at_and_ac_are_retained_without_operator_questions():
    text=('The attack requires winning a race condition. '
          'The attacker must bypass ASLR. No authentication is required.')
    record=source(text)
    def model(system,wire,role):
        result=empty(record)
        result.update(excluded_facts=[
            dict(category='AT',reason='unobservable_condition',statement='A race must be won.',source_refs=[dict(evidence_id='e1')]),
            dict(category='AC',reason='unobservable_condition',statement='ASLR must be bypassed.',source_refs=[dict(evidence_id='e1')])],
            nonrequirements=[dict(category='PR',statement='No authentication is required.',source_refs=[dict(evidence_id='e1')])])
        return dict(prediction=result,llm_used=True,model=dict(model='synthetic'))
    artifact=AUTO.extract(record,runner=model)
    assert artifact['draft']['prerequisites']==[] and artifact['draft']['scenarios']==[]
    assert [f['category'] for f in artifact['draft']['excluded_facts']]==['AT','AC']
    assert artifact['source_dimensions']['AT']['retained_fact_indices']==[0]
    assert artifact['source_dimensions']['PR']['nonrequirement_indices']==[0]
    assert sum('Retained source prerequisite' in u for u in artifact['draft']['unknowns'])==2
    compiled=V.compile_artifact(artifact,record)
    assert compiled['questions']==[] and compiled['gaps']


def test_old_checkpoint_requires_fresh_extraction_not_cvss_relabelling():
    record=source()
    draft=V.resolve_references(recovered(record),V.extraction_packet(record))
    artifact=dict(draft=draft,taxonomy_version='item4-condition-taxonomy/4',
                  source_record_sha256=V.digest(record),operational_evidence_version=EVIDENCE.VERSION)
    artifact['sha256']=V.digest(artifact)
    with pytest.raises(AUTO.CheckpointRejected,match='taxonomy changed'):
        AUTO.revalidate(record,artifact,runner=lambda *a,**k:pytest.fail('Do not infer a migration'))


def test_evidence_chain_preserves_source_categories_and_unknown_dimensions():
    from tests.item4.test_item4_asset_key_workflow import fixture_job
    job,record=fixture_job()
    from tests.item4.test_condition_pipeline_contract import install, assess
    install(job,None)
    result=assess(job,record)
    chain=result['decisions'][0]['evidence_chain']
    assert set(chain['source_dimensions'])==set(T.DIMENSIONS)
    assert all(d['status']=='unknown' for d in chain['source_dimensions'].values())
    assert chain['conditions'][0]['category']=='OTHER'
