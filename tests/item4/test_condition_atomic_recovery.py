"""Generic omission/recovery boundaries; synthetic cases are not accuracy gold."""
from copy import deepcopy
from unittest.mock import patch
import pytest
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.analysis import prerequisite_automation as P
from src.item4.analysis import operational_evidence_catalogue as E
from src.item4.analysis import condition_normalization as N
from src.item4.analysis import source_surface_review as R
from src.item4.analysis import condition_automation as AUTO
from tests.item4.test_empty_extraction_review import source,empty,recovered


def packet(record):return V.TAXONOMY.bind_type_schema(E.bind(V.extraction_packet(record)))


def test_bad_guessed_protocol_does_not_discard_independently_valid_input():
    record=source('A GET alpha.cgi request can cause a buffer overflow.')
    draft=recovered(record);atom=draft['prerequisites'][0]
    atom.update(target='alpha.cgi',statement='alpha.cgi is available.',operational_quote='A GET alpha.cgi request')
    bad=deepcopy(atom);bad.update(id='guessed',condition_id='guessed',target='HTTPS',statement='HTTPS is available.')
    draft['prerequisites'].append(bad)
    result,rejected,notes=P.recover_atoms(draft,packet(record),record,V)
    assert [p['target'] for p in result['prerequisites']]==['alpha.cgi']
    assert rejected and result['unknowns'] and result['scenarios']==[]
    assert result['prerequisites'][0]['extraction_confidence']==.95
    assert result['prerequisites'][0]['observation']['record_type']=='service_inventory'


def test_atomic_recovery_runs_after_bounded_review_exhaustion():
    record=source('A GET alpha.cgi request can cause a buffer overflow.')
    draft=recovered(record);atom=draft['prerequisites'][0]
    atom.update(target='alpha.cgi',statement='alpha.cgi is available.',operational_quote='A GET alpha.cgi request')
    bad=deepcopy(atom);bad.update(id='bad',condition_id='bad',target='HTTPS',statement='HTTPS is available.')
    draft['prerequisites'].append(bad)
    def runner(system,wire,role):
        return dict(prediction=deepcopy(empty(record) if role=='exploitation-prerequisites' else draft),
                    llm_used=True,model=dict(model='synthetic'))
    artifact=P.extract(record,runner=runner)
    assert artifact['coverage_review']['status']=='failed'
    assert [p['target'] for p in artifact['draft']['prerequisites']]==['alpha.cgi']
    assert artifact['draft']['scenarios']==[] and artifact['draft']['unknowns']
    assert len([e for e in artifact['execution_history'] if e['stage']=='condition_review'])==3


def test_static_key_image_does_not_require_running_interface():
    record=source('The WebUI private keys and passwords can be extracted from the firmware image.')
    draft=recovered(record);atom=draft['prerequisites'][0]
    atom.update(target='WebUI',statement='WebUI is available.',operational_quote=record['sources'][0]['text'])
    result,rejected,_=P.recover_atoms(draft,packet(record),record,V)
    assert not result['prerequisites'] and 'static component' in rejected[0]['reason']


def test_quote_alignment_only_uses_already_cited_exact_source_paragraphs():
    record=source('The Web interface login request returns configuration. Successful login is not required.')
    draft=recovered(record);atom=draft['prerequisites'][0]
    atom.update(target='Web interface',statement='Web interface is available for exploitation.',
                operational_quote='Successful login is not required.')
    result,rejected,notes=P.recover_atoms(draft,packet(record),record,V)
    assert not rejected and result['prerequisites'][0]['operational_quote']=='The Web interface login request returns configuration.'
    assert result['prerequisites'][0]['statement']=='The Web interface input is available.'
    assert notes


def test_qualified_input_and_permission_scope_are_never_dropped():
    atom=dict(predicate='interface_available',target='WebUI',statement='WebUI is available for exploitation only from the trusted subnet.')
    normalized,_=N.normalize_atom(atom)
    assert normalized['statement']==atom['statement']
    text='An attacker with permission to transfer files to/from the controller is required to exploit the vulnerability.'
    atom=dict(predicate='privilege_required',statement=text,source_refs=[dict(quote=text)])
    normalized,_=N.normalize_atom(atom)
    assert normalized['statement']=='The assessed principal has permission to transfer files to/from the controller.'
    assert atom['statement']==text


@pytest.mark.parametrize('qualifier',['only from the trusted subnet','in version 4','with an administrator session','without credentials'])
def test_rendering_does_not_erase_additional_source_scope(qualifier):
    statement='WebUI is available for exploitation '+qualifier+'.'
    atom=dict(predicate='interface_available',target='WebUI',statement=statement)
    assert N.normalize_atom(atom)[0]['statement']==statement


def test_typed_coverage_cannot_be_satisfied_by_generic_webui_atom():
    record=source('The WebUI allows plaintext transmission (HTTP). A user follows a malicious link in the WebUI.')
    hints=R.uncovered_hints(record,dict(prerequisites=[dict(predicate='interface_available',target='WebUI')]))
    assert {h['kind'] for h in hints}=={'http_transport','user_performs_action'}
    assert not R.coverage_hints(source('The WebUI contains a hardcoded key in a firmware image.'))


def test_source_restriction_failure_does_not_lock_invalid_atoms_as_evidence_repair():
    failure=AUTO.failure(ValueError('Operational prerequisite rejected: the source clause does not explicitly support an operating restriction or trigger'))
    assert failure['stage']=='condition'


def test_revalidation_rejects_tampered_artifact_before_reusing_scores():
    record=source()
    with pytest.raises(ValueError,match='integrity'):
        P.revalidate(record,dict(sha256='tampered',draft={}))


def test_intact_source_relations_are_preserved_without_new_inference():
    record=source();candidate=recovered(record)
    def runner(system,wire,role):
        return dict(prediction=deepcopy(candidate),llm_used=True,model=dict(model='synthetic'))
    artifact=P.extract(record,runner=runner)
    with patch.object(V.L,'generate',side_effect=AssertionError('No new inference needed')):
        updated=P.revalidate(record,artifact)
    assert updated['draft']['scenarios']==artifact['draft']['scenarios']
    assert updated['revalidation']['intact_candidate_validated'] is True
    assert updated['revalidation']['llm_used'] is False
    assert updated['draft']['prerequisites'][0]['extraction_confidence']==.95


def test_explicit_user_action_without_modal_requires_is_allowed():
    record=source('A user follows a malicious link in the WebUI.')
    atom=dict(predicate='user_performs_action',operator_observable=True,operator='eq',expected=True,
        target='link',statement='A user follows a malicious link in the WebUI.',
        operational_quote=record['sources'][0]['text'],source_refs=[dict(source_id='s',quote=record['sources'][0]['text'])],
        observation=dict(kind='operating_workflow',record_type='maintenance_log',check='Inspect available browser or operator event records; use Unknown if not verified.'))
    V.OP.validate_condition(atom,{'s':record['sources'][0]})
    atom['operational_quote']='The attacker follows a link.'
    atom['source_refs']=[dict(source_id='s',quote=atom['operational_quote'])]
    with pytest.raises(ValueError):V.OP.validate_condition(atom,{'s':dict(text=atom['operational_quote'])})


def test_focused_type_repair_is_bounded_and_does_not_replace_user_action_with_webui():
    record=source('A user follows a malicious link in the WebUI.')
    ordinary=recovered(record);ordinary['prerequisites'][0].update(target='WebUI',statement='WebUI is available.',
        operational_quote=record['sources'][0]['text'])
    calls=[]
    def runner(system,wire,role):
        focus=wire.get('focus_condition_type');calls.append(focus)
        result=deepcopy(ordinary)
        if focus and calls.count(focus)>1:
            atom=result['prerequisites'][0]
            atom.update(category='UI',predicate='user_performs_action',target='link',
                statement='A user follows a malicious link in the WebUI.',
                observation=dict(kind='operating_workflow',record_type='maintenance_log',check='Inspect available user event records; leave unverified occurrence Unknown.'))
        return dict(prediction=result,llm_used=True,model=dict(model='synthetic'))
    artifact=P.extract(record,runner=runner)
    assert {p['predicate'] for p in artifact['draft']['prerequisites']}=={'interface_available','user_performs_action'}
    attempts=[h for h in artifact['execution_history'] if h['stage'].startswith('condition_hint_review')]
    assert [h['status'] for h in attempts]==['rejected','accepted']
    assert artifact['coverage_review']['uncovered_hints']==[]
    assert artifact['draft']['unknowns']


def test_plaintext_transport_default_supports_a_variable_not_a_deployed_answer():
    quote='The default WebUI setting (HTTP) transmits credentials unencrypted.'
    atom=dict(predicate='configuration_required',operator_observable=True,operator='eq',expected=True,
        target='HTTP',statement='The WebUI uses HTTP for the assessed operation.',
        operational_quote=quote,source_refs=[dict(source_id='s',quote=quote)],
        observation=dict(kind='configuration',record_type='configuration_export',check='Inspect the applied WebUI transport configuration; leave unverified use Unknown.'))
    V.OP.validate_condition(atom,{'s':dict(text=quote)})
    atom['statement']='The WebUI uses HTTP by default.'
    with pytest.raises(ValueError,match='source default'):V.OP.validate_condition(atom,{'s':dict(text=quote)})
    atom.update(target='HTTPS',statement='The WebUI uses HTTPS.')
    with pytest.raises(ValueError):V.OP.validate_condition(atom,{'s':dict(text=quote)})


def test_generated_legacy_v1_label_cannot_conflict_with_registered_c1_type():
    wire=packet(source());item=wire['schema']['properties']['prerequisites']['items']
    assert 'vep_category' not in item['properties']
    atom=dict(condition_type='OTHER:configuration_required',vep_category='V1')
    V.TAXONOMY.resolve_type(atom)
    assert atom==dict(category='OTHER',predicate='configuration_required')
    # Native legacy artifacts keep their strict product-applicability guard.
    legacy=dict(category='C1',predicate='configuration_required',vep_category='V1')
    V.TAXONOMY.resolve_type(legacy)
    assert legacy['vep_category']=='V1'


def test_same_pinned_review_retries_only_the_uncovered_type():
    record=source('A user follows a malicious link in the WebUI.')
    original=recovered(record);original['prerequisites'][0].update(target='WebUI',
        statement='WebUI is available.',operational_quote=record['sources'][0]['text'])
    def response(value):return dict(prediction=deepcopy(value),llm_used=True,model=dict(model='synthetic'))
    with patch.object(R,'uncovered_hints',return_value=[]):
        artifact=P.extract(record,runner=lambda *args,**kwargs:response(original))
    focused=deepcopy(original);focused['prerequisites'][0].update(category='UI',predicate='user_performs_action',
        target='link',statement='A user follows a malicious link in the WebUI.',
        observation=dict(kind='operating_workflow',record_type='maintenance_log',check='Inspect available user event records; use Unknown if the action is unverified.'))
    calls=[]
    def runner(system,wire,role):
        calls.append(wire.get('focus_condition_type'));return response(focused)
    updated=P.revalidate(record,artifact,runner=runner)
    assert calls==['UI:user_performs_action']
    assert len(updated['execution_history'])==1
    assert updated['prior_execution_history']==artifact['execution_history']
    assert updated['coverage_review']['checkpoint_reused'] is True


def test_unscoped_numeric_trigger_is_a_blocker_not_an_invented_concurrency_question():
    record=source('The WebUI permits over 51 connections and can stop responding.')
    candidate=recovered(record);candidate['prerequisites'][0].update(target='WebUI',statement='WebUI is available.',
        operational_quote=record['sources'][0]['text'])
    calls=[]
    def runner(system,wire,role):
        calls.append(wire.get('focus_condition_type'))
        return dict(prediction=deepcopy(candidate),llm_used=True,model=dict(model='synthetic'))
    artifact=P.extract(record,runner=runner)
    assert calls==[None,None]
    assert len(artifact['draft']['prerequisites'])==1
    assert any('numeric_measurement_scope' in s for s in artifact['draft']['unknowns'])
    assert not R.coverage_hints(source('The WebUI stops after over 51 concurrent connections.'))


def test_full_unknown_details_survive_bounded_native_schema_without_losing_valid_atoms():
    record=source('A user follows a malicious link in the WebUI.')
    ordinary=recovered(record);ordinary['prerequisites'][0].update(target='WebUI',statement='WebUI is available.',
        operational_quote=record['sources'][0]['text'])
    details=['Unresolved source detail '+str(i)+'.' for i in range(12)]
    def runner(system,wire,role):
        value=empty(record) if wire.get('focus_condition_type') else deepcopy(ordinary)
        if wire.get('focus_condition_type'):value['unknowns']=details
        return dict(prediction=value,llm_used=True,model=dict(model='synthetic'))
    artifact=P.extract(record,runner=runner)
    assert len(artifact['draft']['prerequisites'])==1
    assert len(artifact['draft']['unknowns'])<=12
    assert set(details)<=set(artifact['unknown_overflow_records'][0]['reasons'])
    V.validate(artifact['draft'],record)


def test_post_model_validation_failure_is_not_silently_retried_as_a_fresh_extraction():
    from src.item4.workflow import source_analysis_jobs as Q
    record=source();candidate=recovered(record)
    artifact=P.extract(record,runner=lambda *args,**kwargs:dict(prediction=deepcopy(candidate),llm_used=True,model=dict(model='synthetic')))
    previous=dict(cve=record['cve'],prerequisite=artifact)
    with patch.object(Q,'evidence_packet',return_value=(record,{})), patch.object(V.L,'identity',return_value=dict(model='synthetic')), \
            patch.object(P,'revalidate',side_effect=ValueError('post-model failure')):
        with pytest.raises(ValueError,match='post-model failure'):Q.revalidate_previous(previous,[])


def test_unknown_operating_answer_is_not_a_positive_condition():
    record=source('The WebUI uses plaintext HTTP by default.')
    atom=dict(predicate='configuration_required',operator_observable=True,operator='eq',expected=True,
        target='HTTP',value='plaintext',statement='The current transport used by the WebUI is unknown.',
        operational_quote=record['sources'][0]['text'],source_refs=[dict(source_id='s',quote=record['sources'][0]['text'])],
        observation=dict(kind='configuration',record_type='configuration_export',check='Inspect the current transport setting.'))
    with pytest.raises(ValueError,match='VARIABLE'):V.OP.validate_condition(atom,{'s':record['sources'][0]})


def test_typed_alias_is_derived_and_low_confidence_is_not_raised():
    record=source('An attacker could persuade a user to follow a malicious Web UI link.')
    candidate=empty(record);candidate['prerequisites']=[dict(id='action',condition_id='wrong',
        condition_type='UI:user_performs_action',target='user',value='follows a malicious Web UI link',
        statement="A user follows a malicious Web UI link that tricks the web browser into transmitting unwanted commands with the user's privileges",
        extraction_confidence=.8,operator_observable=True,operator='eq',expected=True,
        operational_quote=record['sources'][0]['text'],source_refs=[dict(evidence_id='e1')],
        observation=dict(kind='operating_workflow',record_type='vendor_documentation',check='User follows a link.'))]
    draft,rejected,notes=P.recover_atoms(candidate,packet(record),record,V)
    assert not rejected
    atom=draft['prerequisites'][0]
    assert atom['condition_id']=='action' and atom['extraction_confidence']==.8
    assert atom['statement']=='A user follows a malicious Web UI link.'
    assert atom['observation']['record_type']=='operating_event_log'
    assert any('derive_condition_alias_from_id' in n['changes'] for n in notes)


def test_valid_saved_draft_is_not_replaced_by_a_bad_rejected_candidate():
    record=source();candidate=recovered(record)
    artifact=P.extract(record,runner=lambda *args,**kwargs:dict(prediction=deepcopy(candidate),llm_used=True,model=dict(model='synthetic')))
    bad=deepcopy(candidate);bad['prerequisites'][0].update(target='GUESS',statement='GUESS is available.')
    artifact['coverage_review']['rejected_prediction']=bad
    artifact['sha256']=V.digest({k:v for k,v in artifact.items() if k!='sha256'})
    updated=P.revalidate(record,artifact)
    assert len(updated['draft']['prerequisites'])==1
    assert updated['draft']['scenarios']==artifact['draft']['scenarios']


def test_verified_older_candidate_can_recover_an_atom_lost_by_later_failure():
    record=source();candidate=recovered(record)
    original=P.extract(record,runner=lambda *args,**kwargs:dict(prediction=deepcopy(candidate),llm_used=True,model=dict(model='synthetic')))
    later=deepcopy(original);later['draft']=empty(record)
    later['sha256']=V.digest({k:v for k,v in later.items() if k!='sha256'})
    with patch.object(V.L,'generate',side_effect=AssertionError('Reuse source-supported atom without resampling confidence')):
        updated=P.revalidate(record,later,extra_artifacts=[original])
    assert len(updated['draft']['prerequisites'])==1
    assert updated['draft']['prerequisites'][0]['extraction_confidence']==.95
    receipts=updated['revalidation']['candidate_recovery']
    assert any(r.get('source_execution_history') and r['origin']==original['sha256'] for r in receipts)


def test_proposed_transport_variable_can_be_rendered_without_guessing_a_deployed_value():
    quote='The WebUI of Example version 4.2 allows plaintext transmission (HTTP) of user credentials by default.'
    atom=dict(predicate='configuration_required',target='HTTP',value='plaintext',extraction_confidence=.91,
        statement='The current transport used by the WebUI of Example version 4.2 for transmitting user credentials is unknown',
        operational_quote=quote,observation=dict(kind='configuration',record_type='vendor_documentation',check='Read vendor default.'))
    rendered,note=N.normalize_atom(atom)
    assert rendered['statement']=='HTTP is used by the WebUI of Example version 4.2 for transmitting user credentials.'
    assert rendered['extraction_confidence']==.91 and rendered['value']=='plaintext'
    assert rendered['observation']['record_type']=='configuration_export'
    assert note and 'unknown' in atom['statement']
    atom['target']='TLS'
    assert N.normalize_atom(atom)[0]['statement']==atom['statement']


def test_literal_default_is_rendered_only_for_an_already_proposed_protocol_variable():
    quote='The WebUI of Example version 4.2 allows for plaintext transmission (HTTP) of user credentials by default.'
    atom=dict(predicate='configuration_required',target='HTTP',value='plaintext',statement=quote.rstrip('.'),
        operational_quote=quote,extraction_confidence=.94,observation=dict(kind='configuration',record_type='vendor_documentation',check='Read the default.'))
    rendered,note=N.normalize_atom(atom)
    assert rendered['statement']=='The WebUI of Example version 4.2 uses HTTP to transmit user credentials.'
    assert rendered['extraction_confidence']==.94 and rendered['target']=='HTTP'
    assert rendered['observation']['record_type']=='configuration_export'
    atom['target']='WebUI'
    assert N.normalize_atom(atom)[0]['statement']==atom['statement']
    atom.update(target='HTTP',statement='The current transport used by the WebUI of Example version 9.9 is unknown')
    assert N.normalize_atom(atom)[0]['statement']==atom['statement']
