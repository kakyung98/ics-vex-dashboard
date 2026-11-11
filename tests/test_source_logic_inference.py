"""Boolean relation inference and semantic counterexamples, separate from gold."""
from src.source_logic_inference import infer_passage
from src.context_vex_pipeline import logic


def test_explicit_nested_relation_and_temporal_scope_are_grounded():
    text='Successful exploitation requires local access and that the client calls read() or write() after an error.'
    result=infer_passage(text,'source');h=result['hypotheses'][0]
    assert h['expression']['op']=='and' and h['expression']['args'][1]['op']=='or'
    assert not h['scope_ambiguous'] and not h['coverage_complete']
    for c in result['conditions']:
        a,b=c['source_ref']['span'];assert text[a:b]==c['source_ref']['quote']


def test_nonrequirement_is_not_not_literal():
    r=infer_passage('Successful exploitation requires no privileges and no user interaction.','s')
    assert not r['hypotheses'] and len(r['nonrequirements'])==2
    r=infer_passage('The service does not require authentication.','s')
    assert not r['hypotheses'] and r['nonrequirements']


def test_negative_configuration_and_concessive_have_different_meanings():
    r=infer_passage('When a safety feature is not enabled, an attacker can trigger the fault.','s')
    assert r['hypotheses'][0]['expression']['op']=='not'
    assert not infer_passage('Even if disabled, the interface can be re-enabled remotely.','s')['hypotheses']


def test_ambiguous_scope_is_inferred_but_needs_disambiguation():
    h=infer_passage('Successful exploitation requires A and B or C.','s')['hypotheses'][0]
    assert h['scope_ambiguous'] and not h['auto_applicable']


def test_neither_and_not_only_have_correct_boolean_scope():
    h=infer_passage('Only when neither A nor B, an attacker can act.','s')['hypotheses'][0]
    assert h['expression']['op']=='not' and h['expression']['args'][0]['op']=='or'
    h=infer_passage('Successful exploitation requires not only A but also B.','s')['hypotheses'][0]
    assert h['expression']['op']=='and'


def test_outcomes_and_recovery_are_not_prerequisite_relations():
    for text in ['A successful exploit could either crash or corrupt the device.',
                 'This causes a hang and requires a manual restart.',
                 'The client needs little CPU and network bandwidth.']:
        assert not infer_passage(text,'s')['hypotheses']


def test_then_and_main_clause_consequences_do_not_enter_condition_body():
    for text in ['If a fatal error occurs then it crashes and corrupts data.',
                 'When a request is malformed, the application crashes and needs a restart.']:
        value=infer_passage(text,'s')
        assert len(value['conditions'])==1
        assert not any(word in value['conditions'][0]['source_ref']['quote'] for word in ('crashes','corrupts','restart'))
    assert not infer_passage('If exploited, the device will crash.','s')['hypotheses']
