from src import vex_roles as VR

def test_conditions_keep_original_source_ids_and_literal_spans(monkeypatch):
    monkeypatch.setattr(VR,'infer',lambda *a: (_ for _ in ()).throw(AssertionError('No analysis model')))
    text='The parse_frame function processes malformed frames from remote attackers.'
    r=VR.extraction('CVE-2099-12345',text)
    assert r['llm_used'] is False and r['strategy']=='deterministic_source_spans'
    sources={s['id']:s for s in r['source_catalog']}
    for c in r['prediction']['conditions']:
        s=sources[c['source_id']];a,b=c['source_span']
        assert s['text'][a:b]==c['evidence'] and c['can_refute'] is False
    assert r['prediction']['function_candidates'][0]['name']=='parse_frame'

def test_model_environment_overrides_cannot_enable_analysis_inference(monkeypatch):
    monkeypatch.setenv('ICSVEX_EXTRACTION_STRATEGY','legacy_quotes')
    monkeypatch.setenv('ICSVEX_CONDITION_SELF_REVIEW','1')
    calls=[];monkeypatch.setattr(VR,'infer',lambda *args:calls.append(args))
    r=VR.extraction('CVE-2099-12346','A malformed frame causes an error.')
    assert not calls and r['llm_used'] is False
    assert r['prediction']['can_refute'] is False

def test_empty_description_does_not_create_conditions_or_functions():
    r=VR.extraction('CVE-2099-99999','')
    assert not r['usable'] and r['prediction'] is None
