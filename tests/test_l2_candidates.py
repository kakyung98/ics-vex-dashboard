from copy import deepcopy
from src.l2_candidates import rank,structure
from src.identity_retrieval import ProductIndex
from src.identity_evidence import parse_components,grounded_versions,validate_identity


def sample(name='Siemens RUGGEDCOM APE1808 vers:all/*'):
    idx=ProductIndex([{'cpe':'cpe:2.3:h:siemens:ruggedcom_ape1808:1.0:*:*:*:*:*:*:*'},
                      {'cpe':'cpe:2.3:h:siemens:ruggedcom_apex1808:1.0:*:*:*:*:*:*:*'}])
    c=parse_components({'bomFormat':'CycloneDX','components':[{'name':name,'type':'device','manufacturer':{'name':'Siemens'}}]})[0]
    v=grounded_versions(c,idx)
    return idx,c,v


def test_source_model_is_preserved_and_nearby_different_model_is_blocked():
    idx,c,v=sample();before=deepcopy(c)
    out=rank(c,v,idx.search(c,v),lambda p:{'prediction':{'ranked_candidate_ids':[], 'evidence_refs':[],'status':'unresolved'}})
    assert c==before
    assert [m['value'] for m in out['structured_input']['model_observations']]==['APE1808']
    wrong=next(x for x in out['candidates'] if x['product']=='ruggedcom_apex1808')
    right=next(x for x in out['candidates'] if x['product']=='ruggedcom_ape1808')
    assert 'model_identifier_not_corroborated' in wrong['conflicts']
    assert 'model_identifier_not_corroborated' not in right['conflicts']
    for m in out['structured_input']['model_observations']:
        assert c['name'][slice(*m['span'])]==m['value']


def test_free_name_generation_and_fabricated_ids_cannot_pass_new_contract():
    idx,c,v=sample()
    for pred in [{'normalized':'ruggedcom_apex1808','status':'resolved'},
                 {'ranked_candidate_ids':['invented'],'evidence_refs':['input:name'],'status':'ranked'}]:
        out=rank(c,v,idx.search(c,v),lambda _: {'prediction':pred})
        assert out['agent']['llm_used'] is False and out['agent']['executed'] is False


def test_llm_cannot_select_conflicting_model_or_remove_competitors():
    idx,c,v=sample();original=idx.search(c,v)
    def wrong(p):
        bad=next(x for x in p['candidates'] if x['product']=='ruggedcom_apex1808')
        return {'prediction':{'ranked_candidate_ids':[bad['candidate_id']],'evidence_refs':['input:name'],'status':'ranked'}}
    out=rank(c,v,original,wrong)
    assert out['agent']['llm_used'] is False and out['agent']['executed'] is False
    assert {x['candidate_id'] for x in out['candidates']}=={x['candidate_id'] for x in original['candidates']}


def test_versions_not_promoted_to_models_and_letter_digit_separators_are_allowed():
    idx,c,v=sample('Siemens APE1808 V9.2.1')
    assert [m['value'] for m in structure(c,v)['model_observations']]==['APE1808']
    c['name']='APE1808'
    idx=ProductIndex([{'cpe':'cpe:2.3:h:siemens:ape_1808:1.0:*:*:*:*:*:*:*'}])
    out=rank(c,v,idx.search(c,v),lambda _: {'prediction':{'ranked_candidate_ids':[],'evidence_refs':[],'status':'unresolved'}})
    assert not out['candidates'][0]['model_identifier_check']['missing']
