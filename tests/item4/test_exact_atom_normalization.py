from copy import deepcopy
from itertools import product
from src.item4.evaluation.exact_atom_normalization import normalize
from src.item4.evaluation.metamorphic_synthetic import state


def draft():
    atom=dict(id='a',condition_type='OTHER:feature_enabled',target='Diagnostic feature',value='enabled',
        statement='Diagnostic feature is enabled.',extraction_confidence=.9,
        source_refs=[dict(evidence_id='e2')],observation=dict(check='Inspect the current applied setting.'))
    second=deepcopy(atom);second['id']='b'
    return dict(prerequisites=[atom,second],scenarios=[dict(expression=dict(op='and',args=[dict(condition='a'),dict(op='not',args=[dict(condition='b')])]))],unknowns=['Other paths remain unknown.'])


def test_duplicate_normalization_preserves_three_valued_formula_and_unknowns():
    before=draft();after,receipt=normalize(before)
    assert len(after['prerequisites'])==1 and receipt[0]['aliases']=={'b':'a'}
    assert before['prerequisites'][1]['id']=='b' and after['unknowns']==before['unknowns']
    for value in (True,False,None):
        assert state(before['scenarios'][0]['expression'],{'a':value,'b':value})==state(after['scenarios'][0]['expression'],{'a':value})


def test_different_scope_evidence_or_confidence_is_not_merged():
    for field,value in [('target','Other feature'),('source_refs',[dict(evidence_id='e3')]),('extraction_confidence',.8),('statement','A privileged user enables the feature.')]:
        before=draft();before['prerequisites'][1][field]=value
        after,receipt=normalize(before)
        assert len(after['prerequisites'])==2 and not receipt


def test_ambiguous_identity_is_left_for_the_original_validator():
    before=draft();before['prerequisites'][1]['id']='a'
    after,receipt=normalize(before)
    assert after==before and not receipt
