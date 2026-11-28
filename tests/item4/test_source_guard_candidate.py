from unittest.mock import patch
import pytest
from src.item4.analysis import operator_verifiable_conditions as O
from src.item4.evaluation import source_guard_candidate as C


def atom(quote):
    return dict(predicate='authentication_required',category='C4',operator_observable=True,
        operator='eq',expected=True,target='diagnostic account',value='required',
        statement='Authentication for the diagnostic account is required.',operational_quote=quote,
        source_refs=[dict(source_id='s',quote=quote)],observation=dict(kind='access_policy',
        record_type='access_control_record',check='Inspect the applied authentication policy for the diagnostic account.'))


@pytest.mark.parametrize('quote',[
    'For the described path, authentication for the diagnostic account is required.',
    'Authentication for the diagnostic account is necessary for the described path.',
])
def test_passive_requirement_does_not_fail_only_because_requires_is_absent(quote):
    with patch.object(O,'EXPLICIT',C.explicit(O.EXPLICIT)):
        O.validate_condition(atom(quote),{'s':dict(text=quote)})


@pytest.mark.parametrize('quote',[
    'Authentication is not required.',
    'Authentication is not necessary.',
    'The described attack does not require authentication.',
])
def test_nonrequirement_never_becomes_required_authentication(quote):
    with patch.object(O,'EXPLICIT',C.explicit(O.EXPLICIT)),patch.object(O,'NONREQUIREMENT',C.nonrequirement(O.NONREQUIREMENT)):
        with pytest.raises(O.OperationalPrerequisiteError,match='nonrequirement'):
            O.validate_condition(atom(quote),{'s':dict(text=quote)})


def test_candidate_does_not_admit_defects_or_make_source_silence_a_condition():
    for quote in ['The software fails to validate input.','A diagnostic account exists.']:
        with patch.object(O,'EXPLICIT',C.explicit(O.EXPLICIT)):
            with pytest.raises(O.OperationalPrerequisiteError):O.validate_condition(atom(quote),{'s':dict(text=quote)})


def test_inner_setting_keyword_does_not_override_structural_negation():
    item=dict(predicate='feature_enabled',target='Diagnostic feature',
        operational_quote='The path requires it is not the case that Diagnostic feature is enabled.')
    original=O.source_polarity
    assert original(item) is True  # Existing lexical check ignores outer NOT.
    assert C.polarity(original)(item) is None
    direct=dict(item,operational_quote='The path requires Diagnostic feature is enabled.')
    assert C.polarity(original)(direct) is True
