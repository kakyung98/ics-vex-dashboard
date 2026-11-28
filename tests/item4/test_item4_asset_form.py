from copy import deepcopy
import pytest
from src.item4.assets.operator_asset_form import DEFS; from src.item4.assets.operator_asset_form import build_form; from src.item4.assets.operator_asset_form import validate_input
from src.item4.assets.asset_profile_fields import COMMON; from src.item4.assets.asset_profile_fields import PROFILES


def test_every_common_and_asset_specific_field_has_a_concrete_question_and_schema():
    assert set(COMMON)|{f for p in PROFILES.values() for f in p}==set(DEFS)
    for aid in PROFILES:
        form=build_form([aid]);r=validate_input(form['definition'],form['input'])
        assert r['passed'] and r['recorded_fields']==0 and not r['proves_non_exploitability']


def test_composite_forms_and_invalid_ports_and_missing_evidence():
    form=build_form(['A0002','A0003'])
    assert {'project_import','program_download'}<=set(form['input']['values'])
    payload=deepcopy(form['input']);v=payload['values']['services']
    v.update(state='recorded',data=[dict(interface='web',protocol='https',transport='tcp',port=443,enabled='false')],evidence_ids=['config-record'])
    assert validate_input(form['definition'],payload)['recorded_fields']==1
    v['data'][0]['port']=70000
    with pytest.raises(ValueError):validate_input(form['definition'],payload)
    v['data'][0]['port']=443;v['evidence_ids']=[]
    with pytest.raises(ValueError):validate_input(form['definition'],payload)


def test_unknown_inventory_does_not_become_empty_or_blocked():
    form=build_form(['A0003']);payload=deepcopy(form['input'])
    payload['values']['services']['data']=[]
    with pytest.raises(ValueError):validate_input(form['definition'],payload)
    payload['values']['services'].update(state='recorded_empty',evidence_ids=['survey'],coverage_scope='All interfaces in the recorded configuration')
    result=validate_input(form['definition'],payload)
    assert result['recorded_fields']==1 and result['automatic_cve_mapping'] is False
    with pytest.raises(ValueError):build_form(['unknown'])
