"""V1 context routing and invalidation; no GPU or external sources required."""
from copy import deepcopy
from unittest.mock import patch
import pytest
from src.item4.assets import question_record_context as R
from src.item4.analysis import exploitation_prerequisites as V
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.workflow import source_analysis_jobs as Q
from tests.item4.test_item4_asset_key_workflow import fixture_job


@pytest.mark.parametrize('aid',[f'A{i:04}' for i in range(1,19)])
def test_all_asset_profiles_supply_record_candidates_without_conditions(aid):
    job=dict(asset_classification=dict(component_ref='asset',status='classified',asset_type_id=aid))
    context=R.extraction_context(job,[dict(ref='asset'),dict(ref='unknown')])
    selected,unknown=context['components']
    assert selected['asset_type_id']==aid
    assert selected['asset_type_name'] and selected['asset_type_source']
    assert all(selected['ics_record_candidates'].values())
    assert unknown['asset_type_id'] is None
    assert not any(unknown['ics_record_candidates'].values())
    assert 'evidence_id' not in str(context) and 'prerequisites' not in context


def test_declared_extraction_passes_context_with_original_icsa_evidence():
    job,record=fixture_job()
    record['sources'][0]['id']='icsa-fixture:cve'
    context=R.extraction_context(job,job['components'])
    with (patch.object(Q,'evidence_packet',return_value=(record,{})),
          patch.object(Q.advisory_context,'packet',return_value=({},{})),
          patch.object(V,'resolve',return_value=job['conditions'][0]['prerequisite']) as model):
        result=Q.extract_declared(record['cve'],job['components'],asset_context=context)
    supplied=model.call_args.args[0]
    assert supplied['asset_type_context']==context
    assert supplied['sources']==record['sources']
    wire=V.extraction_packet(supplied)
    assert wire['asset_type_context']==context
    assert all(e['source_id']=='icsa-fixture:cve' for e in wire['evidence'])
    assert result['evidence_packet']['asset_type_context']==context


def test_changed_asset_context_requeues_v2_even_without_v3_gaps(tmp_path,monkeypatch):
    job,_=fixture_job()
    job['conditions'][0]['asset_type_context_sha256']=Q.digest(R.extraction_context(job,job['components']))
    job['asset_classification']['asset_type_id']='A0003'
    monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3')
    monkeypatch.setattr(Q,'JOBS',{})
    monkeypatch.setattr(Q,'extraction_identity',lambda:job['extraction_identity'])
    monkeypatch.setattr(V3,'requires_generation',lambda _:False)
    Q._save(job)
    with patch.object(Q.QUEUE,'submit') as submit:
        queued=Q.get(job['id'])
    assert queued['status']=='queued' and queued['condition_state']=='queued'
    submit.assert_called_once()


def test_profile_material_change_invalidates_question_plan():
    job,_=fixture_job();previous=job['plan_sha256']
    with patch.dict(R.RECORDS,services='Changed applied service records'):
        Q._prepare_analysis(job)
    assert job['plan_sha256']!=previous
