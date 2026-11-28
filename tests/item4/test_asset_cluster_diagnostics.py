from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import numpy as np
from unittest.mock import patch
from src.item4.assets import cluster_diagnostics as D
from src.item4.assets import asset_classification_inference as M


def test_exact_runtime_model_full_population_and_quality_spaces():
    data=D.load();manifest,_,_=M.load()
    snapshot=json.loads((M.ROOT/'site/asset_vulntology/icsa_role_groups.json').read_text(encoding='utf-8'))
    assert data['source_sha256']==manifest['source_sha256']
    assert data['transforms_sha256']==manifest['transforms_sha256']
    assert len(data['points'])==data['metrics']['population']==3881
    assert len(data['groups'])==data['metrics']['clusters']==18
    assert Counter(p['cluster_id'] for p in data['points'])=={g['id']:g['count'] for g in data['groups']}
    assert sum(p['zero_features'] for p in data['points'])==data['metrics']['zero_feature_records']==7
    for key in ('svd_cosine_silhouette','original_tfidf_cosine_silhouette'):
        assert abs(data['metrics'][key]-snapshot['metrics'][key])<1e-5
    assert data['metrics']['independent_accuracy_validated'] is False
    weighted=sum(g['silhouette']*g['count'] for g in data['groups'])/3881
    assert abs(weighted-data['metrics']['svd_cosine_silhouette'])<1e-6


def fixture():
    name='fl switch 4808e-16fx sm lc-4gc firmware'
    return dict(id='fixture',asset_classification=dict(component_ref='asset',prediction=M.predict(name,[]),
        feature_evidence=[dict(source='BOM component name',text=name)]))


def test_bom_out_of_sample_projection_does_not_fabricate_silhouette_or_change_model():
    job=fixture();original=deepcopy(job);data=D.for_job(job)
    assert job==original and 'projection' not in data
    p=data['bom_points'][0]
    assert p['cluster_id']==job['asset_classification']['prediction']['cluster_id']
    assert np.isfinite([p['x'],p['y']]).all()
    assert p['silhouette'] is None
    assert len(data['points'])==3881, 'BOM is not inserted into the corpus or scored as a member'
    job['asset_classification']['prediction']['source_snapshot_sha256']='different'
    assert D.for_job(job)['bom_points']==[]


def test_api_and_page_wire_the_plot_before_the_main_ui():
    from fastapi.testclient import TestClient
    from tools.item4.serve_nist_operational_vex import app
    from src.item4.workflow import source_analysis_jobs as Q
    client=TestClient(app)
    with patch.object(Q,'get',return_value=fixture()):
        response=client.get('/api/item4/analyses/jobs/fixture/cluster-diagnostics')
    assert response.status_code==200
    assert response.json()['metrics']['population']==3881
    page=client.get('/item4.html').text
    assert page.index('src="/item4-cluster-diagnostics.js')<page.index('src="/item4-questionnaire.js')
