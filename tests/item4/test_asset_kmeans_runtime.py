import json
from pathlib import Path
import re
from unittest.mock import patch
import numpy as np

from src.item4.assets import asset_classification_inference as model
from src.item4.workflow import source_analysis_jobs as jobs

ROOT=Path(__file__).resolve().parents[2]


def test_frozen_centroids_reproduce_the_full_published_partition():
    manifest,vectorizer,arrays=model.load()
    records=json.loads((ROOT/'site/asset_vulntology/icsa_role_groups.json').read_text(encoding='utf-8'))['advisories']
    assert manifest['population']==len(records)==3881
    assert manifest['reproduced_partition_ari']==1.0
    texts=[re.sub(r'\b(?:CVE-\d{4}-\d+|ICSA-\S+|CWE-\d+)\b',' ',r['feature_text'],flags=re.I) for r in records]
    from sklearn.preprocessing import normalize
    z=normalize(vectorizer.transform(texts)@arrays['components'].T)
    labels=np.linalg.norm(z[:,None,:]-arrays['centers'][None,:,:],axis=2).argmin(axis=1)
    assert [manifest['groups'][int(label)]['id'] for label in labels]==[r['group_id'] for r in records]
    assert arrays['centers'].shape[0]==18


def test_operational_classification_runs_without_advisory_identity_matches():
    bom=dict(bomFormat='CycloneDX',components=[{'bom-ref':'asset','name':'fl switch 4808e-16fx sm lc-4gc firmware',
             'description':'Controlled inventory. ','type':'operating-system'}],
             vulnerabilities=[dict(id='CVE-2017-16741',affects=[dict(ref='asset')])])
    component=jobs.inventory(bom)[0][0]
    with patch.object(jobs.advisory_context,'lookup',side_effect=AssertionError('V1 must not require ICSA lookup')):
        result=jobs.classify(bom,component)
    assert result['status']=='classified' and result['asset_type_id']=='A0015'
    assert result['prediction']['cluster_id'].startswith('ICSA-G')
    assert result['prediction']['model_version']==model.VERSION
    assert result['classification_version']==model.VERSION
    assert result['evidence']==[] and result['provisional']
    assert result['supplies_operating_truth'] is False
    assert result['prediction']['accuracy_validated'] is False


def test_unknown_or_ambiguous_bom_text_does_not_force_an_asset_type():
    missing=model.predict('zzzzqqq',[])
    assert missing['status']=='unresolved' and missing['asset_type_id'] is None
    ambiguous=model.predict('PLC HMI',[])
    assert ambiguous['cluster_id']
    assert ambiguous['status']=='unresolved' and ambiguous['asset_type_id'] is None


def test_bom_function_description_is_used_as_model_input():
    result=model.predict('zzzzqqq',[],description='Ethernet network switch')
    same_text=model.predict('Ethernet network switch',[])
    assert result['cluster_id']==same_text['cluster_id']
    assert result['candidate_types']==same_text['candidate_types']
    assert result['candidate_types'][0]['id']=='A0015'
