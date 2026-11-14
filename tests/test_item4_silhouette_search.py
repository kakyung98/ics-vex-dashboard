"""Prevent source-scope confusion and CVE removal in input/cluster search."""
import json
import numpy as np
import pytest
import torch
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import normalize
from src import item4_silhouette_search as search

torch.set_num_threads(1)


def test_cisa_scope_and_shared_fallback_retain_every_target(tmp_path):
    advisory={'a':dict(cves=['CVE-A','CVE-B'],affected_text='Shared controller context',vulns=[])}
    raw=dict(document=dict(notes=[dict(title='Risk evaluation',text='Shared physical process risk'),
                                   dict(title='Recommended Practices',text='generic boilerplate')]),
             vulnerabilities=[dict(cve='CVE-A',notes=[dict(category='summary',text='Specific authentication bypass')])])
    (tmp_path/'a.json').write_text(json.dumps(raw),encoding='utf-8')
    data=search.cisa_inputs(advisory,['CVE-A','CVE-B'],tmp_path)
    assert data['coverage']['population']==2 and data['coverage']['excluded_cves']==0
    assert data['coverage']['shared_context_fallbacks']==1
    assert 'Specific authentication bypass'.lower() in data['scoped'][0]
    assert 'Specific authentication bypass'.lower() not in data['scoped'][1]
    assert 'generic boilerplate' not in data['documents'][0]
    assert data['links']==[[0],[0]]
    with pytest.raises(ValueError,match='Missing advisory'):
        search.cisa_inputs(advisory,['CVE-A','CVE-B','CVE-C'],tmp_path)


def test_cvss_cleanup_does_not_remove_following_technical_sentence():
    text='A CVSS v3 base score of 7.5 has been assigned. The service permits unauthenticated writes.'
    result=search.clean(text)
    assert 'unauthenticated writes' in result
    assert '7.5' not in result


def test_kmeans_and_small_cluster_merge_keep_all_points():
    rng=np.random.default_rng(7)
    x=normalize(np.r_[rng.normal([8,0],.05,size=(20,2)),rng.normal([0,8],.05,size=(20,2)),rng.normal([-8,0],.05,size=(20,2))]).astype(np.float32)
    labels,info=search.gpu_kmeans(x,3,seed=5,n_init=2,max_iter=30,device='cpu')
    assert len(labels)==60 and adjusted_rand_score(np.repeat([0,1,2],20),labels)==1
    assert info['inertia']>=0
    unusual=labels.copy();unusual[0]=99
    merged,count=search.merge_small(x,unusual,minimum=10)
    assert count==1 and len(merged)==60 and np.min(np.bincount(merged))>=10


def test_advisory_pooling_preserves_cve_order_and_normalization():
    v=normalize(np.array([[1.,0.],[0.,1.],[1.,1.]],dtype=np.float32))
    result=search.pool_advisories(v,[[0],[1],[0,2]])
    assert result.shape==(3,2) and np.allclose(np.linalg.norm(result,axis=1),1)
    assert result[0,0]==1 and result[1,1]==1
