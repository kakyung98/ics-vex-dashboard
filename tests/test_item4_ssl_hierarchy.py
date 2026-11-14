"""Check partition and metric semantics against independent reference calculations."""
import numpy as np
import pytest
from sklearn.metrics import silhouette_samples, adjusted_rand_score
from sklearn.preprocessing import normalize
from threadpoolctl import threadpool_limits

from src import item4_ssl_hierarchy as h


def test_query_silhouette_uses_full_population():
    rng=np.random.default_rng(10)
    x=normalize(rng.normal(size=(40,5))).astype(np.float32)
    labels=np.array([0]*17+[1]*15+[2]*7+[3])
    query=np.array([0,3,20,33,39])
    distances=h.cosine_distances(x,query,device='cpu')
    expected=silhouette_samples(x,labels,metric='cosine')[query].mean()
    assert h.sampled_silhouette(distances,labels,query)==pytest.approx(expected,abs=2e-6)
    assert h.sampled_silhouette(distances,np.zeros(40),query) is None


def test_ari_aligns_common_ids_and_ignores_cluster_numbers():
    a=np.array(['C','A','D','B','E'])
    b=np.array(['F','D','B','C','A'])
    la=np.array([[0,1,7],[0,2,8],[0,1,7],[0,2,9],[0,3,10]])
    lb=np.array([[0,5,99],[0,8,30],[0,9,31],[0,8,30],[0,9,32]])
    scores=h.aligned_ari(a,la,b,lb)
    assert all(s['common_cves']==4 for s in scores)
    assert all(s['ari']==1 for s in scores)
    with pytest.raises(ValueError,match='Duplicate'):
        h.aligned_ari(['A','A'],la[:2],b,lb)


def test_ari_changes_only_at_changed_depth_and_flags_trivial_agreement():
    ids=np.array(['a','b','c','d'])
    a=np.array([[0,1,2],[0,1,2],[0,1,3],[0,1,3]])
    b=np.array([[0,8,4],[0,8,5],[0,8,4],[0,8,5]])
    result=h.aligned_ari(ids,a,ids[::-1],b[::-1])
    assert result[0]['ari']==1 and result[0]['degenerate']
    assert result[1]['ari']==pytest.approx(adjusted_rand_score(a[:,2],b[:,2]))
    assert not result[1]['degenerate']


@pytest.mark.parametrize('method',['kmeans','ward'])
def test_early_stop_preserves_parent_and_never_crosses_ancestors(method):
    rng=np.random.default_rng(3)
    x=normalize(np.r_[rng.normal([8,0],.05,size=(10,2)),rng.normal([0,8],.05,size=(10,2))]).astype(np.float32)
    with threadpool_limits(limits=1):
        levels,nodes=h.recursive_partition(x,method,max_depth=3,min_parent=15,min_child=6,device='cpu')
    h.validate_levels(levels,3)
    assert len(np.unique(levels[:,1]))==2
    assert np.array_equal(levels[:,1],levels[:,2])
    assert np.array_equal(levels[:,2],levels[:,3])
    assert any(n.get('stop_reason')=='minimum_size' for n in nodes)
    broken=levels.copy();broken[0,2]=broken[-1,2]
    with pytest.raises(ValueError,match='crosses'):
        h.validate_levels(broken,3)


def test_cwe_cap_is_longest_graph_path_not_number_of_abstraction_types():
    records={}
    for i in range(6):records[str(i)]={'parents_view_1000':[str(i-1)] if i else []}
    records['5']['parents_view_1000'].append('0')
    result=h.cwe_depth(dict(records=records,version='test',view='1000'))
    assert result['max_depth']==6 and len(result['longest_path'])==6
    records['0']['parents_view_1000']=['5']
    with pytest.raises(ValueError,match='Cycle'):
        h.cwe_depth(dict(records=records,version='test',view='1000'))


def test_resampling_keeps_exact_duplicate_text_groups_together():
    groups=np.array(['a','a','b','c','c','d','e','f'])
    selected=h.grouped_subsample(groups,.8,10)
    assert len(selected)==len(set(selected))
    for group in np.unique(groups):
        assert np.isin(np.flatnonzero(groups==group),selected).all() or not np.isin(np.flatnonzero(groups==group),selected).any()
