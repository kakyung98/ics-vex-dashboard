"""Verify leaf preservation and actual stored parent/child nesting."""
import numpy as np
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import normalize
from tools.extend_item4_prototype_hierarchy import prototype_tree


def test_prototype_hierarchy_keeps_every_leaf_and_early_stop_id():
    rng=np.random.default_rng(18)
    x=normalize(rng.normal(size=(70,8))).astype(np.float32)
    flat=np.repeat(np.arange(7),10)
    levels,nodes,structure=prototype_tree(x,flat)
    assert levels.shape==(70,7) and np.all(levels>=0)
    assert adjusted_rand_score(flat,levels[:,-1])==1
    assert structure['contracted_tree_max_depth']<=6
    for depth in range(1,7):
        for label in np.unique(levels[:,depth]):
            assert len(np.unique(levels[levels[:,depth]==label,depth-1]))==1
    for node in nodes:
        assert node['depth']<=6 and node['size']>0
        if node['parent_id'] is not None:
            assert node['depth']==nodes[node['parent_id']]['depth']+1


def test_small_leaf_count_does_not_invent_six_distinct_splits():
    x=normalize(np.array([[1.,0.],[1.,.1],[0.,1.],[.1,1.]],dtype=np.float32))
    levels,nodes,structure=prototype_tree(x,np.array([0,0,1,1]))
    assert all(np.array_equal(levels[:,1],levels[:,d]) for d in range(2,7))
    assert structure['contracted_tree_max_depth']==1
    assert len(nodes)==3
