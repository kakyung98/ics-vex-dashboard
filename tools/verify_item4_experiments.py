"""Independent file-level population and hierarchy audit for the #4 studies."""
import hashlib
import json
from pathlib import Path
import sys

import numpy as np

ROOT=Path(__file__).resolve().parents[1]


def load(path):return json.loads(path.read_text(encoding='utf-8'))


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def nested(levels):
    assert levels.ndim==2 and levels.shape[1]==7 and levels.shape[0]>0
    assert np.issubdtype(levels.dtype,np.integer) and np.all(levels>=0)
    for d in range(1,7):
        pairs=np.unique(levels[:,[d-1,d]],axis=0)
        assert len(pairs)==len(np.unique(levels[:,d])), 'Child crosses parents'


def main():
    corpus=ROOT/'data/item3_ics_cert_full_v1/cves.jsonl'
    expected={json.loads(l)['cve'] for l in corpus.open(encoding='utf-8')}
    assert len(expected)==12418
    names=['item4_ssl_hierarchy_v1','item4_cisa_silhouette_search_v1','item4_prototype_hierarchy_v1',
           'item4_cisa_lowrank_v1','item4_balanced_prefix_correction_v1']
    roots=[ROOT/'results'/name for name in names]
    original,search,proto,low,correction=roots
    assert load(original/'protocol.json')['source_sha256']==digest(ROOT/'results/ics_sentence_conditions_v1/full_inputs.jsonl')
    assert load(search/'protocol.json')['advisory_cache_sha256']==digest(ROOT/'data/cisa_advisories.json')
    flat_count=0;flat_populations=[]
    for root,wanted in [(search,210),(low,129),(correction,24)]:
        rows=[json.loads(l) for l in (root/'screening_results.jsonl').open(encoding='utf-8')]
        assert len(rows)==wanted
        for row in rows:
            path=(root/row['labels_path'] if 'labels_path' in row else
                  root/'representations'/f"labels_d{row['dimension']}_k{row['requested_k']}.npy")
            labels=np.load(path)
            assert labels.shape==(12418,) and np.issubdtype(labels.dtype,np.integer) and np.all(labels>=0)
            _,counts=np.unique(labels,return_counts=True)
            assert counts.sum()==12418 and counts.min()>=30
            flat_populations.append(len(labels));flat_count+=1
    assignments=[]
    paths=[original/'reference_assignments.jsonl']
    paths+=list((search/'final').glob('*/cve_assignments.jsonl'))
    paths+=list(proto.glob('*/cve_assignments.jsonl'))
    paths+=list((low/'selected').glob('*/cve_assignments.jsonl'))
    for path in paths:
        rows=[json.loads(l) for l in path.open(encoding='utf-8')]
        ids=[r['cve'] for r in rows]
        assert len(ids)==len(set(ids))==12418 and set(ids)==expected
        for row in rows:
            labels=row['depth_labels']
            vectors=labels.values() if isinstance(labels,dict) else [labels]
            for vector in vectors:assert len(vector)==7 and all(isinstance(v,int) and v>=0 for v in vector)
        assignments.append(str(path.relative_to(ROOT)))
    full_arrays=0;sample_arrays=0
    for root in roots[:4]:
        for path in root.rglob('levels.npy'):
            levels=np.load(path);nested(levels)
            relative=path.relative_to(root)
            is_subsample=any(str(p).startswith(('subsample_','frozen_','pipeline_')) for p in relative.parts)
            if is_subsample:
                assert 1<len(levels)<12418;sample_arrays+=1
            else:
                assert len(levels)==12418;full_arrays+=1
    exact_files=[]
    for root in [search,proto,low]:
        for path in root.rglob('full_population_metrics.json'):
            for row in load(path):
                assert row['population']==row['query_population']==12418
                for key in ['native_cosine_silhouette','reference_cosine_silhouette']:
                    assert row[key] is not None and np.isfinite(row[key]) and -1<=row[key]<=1
            exact_files.append(str(path.relative_to(ROOT)))
    trees=0
    for root in [proto,low]:
        for path in root.rglob('tree.json'):
            nodes=load(path);mapping={v['node_id']:v for v in nodes}
            for node in nodes:
                assert 0<=node['depth']<=6
                if node['parent_id'] is None:assert node['depth']==0
                else:assert node['depth']==mapping[node['parent_id']]['depth']+1
            trees+=1
    result=dict(target_cves=12418,target_id_set_sha256=hashlib.sha256('\n'.join(sorted(expected)).encode()).hexdigest(),
                flat_conditions_checked=flat_count,flat_population_min=min(flat_populations),flat_population_max=max(flat_populations),
                full_assignment_files_checked=len(assignments),full_assignment_files=assignments,
                full_hierarchy_arrays_checked=full_arrays,stability_subsample_arrays_checked=sample_arrays,
                exact_full_population_metric_files=len(exact_files),prototype_trees_checked=trees,
                all_full_populations_exactly_12418=True,no_missing_or_duplicate_final_cve_ids=True,
                all_partitions_nonnegative_and_nested=True,prototype_actual_parent_depth_at_most_6=True,
                original_sources_unchanged=True,independent_semantic_accuracy_tested=False)
    target=low/'population_integrity_audit.json'
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='full_assignment_files'},ensure_ascii=True))


if __name__=='__main__':main()
