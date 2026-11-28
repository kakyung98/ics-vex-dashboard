"""Describe fixed CVE partitions with CWE/CVSS, without refitting clusters.

All IDs remain assigned. Label availability masks affect auxiliary statistics
only. Metadata agreement does not establish equivalent exploitation conditions.
"""
if __package__ in (None, ''):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.metrics import adjusted_mutual_info_score, normalized_mutual_info_score
from src.item4.evaluation.prerequisite_consistency import parse_vector

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def categorical_stats(clusters, labels, permutations=200, seed=20261124):
    """Permutation preserves both cluster sizes and category marginal counts."""
    if len(clusters) != len(labels):
        raise ValueError('Unaligned labels')
    n = len(labels)
    if not n:
        return dict(n=0, status='no_reference_labels')
    _, a = np.unique(np.asarray(clusters, dtype=str), return_inverse=True)
    _, b = np.unique(np.asarray(labels, dtype=str), return_inverse=True)
    k, m = int(a.max()+1), int(b.max()+1)
    def information(values):
        table = np.bincount(a*m+values, minlength=k*m).reshape(k,m)
        row, col = table.sum(axis=1), table.sum(axis=0)
        ii, jj = np.nonzero(table)
        cells = table[ii,jj]
        mi = float(np.sum(cells/n*np.log(cells*n/(row[ii]*col[jj]))))
        return mi, float(table.max(axis=1).sum()/n)
    mi, purity = information(b)
    counts = np.bincount(b)
    probabilities = counts/n
    entropy = float(-np.sum(probabilities*np.log(probabilities)))
    baseline = float(counts.max()/n)
    result = dict(n=n, occupied_clusters=k, reference_categories=m,
                  weighted_purity=purity, global_majority_baseline=baseline,
                  purity_above_global_majority=purity-baseline,
                  label_entropy_nats=entropy, conditional_entropy_nats=max(0.,entropy-mi),
                  entropy_reduction_fraction=mi/entropy if entropy else None,
                  nmi=float(normalized_mutual_info_score(a,b)),
                  ami=float(adjusted_mutual_info_score(a,b)),
                  status='degenerate_reference' if m==1 else 'computed')
    if permutations and m>1 and k>1:
        rng = np.random.default_rng(seed)
        null = np.array([information(rng.permutation(b)) for _ in range(permutations)])
        result.update(permutations=permutations,
                      permutation_mi_p=(1+int(np.sum(null[:,0]>=mi-1e-12)))/(permutations+1),
                      permutation_purity_mean=float(null[:,1].mean()),
                      purity_above_permuted_mean=purity-float(null[:,1].mean()),
                      permutation_purity_95pct=float(np.quantile(null[:,1],.95)))
    return result


def label_panel(cluster_by_cve, label_by_cve, permutations=200):
    ids=sorted(cluster_by_cve)
    observed=[c for c in ids if label_by_cve.get(c)]
    single=[c for c in observed if not label_by_cve[c].startswith('CONFLICT:')]
    result=dict(population=len(ids), reference_observed=len(observed), reference_missing=len(ids)-len(observed),
                conflicting_reference_cves=len(observed)-len(single),
                all_ids_including_missing=categorical_stats([cluster_by_cve[c] for c in ids],
                    [label_by_cve.get(c) or 'MISSING_REFERENCE' for c in ids],0),
                observed_reference_only=categorical_stats([cluster_by_cve[c] for c in observed],
                    [label_by_cve[c] for c in observed],permutations))
    if len(single)!=len(observed):
        result['single_valued_reference_only']=categorical_stats([cluster_by_cve[c] for c in single],
                    [label_by_cve[c] for c in single],permutations)
    return result


def metadata_labels(ids, cisa_rows, references):
    labels = dict(frozen_CWE_set={}, current_CSAF_CWE_set={})
    unavailable = Counter()
    for cve in ids:
        frozen=sorted(set(filter(None,cisa_rows[cve].get('reported_cwes','').split('|'))))
        labels['frozen_CWE_set'][cve]='|'.join(frozen) or None
        ref=references.get(cve,{})
        labels['current_CSAF_CWE_set'][cve]='|'.join(sorted(set(ref.get('cwes',[])))) or None
        values=defaultdict(set)
        joint=defaultdict(set)
        for row in ref.get('vectors',[]):
            try:
                version, metrics=parse_vector(row['vector'])
            except ValueError:
                unavailable['unsupported_or_invalid_vectors']+=1
                continue
            for key,value in metrics.items():
                values[version+'/'+key].add(value)
            joint[version].add('/'.join(k+':'+metrics[k] for k in ('AV','PR','UI')))
        for key, choices in values.items():
            labels.setdefault('CVSS_'+key,{})[cve]=('|'.join(sorted(choices)) if len(choices)==1
                                                       else 'CONFLICT:'+'|'.join(sorted(choices)))
        for version, choices in joint.items():
            labels.setdefault('CVSS_'+version+'/AV_PR_UI_joint',{})[cve]=(next(iter(choices)) if len(choices)==1
                                                    else 'CONFLICT:'+'|'.join(sorted(choices)))
    return labels,dict(unavailable)


def describe_clusters(assignments, labels, originals, features):
    groups=defaultdict(list)
    for cve,cluster in assignments.items():
        groups[str(cluster)].append(cve)
    output=[]
    for cluster,ids in sorted(groups.items(),key=lambda kv:(-len(kv[1]),kv[0])):
        item=dict(cluster=cluster,size=len(ids),
            original_condition_signature_missing=sum(originals[c]['unknown_conditions'] for c in ids),
            shared_context_only=sum(cisa_truth(features[c].get('cisa_only_shared_context_available')) for c in ids),
            identity_ambiguous=sum(cisa_truth(features[c].get('identity_ambiguous')) for c in ids),
            labels={})
        for name, mapping in labels.items():
            counts=Counter(mapping[c] for c in ids if mapping.get(c))
            n=sum(counts.values())
            item['labels'][name]=dict(observed=n,missing=len(ids)-n,
                top=[dict(label=label,count=count,share_of_observed=count/n) for label,count in counts.most_common(5)])
        output.append(item)
    return output


def cisa_truth(value):
    return str(value).lower()=='true'


def run(folder, references_path, permutations=200):
    folder=Path(folder);snap=folder/'source_snapshots'
    cisa_path=snap/'cve_clusters_cisa_context_svd16.csv'
    condition_path=snap/'cve_assignments.jsonl'
    cisa=list(csv.DictReader(cisa_path.open(encoding='utf-8-sig')))
    original=[json.loads(s) for s in condition_path.read_text(encoding='utf-8').splitlines()]
    cisa_by={r['cve']:r for r in cisa};original_by={r['cve']:r for r in original}
    expected={r['cve'] for r in json.loads((ROOT/'benchmark/item4_evaluation/extracted_ox_v3/population_index.json').read_bytes())}
    if len(cisa)!=12418 or len(original)!=12418 or set(cisa_by)!=expected or set(original_by)!=expected:
        raise ValueError('Both original partitions must assign every one of the 12,418 IDs exactly once')
    feature_rows=[json.loads(s) for s in (snap/'condition_features.jsonl').read_text(encoding='utf-8').splitlines()]
    feature_by={r['cve']:r for r in feature_rows}
    if set(feature_by)!=expected or any(feature_by[c]['condition_signatures']!=original_by[c]['condition_signatures'] for c in expected):
        raise ValueError('Original feature signatures differ from original assignments')
    refs={r['cve']:r for r in json.loads(Path(references_path).read_bytes())}
    labels, reference_issues=metadata_labels(sorted(expected),cisa_by,refs)
    partitions=dict(cisa_context_svd16={c:r['leaf_cluster_id'] for c,r in cisa_by.items()},
                    source_condition_clusters={c:str(r['cluster']) for c,r in original_by.items()})
    report=dict(population=12418,purpose='fixed_partition_auxiliary_metadata_analysis',
        partitions_refitted=False, original_features_and_assignments_preserved=True,
        feature_signature_mismatches=0, reference_issues=reference_issues,
        provenance=dict(assignments_csv_sha256=sha(cisa_path),condition_assignment_sha256=sha(condition_path),
                        original_feature_snapshot_sha256=sha(snap/'condition_features.jsonl'),
                        current_references_sha256=sha(references_path)),partitions={})
    for name,assignments in partitions.items():
        summary=dict(assigned=len(assignments),occupied_clusters=len(set(assignments.values())),
                     association={key:label_panel(assignments,mapping,permutations) for key,mapping in labels.items()},
                     per_cluster=describe_clusters(assignments,labels,original_by,cisa_by))
        # Advisory grouping can explain lexical partitions independently of CWE.
        source_labels={c:original_by[c]['source_group'] for c in expected}
        summary['shared_source_group_association']=label_panel(assignments,source_labels,0)
        if name=='source_condition_clusters':
            summary.update(configured_clusters=16,empty_clusters=16-len(set(assignments.values())),
                           unknown_feature_sentinel='source_conditions_unknown',
                           sentinel_records=sum(r['unknown_conditions'] for r in original))
            summary['fold_sizes']=dict(Counter(r['fold'] for r in original))
        report['partitions'][name]=summary
    hierarchy={}
    for depth in range(1,7):
        assignments={c:r['resolution_'+str(depth)] for c,r in cisa_by.items()}
        hierarchy[str(depth)]=dict(occupied_clusters=len(set(assignments.values())),
            association={key:label_panel(assignments,mapping,0) for key,mapping in labels.items()})
    report['cisa_hierarchy_resolutions']=hierarchy
    report['interpretation']=(
        'CWE/CVSS provide auxiliary association, not semantic gold, prerequisite equivalence or VEX accuracy. '
        'Reference-only masks do not change partitions or population. Missing/conflicting metadata remain explicit. '
        'CWE-set categories preserve multi-label references. CVSS versions are separate. '
        'Purity depends on partition granularity; global-majority and shuffled-partition baselines are included. '
        'Metadata and advisory prose may overlap; observed association is not independent validation. '
        'No new LLM calls, clustering or embedding refits are performed.')
    (folder/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    with (folder/'cve_metadata_ledger.jsonl').open('w',encoding='utf-8') as stream:
        for c in sorted(expected):
            stream.write(json.dumps(dict(cve=c,clusters={k:v[c] for k,v in partitions.items()},
                metadata={k:v.get(c) for k,v in labels.items()},
                original_unknown_feature=original_by[c]['unknown_conditions'],
                original_source_group=original_by[c]['source_group'],
                shared_context_only=cisa_truth(cisa_by[c]['cisa_only_shared_context_available'])))+'\n')
    print(json.dumps({name:dict(clusters=p['occupied_clusters'],association={
        key:{k:v['observed_reference_only'].get(k) for k in ['n','weighted_purity','ami','entropy_reduction_fraction']}
        for key,v in p['association'].items()}) for name,p in report['partitions'].items()},indent=2))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,default=ROOT/'results/cluster_auxiliary_analysis_20261124')
    parser.add_argument('--references',type=Path,default=ROOT/'results/prerequisite_auxiliary_population_20261124/references.json')
    parser.add_argument('--permutations',type=int,default=200)
    args=parser.parse_args()
    run(args.folder,args.references,args.permutations)
