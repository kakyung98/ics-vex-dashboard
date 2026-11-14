"""Organize globally fitted CVE clusters into a six-resolution prototype tree.

Leaf assignments are preserved by construction, not independently rediscovered.
Ward acts on unweighted normalized leaf centroids. The full centroid merge tree
is contracted to six declared nested resolutions. All target CVEs stay assigned.
"""
import argparse
from itertools import combinations
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import sys
import time

import numpy as np
from scipy.cluster.hierarchy import cut_tree,linkage
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import normalize
from threadpoolctl import threadpool_limits
import torch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src import item4_ssl_hierarchy as h,item4_silhouette_search as s,gpu_lease
from src.training_io import atomic_json,read_json
from tools.run_item4_ssl_hierarchy import sha,jsonl,aggregate


def prototype_tree(x,flat,max_depth=6):
    unique,leaf=np.unique(flat,return_inverse=True);n=len(x);k=len(unique)
    levels=np.zeros((n,max_depth+1),dtype=np.int32)
    nodes=[dict(node_id=0,parent_id=None,depth=0,first_resolution=0,size=n,prototype_count=k)]
    if k==1:return levels,nodes,dict(resolution_counts=[1]*max_depth,raw_centroid_tree_depth=0)
    centroids=normalize(np.stack([x[leaf==i].mean(0) for i in range(k)]))
    z=linkage(centroids,method='ward',metric='euclidean')
    heights=np.zeros(2*k-1,dtype=int)
    for i,row in enumerate(z):heights[k+i]=max(heights[int(row[0])],heights[int(row[1])])+1
    counts=np.clip(np.rint(np.geomspace(2,k,max_depth)).astype(int),2,k);counts[-1]=k
    # Independent cuts avoid SciPy's unpopulated-column edge cases when a batch
    # request repeats counts or contains the unmerged k == number-of-leaves cut.
    cuts=np.stack([cut_tree(z,n_clusters=[int(v)]).ravel() for v in counts],axis=1)
    known={tuple(range(k)):0};next_id=1
    for d in range(1,max_depth+1):
        for label in np.unique(cuts[:,d-1]):
            members=tuple(np.flatnonzero(cuts[:,d-1]==label).tolist())
            points=np.flatnonzero(np.isin(leaf,members))
            parent=np.unique(levels[points,d-1])
            if len(parent)!=1:raise ValueError('Prototype cut crossed a parent')
            if members not in known:
                known[members]=next_id;next_id+=1
                parent_depth=nodes[int(parent[0])]['depth']
                nodes.append(dict(node_id=known[members],parent_id=int(parent[0]),depth=parent_depth+1,
                                  first_resolution=d,size=len(points),prototype_count=len(members)))
            levels[points,d]=known[members]
    h.validate_levels(levels,max_depth)
    if adjusted_rand_score(flat,levels[:,-1])!=1:raise ValueError('Leaf assignments changed')
    return levels,nodes,dict(resolution_counts=counts.tolist(),raw_centroid_tree_depth=int(heights[-1]),
                            contracted_tree_max_depth=max(v['depth'] for v in nodes),
                            leaf_partition_preserved=True,
                            meaning='Six stored nested resolutions; resolution index is not necessarily the actual parent-edge depth')


def encode_for_seed(source,dest,spec,seed,status):
    folder=dest/f'encoding_seed_{seed}';folder.mkdir(exist_ok=True)
    if (folder/'complete.json').exists():return np.load(folder/'vectors.npy')
    base=np.load(source/'inputs'/f"{spec['input']}.npy")
    kind=spec['kind'];latent=spec['latent']
    if kind=='raw':z=normalize(base[:,:latent]).astype(np.float32)
    elif kind=='dae':
        status('prototype_denoising_repeat',candidate=dest.name,seed=seed)
        model,z,training=h.train_dae(base,seed,100,latent=latent)
        torch.save(model.state_dict(),folder/'model.pt');atomic_json(folder/'training.json',training);del model
    else:
        status('prototype_contrastive_repeat',candidate=dest.name,seed=seed)
        model,z,training=s.train_neighbor_contrastive(base,latent,50,seed)
        torch.save(model.state_dict(),folder/'model.pt');atomic_json(folder/'training.json',training);del model
    if z.shape[0]!=12418 or not np.isfinite(z).all():raise ValueError('Incomplete representation')
    np.save(folder/'vectors.npy',z);atomic_json(folder/'complete.json',dict(population=12418,seed=seed))
    return z


def validate_candidate(source,dest,spec,candidate,ids,reference,search,confirmation,status,do_stability):
    dest.mkdir(parents=True,exist_ok=True)
    z=np.load(source/spec['path']/'vectors.npy');labels=np.load(source/candidate['labels_path'])
    if len(z)!=12418 or len(labels)!=12418 or len(set(ids))!=12418:raise ValueError('Every target must be clustered')
    if not (dest/'complete.json').exists():
        status('building_prototype_hierarchy',candidate=dest.name,representation=spec['rep_id'])
        levels,nodes,structure=prototype_tree(z,labels)
        np.save(dest/'levels.npy',levels);atomic_json(dest/'tree.json',nodes);atomic_json(dest/'structure.json',structure)
        search_metrics=h.depth_metrics(z,reference,levels,search)
        confirmation_metrics=h.depth_metrics(z,reference,levels,confirmation)
        for row in search_metrics+confirmation_metrics:row['resolution_level']=row.pop('depth')
        atomic_json(dest/'search_metrics.json',search_metrics);atomic_json(dest/'confirmation_metrics.json',confirmation_metrics)
        status('prototype_exact_full_silhouette',candidate=dest.name,population=12418)
        exact=h.depth_metrics(z,reference,levels,np.arange(12418))
        for row in exact:row['resolution_level']=row.pop('depth')
        atomic_json(dest/'full_population_metrics.json',exact)
        jsonl(dest/'cve_assignments.jsonl',(dict(cve=c,depth_labels=levels[i].tolist(),assigned=True) for i,c in enumerate(ids)))
        atomic_json(dest/'selection.json',dict(spec=spec,flat_candidate=candidate,leaf_preservation=True))
        atomic_json(dest/'complete.json',dict(population=12418,excluded=0,max_depth=6,clusters=exact[5]['clusters'],
                                             full_native_silhouette=exact[5]['native_cosine_silhouette'],
                                             full_reference_silhouette=exact[5]['reference_cosine_silhouette']))
    else:levels=np.load(dest/'levels.npy')
    if not do_stability:return []
    jobs=[(np.arange(12418),levels,'seed_42','seed')]
    for seed in [43,44,45,46]:
        folder=dest/f'seed_{seed}';folder.mkdir(exist_ok=True)
        if (folder/'complete.json').exists():v=np.load(folder/'levels.npy')
        else:
            zz=encode_for_seed(source,dest,spec,seed,status)
            status('prototype_seed_stability',candidate=dest.name,seed=seed)
            other,_=s.gpu_kmeans(zz,candidate['requested_k'],seed=seed)
            other,_=s.merge_small(zz,other,30)
            v,nodes,structure=prototype_tree(zz,other)
            np.save(folder/'levels.npy',v);atomic_json(folder/'tree.json',nodes)
            atomic_json(folder/'complete.json',dict(population=12418,structure=structure))
        jobs.append((np.arange(12418),v,f'seed_{seed}','seed'))
    base=np.load(source/'inputs'/f"{spec['input']}.npy")
    groups=np.array([hashlib.sha256(row.tobytes()).hexdigest() for row in base])
    for repeat in range(10):
        ix=h.grouped_subsample(groups,.8,5000+repeat)
        folder=dest/f'subsample_{repeat:02}';folder.mkdir(exist_ok=True)
        if (folder/'complete.json').exists():v=np.load(folder/'levels.npy')
        else:
            status('prototype_subsample_stability',candidate=dest.name,sample=repeat+1,total=10)
            other,_=s.gpu_kmeans(z[ix],candidate['requested_k'],seed=42)
            other,_=s.merge_small(z[ix],other,30)
            v,nodes,structure=prototype_tree(z[ix],other)
            np.save(folder/'indices.npy',ix);np.save(folder/'levels.npy',v);atomic_json(folder/'tree.json',nodes)
            atomic_json(folder/'complete.json',dict(population=len(ix),structure=structure))
        jobs.append((ix,v,f'subsample_{repeat:02}','frozen_resample'))
    summaries=[];pairs=[]
    for family in ['seed','frozen_resample']:
        selected=[j for j in jobs if j[3]==family]
        for a,b in combinations(selected,2):
            for row in h.aligned_ari(a[0],a[1],b[0],b[1]):
                row['resolution_level']=row.pop('depth')
                pairs.append(dict(family=family,run_a=a[2],run_b=b[2],**row))
        for d in range(1,7):
            part=[r for r in pairs if r['family']==family and r['resolution_level']==d]
            summaries.append(dict(candidate=dest.name,family=family,resolution_level=d,runs=len(selected),pairs=len(part),
                                  ari=aggregate([r['ari'] for r in part if not r['degenerate']]),
                                  degenerate_pairs=sum(r['degenerate'] for r in part),
                                  common_cves=aggregate([r['common_cves'] for r in part])))
    jsonl(dest/'ari_pairs.jsonl',pairs);atomic_json(dest/'stability_summary.json',summaries)
    return summaries


def main(args):
    source=ROOT/args.source;out=ROOT/args.output;out.mkdir(parents=True,exist_ok=True)
    protocol=read_json(source/'protocol.json')
    rows=list(map(json.loads,(source/'cve_rows.jsonl').open(encoding='utf-8')));ids=[r['cve'] for r in rows]
    expected={json.loads(l)['cve'] for l in (ROOT/'data/item3_ics_cert_full_v1/cves.jsonl').open(encoding='utf-8')}
    if len(ids)!=12418 or len(set(ids))!=12418 or set(ids)!=expected:raise ValueError('Population mismatch')
    screening=list(map(json.loads,(source/'screening_results.jsonl').open(encoding='utf-8')))
    if len(screening)!=210 or any(r['population']!=12418 or r['retention']!=1 for r in screening):raise ValueError('Incomplete full-population screening')
    specs={s['rep_id']:s for s in read_json(source/'representation_specs.json')}
    good=[r for r in screening if r['eligible']];trained=[r for r in good if r['kind']!='raw']
    candidates={
        'best_reference':max(good,key=lambda r:r['reference_search_silhouette']),
        'best_trained_reference':max(trained,key=lambda r:r['reference_search_silhouette']),
        'best_native':max(good,key=lambda r:r['native_search_silhouette']),
        'best_cisa_reference':max((r for r in good if r['input'].startswith('cisa_')),key=lambda r:r['reference_search_silhouette'])}
    config=dict(schema='item4-prototype-hierarchy/1',population=12418,max_depth=6,source_protocol_sha256=sha(source/'protocol.json'),
                screening_sha256=sha(source/'screening_results.jsonl'),selection_queries='Search cohort only; confirmation cohort unused in selection',
                method='Global leaf K-means, then unweighted Ward on normalized centroids, contracted to six geometric-count resolutions',
                leaf_labels_preserved=True,cwe_depth_reference=protocol['cwe_depth_reference'],
                seeds=[42,43,44,45,46],frozen_resamples=10,subsample_fraction=.8,
                all_target_cves_assigned=True,llm_used=False,script_sha256=sha(__file__),
                caveat='Higher leaf score comes from the global leaf partition, not independent hierarchical rediscovery')
    previous=read_json(out/'protocol.json')
    if previous and previous!=config:raise ValueError('Changed prototype protocol; choose new output')
    atomic_json(out/'protocol.json',config);atomic_json(out/'selected_candidates.json',candidates)
    snap=out/'code_snapshot';snap.mkdir(exist_ok=True);shutil.copyfile(Path(__file__),snap/Path(__file__).name)
    q=read_json(source/'evaluation_queries.json');search=np.array(q['search']);confirmation=np.array(q['confirmation'])
    reference=np.load(source/'inputs/current_mix.npy');torch.set_num_threads(4);started=time.monotonic()
    def status(phase,**kw):
        value=dict(phase=phase,pid=os.getpid(),seconds=round(time.monotonic()-started,1),**kw)
        atomic_json(out/'status.json',value);print(json.dumps(value),flush=True)
    lease=read_json(gpu_lease.FILE)
    if lease.get('active') and any(gpu_lease.alive(lease.get(k)) for k in ['pid','child_pid']):raise RuntimeError('GPU is busy')
    atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=True,purpose='Full population prototype hierarchy',output=str(out)))
    try:
        summaries=[];results=[]
        with threadpool_limits(limits=4):
            for name,candidate in candidates.items():
                dest=out/name
                summaries.extend(validate_candidate(source,dest,specs[candidate['rep_id']],candidate,ids,reference,search,confirmation,status,args.stage=='all'))
                results.append(dict(candidate=name,representation=candidate['rep_id'],**read_json(dest/'complete.json')))
        atomic_json(out/'results.json',results)
        if summaries:atomic_json(out/'stability_summary.json',summaries)
        table=''.join('<tr>'+''.join('<td>'+html.escape(str(v))+'</td>' for v in [r['candidate'],r['representation'],r['clusters'],
                       f"{r['full_native_silhouette']:.4f}",f"{r['full_reference_silhouette']:.4f}",r['population']])+'</tr>' for r in results)
        page='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>#4 전역 군집 기반 계층</title>
<style>body{font:16px system-ui;max-width:1300px;margin:36px auto;padding:0 20px;line-height:1.6}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:8px}</style>
<h1>12,418개 전수: 전역 잎 군집 + 프로토타입 계층</h1>
<p>먼저 전역 군집을 생성하고 그 군집 중심에 Ward 상위 계층을 구성했습니다. 원래 중심 병합 이력은 더 깊을 수 있지만 저장한 모델은 여섯 개 중첩 해상도로 축약했습니다. 첫 전체 루트는 0이며 저장한 부모·자식 계층의 실제 깊이는 최대 6입니다. 해상도 번호는 실제 부모 간선 깊이와 다를 수 있으며, 기존 재귀 분할의 같은 숫자 깊이와 동일한 척도로 해석하지 않습니다. 각 단계가 CWE 의미 수준이라는 뜻은 아닙니다.</p>
<p>최종 잎 군집을 그대로 유지하므로 평면 단계의 점수를 계층이 독립적으로 재발견했다는 뜻이 아닙니다. 중간 계층의 실제 군집 수와 점수도 모두 저장합니다. 12,418개 CVE는 빠짐없이 배정하며 최종 Silhouette는 12,418개 전체를 질의점과 비교 대상으로 사용합니다.</p>
<p>입력·표현을 바꾼 native 점수와 고정 참조 점수를 구분합니다. 권고문을 공유하는 CVE의 정보 중복이 native 점수를 높일 수 있습니다. 높은 점수가 곧 운영 질문·악용 가능성·VEX 정확도라는 주장은 하지 않습니다.</p>
<table><tr><th>선택 기준</th><th>표현</th><th>실제 잎 군집 수</th><th>Native 전수 Silhouette</th><th>Reference 전수 Silhouette</th><th>CVE 수</th></tr>__TABLE__</table>
<p>각 후보 디렉터리에 전수 배정 cve_assignments.jsonl, 깊이별 전수 지표 full_population_metrics.json, 계층 tree.json과 structure.json을 저장합니다. stability_summary.json은 초기값 5회와 표현 고정 재표집 10회의 깊이별 ARI입니다. 표현을 포함한 seed 반복과 표현 고정 재표집을 구분하며, 이 후속 실험은 전처리부터 재표집한 일반화 시험이 아닙니다.</p></html>'''
        (out/'report.html').write_text(page.replace('__TABLE__',table),encoding='utf-8')
        atomic_json(out/'verification.json',dict(population=12418,unique_cves=len(set(ids)),candidates=len(results),
                    all_final_cves_assigned=True,excluded_cves=0,leaf_partitions_preserved=True,
                    max_stored_hierarchy_depth=6,final_silhouette_query_population=12418,stability_complete=args.stage=='all'))
        atomic_json(out/'manifest.json',{str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p.name not in ['manifest.json','status.json']})
        status('complete' if args.stage=='all' else 'hierarchies_complete',population=12418,candidates=len(results))
    except Exception as e:status('failed',error=repr(e));raise
    finally:
        if read_json(gpu_lease.FILE).get('pid')==os.getpid():atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,purpose='Prototype hierarchy released'))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',default='results/item4_cisa_silhouette_search_v1')
    p.add_argument('--output',default='results/item4_prototype_hierarchy_v1')
    p.add_argument('--stage',choices=['hierarchy','all'],default='all')
    main(p.parse_args())
