"""Search non-LLM CISA representations without dropping any target CVEs.

Flat GPU K-means is a screening stage, not a substitute for bounded hierarchical
validation. Search and confirmation query cohorts are fixed before screening.
"""
import argparse
from collections import defaultdict
import hashlib
import html
import json
from pathlib import Path
import shutil
import sys
import time
import os

import joblib
import numpy as np
import torch
from sklearn.preprocessing import normalize
from threadpoolctl import threadpool_limits

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src import item4_ssl_hierarchy as h,item4_silhouette_search as s,gpu_lease
from src.training_io import atomic_json,read_json
from tools.run_item4_ssl_hierarchy import sha,jsonl,aggregate


def check_population(x,n=12418):
    if len(x)!=n or not np.isfinite(x).all():raise ValueError('Every representation must contain all 12,418 finite CVE vectors')
    if np.any(np.linalg.norm(x,axis=1)<1e-9):raise ValueError('Zero vector: no CVE may be silently removed')


def setup(args):
    out=ROOT/args.output;out.mkdir(parents=True,exist_ok=True)
    source=ROOT/'results/ics_sentence_conditions_v1/full_inputs.jsonl'
    rows=sorted(map(json.loads,source.open(encoding='utf-8')),key=lambda r:r['cve'])
    ids=[r['cve'] for r in rows]
    expected={json.loads(l)['cve'] for l in (ROOT/'data/item3_ics_cert_full_v1/cves.jsonl').open(encoding='utf-8')}
    if len(ids)!=12418 or len(set(ids))!=12418 or set(ids)!=expected:raise ValueError('Population mismatch')
    reference_protocol=read_json(ROOT/'results/item4_ssl_hierarchy_v1/protocol.json')
    if reference_protocol.get('source_sha256')!=sha(source) or reference_protocol.get('depth',{}).get('max_depth')!=6:
        raise ValueError('Frozen reference source/CWE depth mismatch')
    config=dict(schema='item4-cisa-silhouette-search/1',population=12418,source_sha256=sha(source),
                advisory_cache_sha256=sha(ROOT/'data/cisa_advisories.json'),reference='Original full-population mixed-source SVD256, frozen',
                input_views=['current_mix','cisa_scoped','cisa_context','cisa_advisory_pool','balanced_views'],
                representations=['raw64','raw128','raw256','dae32','dae64','neighbor32','neighbor64'],
                training_labels=[],llm_used=False,pretrained_language_model_used=False,
                screening_k=[4,8,16,32,64,128],kmeans_init=3,kmeans_iterations=80,min_cluster=30,
                small_cluster_policy='Merge small clusters into closest large centroid; retain every point',
                screen_query_count=1000,confirmation_query_count=1000,
                primary_selection='Reference silhouette on search queries; full retention; largest share <= .65',
                secondary_selection='Native-space silhouette retained separately; not declared semantic improvement',
                hierarchy_max_depth=6,cwe_depth_reference=reference_protocol['depth'],dae_epochs=100,neighbor_epochs=50,
                sources={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__).resolve(),ROOT/'src/item4_silhouette_search.py',ROOT/'src/item4_ssl_hierarchy.py']})
    prior=read_json(out/'protocol.json')
    if prior and prior!=config:raise ValueError('Search protocol changed; choose a new output')
    atomic_json(out/'protocol.json',config)
    snap=out/'code_snapshot';snap.mkdir(exist_ok=True)
    for source_name in config['sources']:
        dest=snap/Path(source_name).name
        if not dest.exists():shutil.copyfile(ROOT/source_name,dest)
    jsonl(out/'cve_rows.jsonl',(dict(row=i,cve=c,identity_ambiguous=rows[i].get('identity_ambiguous'),
          original_excluded_flag=rows[i].get('excluded')) for i,c in enumerate(ids)))
    return out,rows,ids,config


def prepare(out,ids,status):
    folder=out/'inputs';folder.mkdir(exist_ok=True)
    if (folder/'complete.json').exists():return
    baseline=ROOT/'results/item4_ssl_hierarchy_v1'
    ref=np.load(baseline/'full_features/vectors.npy');check_population(ref)
    baseline_ids=[r['cve'] for r in map(json.loads,(baseline/'corpus_index.jsonl').open(encoding='utf-8'))]
    if baseline_ids!=ids:raise ValueError('Reference row alignment mismatch')
    np.save(folder/'current_mix.npy',ref)
    status('preparing_cisa_sources')
    data=s.cisa_inputs(read_json(ROOT/'data/cisa_advisories.json'),ids,ROOT/'data/public_sbom/20261101T113013Z/csaf')
    atomic_json(out/'input_coverage.json',data['coverage'])
    jsonl(out/'cve_advisory_links.jsonl',data['ledger']);jsonl(out/'advisory_provenance.jsonl',data['provenance'])
    jsonl(out/'advisory_documents.jsonl',(dict(advisory_id=a,text=t) for a,t in zip(data['doc_ids'],data['documents'])))
    for key in ['scoped','context']:
        status('fitting_cisa_features',view=key)
        fitted,x=h.fit_features(data[key],256);check_population(x)
        joblib.dump(fitted,folder/f'cisa_{key}_preprocessing.joblib');np.save(folder/f'cisa_{key}.npy',x)
    status('fitting_cisa_features',view='advisory_documents')
    fitted,doc_vectors=h.fit_features(data['documents'],256)
    pooled=s.pool_advisories(doc_vectors,data['links']);check_population(pooled)
    joblib.dump(fitted,folder/'advisory_preprocessing.joblib');np.save(folder/'advisory_vectors.npy',doc_vectors)
    np.save(folder/'cisa_advisory_pool.npy',pooled)
    context=np.load(folder/'cisa_context.npy')
    balanced=normalize(np.concatenate([normalize(ref[:,:128]),normalize(context[:,:128])],axis=1)).astype(np.float32)
    check_population(balanced);np.save(folder/'balanced_views.npy',balanced)
    atomic_json(folder/'complete.json',dict(population=12418,views=5,excluded=0,coverage=data['coverage']))


def representation(out,input_name,kind,latent,seed,status):
    rep_id=f'{input_name}_{kind}{latent}_seed{seed}'
    dest=out/'representations'/rep_id;dest.mkdir(parents=True,exist_ok=True)
    spec=dict(rep_id=rep_id,input=input_name,kind=kind,latent=latent,seed=seed,path=str(dest.relative_to(out)))
    if (dest/'complete.json').exists():
        z=np.load(dest/'vectors.npy');check_population(z);return spec,z
    x=np.load(out/'inputs'/f'{input_name}.npy');check_population(x)
    if kind=='raw':z=normalize(x[:,:latent]).astype(np.float32);training=None
    elif kind=='dae':
        status('denoising_self_supervision',representation=rep_id)
        model,z,training=h.train_dae(x,seed,100,latent=latent,callback=lambda row:status('denoising_self_supervision',representation=rep_id,**row))
        torch.save(dict(state_dict=model.state_dict(),spec=spec),dest/'model.pt');del model
    else:
        status('neighbor_contrastive_self_supervision',representation=rep_id)
        model,z,training=s.train_neighbor_contrastive(x,latent,50,seed,callback=lambda row:status('neighbor_contrastive_self_supervision',representation=rep_id,**row))
        torch.save(dict(state_dict=model.state_dict(),spec=spec),dest/'model.pt');del model
    check_population(z)
    np.save(dest/'vectors.npy',z)
    if training:atomic_json(dest/'training_history.json',training)
    atomic_json(dest/'complete.json',dict(spec=spec,population=12418,finite=True,excluded=0))
    torch.cuda.empty_cache()
    return spec,z


def run_screen(out,ids,config,status):
    ref=np.load(out/'inputs/current_mix.npy')
    order=np.argsort([hashlib.sha256(('evaluation-query:'+c).encode()).hexdigest() for c in ids])
    search=np.sort(order[:1000]);confirmation=np.sort(order[1000:2000])
    atomic_json(out/'evaluation_queries.json',dict(search=search.tolist(),confirmation=confirmation.tolist(),
                note='Disjoint scoring cohorts; model fitting is transductive on all 12,418 CVEs, not an unseen-CVE generalization test'))
    reference_distance=h.cosine_distances(ref,search)
    records=[];specs=[]
    for input_name in config['input_views']:
        for kind,latent in [('raw',64),('raw',128),('raw',256),('dae',32),('dae',64),('neighbor',32),('neighbor',64)]:
            spec,z=representation(out,input_name,kind,latent,42,status);specs.append(spec)
            rep_dir=out/spec['path'];cached=read_json(rep_dir/'screening.json')
            if cached:
                records.extend(cached);continue
            native=h.cosine_distances(z,search);local=[]
            for k in config['screening_k']:
                status('gpu_screening',representation=spec['rep_id'],k=k,completed_representations=len(specs)-1,total_representations=35)
                labels,fit=s.gpu_kmeans(z,k)
                labels,merged=s.merge_small(z,labels,30)
                counts=np.bincount(labels)
                if len(labels)!=12418 or np.any(labels<0) or counts.min()<30:raise ValueError('Full retention/minimum size violated')
                score=h.sampled_silhouette(reference_distance,labels,search)
                ns=h.sampled_silhouette(native,labels,search)
                r=dict(rep_id=spec['rep_id'],input=input_name,kind=kind,latent=latent,requested_k=k,
                       actual_clusters=len(counts),population=12418,retention=1.,minimum_size=int(counts.min()),
                       largest_share=float(counts.max()/12418),small_clusters_merged=merged,
                       reference_search_silhouette=score,native_search_silhouette=ns,
                       eligible=bool(len(counts)>1 and counts.max()/12418<=.65 and score is not None),
                       labels_path=str((rep_dir/f'labels_k{k}.npy').relative_to(out)))
                np.save(out/r['labels_path'],labels);records.append(r);local.append(r)
            atomic_json(rep_dir/'screening.json',local);jsonl(out/'screening_results.jsonl',records)
    atomic_json(out/'representation_specs.json',specs);jsonl(out/'screening_results.jsonl',records)
    by_rep={}
    for r in records:
        if r['eligible'] and (r['rep_id'] not in by_rep or r['reference_search_silhouette']>by_rep[r['rep_id']]['reference_search_silhouette']):by_rep[r['rep_id']]=r
    if not by_rep:raise ValueError('No eligible screening candidate; all CVEs still preserved')
    ranking=sorted(by_rep.values(),key=lambda r:r['reference_search_silhouette'],reverse=True)
    chosen=[]
    for r in ranking:
        if not any(c['input']==r['input'] for c in chosen):chosen.append(r)
        if len(chosen)>=3:break
    trained=next((r for r in ranking if r['kind']!='raw'),None)
    native_best=max((r for r in records if r['eligible']),key=lambda r:r['native_search_silhouette'])
    for r in [trained,native_best]:
        if r and r['rep_id'] not in {v['rep_id'] for v in chosen}:chosen.append(r)
    atomic_json(out/'screening_ranking.json',dict(best_per_representation=ranking,best_native=native_best,
                hierarchical_shortlist=chosen,selection_note='Diverse inputs plus best trained and best native; screening scores are not final hierarchical scores'))
    return specs,chosen,search,confirmation


def validate_hierarchies(out,ids,specs,chosen,search,confirmation,status):
    ref=np.load(out/'inputs/current_mix.npy');specs={s['rep_id']:s for s in specs}
    summaries=[]
    for candidate in chosen:
        spec=specs[candidate['rep_id']];z=np.load(out/spec['path']/'vectors.npy')
        for method in ['kmeans','ward']:
            dest=out/'hierarchies'/spec['rep_id']/method;dest.mkdir(parents=True,exist_ok=True)
            if (dest/'complete.json').exists():m=read_json(dest/'complete.json')
            else:
                status('hierarchical_validation',representation=spec['rep_id'],method=method)
                levels,nodes=h.recursive_partition(z,method,max_depth=6,seed=42,min_child=30,min_parent=100)
                if levels.shape!=(12418,7):raise ValueError('Incomplete final hierarchy')
                np.save(dest/'levels.npy',levels);atomic_json(dest/'tree.json',nodes)
                search_m=h.depth_metrics(z,ref,levels,search)
                confirmation_m=h.depth_metrics(z,ref,levels,confirmation)
                atomic_json(dest/'search_metrics.json',search_m);atomic_json(dest/'confirmation_metrics.json',confirmation_m)
                m=dict(rep_id=spec['rep_id'],spec=spec,method=method,path=str(dest.relative_to(out)),population=12418,
                       primary_depth=6,reference_search_silhouette=search_m[5]['reference_cosine_silhouette'],
                       native_search_silhouette=search_m[5]['native_cosine_silhouette'],
                       reference_confirmation_silhouette=confirmation_m[5]['reference_cosine_silhouette'],
                       native_confirmation_silhouette=confirmation_m[5]['native_cosine_silhouette'],
                       clusters=search_m[5]['clusters'],minimum_size=search_m[5]['min_cluster_size'],
                       largest_share=search_m[5]['largest_cluster_share'],
                       eligible=bool(search_m[5]['clusters']>1 and search_m[5]['largest_cluster_share']<=.65))
                atomic_json(dest/'complete.json',m)
            summaries.append(m);atomic_json(out/'hierarchy_results.json',summaries)
    good=[r for r in summaries if r['eligible']]
    if not good:raise ValueError('No eligible hierarchy; no points were removed')
    winners=dict(best_reference=max(good,key=lambda r:r['reference_search_silhouette']),
                 best_native=max(good,key=lambda r:r['native_search_silhouette']))
    atomic_json(out/'selected_candidates.json',winners)
    for name,winner in winners.items():
        dest=out/'final'/name;dest.mkdir(parents=True,exist_ok=True)
        z=np.load(out/winner['spec']['path']/'vectors.npy');levels=np.load(out/winner['path']/'levels.npy')
        if not (dest/'full_population_metrics.json').exists():
            status('exact_full_population_silhouette',winner=name,population=12418)
            metrics=h.depth_metrics(z,ref,levels,np.arange(12418))
            atomic_json(dest/'full_population_metrics.json',metrics)
        np.save(dest/'levels.npy',levels)
        jsonl(dest/'cve_assignments.jsonl',(dict(cve=c,depth_labels=levels[i].tolist(),assigned=True) for i,c in enumerate(ids)))
        atomic_json(dest/'selection.json',winner)
    return winners


def stability(out,ids,winners,status):
    summaries=[]
    for name,winner in winners.items():
        spec=winner['spec'];method=winner['method'];ref_levels=np.load(out/winner['path']/'levels.npy')
        full_z=np.load(out/spec['path']/'vectors.npy');base=np.load(out/'inputs'/f"{spec['input']}.npy")
        dest=out/'final'/name;indices_all=np.arange(12418)
        jobs=[(indices_all,ref_levels,'seed_42','seed')]
        for seed in [43,44,45,46]:
            folder=dest/f'seed_{seed}';folder.mkdir(exist_ok=True)
            if (folder/'complete.json').exists():levels=np.load(folder/'levels.npy')
            else:
                _,z=representation(out,spec['input'],spec['kind'],spec['latent'],seed,status)
                status('selected_seed_stability',winner=name,seed=seed)
                levels,nodes=h.recursive_partition(z,method,max_depth=6,seed=seed)
                np.save(folder/'levels.npy',levels);atomic_json(folder/'tree.json',nodes)
                atomic_json(folder/'complete.json',dict(population=12418))
            jobs.append((indices_all,levels,f'seed_{seed}','seed'))
        # Exact representation duplicates are kept together. This is frozen-view stability.
        groups=np.array([hashlib.sha256(row.tobytes()).hexdigest() for row in base])
        for i in range(10):
            ix=h.grouped_subsample(groups,.8,3000+i)
            folder=dest/f'subsample_{i:02}';folder.mkdir(exist_ok=True)
            if (folder/'complete.json').exists():levels=np.load(folder/'levels.npy')
            else:
                status('selected_resampling_stability',winner=name,sample=i+1,total=10)
                levels,nodes=h.recursive_partition(full_z[ix],method,max_depth=6,seed=42)
                np.save(folder/'indices.npy',ix);np.save(folder/'levels.npy',levels)
                atomic_json(folder/'tree.json',nodes);atomic_json(folder/'complete.json',dict(population=len(ix)))
            jobs.append((ix,levels,f'subsample_{i:02}','frozen_resample'))
        pairs=[]
        from itertools import combinations
        for family in ['seed','frozen_resample']:
            selected=[j for j in jobs if j[3]==family]
            for a,b in combinations(selected,2):
                for row in h.aligned_ari(a[0],a[1],b[0],b[1]):pairs.append(dict(winner=name,family=family,run_a=a[2],run_b=b[2],**row))
            for depth in range(1,7):
                chosen=[p for p in pairs if p['family']==family and p['depth']==depth]
                summaries.append(dict(winner=name,family=family,depth=depth,runs=len(selected),pairs=len(chosen),
                                      ari=aggregate([p['ari'] for p in chosen if not p['degenerate']]),
                                      degenerate_pairs=sum(p['degenerate'] for p in chosen),
                                      common_cves=aggregate([p['common_cves'] for p in chosen])))
        jsonl(dest/'ari_pairs.jsonl',pairs)
    atomic_json(out/'selected_stability.json',summaries)
    return summaries


def report(out,winners):
    records=list(map(json.loads,(out/'screening_results.jsonl').open(encoding='utf-8')))
    per_rep={}
    for r in records:
        if r['eligible'] and (r['rep_id'] not in per_rep or r['reference_search_silhouette']>per_rep[r['rep_id']]['reference_search_silhouette']):per_rep[r['rep_id']]=r
    table=''.join('<tr>'+''.join('<td>'+html.escape(str(v))+'</td>' for v in [r['rep_id'],r['requested_k'],r['actual_clusters'],
                     f"{r['native_search_silhouette']:.4f}",f"{r['reference_search_silhouette']:.4f}",r['population']])+'</tr>' for r in sorted(per_rep.values(),key=lambda r:r['reference_search_silhouette'],reverse=True))
    blocks=[]
    for name,w in winners.items():
        exact=read_json(out/'final'/name/'full_population_metrics.json')
        blocks.append('<h2>'+name+'</h2><pre>'+html.escape(json.dumps(dict(representation=w['rep_id'],method=w['method'],depth6=exact[5]),ensure_ascii=False,indent=2))+'</pre>')
    page='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>#4 CISA 입력·표현 탐색</title>
<style>body{font:15px system-ui;max-width:1300px;margin:36px auto;padding:0 20px;line-height:1.6}td,th{border:1px solid #ccc;padding:7px}table{border-collapse:collapse;width:100%}pre{white-space:pre-wrap}</style>
<h1>12,418개 전수: CISA 입력·자기지도 표현 탐색</h1>
<p>어려운 CVE·모호한 식별자·낮은 점수를 이유로 제외하지 않습니다. 모든 유효 후보는 12,418개를 배정합니다. 작은 군집은 점을 버리지 않고 가까운 큰 군집에 병합합니다. 재표집은 안정성 평가에서만 사용합니다.</p>
<p>현재 혼합 입력, CISA CVE별 설명, CISA 공유 맥락 추가, 권고문 임베딩의 CVE별 평균, 두 입력의 균형 결합을 비교합니다. raw는 자기지도학습 없는 기준선, dae는 Denoising Autoencoder, neighbor는 특성 이웃을 양성 쌍으로 삼는 대조 자기지도학습입니다. LLM·사전학습 언어모델·CWE 정답 라벨은 쓰지 않습니다.</p>
<p>권고문 공유 맥락과 문서 임베딩은 여러 CVE에 반복될 수 있습니다. 높은 native Silhouette가 문서·제품 공유를 반영할 수 있으므로 공통 참조 점수와 함께 해석해야 합니다. 공유 맥락을 CVE별 악용 전제조건으로 주장하지 않습니다.</p>
<p>GPU 평면 K-means는 1차 탐색입니다. 선택 후보는 최대 깊이 6의 실제 계층으로 다시 평가합니다. 비교 깊이는 사전에 6으로 고정하며 모든 깊이의 결과를 저장합니다. 탐색·확인 질의점은 각각 1,000개로 분리했습니다. 모델 자체는 전수 학습이므로 새로운 CVE에 대한 독립 일반화 시험은 아닙니다. 최종 두 후보에는 12,418개 전수 Silhouette도 계산합니다.</p>
<p><strong>입력·표현 공간을 바꿔 얻은 native 점수와 고정 참조 점수를 혼용하지 않습니다. 분리도·안정성은 운영 질문·악용 가능성·VEX 정확도의 정답 평가가 아닙니다.</strong></p>
__BLOCKS__<table><tr><th>표현</th><th>요청 K</th><th>실제 군집</th><th>Native(탐색)</th><th>Reference(탐색)</th><th>CVE 수</th></tr>__TABLE__</table>
<p>전체 탐색값은 screening_results.jsonl, 계층 결과는 hierarchy_results.json, 최종 전수 배정은 final/*/cve_assignments.jsonl, 반복·재표집은 selected_stability.json을 확인합니다.</p></html>'''
    (out/'report.html').write_text(page.replace('__TABLE__',table).replace('__BLOCKS__',''.join(blocks)),encoding='utf-8')


def main(args):
    torch.set_num_threads(4);out,rows,ids,config=setup(args);start=time.monotonic()
    def status(phase,**kw):
        value=dict(phase=phase,pid=os.getpid(),seconds=round(time.monotonic()-start,1),**kw)
        atomic_json(out/'status.json',value);print(json.dumps(value),flush=True)
    with threadpool_limits(limits=4):
        prepare(out,ids,status)
        if args.stage=='prepare':status('prepared',population=12418);return
        if not torch.cuda.is_available():raise RuntimeError('CUDA required')
        lease=read_json(gpu_lease.FILE)
        if lease.get('active') and any(gpu_lease.alive(lease.get(k)) for k in ['pid','child_pid']):raise RuntimeError('Another GPU job is active; preparations are retained')
        atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=True,purpose='Full population CISA silhouette search',output=str(out)))
        try:
            if args.stage!='validate':specs,chosen,search,confirmation=run_screen(out,ids,config,status)
            else:
                specs=read_json(out/'representation_specs.json');chosen=read_json(out/'screening_ranking.json')['hierarchical_shortlist']
                q=read_json(out/'evaluation_queries.json');search=np.array(q['search']);confirmation=np.array(q['confirmation'])
            winners=validate_hierarchies(out,ids,specs,chosen,search,confirmation,status)
            atomic_json(out/'search_summary.json',dict(population=12418,representations=35,screening_fits=210,
                        hierarchy_candidates=len(chosen)*2,full_retention=True,primary_depth=6,winners=winners,
                        independent_semantic_accuracy=None))
            if args.stage in ['all','validate']:stability(out,ids,winners,status)
            report(out,winners)
            atomic_json(out/'verification.json',dict(population=12418,unique_cves=len(set(ids)),all_candidates_retain_all_cves=True,
                        all_final_cves_assigned=True,excluded_cves=0,primary_depth=6,final_silhouette_query_population=12418))
            atomic_json(out/'manifest.json',{str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p.name not in ['manifest.json','status.json']})
            status('complete' if args.stage in ['all','validate'] else 'search_complete',population=12418)
        except Exception as exc:status('failed',error=repr(exc));raise
        finally:
            if read_json(gpu_lease.FILE).get('pid')==os.getpid():atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,purpose='CISA search released'))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='results/item4_cisa_silhouette_search_v1')
    parser.add_argument('--stage',choices=['prepare','search','validate','all'],default='all')
    main(parser.parse_args())
