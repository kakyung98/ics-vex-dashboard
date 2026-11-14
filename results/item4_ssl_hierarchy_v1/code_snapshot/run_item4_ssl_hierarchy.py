"""Run and resume Item #4 self-supervised / hierarchical stability comparisons."""
import argparse
from collections import defaultdict
import hashlib
import html
import importlib.metadata
from itertools import combinations
import json
import os
from pathlib import Path
import shutil
import sys
import time

import joblib
import numpy as np
import torch
from threadpoolctl import threadpool_limits

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src import gpu_lease
from src import item4_ssl_hierarchy as study
from src.training_io import atomic_json,read_json

METHODS={'svd_kmeans':('svd','kmeans'),'ssl_kmeans':('ssl','kmeans'),'ssl_ward':('ssl','ward')}


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def jsonl(path,rows):
    with Path(path).open('w',encoding='utf-8') as f:
        for row in rows:f.write(json.dumps(row,ensure_ascii=False)+'\n')


def aggregate(values):
    x=np.asarray([v for v in values if v is not None],dtype=float)
    return dict(n=len(x),mean=float(x.mean()) if len(x) else None,std=float(x.std()) if len(x) else None,
                p10=float(np.quantile(x,.1)) if len(x) else None,p90=float(np.quantile(x,.9)) if len(x) else None,
                min=float(x.min()) if len(x) else None,max=float(x.max()) if len(x) else None)


def evaluate_stability(out,jobs,depth):
    cached={j['job_id']:(np.load(out/j['path']/'indices.npy'),np.load(out/j['path']/'levels.npy')) for j in jobs}
    grouped=defaultdict(list)
    for j in jobs:grouped[(j['family'],j['method'])].append(j)
    pairs=[];summaries=[]
    for (family,method),group in grouped.items():
        bucket=defaultdict(list)
        for a,b in combinations(group,2):
            ia,la=cached[a['job_id']];ib,lb=cached[b['job_id']]
            for metric in study.aligned_ari(ia,la,ib,lb):
                pair=dict(family=family,method=method,run_a=a['job_id'],run_b=b['job_id'],**metric)
                pairs.append(pair);bucket[metric['depth']].append(pair)
        for d in range(1,depth+1):
            rows=bucket[d]
            summaries.append(dict(family=family,method=method,depth=d,runs=len(group),pairs=len(rows),
                                  ari_all_pairs=aggregate([r['ari'] for r in rows]),
                                  ari_nondegenerate_pairs=aggregate([r['ari'] for r in rows if not r['degenerate']]),
                                  degenerate_pairs=sum(r['degenerate'] for r in rows),
                                  common_cves=aggregate([r['common_cves'] for r in rows])))
    jsonl(out/'ari_pairs.jsonl',pairs)
    atomic_json(out/'stability_summary.json',summaries)
    agreement=[]
    by_run=defaultdict(list)
    for j in jobs:by_run[j['run_id']].append(j)
    for run,group in by_run.items():
        for a,b in combinations(group,2):
            ia,la=cached[a['job_id']];ib,lb=cached[b['job_id']]
            for row in study.aligned_ari(ia,la,ib,lb):agreement.append(dict(run_id=run,method_a=a['method'],method_b=b['method'],**row))
    jsonl(out/'cross_method_agreement.jsonl',agreement)
    return summaries


def summarize(out,jobs,stability,depth):
    metrics=[]
    for j in jobs:
        for m in read_json(out/j['path']/'metrics.json'):
            metrics.append(dict(family=j['family'],method=j['method'],run_id=j['run_id'],**m))
    jsonl(out/'depth_metrics.jsonl',metrics)
    rows=[]
    for family in ['seed','frozen_resample','pipeline_resample']:
        for method in METHODS:
            for d in range(1,depth+1):
                selected=[m for m in metrics if m['family']==family and m['method']==method and m['depth']==d]
                if not selected:continue
                rows.append(dict(family=family,method=method,depth=d,runs=len(selected),
                                 clusters=aggregate([m['clusters'] for m in selected]),
                                 native_silhouette=aggregate([m['native_cosine_silhouette'] for m in selected]),
                                 reference_silhouette=aggregate([m['reference_cosine_silhouette'] for m in selected]),
                                 largest_cluster_share=aggregate([m['largest_cluster_share'] for m in selected])))
    atomic_json(out/'comparison_summary.json',rows)
    ari={(s['family'],s['method'],s['depth']):s for s in stability}
    table=[]
    def fmt(v):return 'N/A' if v is None else f'{v:.4f}'
    for r in rows:
        s=ari[(r['family'],r['method'],r['depth'])]
        table.append('<tr>'+''.join('<td>'+html.escape(str(x))+'</td>' for x in [r['family'],r['method'],r['depth'],
                     fmt(r['clusters']['mean']),fmt(r['native_silhouette']['mean']),fmt(r['reference_silhouette']['mean']),
                     fmt(s['ari_nondegenerate_pairs']['mean']),s['pairs'],s['degenerate_pairs']])+'</tr>')
    report='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>Item #4 자기지도 계층 군집 비교</title>
<style>body{font:15px system-ui;max-width:1450px;margin:36px auto;padding:0 20px;line-height:1.6}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:7px;text-align:left}th{background:#edf2fa}pre{white-space:pre-wrap}</style>
<h1>#4 자기지도학습 후 계층적 비지도 군집화</h1>
<p>12,418개 CVE 전체를 추적합니다. LLM·사전학습 언어모델·CWE 정답 라벨은 사용하지 않습니다. 모델 입력은 CVE별 출처 원문입니다. 식별 모호성·기존 제외 표시는 메타데이터로 보존하며, 이 실험에서는 텍스트를 임의 수정하거나 CVE를 조용히 제외하지 않습니다.</p>
<p>svd_kmeans: TF-IDF/SVD + 재귀 K-means. ssl_kmeans: Denoising Autoencoder + 같은 재귀 K-means. ssl_ward: 같은 잠재벡터 + 재귀 Ward 분할. 전체 가상 루트는 깊이 0이며 최대 깊이는 고정한 CWE-1000 그래프의 최장 경로에서 계산합니다. 각 단계가 CWE 추상화 수준이라는 의미는 아닙니다.</p>
<p>seed: 전체 자료에서 초기값 변경. frozen_resample: 표현과 전처리를 고정한 80% 그룹 재표집. pipeline_resample: 표본 안에서 TF-IDF/SVD와 자기지도학습부터 다시 실행. 재표집은 복원 없는 subsampling이며 동일한 정제 텍스트를 가진 CVE는 함께 선택합니다.</p>
<p>Silhouette는 고정한 평가 CVE 중 각 실행에 포함된 질의점에서 계산하되, 질의점마다 그 실행의 모든 CVE까지 거리를 사용합니다. native는 해당 표현 공간, reference는 전체 자료로 고정한 공통 SVD 공간입니다. reference는 평가에만 사용하며 pipeline_resample 학습 입력에 들어가지 않습니다. 모든 거리는 L2 정규화 벡터의 cosine distance입니다.</p>
<p>ARI는 실행 두 개의 공통 CVE를 정렬하고 깊이별로 계산합니다. 군집 번호를 수동 대응하지 않습니다. 조기 종료한 가지는 부모 ID를 유지합니다. 단일 군집 등 퇴화한 비교는 별도 집계하며 평균 ARI만으로 안정성을 주장하지 않습니다. 표의 ARI는 비퇴화 쌍의 평균입니다. 실행 쌍들은 독립 표본이 아니므로 p10/p90·표준편차를 신뢰구간으로 해석하지 않습니다.</p>
<p><strong>이 결과는 기하학적 분리도와 재현성 평가입니다. 보고서 범주, 운영 질문 호환성, 악용 가능성, VEX 정확도를 검증하지 않습니다. vendor·제품명·반복 문구에 따른 군집 여부는 별도 원문 검토가 필요합니다.</strong></p>
<table><tr><th>비교군</th><th>방법</th><th>깊이</th><th>평균 군집 수</th><th>Native Silhouette</th><th>Reference Silhouette</th><th>ARI</th><th>비교 쌍 수</th><th>퇴화 쌍 수</th></tr>__TABLE__</table>
<p>원시 지표: depth_metrics.jsonl, ari_pairs.jsonl. 집계: comparison_summary.json, stability_summary.json. 대표 CVE·출처는 representative_cves.jsonl, 전체 깊이별 배정은 reference_assignments.jsonl에 있습니다.</p></html>'''
    (out/'report.html').write_text(report.replace('__TABLE__',''.join(table)),encoding='utf-8')
    return rows


def main(args):
    if not torch.cuda.is_available():raise RuntimeError('This experiment requires CUDA')
    torch.set_num_threads(4)
    out=ROOT/args.output;out.mkdir(parents=True,exist_ok=True)
    started=time.monotonic()
    def status(phase,**kw):
        data=dict(phase=phase,pid=os.getpid(),seconds=round(time.monotonic()-started,1),**kw)
        atomic_json(out/'status.json',data);print(json.dumps(data),flush=True)
    source=ROOT/'results/ics_sentence_conditions_v1/full_inputs.jsonl'
    rows=sorted(map(json.loads,source.open(encoding='utf-8')),key=lambda r:r['cve'])
    ids=np.asarray([r['cve'] for r in rows])
    expected={json.loads(l)['cve'] for l in (ROOT/'data/item3_ics_cert_full_v1/cves.jsonl').open(encoding='utf-8')}
    if len(rows)!=12418 or len(set(ids))!=12418 or set(ids)!=expected:raise ValueError('Full 12,418-CVE population required')
    texts,groups=study.corpus_texts(rows)
    catalog_path=ROOT/read_json(ROOT/'data/cwe_taxonomy/current.json')['path']
    catalog=read_json(catalog_path);depth_info=study.cwe_depth(catalog);depth=depth_info['max_depth']
    config=dict(schema='item4-ssl-hierarchy/1',population=12418,source_sha256=sha(source),
                cwe_sha256=sha(catalog_path),depth=depth_info,methods={k:list(v) for k,v in METHODS.items()},
                scripts={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__).resolve(),ROOT/'src/item4_ssl_hierarchy.py']},
                seeds=list(range(42,42+args.seed_runs)),frozen_resamples=args.frozen_resamples,
                pipeline_resamples=args.pipeline_resamples,fraction=.8,epochs=args.epochs,
                dimension=args.dimension,latent=64,batch=512,corruption=dict(mask_fraction=.2,gaussian_std=.05),
                candidates=[2,3,4,5],min_child=args.min_child,min_parent=args.min_parent,
                min_local_silhouette=.02,local_query_count=256,metric_query_count=args.queries,
                llm_used=False,pretrained_language_model_used=False,training_labels=[],
                fit_deduplication='Exact cleaned source text / identical input vectors',
                resampling='80% cleaned-text groups, without replacement; all CVEs in each group retained',
                native_distance='Cosine on L2-normalized native vectors',reference_distance='Cosine on fixed full-corpus L2 SVD vectors',
                silhouette_estimator='Query points sampled; each query uses all members in its current run',
                local_stop_policy='Depth or size cap, or best feasible local silhouette below .02; ARI evaluated afterwards',
                no_semantic_accuracy_claim=True,transductive=True)
    previous=read_json(out/'protocol.json')
    if previous and previous!=config:raise ValueError('Configuration/source/code differs from existing output; choose new output')
    if not previous:atomic_json(out/'protocol.json',config)
    snapshots=out/'code_snapshot';snapshots.mkdir(exist_ok=True)
    for name in config['scripts']:
        target=snapshots/Path(name).name
        if not target.exists():shutil.copyfile(ROOT/name,target)
    atomic_json(out/'environment.json',dict(gpu=torch.cuda.get_device_name(),versions={n:importlib.metadata.version(n) for n in ['torch','numpy','scipy','scikit-learn']}))
    jsonl(out/'corpus_index.jsonl',(dict(row=i,cve=r['cve'],cleaned_text_sha256=groups[i],
           source_ids=[s['id'] for s in r['sources']],identity_ambiguous=r.get('identity_ambiguous'),
           original_excluded_flag=r.get('excluded'),original_nvd_status=r.get('original_nvd_status')) for i,r in enumerate(rows)))
    lease=read_json(gpu_lease.FILE)
    if lease.get('active') and any(gpu_lease.alive(lease.get(k)) for k in ['pid','child_pid']):raise RuntimeError('GPU owned by another job')
    atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=True,purpose='Item4 SSL hierarchical comparison',output=str(out)))
    jobs=[]
    try:
        feature_dir=out/'full_features';feature_dir.mkdir(exist_ok=True)
        with threadpool_limits(limits=4):
            if (feature_dir/'complete.json').exists():
                features=joblib.load(feature_dir/'preprocessing.joblib');reference=np.load(feature_dir/'vectors.npy')
            else:
                status('fitting_reference_features')
                features,reference=study.fit_features(texts,args.dimension)
                joblib.dump(features,feature_dir/'preprocessing.joblib');np.save(feature_dir/'vectors.npy',reference)
                atomic_json(feature_dir/'complete.json',dict(population=len(reference),explained_variance=features['explained_variance']))
            # IDs fixed before model fitting; matching cohort for native/reference and method comparisons.
            query_order=np.argsort([hashlib.sha256(('evaluation-query:'+c).encode()).hexdigest() for c in ids])
            query_ids=set(query_order[:min(args.queries,len(ids))].tolist())
            atomic_json(out/'evaluation_query_rows.json',sorted(query_ids))
            all_indices=np.arange(len(ids));plans=[]
            for seed in config['seeds']:plans.append(dict(run_id=f'seed_{seed}',family='seed',seed=seed,indices=all_indices))
            for i in range(args.frozen_resamples):plans.append(dict(run_id=f'frozen_{i:02}',family='frozen_resample',seed=42,indices=study.grouped_subsample(groups,.8,1000+i)))
            for i in range(args.pipeline_resamples):plans.append(dict(run_id=f'pipeline_{i:02}',family='pipeline_resample',seed=42,indices=study.grouped_subsample(groups,.8,1000+i)))
            full_ssl=None
            for plan_index,plan in enumerate(plans):
                run_id=plan['run_id'];indices=plan['indices'];family=plan['family'];seed=plan['seed']
                run_dir=out/'runs'/run_id;run_dir.mkdir(parents=True,exist_ok=True)
                jsonl(run_dir/'sampled_cves.jsonl',(dict(row=int(i),cve=ids[i]) for i in indices))
                if family=='pipeline_resample':
                    if (run_dir/'features_complete.json').exists():base=np.load(run_dir/'svd_vectors.npy')
                    else:
                        status('refitting_subsample_features',run=run_id,plan=plan_index+1,plans=len(plans))
                        fitted,base=study.fit_features([texts[i] for i in indices],args.dimension)
                        joblib.dump(fitted,run_dir/'preprocessing.joblib');np.save(run_dir/'svd_vectors.npy',base)
                        atomic_json(run_dir/'features_complete.json',dict(population=len(indices),fit_scope='This sample only'))
                else:base=reference[indices]
                if family=='frozen_resample':
                    if full_ssl is None:full_ssl=np.load(out/'runs/seed_42/ssl_vectors.npy')
                    latent=full_ssl[indices]
                elif (run_dir/'ssl_complete.json').exists():latent=np.load(run_dir/'ssl_vectors.npy')
                else:
                    status('self_supervised_training',run=run_id,plan=plan_index+1,plans=len(plans))
                    model,latent,training=study.train_dae(base,seed,args.epochs,callback=lambda m:status('self_supervised_training',run=run_id,**m))
                    torch.save(dict(state_dict=model.state_dict(),dimension=args.dimension,latent=64,seed=seed),run_dir/'encoder.pt')
                    np.save(run_dir/'ssl_vectors.npy',latent);atomic_json(run_dir/'training_history.json',training)
                    atomic_json(run_dir/'ssl_complete.json',dict(population=len(indices),weight_change_l2=training['weight_change_l2']))
                    del model;torch.cuda.empty_cache()
                if family=='seed' and seed==42:full_ssl=latent
                ref=reference[indices]
                query=np.array([j for j,i in enumerate(indices) if int(i) in query_ids],dtype=int)
                for method,(representation,splitter) in METHODS.items():
                    job_dir=run_dir/method;job_dir.mkdir(exist_ok=True)
                    job=dict(job_id=run_id+'/'+method,run_id=run_id,family=family,method=method,path=str(job_dir.relative_to(out)))
                    if not (job_dir/'complete.json').exists():
                        status('hierarchical_clustering',run=run_id,method=method,plan=plan_index+1,plans=len(plans))
                        x=base if representation=='svd' else latent
                        levels,nodes=study.recursive_partition(x,splitter,max_depth=depth,seed=seed,
                                     min_child=args.min_child,min_parent=args.min_parent)
                        np.save(job_dir/'indices.npy',indices);np.save(job_dir/'levels.npy',levels)
                        atomic_json(job_dir/'tree.json',nodes)
                        metric=study.depth_metrics(x,ref,levels,query)
                        atomic_json(job_dir/'metrics.json',metric)
                        atomic_json(job_dir/'complete.json',dict(population=len(indices),nodes=len(nodes),max_depth=depth))
                    jobs.append(job);atomic_json(out/'jobs.json',jobs)
                status('run_complete',run=run_id,completed_jobs=len(jobs),expected_jobs=len(plans)*len(METHODS))
            status('pairwise_stability',jobs=len(jobs))
            stability=evaluate_stability(out,jobs,depth)
            comparison=summarize(out,jobs,stability,depth)
            # Export all full-population reference partitions and source-linked representatives.
            selected={m:np.load(out/'runs/seed_42'/m/'levels.npy') for m in METHODS}
            jsonl(out/'reference_assignments.jsonl',(dict(cve=ids[i],identity_ambiguous=rows[i].get('identity_ambiguous'),
                original_excluded_flag=rows[i].get('excluded'),depth_labels={m:v[i].tolist() for m,v in selected.items()}) for i in range(len(ids))))
            representatives=[]
            for method,levels in selected.items():
                x=reference if method=='svd_kmeans' else full_ssl
                for d in range(1,depth+1):
                    for label in np.unique(levels[:,d]):
                        members=np.flatnonzero(levels[:,d]==label)
                        center=x[members].mean(0);center/=max(np.linalg.norm(center),1e-12)
                        nearest=members[np.argsort(-(x[members]@center))[:3]]
                        representatives.append(dict(method=method,depth=d,node_id=int(label),size=len(members),
                            examples=[dict(cve=ids[i],sources=rows[i]['sources']) for i in nearest]))
            jsonl(out/'representative_cves.jsonl',representatives)
            for j in jobs:
                index=np.load(out/j['path']/'indices.npy');levels=np.load(out/j['path']/'levels.npy')
                if len(index)!=len(np.unique(index)):raise ValueError('Duplicate IDs in job')
                study.validate_levels(levels,depth)
                if levels.shape[0]!=len(index):raise ValueError('Partition population mismatch')
                if j['family']=='seed' and not np.array_equal(index,all_indices):raise ValueError('Missing full-population CVE')
            verification=dict(population=12418,all_full_runs_retain_population=True,jobs=len(jobs),
                              expected_jobs=len(plans)*len(METHODS),max_depth=depth,partitions_complete_and_nested=True,
                              early_stops_preserve_parent=True,ari_uses_aligned_intersection=True,
                              identity_or_original_excluded_flags=sum(bool(r.get('identity_ambiguous') or r.get('excluded')) for r in rows),
                              independent_semantic_accuracy_tested=False)
            atomic_json(out/'verification.json',verification)
            atomic_json(out/'summary.json',dict(**verification,seed_runs=args.seed_runs,frozen_resamples=args.frozen_resamples,
                        pipeline_resamples=args.pipeline_resamples,unique_cleaned_texts=len(np.unique(groups)),
                        comparison_rows=len(comparison),ari_aggregation='Pairwise means and empirical dispersion; correlated pairs, no CI',
                        production_vex_changed=False,seconds=time.monotonic()-started))
            atomic_json(out/'manifest.json',{str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p.name not in ['manifest.json','status.json']})
            status('complete',**verification)
    except Exception as exc:
        status('failed',error=repr(exc));raise
    finally:
        if read_json(gpu_lease.FILE).get('pid')==os.getpid():atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,purpose='Item4 SSL hierarchy released'))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',default='results/item4_ssl_hierarchy_v1')
    p.add_argument('--seed-runs',type=int,default=5)
    p.add_argument('--frozen-resamples',type=int,default=20)
    p.add_argument('--pipeline-resamples',type=int,default=10)
    p.add_argument('--epochs',type=int,default=100)
    p.add_argument('--dimension',type=int,default=256)
    p.add_argument('--min-child',type=int,default=30)
    p.add_argument('--min-parent',type=int,default=100)
    p.add_argument('--queries',type=int,default=2000)
    args=p.parse_args()
    if args.seed_runs<1 or args.frozen_resamples<0 or args.pipeline_resamples<0 or args.epochs<1 or args.queries<2:
        p.error('Require positive seed runs/epochs, nonnegative resamples, and at least two evaluation queries')
    main(args)
