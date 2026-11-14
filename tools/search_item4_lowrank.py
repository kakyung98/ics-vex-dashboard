"""Second declared search round: smaller representations and larger leaf K.

Retains all 12,418 CVEs. Reuses frozen CISA inputs and scoring cohorts. Only
search-cohort improvements are promoted; exact full-population and stability
measurements follow using the prototype-resolution hierarchy.
"""
import argparse
import html
import json
import os
from pathlib import Path
import shutil
import sys
import time

import numpy as np
import torch
from threadpoolctl import threadpool_limits

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src import item4_ssl_hierarchy as h,item4_silhouette_search as s,gpu_lease
from src.training_io import atomic_json,read_json
from tools.run_item4_ssl_hierarchy import sha,jsonl
from tools.search_item4_cisa_silhouette import representation,check_population
from tools.extend_item4_prototype_hierarchy import validate_candidate


def main(args):
    source=ROOT/args.source;out=ROOT/args.output;out.mkdir(parents=True,exist_ok=True)
    original=read_json(source/'protocol.json');rows=list(map(json.loads,(source/'cve_rows.jsonl').open(encoding='utf-8')))
    ids=[r['cve'] for r in rows]
    expected={json.loads(l)['cve'] for l in (ROOT/'data/item3_ics_cert_full_v1/cves.jsonl').open(encoding='utf-8')}
    if len(ids)!=12418 or len(set(ids))!=12418 or set(ids)!=expected:raise ValueError('Require all 12,418 target CVEs')
    previous=list(map(json.loads,(source/'screening_results.jsonl').open(encoding='utf-8')))
    if len(previous)!=210:raise ValueError('First search round incomplete')
    config=dict(schema='item4-lowrank-search/1',population=12418,source_protocol_sha256=sha(source/'protocol.json'),
                input_views=original['input_views'],new_representations=['raw16','raw32','dae16','neighbor16'],
                screening_k=[4,8,16,32,64,128],expanded_k=[192,256,384],
                expanded_existing=['current_mix_raw256_seed42','current_mix_dae64_seed42','cisa_advisory_pool_dae32_seed42'],
                expected_new_fits=129,improvement_margin=.005,cwe_depth_reference=original['cwe_depth_reference'],
                all_cves_assigned=True,excluded_cves=0,llm_used=False,training_labels=[],
                scoring='Same 1000 search queries as first round; confirmation unused in promotion',
                hierarchy='Global leaf partition + contracted prototype Ward hierarchy; actual stored depth <= 6',
                script_sha256=sha(__file__),prototype_helper_sha256=sha(ROOT/'tools/extend_item4_prototype_hierarchy.py'))
    prior=read_json(out/'protocol.json')
    if prior and prior!=config:raise ValueError('Changed low-rank protocol; choose new output')
    atomic_json(out/'protocol.json',config)
    snap=out/'code_snapshot';snap.mkdir(exist_ok=True);shutil.copyfile(Path(__file__),snap/Path(__file__).name)
    inputs=out/'inputs';inputs.mkdir(exist_ok=True)
    for name in config['input_views']:
        target=inputs/f'{name}.npy'
        if not target.exists():shutil.copyfile(source/'inputs'/target.name,target)
    for name in ['cve_rows.jsonl','evaluation_queries.json','input_coverage.json','input_geometry_audit.json']:
        if (source/name).exists() and not (out/name).exists():shutil.copyfile(source/name,out/name)
    started=time.monotonic();torch.set_num_threads(4)
    def status(phase,**kw):
        value=dict(phase=phase,pid=os.getpid(),seconds=round(time.monotonic()-started,1),**kw)
        atomic_json(out/'status.json',value);print(json.dumps(value),flush=True)
    if args.stage=='prepare':status('prepared',population=12418);return
    lease=read_json(gpu_lease.FILE)
    if lease.get('active') and any(gpu_lease.alive(lease.get(k)) for k in ['pid','child_pid']):raise RuntimeError('Another GPU job is active')
    atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=True,purpose='Full-population low-rank search',output=str(out)))
    try:
        with threadpool_limits(limits=4):
            reference=np.load(inputs/'current_mix.npy');check_population(reference)
            q=read_json(out/'evaluation_queries.json');search=np.array(q['search']);confirmation=np.array(q['confirmation'])
            ref_dist=h.cosine_distances(reference,search)
            plans=[(name,kind,dim,None) for name in config['input_views'] for kind,dim in [('raw',16),('raw',32),('dae',16),('neighbor',16)]]
            old_specs={r['rep_id']:r for r in read_json(source/'representation_specs.json')}
            for key in config['expanded_existing']:
                spec=old_specs[key];plans.append((spec['input'],spec['kind'],spec['latent'],key))
            records=[];specs=[]
            for plan_index,(name,kind,dim,existing) in enumerate(plans):
                if existing:
                    old=old_specs[existing];target=out/old['path']
                    if not target.exists():shutil.copytree(source/old['path'],target)
                    spec=old;z=np.load(target/'vectors.npy');ks=config['expanded_k']
                else:
                    spec,z=representation(out,name,kind,dim,42,status);ks=config['screening_k']
                check_population(z);specs.append(spec);folder=out/spec['path']
                cached=read_json(folder/'round2_screening.json')
                if cached:records.extend(cached);continue
                native=h.cosine_distances(z,search);local=[]
                for k in ks:
                    status('lowrank_gpu_screening',plan=plan_index+1,plans=len(plans),representation=spec['rep_id'],k=k)
                    labels,fit=s.gpu_kmeans(z,k);labels,merged=s.merge_small(z,labels,30)
                    counts=np.bincount(labels)
                    if len(labels)!=12418 or np.any(labels<0) or counts.min()<30:raise ValueError('No target may be removed')
                    rs=h.sampled_silhouette(ref_dist,labels,search);ns=h.sampled_silhouette(native,labels,search)
                    row=dict(rep_id=spec['rep_id'],input=name,kind=kind,latent=dim,requested_k=k,actual_clusters=len(counts),
                             population=12418,retention=1.,minimum_size=int(counts.min()),largest_share=float(counts.max()/12418),
                             small_clusters_merged=merged,reference_search_silhouette=rs,native_search_silhouette=ns,
                             eligible=bool(len(counts)>1 and counts.max()/12418<=.65 and rs is not None),
                             labels_path=str((folder/f'round2_labels_k{k}.npy').relative_to(out)))
                    np.save(out/row['labels_path'],labels);records.append(row);local.append(row)
                atomic_json(folder/'round2_screening.json',local);jsonl(out/'screening_results.jsonl',records)
            if len(records)!=129:raise ValueError('Incomplete declared search grid')
            atomic_json(out/'representation_specs.json',specs);jsonl(out/'screening_results.jsonl',records)
            good=[r for r in records if r['eligible']];old_good=[r for r in previous if r['eligible']]
            candidates={};comparisons=[]
            for key,metric,trained_only in [('reference_gain','reference_search_silhouette',False),
                    ('trained_reference_gain','reference_search_silhouette',True),
                    ('native_gain','native_search_silhouette',False),('trained_native_gain','native_search_silhouette',True)]:
                pool=[r for r in good if not trained_only or r['kind']!='raw']
                old_pool=[r for r in old_good if not trained_only or r['kind']!='raw']
                best=max(pool,key=lambda r:r[metric]);old=max(old_pool,key=lambda r:r[metric])
                improved=best[metric]>old[metric]+.005
                comparisons.append(dict(criterion=key,old_search_score=old[metric],new_search_score=best[metric],
                                        improvement=best[metric]-old[metric],promoted=improved,representation=best['rep_id']))
                if improved and not any((c['rep_id'],c['requested_k'])==(best['rep_id'],best['requested_k']) for c in candidates.values()):candidates[key]=best
            atomic_json(out/'round_comparison.json',comparisons);atomic_json(out/'selected_candidates.json',candidates)
            specs={r['rep_id']:r for r in specs};summaries=[];results=[]
            for key,candidate in candidates.items():
                dest=out/'selected'/key
                summaries.extend(validate_candidate(out,dest,specs[candidate['rep_id']],candidate,ids,reference,search,confirmation,status,args.stage=='all'))
                results.append(dict(candidate=key,representation=candidate['rep_id'],**read_json(dest/'complete.json')))
            atomic_json(out/'results.json',results)
            if summaries:atomic_json(out/'stability_summary.json',summaries)
            table=''.join('<tr>'+''.join('<td>'+html.escape(str(v))+'</td>' for v in [r['candidate'],r['representation'],r['clusters'],
                        f"{r['full_native_silhouette']:.4f}",f"{r['full_reference_silhouette']:.4f}",r['population']])+'</tr>' for r in results)
            page='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>#4 저차원·세분화 추가 탐색</title>
<style>body{font:16px system-ui;max-width:1300px;margin:36px auto;padding:0 20px;line-height:1.6}td,th{border:1px solid #ccc;padding:8px}table{border-collapse:collapse}pre{white-space:pre-wrap}</style>
<h1>12,418개 전수: 2차 입력·표현 탐색</h1>
<p>1차의 동일 입력 5종에 raw 16/32차원, DAE 16차원, 이웃 대조학습 16차원을 추가했습니다. 기존 표현 3종에는 K=192/256/384를 추가했습니다. 새 평면 후보는 129개이며 1차 210개와 합쳐 339개 조건입니다. 입력·군집 배정은 모든 후보에서 12,418개를 유지합니다.</p>
<p>같은 탐색 질의점에서 1차 최고 점수를 .005 이상 개선한 후보만 전수 평가·안정성 검증으로 승격합니다. 전역 잎 군집을 그대로 유지하는 프로토타입 계층 방식이며, 여섯 해상도 번호와 실제 부모 간선 깊이를 구분합니다. 저장 모델의 실제 깊이는 최대 6입니다. 높은 native 점수를 다른 공간의 점수와 혼용하지 않습니다.</p>
<pre>__COMPARISONS__</pre><table><tr><th>선택 기준</th><th>표현</th><th>잎 군집 수</th><th>Native 전수 Silhouette</th><th>Reference 전수 Silhouette</th><th>CVE 수</th></tr>__TABLE__</table>
<p>selected/*/cve_assignments.jsonl에 모든 CVE의 배정이 있습니다. full_population_metrics.json은 12,418개 전체 질의점과 전체 비교 대상을 사용한 지표입니다. stability_summary.json은 초기값 5회와 표현 고정 재표집 10회의 ARI입니다. 반복 실행 쌍은 서로 독립 표본이 아니며 분산·분위수를 신뢰구간으로 해석하지 않습니다. 의미·악용 가능성·VEX 정확도는 검증하지 않았습니다.</p></html>'''
            (out/'report.html').write_text(page.replace('__TABLE__',table).replace('__COMPARISONS__',html.escape(json.dumps(comparisons,ensure_ascii=False,indent=2))),encoding='utf-8')
            atomic_json(out/'verification.json',dict(population=12418,unique_cves=len(set(ids)),screened_candidates=129,
                        all_screened_candidates_full_population=True,excluded_cves=0,selected_candidates=len(results),
                        final_query_population=12418,max_stored_hierarchy_depth=6,stability_complete=args.stage=='all'))
            atomic_json(out/'manifest.json',{str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p.name not in ['manifest.json','status.json']})
            status('complete' if args.stage=='all' else 'search_complete',population=12418,candidates=129,selected=len(results))
    except Exception as exc:status('failed',error=repr(exc));raise
    finally:
        if read_json(gpu_lease.FILE).get('pid')==os.getpid():atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,purpose='Low-rank search released'))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',default='results/item4_cisa_silhouette_search_v1')
    parser.add_argument('--output',default='results/item4_cisa_lowrank_v1')
    parser.add_argument('--stage',choices=['prepare','search','all'],default='all')
    main(parser.parse_args())
