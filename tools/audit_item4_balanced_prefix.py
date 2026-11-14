"""Audit one-view prefix controls and evaluate corrected balanced raw views."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import sys
import time

import numpy as np
from sklearn.preprocessing import normalize
import torch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src import item4_ssl_hierarchy as h,item4_silhouette_search as s,gpu_lease
from src.training_io import atomic_json,read_json
from tools.run_item4_ssl_hierarchy import sha,jsonl


def main(args):
    source=ROOT/args.source;out=ROOT/args.output;out.mkdir(parents=True,exist_ok=True)
    rows=list(map(json.loads,(source/'cve_rows.jsonl').open(encoding='utf-8')));ids=[r['cve'] for r in rows]
    expected={json.loads(l)['cve'] for l in (ROOT/'data/item3_ics_cert_full_v1/cves.jsonl').open(encoding='utf-8')}
    if len(ids)!=12418 or len(set(ids))!=12418 or set(ids)!=expected:raise ValueError('Full population required')
    reference=np.load(source/'inputs/current_mix.npy');context=np.load(source/'inputs/cisa_context.npy')
    old=np.load(source/'inputs/balanced_views.npy');prepared=out/'representations';prepared.mkdir(exist_ok=True)
    audit=[]
    for dim in [16,32,64,128]:
        left=normalize(reference[:,:dim//2]);right=normalize(context[:,:dim//2])
        corrected=normalize(np.concatenate([left,right],axis=1)).astype(np.float32)
        if corrected.shape!=(12418,dim) or not np.isfinite(corrected).all():raise ValueError('Missing corrected vector')
        if not np.allclose(np.linalg.norm(corrected[:,:dim//2],axis=1),2**-.5,atol=1e-5):raise ValueError('Left view imbalance')
        if not np.allclose(np.linalg.norm(corrected[:,dim//2:],axis=1),2**-.5,atol=1e-5):raise ValueError('Right view imbalance')
        legacy=normalize(old[:,:dim]);one_view=normalize(reference[:,:dim])
        audit.append(dict(dimension=dim,population=12418,legacy_prefix_max_difference_from_mixed_only=float(np.max(np.abs(legacy-one_view))),
                          legacy_interpretation='Mixed-only prefix control, not a two-view balanced raw representation',
                          corrected_per_view_components=dim//2,corrected_per_view_norm=2**-.5))
        np.save(prepared/f'balanced_raw{dim}.npy',corrected)
    atomic_json(out/'prefix_audit.json',audit)
    config=dict(schema='item4-balanced-prefix-correction/1',population=12418,dimensions=[16,32,64,128],
                k=[4,8,16,32,64,128],source_protocol_sha256=sha(source/'protocol.json'),
                correction='Per-view component selection and normalization before concatenation; preserve both views',
                excluded_cves=0,script_sha256=sha(__file__))
    previous=read_json(out/'protocol.json')
    if previous and previous!=config:raise ValueError('Changed correction protocol')
    atomic_json(out/'protocol.json',config)
    snap=out/'code_snapshot';snap.mkdir(exist_ok=True);shutil.copyfile(Path(__file__),snap/Path(__file__).name)
    if args.stage=='prepare':atomic_json(out/'status.json',dict(phase='prepared',population=12418));return
    lease=read_json(gpu_lease.FILE)
    if lease.get('active') and any(gpu_lease.alive(lease.get(k)) for k in ['pid','child_pid']):raise RuntimeError('GPU is busy; preparations retained')
    atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=True,purpose='Corrected balanced-prefix audit',output=str(out)))
    started=time.monotonic()
    try:
        query=np.array(read_json(source/'evaluation_queries.json')['search']);ref_distance=h.cosine_distances(reference,query)
        records=[]
        for dim in config['dimensions']:
            x=np.load(prepared/f'balanced_raw{dim}.npy');native=h.cosine_distances(x,query)
            for k in config['k']:
                labels,fit=s.gpu_kmeans(x,k);labels,merged=s.merge_small(x,labels,30);counts=np.bincount(labels)
                if len(labels)!=12418 or np.any(labels<0):raise ValueError('Unassigned target')
                r=dict(dimension=dim,requested_k=k,clusters=len(counts),population=12418,retention=1.,
                       native_search_silhouette=h.sampled_silhouette(native,labels,query),
                       reference_search_silhouette=h.sampled_silhouette(ref_distance,labels,query),
                       min_size=int(counts.min()),largest_share=float(counts.max()/12418),small_clusters_merged=merged)
                records.append(r);np.save(prepared/f'labels_d{dim}_k{k}.npy',labels)
                atomic_json(out/'status.json',dict(phase='screening',dimension=dim,k=k,completed=len(records),total=24,population=12418))
        jsonl(out/'screening_results.jsonl',records)
        table=''.join('<tr>'+''.join('<td>'+html.escape(str(v))+'</td>' for v in [r['dimension'],r['requested_k'],r['clusters'],
                           f"{r['native_search_silhouette']:.4f}",f"{r['reference_search_silhouette']:.4f}",12418])+'</tr>' for r in records)
        page='''<!doctype html><html lang="ko"><meta charset="utf-8"><title>결합 입력 저차원 검사</title>
<style>body{font:16px system-ui;max-width:1200px;margin:36px auto;line-height:1.6}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:8px}</style>
<h1>결합 입력의 저차원 기준선 수정</h1><p>기존 balanced_views는 [기존 혼합 입력 128차원, CISA context 128차원] 순서입니다. 앞쪽 16/32/64/128개를 단순 선택하면 기존 혼합 입력만 남습니다. 해당 raw-prefix 결과를 두 입력 결합 효과로 해석하면 안 됩니다. 전체 256차원을 입력받은 DAE·대조학습과 raw256은 두 입력을 모두 사용하므로 이 문제와 구분합니다.</p>
<p>수정 기준선은 각 입력에서 차원의 절반씩 선택하고 두 입력을 각각 정규화한 뒤 결합합니다. 모든 24개 조건에 12,418개 CVE를 포함합니다. 아래는 탐색 질의점 기준 평면 군집이며 최종 계층·독립 의미 정확도 결과가 아닙니다.</p>
<table><tr><th>총 차원</th><th>요청 K</th><th>군집 수</th><th>Native 탐색 점수</th><th>Reference 탐색 점수</th><th>CVE 수</th></tr>__TABLE__</table></html>'''
        (out/'report.html').write_text(page.replace('__TABLE__',table),encoding='utf-8')
        atomic_json(out/'verification.json',dict(population=12418,conditions=24,all_cves_assigned=True,excluded_cves=0,views_balanced=True))
        atomic_json(out/'manifest.json',{str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p.name not in ['manifest.json','status.json']})
        atomic_json(out/'status.json',dict(phase='complete',population=12418,conditions=24,seconds=time.monotonic()-started))
        print(json.dumps(dict(phase='complete',population=12418,conditions=24)),flush=True)
    except Exception as e:atomic_json(out/'status.json',dict(phase='failed',error=repr(e)));raise
    finally:
        if read_json(gpu_lease.FILE).get('pid')==os.getpid():atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,purpose='Balanced-prefix audit released'))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',default='results/item4_cisa_silhouette_search_v1')
    p.add_argument('--output',default='results/item4_balanced_prefix_correction_v1')
    p.add_argument('--stage',choices=['prepare','all'],default='all')
    main(p.parse_args())
