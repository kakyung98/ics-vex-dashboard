"""Source-disjoint evaluation of the neighbor-contrastive pretext task.

Evaluation-only retraining; never replaces the full-population clustering model.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

import joblib
import numpy as np
import torch
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from threadpoolctl import threadpool_limits

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src import item4_ssl_hierarchy as h, item4_silhouette_search as s, gpu_lease
from src.training_io import atomic_json, read_json

OUT = ROOT/'results/item4_ssl_pretext_evaluation_v1'
SOURCE = ROOT/'results/item4_cisa_silhouette_search_v1'

def rows(path):
    return [json.loads(line) for line in path.open(encoding='utf-8')]

def write_rows(path, records):
    with path.open('w', encoding='utf-8') as f:
        for r in records: f.write(json.dumps(r, ensure_ascii=False)+'\n')

def split_sources(links, docs, extra_groups=()):
    parent = list(range(len(links)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]; i = parent[i]
        return i
    seen = {}
    for i, row in enumerate(links):
        for a in row['advisory_ids']:
            # Identical advisory texts also belong to the same source component.
            key = hashlib.sha256(docs[a].encode()).hexdigest()
            if key in seen: parent[find(i)] = find(seen[key])
            else: seen[key] = i
    for group in extra_groups:
        for i in group[1:]: parent[find(i)] = find(group[0])
    groups = {}
    for i in range(len(links)): groups.setdefault(find(i), []).append(i)
    ordered = sorted(groups.values(), key=lambda g: (-len(g), links[g[0]]['cve']))
    sizes = np.zeros(3, dtype=int); targets = np.array([.7,.15,.15])*len(links)
    split = np.empty(len(links), dtype=int)
    for group in ordered:
        dest = int(np.argmax(targets-sizes)); split[group] = dest; sizes[dest] += len(group)
    sets = [{a for i,r in enumerate(links) if split[i]==k for a in r['advisory_ids']} for k in range(3)]
    texts = [{docs[a] for a in aset} for aset in sets]
    for a in range(3):
        for b in range(a):
            assert not sets[a]&sets[b] and not texts[a]&texts[b]
    return split, sets, dict(cve_counts=sizes.tolist(), source_components=len(groups), largest_component=len(ordered[0]), advisory_overlap=0, exact_document_overlap=0)

def pairs(x, seed):
    rng = np.random.default_rng(seed)
    sim = x@x.T; np.fill_diagonal(sim, -np.inf)
    ranking = np.argsort(-sim, axis=1)
    result=[]
    for i, rank in enumerate(ranking):
        positives=rank[:5]
        # Each stratum is balanced. Hard negatives lie just outside the positive set.
        hard=rng.choice(rank[5:min(50,len(x)-1)], 5, replace=False)
        random=rng.choice(rank[5:len(x)-1], 5, replace=False)
        for stratum, negatives in [('random',random),('hard',hard)]:
            result.extend((i,int(j),1,stratum) for j in positives)
            result.extend((i,int(j),0,stratum) for j in negatives)
    return result

def metrics(y, score, threshold):
    pred=score>=threshold
    return dict(accuracy=float(accuracy_score(y,pred)), precision=float(precision_score(y,pred,zero_division=0)),
                recall=float(recall_score(y,pred,zero_division=0)), f1=float(f1_score(y,pred,zero_division=0)),
                roc_auc=float(roc_auc_score(y,score)), confusion_matrix_tn_fp_fn_tp=confusion_matrix(y,pred,labels=[0,1]).ravel().tolist(), pairs=len(y))

def main():
    OUT.mkdir(exist_ok=True)
    gpu_lease.assert_inference_available()
    atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=True,purpose='Item4 source-disjoint self-supervised pretext evaluation'))
    try:
        links=rows(SOURCE/'cve_advisory_links.jsonl')
        docs={r['advisory_id']:r['text'] for r in rows(SOURCE/'advisory_documents.jsonl')}
        assert len(links)==12418 and len({r['cve'] for r in links})==12418
        extra_groups=[]
        for attempt in range(10):
            split, source_sets, audit=split_sources(links,docs,extra_groups)
            fitted,_=h.fit_features([docs[a] for a in sorted(source_sets[0])],256)
            keys=sorted(docs); index={a:i for i,a in enumerate(keys)}
            dv=h.transform_features(fitted,[docs[a] for a in keys])
            x=s.pool_advisories(dv,[[index[a] for a in r['advisory_ids']] for r in links])
            buckets={}
            for i,v in enumerate(x): buckets.setdefault(bytes(v),[]).append(i)
            overlaps=[g for g in buckets.values() if len({split[i] for i in g})>1]
            if not overlaps: break
            extra_groups.extend(overlaps)
            print('merging cross-split identical projected inputs',len(overlaps),flush=True)
        else: raise ValueError('Cannot produce disjoint input groups')
        audit['exact_projected_input_overlap']=0
        audit['split_refinement_rounds']=attempt
        write_rows(OUT/'cve_split_ledger.jsonl', (dict(cve=r['cve'],split=['train','validation','test'][split[i]],advisory_ids=r['advisory_ids']) for i,r in enumerate(links)))
        atomic_json(OUT/'split_audit.json',audit)
        print('source split', audit, flush=True)
        joblib.dump(fitted,OUT/'train_only_preprocessing.joblib');np.save(OUT/'all_cve_inputs.npy',x)
        unique=[np.unique(x[split==k],axis=0) for k in range(3)]
        for a in range(3):
            for b in range(a):
                assert not set(map(bytes,unique[a]))&set(map(bytes,unique[b]))
        print('unique inputs', [len(v) for v in unique],flush=True)
        torch.manual_seed(42)
        untrained=s.ContrastiveEncoder(256,16).cuda().eval()
        model,_,history=s.train_neighbor_contrastive(unique[0],16,50,42,callback=lambda r:print(r,flush=True))
        torch.save(dict(state_dict=model.state_dict()),OUT/'evaluation_only_model.pt')
        atomic_json(OUT/'training_history.json',history)
        scores={};pairsets={}
        for k,name in [(1,'validation'),(2,'test')]:
            base=unique[k]; pp=pairs(base,100+k);pairsets[name]=pp
            np.save(OUT/f'{name}_unique_inputs.npy',base)
            rng=np.random.default_rng(200+k)
            left=base*(rng.random(base.shape)>=.1);right=base*(rng.random(base.shape)>=.1)
            left=left/np.maximum(np.linalg.norm(left,axis=1,keepdims=True),1e-12)
            right=right/np.maximum(np.linalg.norm(right,axis=1,keepdims=True),1e-12)
            ia=np.array([p[0] for p in pp]);ib=np.array([p[1] for p in pp])
            for method,encoder in [('raw_input',None),('untrained_encoder',untrained),('trained_encoder',model)]:
                if encoder is None:za,zb=left,right
                else:
                    with torch.inference_mode():
                        za=encoder(torch.tensor(left,dtype=torch.float32,device='cuda')).cpu().numpy()
                        zb=encoder(torch.tensor(right,dtype=torch.float32,device='cuda')).cpu().numpy()
                scores[name,method]=np.sum(za[ia]*zb[ib],axis=1)
            write_rows(OUT/f'{name}_pairs.jsonl',(dict(anchor_unique_index=a,other_unique_index=b,target=y,stratum=st,
                **{method:float(scores[name,method][j]) for method in ['raw_input','untrained_encoder','trained_encoder']}) for j,(a,b,y,st) in enumerate(pp)))
        results={}
        for method in ['raw_input','untrained_encoder','trained_encoder']:
            val=scores['validation',method]; y=np.array([p[2] for p in pairsets['validation']])
            thresholds=np.unique(np.quantile(val,np.linspace(0,1,1001)))
            threshold=float(max(thresholds,key=lambda t:f1_score(y,val>=t)))
            result=dict(threshold=threshold,threshold_selection='Highest balanced mixed validation F1 on 1001 score quantiles; test never used',validation=metrics(y,val,threshold),test={})
            for st in ['mixed','random','hard']:
                mask=np.array([st=='mixed' or p[3]==st for p in pairsets['test']]);yt=np.array([p[2] for p in pairsets['test']])[mask]
                result['test'][st]=metrics(yt,scores['test',method][mask],threshold)
            results[method]=result
        protocol=dict(population=12418,encoded_population=len(x),split=audit,unique_input_counts=[len(v) for v in unique],seed=42,epochs=50,latent=16,
            target='Within-split original-input nearest five = positive; non-neighbor random or ranks 6..50 = negative',
            augmentation='Independent 10% feature masks for left/right; one fixed evaluation draw per split',
            evaluation_unit='Directed pairs of unique pooled advisory vectors, not independent CVEs; repeated anchors and duplicated positive pairs across strata are dependent',
            fitting='TF-IDF/SVD and encoder fitted on training sources only; evaluation-only retraining, original production clustering unchanged',
            limitation='Heuristic neighbor targets; raw-input baseline favored by target construction; no semantic vulnerability-class accuracy or VEX validation',
            original_full_population_clustering='All 12,418 assignments retained; this split only evaluates representation learning',
            device=torch.cuda.get_device_name(0),sources={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [SOURCE/'cve_advisory_links.jsonl',SOURCE/'advisory_documents.jsonl',Path(__file__),ROOT/'src/item4_silhouette_search.py',ROOT/'src/item4_ssl_hierarchy.py']})
        atomic_json(OUT/'protocol.json',protocol);atomic_json(OUT/'metrics.json',results)
        atomic_json(OUT/'status.json',dict(status='complete',population=12418))
        print(json.dumps(results,indent=2),flush=True)
    finally:
        atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,purpose='Self-supervised pretext evaluation released'))

if __name__=='__main__':
    with threadpool_limits(limits=4): main()
