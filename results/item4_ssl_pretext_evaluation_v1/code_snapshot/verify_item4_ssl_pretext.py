"""Recompute saved test metrics and verify source-disjoint population ledger."""
import json
from pathlib import Path
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, precision_score, recall_score

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/item4_ssl_pretext_evaluation_v1'
def read(path):return [json.loads(l) for l in path.open(encoding='utf-8')]
ledger=read(OUT/'cve_split_ledger.jsonl')
expected={r['cve'] for r in read(ROOT/'data/item3_ics_cert_full_v1/cves.jsonl')}
assert len(ledger)==12418 and {r['cve'] for r in ledger}==expected
docs={r['advisory_id']:r['text'] for r in read(ROOT/'results/item4_cisa_silhouette_search_v1/advisory_documents.jsonl')}
x=np.load(OUT/'all_cve_inputs.npy');assert x.shape==(12418,256) and np.isfinite(x).all()
names=['train','validation','test'];aset=[];tset=[];vset=[]
for name in names:
    aset.append({a for r in ledger if r['split']==name for a in r['advisory_ids']})
    tset.append({docs[a] for a in aset[-1]})
    vset.append({bytes(x[i]) for i,r in enumerate(ledger) if r['split']==name})
for a in range(3):
    for b in range(a):assert not aset[a]&aset[b] and not tset[a]&tset[b] and not vset[a]&vset[b]
pp=read(OUT/'test_pairs.jsonl');testx=np.load(OUT/'test_unique_inputs.npy')
sim=testx@testx.T;np.fill_diagonal(sim,-np.inf)
nearest=np.argsort(-sim,axis=1)[:,:5]
for r in pp:assert (r['other_unique_index'] in nearest[r['anchor_unique_index']])==bool(r['target'])
results=json.loads((OUT/'metrics.json').read_text())
for method,result in results.items():
    for st,m in result['test'].items():
        rr=[r for r in pp if st=='mixed' or r['stratum']==st]
        y=[r['target'] for r in rr];pred=np.array([r[method] for r in rr])>=result['threshold']
        for key,fn in [('accuracy',accuracy_score),('precision',precision_score),('recall',recall_score),('f1',f1_score)]:assert abs(fn(y,pred)-m[key])<1e-12
        assert confusion_matrix(y,pred).ravel().tolist()==m['confusion_matrix_tn_fp_fn_tp']
audit=dict(passed=True,population=12418,source_overlap=0,identical_text_overlap=0,identical_input_overlap=0,test_pairs=len(pp),recomputed_metric_sets=9)
(OUT/'verification.json').write_text(json.dumps(audit,indent=2)+'\n',encoding='utf-8')
print(json.dumps(audit))
