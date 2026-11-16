"""Train-only spherical condition clustering; full CVE population retained.

Common questions are drafts. Exact normalized propositions count support;
cluster membership alone never establishes equivalent prerequisites.
"""
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import sys
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json
from src.asset_vulntology import DATA,digest,question


def build(k=16,threshold=.6):
    out=ROOT/'results/item4_condition_clusters_v1'
    if (out/'manifest.json').exists():raise FileExistsError(out)
    out.mkdir(parents=True,exist_ok=True)
    catalogue=json.loads((DATA/'catalogue.json').read_text(encoding='utf-8'))
    records={}
    for file in sorted(DATA.glob('records_*.json')):records.update(json.loads(file.read_text(encoding='utf-8')))
    ids=sorted(r['cve'] for r in catalogue['cves'])
    if set(ids)!=set(records) or len(ids)!=12418:raise ValueError('Full fixed population required')
    parents={c:c for c in ids}
    def find(x):
        while parents[x]!=x:parents[x]=parents[parents[x]];x=parents[x]
        return x
    advisory={}
    for cid in ids:
        for source in records[cid]['sources']:
            url=source.get('url')
            if not url:continue
            if url in advisory:
                a,b=find(cid),find(advisory[url]);parents[max(a,b)]=min(a,b)
            else:advisory[url]=cid
    groups=defaultdict(list)
    for cid in ids:groups[find(cid)].append(cid)
    ordered=sorted(groups,key=lambda g:hashlib.sha256(g.encode()).hexdigest())
    train=set();target=int(.7*len(ids))
    for group in ordered:
        if abs(len(train)+len(groups[group])-target)<=abs(len(train)-target):train.update(groups[group])
    if not train or len(train)==len(ids):raise ValueError('Advisory grouping cannot support a held-out split')
    texts=[];signatures={};conditions={}
    for cid in ids:
        allc=[c for scenario in records[cid].get('scenarios',[]) for c in scenario.get('conditions',[])]
        unique={digest({k:c.get(k) for k in ('kind','proposition','target_hint')}):c for c in allc}
        conditions[cid]=unique
        signatures[cid]=set(unique)
        texts.append(' '.join((c.get('kind','')+' '+c.get('proposition','')+' '+str(c.get('target_hint',''))) for c in unique.values()) or 'source_conditions_unknown')
    train_indices=np.array([i for i,cid in enumerate(ids) if cid in train])
    vectorizer=TfidfVectorizer(ngram_range=(1,2),min_df=1,max_features=12000,sublinear_tf=True)
    vectorizer.fit([texts[i] for i in train_indices]);x=normalize(vectorizer.transform(texts))
    tx=x[train_indices];rng=np.random.default_rng(20261116)
    centers=tx[rng.choice(len(train_indices),size=k,replace=False)].toarray()
    centers=normalize(centers)
    for iteration in range(30):
        labels=np.asarray(tx@centers.T).argmax(axis=1)
        updated=np.array([np.asarray(tx[labels==j].mean(axis=0)).ravel() if np.any(labels==j) else centers[j] for j in range(k)])
        updated=normalize(updated)
        if np.allclose(centers,updated,atol=1e-6):break
        centers=updated
    assigned=np.asarray(x@centers.T).argmax(axis=1)
    common={};support={}
    for cluster in range(k):
        members=[ids[i] for i in train_indices if assigned[i]==cluster]
        counts=Counter(sig for cid in members for sig in signatures[cid])
        chosen={s for s,n in counts.items() if members and n/len(members)>=threshold}
        common[cluster]=chosen;support[cluster]=dict(train_CVEs=len(members),threshold=threshold,
            common_questions=[dict(signature=s,support_count=counts[s],support_fraction=counts[s]/len(members),
                question=question(next(conditions[c][s] for c in members if s in conditions[c])),semantic_reviewed=False) for s in sorted(chosen)])
    with (out/'cve_assignments.jsonl').open('w',encoding='utf-8') as f:
        for i,cid in enumerate(ids):
            own=signatures[cid];covered=own&common[int(assigned[i])]
            f.write(json.dumps(dict(cve=cid,cluster=int(assigned[i]),fold='train' if cid in train else 'evaluation',
                source_group=find(cid),condition_signatures=sorted(own),unknown_conditions=not bool(own),
                draft_common_questions_cover_all=bool(own) and own<=common[int(assigned[i])],
                specific_questions=[dict(signature=s,question=question(conditions[cid][s])) for s in sorted(own-covered)],
                unknown_preserved=True,automatic_VEX_authorized=False),ensure_ascii=False)+'\n')
    atomic_json(out/'common_question_templates.json',support)
    atomic_json(out/'manifest.json',dict(population=len(ids),assigned=len(ids),clusters=k,
        train_CVEs=len(train),evaluation_CVEs=len(ids)-len(train),split_unit='connected shared source URLs',
        groups=len(groups),largest_group=max(map(len,groups.values())),
        method='TRAIN TF-IDF then unit-normalized spherical K-means; fixed centers for evaluation assignment',
        support_count_unit='distinct training CVEs with exact normalized condition signature',
        no_condition_CVEs=sum(not signatures[c] for c in ids),
        test_fitted=False,independent_semantic_accuracy_verified=False,
        warning='Shared-context fallback remains unknown; questions require CVE/product/path-specific semantic review.'))
    print(json.dumps(json.loads((out/'manifest.json').read_text(encoding='utf-8'))),flush=True)


if __name__=='__main__':build()
