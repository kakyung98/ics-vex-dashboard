"""Materialize all 12,418 CVEs and cluster available structured condition drafts."""
import argparse
from collections import Counter,defaultdict
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import sqlite3
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src import operational_corpus as corpus
from src.training_io import atomic_json


STATUS=ROOT/'results/operational_corpus_v1/build_status.json'


def semantic_vectors(texts,folder):
    """Encode new condition strings only; resumes do not re-embed the population."""
    import numpy as np
    from src.prerequisite_models import embed_conditions,model_status
    model=model_status()['embedding_model']
    keys=[hashlib.sha256(corpus.encoded([model,text]).encode()).hexdigest() for text in texts]
    with sqlite3.connect(Path(folder)/'embedding_cache.sqlite3',timeout=60) as db:
        db.execute('CREATE TABLE IF NOT EXISTS vectors(key TEXT PRIMARY KEY,model TEXT,vector BLOB)')
        cached={key:np.frombuffer(vector,dtype=np.float32).copy() for key,vector in db.execute('SELECT key,vector FROM vectors WHERE model=?',(model,))}
        missing=list(dict.fromkeys(key for key in keys if key not in cached))
        text_by_key=dict(zip(keys,texts))
        if missing:
            matrix,_=embed_conditions([text_by_key[key] for key in missing])
            for key,vector in zip(missing,matrix):cached[key]=np.asarray(vector,dtype=np.float32)
            db.executemany('INSERT OR REPLACE INTO vectors VALUES(?,?,?)',[(key,model,cached[key].tobytes()) for key in missing])
    return np.stack([cached[key] for key in keys]),model


def cluster(database=None,mode='semantic',ks=(8,16,32),threshold=.5):
    import numpy as np
    from sklearn.metrics import silhouette_score
    from threadpoolctl import threadpool_limits
    database=Path(database or corpus.DATABASE)
    start=time.monotonic();points=[]
    with corpus.connect(database) as db:
        for row in db.execute('SELECT cve,draft FROM corpus ORDER BY cve'):
            draft=json.loads(row['draft'])
            for c in draft['conditions']:
                if c['proposed_necessity']!='explicitly_required':continue
                points.append(dict(cve=row['cve'],id=c['id'],domain=c['domain'],kind=c['kind'],
                    text='kind='+c['kind']+'; condition='+c['value'],condition=c['value'],
                    source_read=draft['source_reading_complete'],observable=c['operator_observable']))
    if not points:
        return dict(status='no_confirmed_necessary_candidates',candidate_count=0,assigned_cves=0)
    atomic_json(STATUS,dict(phase='embedding_conditions',population=corpus.summary(database)['population'],condition_candidates=len(points),mode=mode))
    texts=[p['text'] for p in points]
    identity=hashlib.sha256(corpus.encoded([mode,texts]).encode()).hexdigest()
    vector_file=database.parent/('condition_vectors_'+identity[:16]+'.npz')
    if mode=='semantic':
        from src.prerequisite_models import model_status
        identity=hashlib.sha256((identity+model_status()['embedding_model']).encode()).hexdigest()
        vector_file=database.parent/('condition_vectors_'+identity[:16]+'.npz')
        if vector_file.exists():
            cache=np.load(vector_file,allow_pickle=False);x=cache['vectors'];model=str(cache['model'])
        else:
            x,model=semantic_vectors(texts,database.parent);np.savez_compressed(vector_file,vectors=x,model=np.array(model))
    elif mode=='structured':
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.decomposition import TruncatedSVD
        # Bounded dense projection, not a 12k x vocabulary allocation.
        sparse=TfidfVectorizer(ngram_range=(1,2),max_features=12000).fit_transform(texts)
        dimensions=min(128,sparse.shape[0]-1,sparse.shape[1]-1)
        x=TruncatedSVD(n_components=dimensions,random_state=42).fit_transform(sparse) if dimensions>=2 else sparse.toarray()
        model='Structured condition text TF-IDF/SVD; no language embedding model'
    else:raise ValueError('Unsupported corpus embedding mode')
    x=np.asarray(x,dtype=np.float32);norm=np.linalg.norm(x,axis=1,keepdims=True)
    if np.any(norm==0) or not np.isfinite(x).all():raise ValueError('Invalid condition vectors')
    x/=norm
    unique=len(np.unique(x,axis=0));candidates=sorted({min(int(k),unique,len(x)) for k in ks if int(k)>0})
    if not candidates:raise ValueError('Provide positive K candidates')
    runs=[]
    with threadpool_limits(limits=4):
        for k in candidates:
            atomic_json(STATUS,dict(phase='spherical_clustering',population=corpus.summary(database)['population'],condition_candidates=len(points),k=k,mode=mode))
            rng=np.random.default_rng(42);chosen=[int(rng.integers(len(x)))];nearest=x@x[chosen[0]]
            for _ in range(1,k):
                chosen.append(int(np.argmin(nearest)));nearest=np.maximum(nearest,x@x[chosen[-1]])
            centers=x[chosen].copy();previous=None
            for _ in range(40):
                labels=(x@centers.T).argmax(axis=1)
                if previous is not None and np.array_equal(previous,labels):break
                previous=labels.copy()
                for label in range(k):
                    members=x[labels==label]
                    if len(members):
                        center=members.mean(axis=0);n=np.linalg.norm(center)
                        if n:centers[label]=center/n
            labels=(x@centers.T).argmax(axis=1);similarity=(x*centers[labels]).sum(axis=1)
            realized=len(np.unique(labels));score=None
            if 1<realized<len(x):
                score=float(silhouette_score(x,labels,metric='cosine',sample_size=min(1000,len(x)),random_state=42))
            runs.append(dict(k=k,realized_k=realized,silhouette=score,mean_cosine=float(similarity.mean()),labels=labels,similarity=similarity))
    best=max(runs,key=lambda r:((r['silhouette'] if r['silhouette'] is not None else -2),-r['k']))
    groups=defaultdict(list);assignments=[];unassigned=set()
    for point,label,similarity in zip(points,best['labels'],best['similarity']):
        if similarity<threshold:unassigned.add(point['cve']);continue
        gid='C'+str(int(label)+1);groups[gid].append(point)
        assignments.append((point['id'],point['cve'],gid,float(similarity)))
    templates=[]
    for gid,members in sorted(groups.items()):
        cves={p['cve'] for p in members};counts=Counter((p['domain'],p['condition']) for p in members)
        common=[]
        for (domain,condition),count in counts.most_common(20):
            matching={p['cve'] for p in members if p['domain']==domain and p['condition']==condition}
            common.append(dict(domain=domain,condition=condition,distinct_cves=len(matching),support=len(matching)/len(cves),
                scope='observed candidate confirmation among cluster CVEs; not attack-path necessity probability',
                question_reuse_approved=False))
        templates.append(dict(cluster_id=gid,distinct_cves=len(cves),condition_count=len(members),
            domains=dict(Counter(p['domain'] for p in members)),source_read_cves=len({p['cve'] for p in members if p['source_read']}),
            common_candidates=common,eligible_for_vex=False,validation_status='pending_review',unit='condition candidate; no inferred AND'))
    assigned={r[1] for r in assignments}
    report=dict(status='draft_clusters_built',method='spherical_kmeans_'+mode,embedding=model,
        unit='source-linked necessary-condition candidate; source path proposals remain separate',
        candidate_count=len(points),assigned_cves=len(assigned),unassigned_cves=corpus.summary(database)['population']-len(assigned),
        exception_candidate_count=len(points)-len(assignments),similarity_threshold=threshold,selected_k=len(groups),
        scores=[{k:v for k,v in r.items() if k not in {'labels','similarity'}} for r in runs],
        silhouette_sample_size=min(1000,len(x)),automatic_approvals=0,eligible_for_vex=False,seconds=round(time.monotonic()-start,2))
    with corpus.connect(database,write=True) as db:
        db.execute('DELETE FROM assignments');db.execute('DELETE FROM clusters')
        db.executemany('INSERT INTO assignments VALUES(?,?,?,?)',assignments)
        db.executemany('INSERT INTO clusters VALUES(?,?)',[(r['cluster_id'],corpus.encoded(r)) for r in templates])
        current=corpus.summary(database);current['clustering']=report
        db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('summary',corpus.encoded(current)))
    atomic_json(STATUS,dict(phase='complete',**corpus.summary(database)))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['semantic','structured','none'],default='semantic')
    args=parser.parse_args()
    atomic_json(STATUS.parent/'build_process.json',dict(pid=os.getpid(),mode=args.mode))
    try:
        atomic_json(STATUS,dict(phase='indexing_full_population',population=12418))
        summary=corpus.build()
        if args.mode!='none':cluster(mode=args.mode)
        summary=corpus.summary();atomic_json(STATUS,dict(phase='complete',**summary));print(corpus.encoded(summary),flush=True)
    except Exception as exc:
        atomic_json(STATUS,dict(phase='failed',error=type(exc).__name__+': '+str(exc)));raise


if __name__=='__main__':main()
