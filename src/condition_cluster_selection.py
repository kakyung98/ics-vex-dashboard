"""Three-index K selection in one original, normalized embedding space."""
import numpy as np
from scipy.stats import rankdata
from sklearn.metrics import silhouette_score,calinski_harabasz_score,davies_bouldin_score


def score(x,labels,embedding_id):
    x=np.asarray(x);labels=np.asarray(labels)
    if x.ndim!=2 or labels.shape!=(len(x),) or not np.isfinite(x).all():raise ValueError('Invalid full population')
    if not np.allclose(np.linalg.norm(x,axis=1),1,atol=1e-5):raise ValueError('Use original L2-normalized embeddings')
    if not np.issubdtype(labels.dtype,np.integer) or np.any(labels<0):raise ValueError('Unassigned points are not allowed')
    _,counts=np.unique(labels,return_counts=True);k=len(counts)
    if not 2<=k<len(x):raise ValueError('Require 2 <= realized K < population')
    return dict(k=k,population=len(x),embedding_id=embedding_id,
        silhouette=float(silhouette_score(x,labels,metric='cosine')),
        calinski_harabasz=float(calinski_harabasz_score(x,labels)),
        davies_bouldin=float(davies_bouldin_score(x,labels)),
        silhouette_metric='cosine',ch_db_geometry='Euclidean on the same original L2-normalized vectors',
        silhouette_population='full',min_cluster_size=int(counts.min()),max_cluster_size=int(counts.max()),
        singleton_clusters=int(sum(counts==1)),max_cluster_fraction=float(counts.max()/len(x)))


def select(rows):
    if not rows:raise ValueError('No candidates')
    if len({(r['embedding_id'],r['population']) for r in rows})!=1:raise ValueError('Do not rank different populations or embedding spaces together')
    values=np.array([[r['silhouette'],r['calinski_harabasz'],-r['davies_bouldin']] for r in rows])
    if not np.isfinite(values).all():raise ValueError('Nonfinite scores')
    ranks=np.stack([rankdata(-values[:,j],method='average') for j in range(3)],axis=1)
    ranked=[]
    for i,r in enumerate(rows):
        dominated=any(np.all(v>=values[i]) and np.any(v>values[i]) for j,v in enumerate(values) if j!=i)
        ranked.append(dict(r,pareto_optimal=not dominated,mean_metric_rank=float(ranks[i].mean()),
            metric_ranks=dict(zip(('silhouette','calinski_harabasz','davies_bouldin'),ranks[i].tolist()))))
    ranked.sort(key=lambda r:(not r['pareto_optimal'],r['mean_metric_rank'],-r['silhouette'],r['k']))
    return dict(suggested_k=ranked[0]['k'],ranked_candidates=ranked,
        policy='Pareto frontier first, equal-weight mean rank of three indices, then silhouette, then smaller K',
        final_semantic_acceptance=False,
        caution='Relative geometric preference only; inspect collapse, singleton clusters, stability and condition-pair validation.')
