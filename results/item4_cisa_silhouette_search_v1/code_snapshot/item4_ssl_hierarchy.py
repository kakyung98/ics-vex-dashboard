"""Self-supervised representations and bounded recursive CVE partitions.

No LLM, pretrained language model, CWE labels, or VEX decisions are used.
"""
from collections import Counter
from functools import lru_cache
import hashlib
import re

import numpy as np
from scipy.cluster.hierarchy import cut_tree, linkage
from sklearn.cluster import KMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import normalize
import torch
from torch import nn
from torch.nn import functional as F


def clean_text(text):
    text = text.lower()
    text = re.sub(r'cve-\d{4}-\d+|cwe-\d+|cvss:[^\s]+|https?://\S+', ' ', text)
    # Remove score boilerplate up to the original newline, before whitespace folding.
    text = re.sub(r'a cvss[^\n]*', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def corpus_texts(rows):
    texts, groups = [], []
    for r in rows:
        seen, parts = set(), []
        for s in r['sources']:
            digest = hashlib.sha256(s['text'].encode()).hexdigest()
            if digest != s['text_sha256']:
                raise ValueError('Source digest mismatch: ' + r['cve'])
            if digest not in seen:
                parts.append(s['text']); seen.add(digest)
        text = clean_text('\n'.join(parts))
        if not text:
            raise ValueError('Empty source text; retain explicitly rather than fabricate: ' + r['cve'])
        texts.append(text); groups.append(hashlib.sha256(text.encode()).hexdigest())
    return texts, np.asarray(groups)


def cwe_depth(catalog):
    records = catalog['records']
    visiting = set()
    @lru_cache(None)
    def path(k):
        if k in visiting:
            raise ValueError('Cycle in pinned CWE graph')
        visiting.add(k)
        parents = records[k]['parents_view_1000']
        p = max((path(v) + (k,) for v in parents), key=len) if parents else (k,)
        visiting.remove(k)
        return p
    longest = max((path(k) for k in records), key=len)
    return dict(max_depth=len(longest), longest_path=list(longest), root_convention='CWE roots=1; synthetic all-CVE root=0',
                version=catalog['version'], view=catalog['view'], relation='ChildOf in View 1000',
                meaning='Structural cap only; learned levels are not CWE abstraction labels')


def fit_features(texts, dim=256):
    unique = list(dict.fromkeys(texts))
    stop = sorted((set(ENGLISH_STOP_WORDS) - {'no','not','nor','only','before','after','without'}) |
                  {'vulnerability','vulnerabilities','cve','cwe','cvss'})
    vectorizer = TfidfVectorizer(max_features=20000, ngram_range=(1,2), min_df=2, max_df=.98,
                                sublinear_tf=True, stop_words=stop, dtype=np.float32,
                                token_pattern=r'(?u)\b[a-z][a-z0-9_+-]{1,}\b')
    tf = vectorizer.fit_transform(unique)
    if min(tf.shape) <= dim:
        raise ValueError('Insufficient feature rank for configured SVD dimension')
    svd = TruncatedSVD(n_components=dim, random_state=42)
    svd.fit(tf)
    result = dict(vectorizer=vectorizer, svd=svd, dimension=dim,
                  unique_fit_documents=len(unique), explained_variance=float(svd.explained_variance_ratio_.sum()))
    return result, transform_features(result, texts)


def transform_features(features, texts):
    x = features['svd'].transform(features['vectorizer'].transform(texts)).astype(np.float32)
    if not np.isfinite(x).all() or np.any(np.linalg.norm(x, axis=1) < 1e-9):
        raise ValueError('Zero/nonfinite text representation; no silent exclusions')
    return normalize(x).astype(np.float32)


class DenoisingAutoencoder(nn.Module):
    def __init__(self, dim=256, latent=64):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(dim,512),nn.ReLU(),nn.Linear(512,256),nn.ReLU(),nn.Linear(256,latent))
        self.decoder = nn.Sequential(nn.Linear(latent,256),nn.ReLU(),nn.Linear(256,512),nn.ReLU(),nn.Linear(512,dim))

    def forward(self, x):
        return self.decoder(self.encoder(x))


def train_dae(x, seed, epochs=100, batch=512, device='cuda', callback=None, latent=64):
    torch.manual_seed(seed); np.random.seed(seed)
    if device.startswith('cuda'):
        torch.cuda.manual_seed_all(seed)
    # Deduplicate training inputs, while retaining every CVE in exported partitions.
    unique = np.unique(x, axis=0)
    tensor = torch.tensor(unique * np.sqrt(x.shape[1]), dtype=torch.float32, device=device)
    model = DenoisingAutoencoder(x.shape[1],latent).to(device)
    initial = {n:p.detach().clone() for n,p in model.named_parameters()}
    optimizer = torch.optim.Adam(model.parameters(),lr=1e-3)
    history = []
    model.train()
    for epoch in range(epochs):
        total, count = 0., 0
        for ix in torch.randperm(len(tensor), device=device).split(batch):
            target = tensor[ix]
            corrupted = target * (torch.rand_like(target) >= .2) + .05 * torch.randn_like(target)
            optimizer.zero_grad(set_to_none=True)
            loss = F.mse_loss(model(corrupted),target)
            if not torch.isfinite(loss):
                raise ValueError('Nonfinite denoising loss')
            loss.backward(); optimizer.step()
            total += float(loss.detach()) * len(ix); count += len(ix)
        history.append(dict(epoch=epoch+1,denoising_mse=total/count))
        if callback and ((epoch+1)%20==0 or epoch+1==epochs): callback(history[-1])
    model.eval()
    with torch.no_grad():
        change = float(sum((p-initial[n]).square().sum() for n,p in model.named_parameters()).sqrt())
    if change <= 0: raise ValueError('Model weights did not train')
    z = encode_dae(model,x,device)
    return model,z,dict(history=history,weight_change_l2=change,unique_training_vectors=len(unique))


def encode_dae(model,x,device='cuda'):
    model.eval(); parts=[]
    with torch.inference_mode():
        for start in range(0,len(x),1024):
            t=torch.tensor(x[start:start+1024]*np.sqrt(x.shape[1]),dtype=torch.float32,device=device)
            parts.append(model.encoder(t).cpu().numpy())
    z=np.concatenate(parts)
    if not np.isfinite(z).all() or np.any(np.linalg.norm(z,axis=1)<1e-9): raise ValueError('Invalid latent vectors')
    return normalize(z).astype(np.float32)


def cosine_distances(x,query_indices,device='cuda'):
    # Evaluated query silhouettes use distances to ALL members, not only query peers.
    t=torch.tensor(x,dtype=torch.float32,device=device)
    queries=torch.tensor(query_indices,dtype=torch.long,device=device)
    d=(1-t[queries]@t.T).clamp(0,2)
    d[torch.arange(len(queries),device=device),queries]=0
    return d.cpu().numpy()


def sampled_silhouette(distances,labels,query_indices):
    labels=np.asarray(labels);query_indices=np.asarray(query_indices)
    unique,inverse,counts=np.unique(labels,return_inverse=True,return_counts=True)
    if len(unique)<2 or len(unique)>=len(labels): return None
    means=np.stack([distances[:,inverse==j].sum(1)/n for j,n in enumerate(counts)],axis=1)
    own=inverse[query_indices]; own_counts=counts[own]
    a=means[np.arange(len(own)),own]*own_counts/np.maximum(own_counts-1,1)
    means[np.arange(len(own)),own]=np.inf
    b=means.min(1)
    values=(b-a)/np.maximum(np.maximum(a,b),1e-12)
    values[own_counts==1]=0
    return float(values.mean())


def recursive_partition(x,method,max_depth=6,seed=42,min_child=30,min_parent=100,
                        min_silhouette=.02,local_queries=256,device='cuda'):
    n=len(x); levels=np.zeros((n,max_depth+1),dtype=np.int32); nodes=[];next_id=1
    def visit(indices,node_id,parent_id,depth):
        nonlocal next_id
        levels[indices,depth:]=node_id
        record=dict(node_id=node_id,parent_id=parent_id,depth=depth,size=len(indices),split=False)
        nodes.append(record)
        if depth>=max_depth:
            record['stop_reason']='max_depth';return
        if len(indices)<max(min_parent,2*min_child):
            record['stop_reason']='minimum_size';return
        local=x[indices]
        possible=list(range(2,min(5,len(indices)//min_child)+1))
        if not possible: record['stop_reason']='no_feasible_k';return
        node_seed=int((seed*1000003+node_id*9176+depth)%2147483647)
        query=np.sort(np.random.default_rng(node_seed).choice(len(local),min(local_queries,len(local)),replace=False))
        distances=cosine_distances(local,query,device)
        ward_labels=None
        if method=='ward':
            z=linkage(local,method='ward',metric='euclidean')
            ward_labels=cut_tree(z,n_clusters=possible)
        candidates=[];best=None
        for j,k in enumerate(possible):
            labels=(ward_labels[:,j] if ward_labels is not None else
                    KMeans(n_clusters=k,n_init=5,random_state=node_seed).fit_predict(local))
            _,counts=np.unique(labels,return_counts=True)
            if len(counts)!=k or counts.min()<min_child:
                candidates.append(dict(k=k,eligible=False,reason='minimum_child_or_realized_k'));continue
            sil=sampled_silhouette(distances,labels,query)
            candidates.append(dict(k=k,eligible=True,silhouette=sil))
            if sil is not None and (best is None or sil>best[0]+1e-8):best=(sil,k,labels)
        record['candidate_splits']=candidates
        if best is None or best[0]<min_silhouette:
            record['stop_reason']='insufficient_local_separation';return
        score,k,labels=best
        record.update(split=True,children=k,local_cosine_silhouette=score)
        for label in range(k):
            child=next_id;next_id+=1
            visit(indices[labels==label],child,node_id,depth+1)
    visit(np.arange(n),0,None,0)
    validate_levels(levels,max_depth)
    return levels,nodes


def validate_levels(levels,max_depth):
    if levels.ndim!=2 or levels.shape[1]!=max_depth+1 or np.any(levels<0): raise ValueError('Incomplete depth partitions')
    if len(np.unique(levels[:,0]))!=1: raise ValueError('Synthetic root must be unique')
    for depth in range(1,max_depth+1):
        for child in np.unique(levels[:,depth]):
            if len(np.unique(levels[levels[:,depth]==child,depth-1]))!=1: raise ValueError('Child crosses parent partitions')


def depth_metrics(x,reference,levels,query_indices,device='cuda'):
    native=cosine_distances(x,query_indices,device)
    common=native if x is reference else cosine_distances(reference,query_indices,device)
    metrics=[]
    for depth in range(1,levels.shape[1]):
        labels=levels[:,depth];counts=Counter(labels.tolist())
        metrics.append(dict(depth=depth,clusters=len(counts),population=len(x),query_population=len(query_indices),
                            min_cluster_size=min(counts.values()),max_cluster_size=max(counts.values()),
                            largest_cluster_share=max(counts.values())/len(x),
                            native_cosine_silhouette=sampled_silhouette(native,labels,query_indices),
                            reference_cosine_silhouette=sampled_silhouette(common,labels,query_indices)))
    return metrics


def aligned_ari(ids_a,levels_a,ids_b,levels_b):
    if len(set(ids_a))!=len(ids_a) or len(set(ids_b))!=len(ids_b):raise ValueError('Duplicate CVE IDs in ARI inputs')
    common,ia,ib=np.intersect1d(ids_a,ids_b,return_indices=True)
    if len(common)<2:raise ValueError('Insufficient common CVEs')
    if levels_a.shape[1]!=levels_b.shape[1]:raise ValueError('Different depth limits')
    result=[]
    for depth in range(1,levels_a.shape[1]):
        a=levels_a[ia,depth];b=levels_b[ib,depth]
        ka,kb=len(np.unique(a)),len(np.unique(b))
        result.append(dict(depth=depth,common_cves=len(common),clusters_a_on_common=ka,clusters_b_on_common=kb,
                           ari=float(adjusted_rand_score(a,b)),degenerate=(ka<2 or kb<2)))
    return result


def grouped_subsample(groups,fraction,seed):
    if not 0<fraction<1:raise ValueError('Subsample fraction must be between zero and one')
    unique=np.unique(groups)
    selected=np.random.default_rng(seed).choice(unique,max(1,int(len(unique)*fraction)),replace=False)
    return np.flatnonzero(np.isin(groups,selected))
