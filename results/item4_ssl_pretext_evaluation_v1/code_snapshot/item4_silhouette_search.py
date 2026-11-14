"""Full-population CISA input construction and non-language-model GPU search."""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re

import numpy as np
from sklearn.preprocessing import normalize
import torch
from torch import nn
from torch.nn import functional as F


def clean(text):
    text=text.lower()
    text=re.sub(r'https?://\S+|cve-\d{4}-\d+|cwe-\d+|cvss:[^\s)]+',' ',text)
    text=re.sub(r'\b(?:av|ac|pr|ui|s|c|i|a):[a-z](?:/[a-z]{1,4}:[a-z])+',' ',text)
    text=re.sub(r'a cvss\s+v?\d+(?:\.\d+)?\s+(?:base\s+)?score\s+(?:of\s+)?\d+(?:\.\d+)?(?:\s+has\s+been\s+assigned)?[.;]?',' ',text)
    return re.sub(r'\s+',' ',text).strip()


def dedup_text(parts):
    return '\n'.join(dict.fromkeys(p.strip() for p in parts if p and p.strip()))


def cisa_inputs(advisories,ids,raw_root):
    docs=[];doc_ids=[];scoped=defaultdict(list);contexts=defaultdict(list);links=defaultdict(list)
    targets=set(ids)
    provenance=[];raw_count=0
    banned=('recommended','legal','country','countries','headquarters','disclaimer')
    for aid,row in sorted(advisories.items()):
        target=set(row.get('cves',[]))&targets
        if not target:continue
        raw_path=Path(raw_root)/(aid+'.json')
        raw=json.loads(raw_path.read_text(encoding='utf-8')) if raw_path.exists() else None
        if raw:
            raw_count+=1
            scope={}
            for v in raw.get('vulnerabilities',[]):
                c=v.get('cve')
                text=dedup_text(n.get('text','') for n in v.get('notes',[]) if n.get('category') in {'summary','description'})
                if c in target and text:scope[c]=text
            notes=[n.get('text','') for n in raw.get('document',{}).get('notes',[])
                   if n.get('category')!='legal_disclaimer' and not any(b in n.get('title','').lower() for b in banned)]
            context=dedup_text(notes)
            body=dedup_text([context,*scope.values()])
            source_kind='archived_csaf_document'
            source_hash=hashlib.sha256(raw_path.read_bytes()).hexdigest()
        else:
            scope={v['cve']:v['description'] for v in row.get('vulns',[]) if v.get('cve') in target and v.get('description')}
            context=re.split(r'CVE-\d{4}-\d+',row.get('affected_text',''),maxsplit=1)[0]
            body=dedup_text([row.get('affected_text',''),*scope.values()])
            source_kind='local_cisa_advisory_cache'
            source_hash=hashlib.sha256(json.dumps(row,sort_keys=True).encode()).hexdigest()
        # Cache descriptions remain distinct from independently verified archived notes.
        for v in row.get('vulns',[]):
            if v.get('cve') in target and v.get('description') and not scope.get(v['cve']):
                scope[v['cve']]=v['description']
        if not body.strip():body=dedup_text(scope.values())
        if not body.strip():raise ValueError('No substantive advisory text: '+aid)
        di=len(docs);doc_ids.append(aid);docs.append(clean(body))
        for c in target:
            links[c].append(di)
            if scope.get(c):scoped[c].append(scope[c])
            contexts[c].append(context if context.strip() else body)
        provenance.append(dict(advisory_id=aid,url=row.get('url'),source_kind=source_kind,
                               source_sha256=source_hash,target_cves=sorted(target),
                               scope='Full advisory view may include multiple CVEs; not a CVE-specific prerequisite assertion'))
    scoped_texts=[];context_texts=[];ledger=[]
    for c in ids:
        if not links[c]:raise ValueError('Missing advisory association for target CVE: '+c)
        s=dedup_text(scoped[c]);context=dedup_text(contexts[c]);fallback=not bool(s.strip())
        text=clean(s if s.strip() else context)
        if not text:raise ValueError('No usable CISA text for '+c)
        scoped_texts.append(text);context_texts.append(clean(dedup_text([s,context])))
        ledger.append(dict(cve=c,advisory_ids=[doc_ids[i] for i in links[c]],
                           shared_context_fallback=fallback,cve_specific_description_present=not fallback,
                           note='Shared context is not asserted to describe this CVE alone' if fallback else None))
    coverage=dict(population=len(ids),advisories=len(docs),archived_csaf_documents=raw_count,
                  cve_specific=sum(not r['shared_context_fallback'] for r in ledger),
                  shared_context_fallbacks=sum(r['shared_context_fallback'] for r in ledger),
                  excluded_cves=0,missing_cves=0)
    return dict(documents=docs,doc_ids=doc_ids,scoped=scoped_texts,context=context_texts,
                links=[links[c] for c in ids],ledger=ledger,provenance=provenance,coverage=coverage)


def pool_advisories(vectors,links):
    result=np.stack([vectors[ix].mean(0) for ix in links]).astype(np.float32)
    if np.any(np.linalg.norm(result,axis=1)<1e-9):raise ValueError('Zero pooled advisory embedding')
    return normalize(result).astype(np.float32)


def gpu_kmeans(x,k,seed=42,n_init=3,max_iter=80,device='cuda'):
    """Lloyd iterations with k-means++ seeding and explicit empty-center repair."""
    t=torch.as_tensor(x,dtype=torch.float32,device=device)
    if not torch.isfinite(t).all() or k<2 or k>len(t):raise ValueError('Invalid K-means input')
    best=None
    with torch.inference_mode():
        norms=t.square().sum(1)
        for init in range(n_init):
            generator=torch.Generator(device=device).manual_seed(seed+init*1009)
            first=int(torch.randint(len(t),(1,),generator=generator,device=device))
            selected=[t[first]];distance=(t-t[first]).square().sum(1)
            for _ in range(k-1):
                if float(distance.sum())<1e-10:
                    chosen=int(torch.randint(len(t),(1,),generator=generator,device=device))
                else:chosen=int(torch.multinomial(distance,1,generator=generator))
                selected.append(t[chosen]);distance=torch.minimum(distance,(t-t[chosen]).square().sum(1))
            centers=torch.stack(selected);previous=None
            for step in range(max_iter):
                d=(norms[:,None]+centers.square().sum(1)[None,:]-2*t@centers.T).clamp_min(0)
                labels=d.argmin(1)
                if previous is not None and torch.equal(labels,previous):break
                previous=labels.clone()
                counts=torch.bincount(labels,minlength=k)
                sums=torch.zeros_like(centers);sums.index_add_(0,labels,t)
                centers=sums/counts.clamp_min(1)[:,None]
                empty=torch.nonzero(counts==0).flatten()
                if len(empty):
                    far=torch.argsort(d.min(1).values,descending=True)[:len(empty)]
                    centers[empty]=t[far]
            d=(norms[:,None]+centers.square().sum(1)[None,:]-2*t@centers.T).clamp_min(0)
            labels=d.argmin(1);inertia=float(d[torch.arange(len(t),device=device),labels].sum())
            if best is None or inertia<best[0]:best=(inertia,labels.cpu().numpy(),centers.cpu().numpy(),step+1)
    return best[1],dict(inertia=best[0],iterations=best[3],centers=best[2])


def merge_small(x,labels,minimum=30):
    labels=labels.copy()
    unique,counts=np.unique(labels,return_counts=True)
    large=unique[counts>=minimum];small=unique[counts<minimum]
    if not len(large):raise ValueError('No cluster meets minimum size')
    if len(small):
        centers=normalize(np.stack([x[labels==v].mean(0) for v in large]))
        indices=np.flatnonzero(np.isin(labels,small))
        labels[indices]=large[(x[indices]@centers.T).argmax(1)]
    _,labels=np.unique(labels,return_inverse=True)
    return labels.astype(np.int32),len(small)


class ContrastiveEncoder(nn.Module):
    def __init__(self,dim=256,latent=64):
        super().__init__()
        self.encoder=nn.Sequential(nn.Linear(dim,512),nn.ReLU(),nn.Linear(512,128),nn.ReLU(),nn.Linear(128,latent))
    def forward(self,x):return F.normalize(self.encoder(x),dim=1)


def train_neighbor_contrastive(x,latent=64,epochs=50,seed=42,device='cuda',callback=None):
    """Declared kNN-positive contrastive adaptation, not an exact paper reproduction."""
    torch.manual_seed(seed);torch.cuda.manual_seed_all(seed)
    unique=np.unique(x,axis=0);t=torch.tensor(unique,dtype=torch.float32,device=device)
    neighbors=[]
    with torch.inference_mode():
        for start in range(0,len(t),512):
            sim=t[start:start+512]@t.T
            sim[torch.arange(len(sim),device=device),torch.arange(start,start+len(sim),device=device)]=-torch.inf
            neighbors.append(sim.topk(min(5,len(t)-1),dim=1).indices)
    neighbors=torch.cat(neighbors)
    model=ContrastiveEncoder(x.shape[1],latent).to(device)
    initial={n:p.detach().clone() for n,p in model.named_parameters()}
    optimizer=torch.optim.Adam(model.parameters(),lr=3e-4);history=[]
    model.train()
    for epoch in range(epochs):
        losses=[]
        for ix in torch.randperm(len(t),device=device).split(256):
            if len(ix)<2:continue
            choice=torch.randint(neighbors.shape[1],(len(ix),),device=device)
            a=t[ix];b=t[neighbors[ix,choice]]
            aa=F.normalize(a*(torch.rand_like(a)>=.1),dim=1)
            bb=F.normalize(b*(torch.rand_like(b)>=.1),dim=1)
            optimizer.zero_grad(set_to_none=True)
            za,zb=model(aa),model(bb);logits=za@zb.T/.1;target=torch.arange(len(ix),device=device)
            loss=(F.cross_entropy(logits,target)+F.cross_entropy(logits.T,target))/2
            loss=loss+.1*F.mse_loss(za@za.T,a@a.T)
            if not torch.isfinite(loss):raise ValueError('Nonfinite contrastive loss')
            loss.backward();optimizer.step();losses.append(float(loss.detach()))
        history.append(dict(epoch=epoch+1,loss=float(np.mean(losses))))
        if callback and (epoch+1)%25==0:callback(history[-1])
    model.eval();encoded=[]
    with torch.inference_mode():
        for start in range(0,len(x),1024):encoded.append(model(torch.tensor(x[start:start+1024],device=device)).cpu().numpy())
        change=float(sum((p-initial[n]).square().sum() for n,p in model.named_parameters()).sqrt())
    if change<=0:raise ValueError('Contrastive model did not train')
    return model,np.concatenate(encoded),dict(history=history,weight_change_l2=change,unique_training_vectors=len(t),
           objective='kNN-positive symmetric InfoNCE + 0.1 cosine-geometry MSE; no class/CWE labels',
           limitation='Feature-neighbor positives are a heuristic, not verified shared vulnerability classes')
