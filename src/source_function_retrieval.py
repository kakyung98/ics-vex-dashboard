"""Source-function BM25 retrieval. LLM queries are hints, never identity evidence."""
from collections import Counter
import math,re


def tokens(text):
    text=re.sub(r'([a-z0-9])([A-Z])',r'\1 \2',text)
    return re.findall(r'[a-z][a-z0-9]+',text.lower())


def rank(functions,query,known_names=(),patch_files=(),limit=12):
    docs=[tokens(f['name']+' '+f['file']+' '+f.get('code_excerpt','')) for f in functions]
    counts=[Counter(d) for d in docs];n=len(docs);mean=sum(map(len,docs))/n if n else 1
    df=Counter(t for d in counts for t in d);query=set(tokens(query));ranked=[]
    for f,bag,doc in zip(functions,counts,docs):
        score=0.0
        for term in query:
            tf=bag[term]
            if tf:score+=math.log(1+(n-df[term]+.5)/(df[term]+.5))*tf*2.2/(tf+1.2*(.25+.75*len(doc)/mean))
        if f['name'] in known_names or f.get('symbol') in known_names:score+=100
        if any(f['file']==p or f['file'].endswith('/'+p) for p in patch_files):score+=30
        ranked.append({**f,'retrieval_score':round(score,6),'score_is_not_confidence':True})
    ranked.sort(key=lambda f:(-f['retrieval_score'],f['file'],f.get('line') or 0,f['id']))
    return ranked[:limit]
