"""Sparse TF-IDF character vectors; similarity is retrieval, never identity proof."""
from collections import Counter
import math


class CharacterVectorIndex:
    def __init__(self, postings, count):
        self.postings = postings
        self.idf = {gram: math.log((1 + count) / (1 + len(ids))) + 1 for gram, ids in postings.items()}
        squared = Counter()
        for gram, ids in postings.items():
            weight = self.idf[gram] ** 2
            for rid in ids:
                squared[rid] += weight
        self.norms = {rid: math.sqrt(value) for rid, value in squared.items()}
        # The same exact sparse cosine, accumulated in compiled sparse algebra.
        # This changes retrieval cost, not eligibility or acceptance thresholds.
        import numpy as np
        from scipy.sparse import csr_matrix
        self.ids = sorted(self.norms)
        columns = {rid:i for i,rid in enumerate(self.ids)}
        self.gram_rows = {g:i for i,g in enumerate(postings)}
        indptr=[0];indices=[];data=[]
        for gram, ids in postings.items():
            for rid in sorted(ids):
                indices.append(columns[rid]);data.append(self.idf[gram]**2/self.norms[rid])
            indptr.append(len(indices))
        self.matrix=csr_matrix((np.asarray(data),np.asarray(indices),np.asarray(indptr)),shape=(len(postings),len(self.ids)))

    def search(self, grams, limit=100):
        weights = {g: self.idf[g] for g in grams if g in self.idf}
        query_norm = math.sqrt(sum(w * w for w in weights.values()))
        if not query_norm:
            return []
        import numpy as np
        scores=np.asarray(self.matrix[[self.gram_rows[g] for g in weights]].sum(axis=0)).ravel()/query_norm
        nonzero=np.flatnonzero(scores)
        # Select all boundary ties before deterministic ID ordering.
        if len(nonzero)>limit:
            cutoff=np.partition(scores[nonzero],-limit)[-limit]
            nonzero=nonzero[scores[nonzero]>=cutoff]
        return sorted(((self.ids[i],float(scores[i])) for i in nonzero),key=lambda r:(-r[1],r[0]))[:limit]
