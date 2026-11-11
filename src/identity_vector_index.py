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

    def search(self, grams, limit=100):
        weights = {g: self.idf[g] for g in grams if g in self.idf}
        query_norm = math.sqrt(sum(w * w for w in weights.values()))
        if not query_norm:
            return []
        # Inverted postings evaluate exact sparse cosine without a dense matrix.
        scores = Counter()
        for gram, weight in weights.items():
            for rid in self.postings[gram]:
                scores[rid] += weight * weight
        return sorted(((rid, dot / (query_norm * self.norms[rid])) for rid, dot in scores.items()),
                      key=lambda r: (-r[1], r[0]))[:limit]
