"""Frozen TF-IDF/SVD/K-means inference from BOM text, without an ICSA match gate."""
from functools import lru_cache
from pathlib import Path
import hashlib
import json
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

ROOT=Path(__file__).resolve().parents[3]
VERSION='asset-tfidf-svd-kmeans/1'
BUNDLE=ROOT/'data/runtime/asset_kmeans_v1'


@lru_cache(maxsize=1)
def load():
    manifest=json.loads((BUNDLE/'manifest.json').read_text(encoding='utf-8'))
    arrays=BUNDLE/'transforms.npz'
    if manifest['version']!=VERSION or hashlib.sha256(arrays.read_bytes()).hexdigest()!=manifest['transforms_sha256']:
        raise ValueError('Asset K-means model integrity failure')
    vectorizer=TfidfVectorizer(vocabulary=manifest['vocabulary'],
        ngram_range=tuple(manifest['settings']['ngram_range']),stop_words='english',
        sublinear_tf=manifest['settings']['sublinear_tf'],dtype=np.float32)
    with np.load(arrays,allow_pickle=False) as saved:
        values={key:saved[key] for key in saved.files}
    vectorizer.idf_=values['idf']
    return manifest,vectorizer,values


def predict(name,evidence,description=''):
    manifest,vectorizer,arrays=load()
    text='\n'.join(part for part in (name,description) if part)
    text=re.sub(r'\b(?:CVE-\d{4}-\d+|ICSA-\S+|CWE-\d+)\b',' ',text,flags=re.I)
    x=vectorizer.transform([text])
    result=dict(status='unresolved',asset_type_id=None,model=manifest['algorithm'],
        model_version=VERSION,input_basis='BOM component name and description',
        accuracy_validated=False,supplies_operating_truth=False,
        mapping_policy=manifest['mapping_policy'],source_snapshot_sha256=manifest['source_sha256'])
    if not x.nnz:return dict(result,reason='No known TF-IDF features in the BOM component text.')
    z=normalize(x@arrays['components'].T)
    if not np.any(z):return dict(result,reason='The BOM text has no usable SVD projection.')
    distances=np.linalg.norm(arrays['centers']-z,axis=1)
    order=np.argsort(distances);label=int(order[0])
    result.update(cluster_id=manifest['groups'][label]['id'],cluster_name=manifest['groups'][label]['name'],
        distance_to_centroid=float(distances[label]),centroid_margin=float(distances[order[1]]-distances[label]),
        cluster_uncertain=bool(distances[order[1]]-distances[label]<manifest['min_similarity']),
        clustering_method='Nearest saved K-means centroid in normalized SVD space')
    lexical=np.asarray(x@arrays['asset_vectors'].T).ravel()
    support=arrays['cluster_asset_similarity'][label]
    ranking=np.argsort(lexical*np.maximum(support,0))[::-1]
    result['candidate_types']=[dict(manifest['assets'][int(i)],text_similarity=float(lexical[i]),
        cluster_similarity=float(support[i])) for i in ranking[:3]]
    best=int(ranking[0]);second=int(ranking[1]);minimum=manifest['min_similarity']
    if result['cluster_uncertain'] or lexical[best]<minimum or lexical[best]-lexical[second]<minimum or support[best]<minimum:
        return dict(result,reason='K-means cluster assigned; BOM text does not distinguish one asset type with sufficient definition similarity.')
    return dict(result,status='classified',asset_type_id=manifest['assets'][best]['id'],
        reference_similarity=float(lexical[best]),score=float(lexical[best]*support[best]),
        reason='Provisional asset type from BOM text and taxonomy similarity in the predicted K-means context.')
