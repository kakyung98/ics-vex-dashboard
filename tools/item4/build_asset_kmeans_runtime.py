"""Reproduce the published K-means partition and freeze inference transforms."""
from pathlib import Path
import hashlib
import json
import re
import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import adjusted_rand_score
from sklearn.preprocessing import normalize
from threadpoolctl import threadpool_limits

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'data/runtime/asset_kmeans_v1'


def build():
    source=ROOT/'site/asset_vulntology/icsa_role_groups.json'
    taxonomy=ROOT/'site/asset_vulntology/icsa_asset_navigation.json'
    snapshot=json.loads(source.read_text(encoding='utf-8'))
    nav=json.loads(taxonomy.read_text(encoding='utf-8'))
    settings=snapshot['method'];rows=snapshot['advisories']
    texts=[re.sub(r'\b(?:CVE-\d{4}-\d+|ICSA-\S+|CWE-\d+)\b',' ',r['feature_text'],flags=re.I) for r in rows]
    with threadpool_limits(limits=1):
        vectorizer=TfidfVectorizer(ngram_range=tuple(settings['ngram_range']),
            min_df=settings['min_df'],max_features=settings['max_features'],
            sublinear_tf=settings['sublinear_tf'],stop_words='english',dtype=np.float32)
        x=vectorizer.fit_transform(texts)
        svd=TruncatedSVD(n_components=settings['svd_dimensions'],random_state=settings['svd_random_state'])
        z=normalize(svd.fit_transform(x))
        model=KMeans(n_clusters=settings['k'],random_state=settings['random_state'],
                     n_init=settings['n_init'],max_iter=500).fit(z)
    agreement=adjusted_rand_score([r['group_id'] for r in rows],model.labels_)
    if agreement!=1.0:raise ValueError(f'Published partition not reproduced: ARI={agreement}')
    groups=[]
    for label in range(settings['k']):
        recorded={rows[i]['group_id'] for i in np.flatnonzero(model.labels_==label)}
        if len(recorded)!=1:raise ValueError('Cluster identities differ from the saved partition.')
        groups.append(next(g for g in snapshot['groups'] if g['id']==next(iter(recorded))))
    assets=[dict(id=c['id'],name=c['name']) for c in nav['categories']]
    # Cluster IDs and MITRE asset IDs are different namespaces. Definition
    # similarity provides provisional mappings, not semantic accuracy labels.
    definitions=[' '.join(d['name']+' '+d['description'] for d in nav['taxonomy_templates'].values()
                         if d['parent_id']==a['id']) for a in assets]
    asset_vectors=vectorizer.transform(definitions)
    asset_z=normalize(asset_vectors@svd.components_.T)
    OUT.mkdir(parents=True,exist_ok=True)
    arrays=OUT/'transforms.npz'
    np.savez_compressed(arrays,idf=vectorizer.idf_,components=svd.components_,
        centers=model.cluster_centers_,asset_vectors=asset_vectors.toarray(),
        cluster_asset_similarity=normalize(model.cluster_centers_)@asset_z.T)
    manifest=dict(version='asset-tfidf-svd-kmeans/1',algorithm='TF-IDF -> SVD -> L2 normalization -> K-means',
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        taxonomy_sha256=hashlib.sha256(taxonomy.read_bytes()).hexdigest(),
        transforms_sha256=hashlib.sha256(arrays.read_bytes()).hexdigest(),
        settings=settings,vocabulary={term:int(index) for term,index in vectorizer.vocabulary_.items()},assets=assets,
        groups=[dict(id=g['id'],name=g['name']) for g in groups],population=len(rows),
        reproduced_partition_ari=agreement,accuracy_validated=False,
        mapping_policy='BOM text / taxonomy definition similarity supported by the predicted cluster; ambiguous mappings remain unresolved.',
        min_similarity=0.05)
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:manifest[k] for k in ('version','population','reproduced_partition_ari','accuracy_validated')}))


if __name__=='__main__':build()
