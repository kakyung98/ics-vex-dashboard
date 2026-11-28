"""Evaluate the frozen runtime partition and save a display-only PCA projection.

No fitting of TF-IDF/SVD/K-means, no excluded rows, no asset-accuracy claim.
"""
from pathlib import Path
import hashlib
import json
import re
import sys
import numpy as np
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_samples, calinski_harabasz_score, davies_bouldin_score
from sklearn.preprocessing import normalize
from threadpoolctl import threadpool_limits

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from src.item4.assets.asset_classification_inference import load,BUNDLE


def build():
    manifest,vectorizer,arrays=load()
    source=ROOT/'site/asset_vulntology/icsa_role_groups.json'
    if hashlib.sha256(source.read_bytes()).hexdigest()!=manifest['source_sha256']:
        raise ValueError('Runtime source snapshot differs; do not mix model evaluations')
    snapshot=json.loads(source.read_text(encoding='utf-8'));rows=snapshot['advisories']
    texts=[re.sub(r'\b(?:CVE-\d{4}-\d+|ICSA-\S+|CWE-\d+)\b',' ',r['feature_text'],flags=re.I) for r in rows]
    index={g['id']:i for i,g in enumerate(manifest['groups'])}
    labels=np.array([index[r['group_id']] for r in rows])
    with threadpool_limits(limits=1):
        x=vectorizer.transform(texts);z=normalize(x@arrays['components'].T)
        predicted=np.argmin(((z[:,None,:]-arrays['centers'][None,:,:])**2).sum(axis=2),axis=1)
        if not np.array_equal(predicted,labels):raise ValueError('Frozen centroid assignments differ from published membership')
        native=silhouette_samples(z,labels,metric='cosine')
        original=silhouette_samples(x,labels,metric='cosine')
        pca=PCA(n_components=2,svd_solver='full').fit(z)
        xy=pca.transform(z);centers=pca.transform(arrays['centers'])
        radius=np.linalg.norm(z-arrays['centers'][labels],axis=1)
        metrics=dict(population=len(rows),clusters=len(index),metric='cosine',full_population=True,
            svd_cosine_silhouette=float(native.mean()),original_tfidf_cosine_silhouette=float(original.mean()),
            negative_silhouette_records=int((native<0).sum()),zero_feature_records=int((x.getnnz(axis=1)==0).sum()),
            mean_centroid_distance=float(radius.mean()),sum_squared_centroid_distance=float((radius**2).sum()),
            davies_bouldin_euclidean=float(davies_bouldin_score(z,labels)),
            calinski_harabasz_euclidean=float(calinski_harabasz_score(z,labels)),
            svd_dimensions=int(z.shape[1]),svd_explained_variance=snapshot['metrics']['svd_explained_variance'],
            projection_explained_variance=pca.explained_variance_ratio_.tolist(),
            selection_candidates=snapshot['metrics'].get('selection_candidates'),independent_accuracy_validated=False)
    groups=[]
    for i,g in enumerate(manifest['groups']):
        mask=labels==i
        groups.append(dict(id=g['id'],name=g['name'],count=int(mask.sum()),
            silhouette=float(native[mask].mean()),original_tfidf_silhouette=float(original[mask].mean()),
            mean_centroid_distance=float(radius[mask].mean()),negative_silhouette_records=int((native[mask]<0).sum()),
            center=centers[i].tolist()))
    data=dict(version='asset-cluster-diagnostics/1',model_version=manifest['version'],
        source_sha256=manifest['source_sha256'],transforms_sha256=manifest['transforms_sha256'],
        metrics=metrics,groups=groups,projection=dict(method='PCA of frozen normalized SVD coordinates; display only',
            mean=pca.mean_.tolist(),components=pca.components_.tolist()),
        points=[dict(id=r['id'],title=r['title'],cluster_id=r['group_id'],x=float(xy[i,0]),y=float(xy[i,1]),
            silhouette=float(native[i]),zero_features=bool(x.getnnz(axis=1)[i]==0)) for i,r in enumerate(rows)],
        limitations=['All source rows, including zero-feature rows, are included.',
            'Metrics are computed in the full frozen model space, not on the 2D scatter.',
            'The 2D projection distorts distances; overlap or separation in the plot is not a classification score.',
            'The BOM point is an out-of-sample projection; it has no corpus silhouette label.',
            'Cluster structure, centroid proximity and reproduced membership do not measure asset-type accuracy.',
            'The selected partition was chosen among candidates on this same corpus, not on a held-out population.'])
    encoded=json.dumps(data,ensure_ascii=False,separators=(',',':')).encode()
    (BUNDLE/'diagnostics.json').write_bytes(encoded)
    (BUNDLE/'diagnostics.sha256').write_text(hashlib.sha256(encoded).hexdigest(),encoding='ascii')
    print(json.dumps(metrics))


if __name__=='__main__':build()
