"""Load the source-reference discriminant model without fitting on predictions."""
import json,hashlib
from pathlib import Path
from types import SimpleNamespace
import numpy as np
from sklearn.preprocessing import normalize
from sklearn.metrics import silhouette_samples
from tools.item4.fixed_asset_model import ROOT,prepare,reference_labels

BUNDLE=ROOT/'results/icsa_fixed18_improvement_v2'


def load_model(prefix=None):
    if prefix is None:
        marker=BUNDLE/'active_model.json'
        prefix=json.loads(marker.read_text())['prefix'] if marker.exists() else 'focused_best'
    selected=json.loads((BUNDLE/(prefix+'.json')).read_text(encoding='utf-8'))
    p=prepare(selected['variant']);arrays={}
    if selected.get('source_snapshot_sha256'):
        path=ROOT/'results/icsa_fixed18_reclassification/source_advisories_fulltext_v3.json'
        assert hashlib.sha256(path.read_bytes()).hexdigest()==selected['source_snapshot_sha256']
    for key in ['components','centers','source_seed_indices','source_seed_labels','reduced','labels']:
        arrays[key]=np.load(BUNDLE/(prefix+'_'+key+'.npy'),allow_pickle=False)
    reference=reference_labels(p,consistent=selected.get('seed_policy')=='consistent_legacy')
    indices=np.flatnonzero(reference>=0)
    assert np.array_equal(indices,arrays['source_seed_indices'])
    assert np.array_equal(reference[indices],arrays['source_seed_labels'])
    # Infer with the combined linear transform used by the word explanations.
    components=arrays['components'];z=normalize(p['x']@components.T)
    scores=z@arrays['centers'].T
    for i,a in enumerate(p['allowed']):
        if 11 not in a:scores[i,11]=-1e6
    labels=scores.argmax(axis=1)
    for i,allowed in enumerate(p['allowed']):
        if len(allowed):labels[i]=allowed[np.argmax(scores[i,allowed])]
    reject=(p['max_raw']<.05)|(p['x'].getnnz(axis=1)==0)
    for i in range(len(z)):
        if len(p['allowed'][i]) or len(p['legacy'][i]):reject[i]=False
    labels[reject]=-1;native=silhouette_samples(z,labels,metric='cosine')
    metrics=dict(full_population=len(z),unassigned=int(reject.sum()),assigned=int((~reject).sum()),
        full_svd_cosine_silhouette=float(native.mean()),
        full_embedding_cosine_silhouette=float(native.mean()),
        metric_space=f"TF-IDF / SVD{selected['svd_dimensions']} / source-reference LDA{selected['discriminant_dimensions']}",
        svd_explained_variance=selected['explained_variance'],
        source_training_references=len(indices),reference_training_includes_evaluated_rows=True,
        prediction_labels_used_for_projection_training=False,
        nonempty_asset_types=len(set(labels)-{-1}),unassigned_scored_as_separate_group=True,
        negative_silhouette_records=int((native<0).sum()),
        literal_phrase_advisories=sum(bool(e['strong']) for e in p['evidence']),
        target_silhouette_met=float(native.mean())>.5,target_unassigned_met=int(reject.sum())<=500)
    selected=dict(selected,model_family='source_reference_discriminant',
        min_lexical_similarity=.05,bundle_files_sha256={path.name:hashlib.sha256(path.read_bytes()).hexdigest()
        for path in BUNDLE.glob(prefix+'_*.npy')})
    model=dict(labels=labels,model_labels=labels.copy(),z=z,centers=arrays['centers'],scores=scores,
        svd=SimpleNamespace(components_=components),native=native,metrics=metrics)
    return p,model,selected
