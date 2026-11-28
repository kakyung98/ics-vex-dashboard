"""Read-only diagnostics for the exact frozen runtime clustering model."""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import re
import numpy as np
from sklearn.preprocessing import normalize
from src.item4.assets import asset_classification_inference as M


@lru_cache(maxsize=1)
def load():
    manifest,_,_=M.load();raw=(M.BUNDLE/'diagnostics.json').read_bytes()
    expected=(M.BUNDLE/'diagnostics.sha256').read_text(encoding='ascii').strip()
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Cluster diagnostics integrity failure')
    data=json.loads(raw)
    if any(data[k]!=manifest[k] for k in ('source_sha256','transforms_sha256')):
        raise ValueError('Cluster diagnostics belong to a different frozen model')
    if data['model_version']!=manifest['version'] or len(data['points'])!=manifest['population']:
        raise ValueError('Cluster diagnostics population or model version mismatch')
    if len({p['id'] for p in data['points']})!=manifest['population']:
        raise ValueError('Duplicate corpus points in cluster diagnostics')
    return data


def for_job(job):
    data=deepcopy(load());projection=data.pop('projection');manifest,vectorizer,arrays=M.load()
    classification=job.get('asset_classification') or {}
    entries=classification.get('component_classifications') or [classification]
    points=[]
    for entry in entries:
        old=entry.get('prediction') or {}
        if old.get('source_snapshot_sha256')!=data['source_sha256']:
            continue
        evidence={e['source']:e['text'] for e in entry.get('feature_evidence',[])}
        name=evidence.get('BOM component name',entry.get('representative',{}).get('name',''))
        description=evidence.get('BOM component description','')
        current=M.predict(name,[],description)
        if not current.get('cluster_id') or current['cluster_id']!=old.get('cluster_id'):continue
        text=re.sub(r'\b(?:CVE-\d{4}-\d+|ICSA-\S+|CWE-\d+)\b',' ', '\n'.join(p for p in (name,description) if p),flags=re.I)
        z=normalize(vectorizer.transform([text])@arrays['components'].T)
        xy=(z-np.asarray(projection['mean']))@np.asarray(projection['components']).T
        points.append(dict(name=name,component_ref=entry.get('component_ref'),cluster_id=current['cluster_id'],
            x=float(xy[0,0]),y=float(xy[0,1]),distance_to_centroid=current['distance_to_centroid'],
            centroid_margin=current['centroid_margin'],asset_type_id=current.get('asset_type_id'),
            silhouette=None,scope='out-of-sample BOM projection; not a corpus member'))
    data.update(job_id=job['id'],bom_points=points,
        bom_projection_note=None if points else 'No BOM projection is available for this saved classification and frozen model.')
    return data
