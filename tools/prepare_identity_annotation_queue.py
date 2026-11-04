"""Prepare blind identity review inputs; never fabricate independent gold."""
import json,sys,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

def main():
    folder=ROOT/'data/identity_evidence_v3_annotation'
    if (folder/'manifest.json').exists():raise FileExistsError('Do not overwrite frozen annotation inputs.')
    audit=ROOT/'results/identity_evidence_v3_reference_audit.json';report=json.loads(audit.read_text(encoding='utf-8'))
    records=sorted(report['records'],key=lambda r:r['id'])
    # Diversity across decisions; do not show the legacy reference or system ranking to reviewers.
    buckets={}
    for r in records:buckets.setdefault(r['decision']['identity_status'],[]).append(r)
    picked=[]
    while len(picked)<300 and any(buckets.values()):
        for key in sorted(buckets):
            if buckets[key] and len(picked)<300:picked.append(buckets[key].pop(0))
    rows=[{'id':r['id'],'input':r['input'],'input_origin':'legacy_advisory_derived_synthetic_input_not_independent_real_asset',
        'identity':None,'version_annotations':None,'review_status':'pending','reviewers':[],'adjudicator':None,
        'annotation_basis':None,'source_references':[],'split':'unassigned_until_identity_grouping',
        'instruction':'Review input identity independently; record manufacturer/brand/distributor distinctions, supported identifiers, version source/meaning, ambiguity and supporting public sources. Do not use model output as gold.'} for r in picked]
    folder.mkdir(exist_ok=True);file=folder/'blind_review_inputs.jsonl'
    file.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
    manifest={'count':len(rows),'adjudicated_labels':0,'training_started':False,'independent_real_asset_benchmark':False,
        'peer_or_model_answers_included':False,'source_audit_sha256':hashlib.sha256(audit.read_bytes()).hexdigest(),
        'input_sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'split_policy':'After adjudication, group by vendor/product and near-duplicate/advisory before splitting. Add independently collected real SBOMs for a real-world claim.',
        'external_api_calls':0,'calibration_ready':False}
    (folder/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8');print(json.dumps(manifest,indent=2))

if __name__=='__main__':main()
