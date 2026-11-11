"""Explicit operational-role activation; training history is never rewritten."""
from pathlib import Path
import hashlib,json,os
ROOT=Path(__file__).resolve().parents[1]
CONFIG=ROOT/'data/operational_runtime_models.json'
ROLES={'item4-questions','operation-assessment'}


def configured(role,*,force_base=False):
    if role!='item4-questions' or force_base or os.environ.get('ICSVEX_QUESTION_GENERATOR')=='rules':return None
    config=json.loads(CONFIG.read_text(encoding='utf-8'))
    spec=config.get('roles',{}).get(role,{})
    if not spec.get('enabled'):return None
    folder=(ROOT/spec['path']).resolve()
    if not folder.is_relative_to((ROOT/'models').resolve()):raise ValueError('Adapter path escapes models directory.')
    if not (folder/'training_complete.json').is_file():raise RuntimeError('Question adapter training is incomplete.')
    return {**spec,'folder':folder}


def verify_weights(spec):
    actual=hashlib.sha256((spec['folder']/'adapter_model.safetensors').read_bytes()).hexdigest()
    if actual!=spec['weights_sha256']:raise RuntimeError('Operational adapter fingerprint changed.')
    return actual


def status():
    rows=[]
    for role in sorted(ROLES):
        try:
            spec=configured(role)
            rows.append({'role':role,'configured_mode':'tuned_rag' if spec else 'rules',
                'weights_available':bool(spec),'adapter':spec['folder'].name if spec else None,
                'experimental':bool(spec),'independent_semantic_accuracy_established':False})
        except Exception as e:
            rows.append({'role':role,'configured_mode':'tuned','weights_available':False,'error':str(e),
                         'base_fallback_enabled':False})
    return {'roles':rows,'base_fallback_enabled':False,'outputs_require_review':True}
