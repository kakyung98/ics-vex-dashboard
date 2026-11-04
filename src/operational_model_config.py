"""Explicit operational-role activation; training history is never rewritten."""
from pathlib import Path
import hashlib,json,os
ROOT=Path(__file__).resolve().parents[1]
CONFIG=ROOT/'data/operational_runtime_models.json'
ROLES={'item4-questions','operation-assessment'}


def configured(role,*,force_base=False):
    # Operational roles are implemented by rules; no adapter or base inference.
    return None


def verify_weights(spec):
    actual=hashlib.sha256((spec['folder']/'adapter_model.safetensors').read_bytes()).hexdigest()
    if actual!=spec['weights_sha256']:raise RuntimeError('Operational adapter fingerprint changed.')
    return actual


def status():
    rows=[]
    for role in sorted(ROLES):
        try:
            spec=configured(role)
            rows.append({'role':role,'configured_mode':'rules',
                'weights_available':bool(spec),'adapter':spec['folder'].name if spec else None,
                'experimental':bool(spec),'independent_semantic_accuracy_established':False})
        except Exception as e:
            rows.append({'role':role,'configured_mode':'tuned','weights_available':False,'error':str(e),
                         'base_fallback_enabled':True})
    return {'roles':rows,'base_fallback_enabled':True,'outputs_require_review':True}
