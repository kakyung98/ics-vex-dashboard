"""Pinned official ATT&CK ICS metadata and Vulntology validation."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
FOLDER=ROOT/'data/standards'


@lru_cache(maxsize=1)
def attack_index():
    spec=json.loads((FOLDER/'manifest.json').read_text(encoding='utf-8'))['ics-attack-20.1.json']
    raw=(FOLDER/'ics-attack-20.1.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=spec['sha256']:raise ValueError('Pinned ATT&CK source changed')
    objects=json.loads(raw)['objects'];index={}
    for obj in objects:
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):continue
        if obj['type'] not in {'x-mitre-asset','attack-pattern'}:continue
        for ref in obj.get('external_references',[]):
            if ref.get('source_name')=='mitre-attack' and ref.get('external_id'):
                index[ref['external_id']]=dict(id=ref['external_id'],stix_id=obj['id'],name=obj['name'],
                    type=obj['type'],url=ref.get('url'),description=obj.get('description',''))
    return index


def attack_context(asset_ids=(),technique_ids=()):
    index=attack_index();assets=[];techniques=[]
    for ids,kind,out in ((asset_ids,'x-mitre-asset',assets),(technique_ids,'attack-pattern',techniques)):
        for identity in ids:
            if identity not in index or index[identity]['type']!=kind:raise ValueError('Unsupported ATT&CK ICS identifier: '+str(identity))
            out.append(index[identity])
    return dict(version='ICS ATT&CK 20.1',assets=assets,techniques=techniques,
        meaning='Browsing and evidence context only; membership does not establish a CVE prerequisite or an attack path')


def validate_native(document):
    from jsonschema import Draft7Validator,FormatChecker
    from referencing import Registry
    raw=(FOLDER/'vulntology-schema.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!='fc2b278520b7035f5951b3b9e7a15d72a32735930ac86ab4dc41aac21f5ae0e8':
        raise ValueError('Pinned NIST Vulntology schema changed')
    # Deliberately do not retrieve arbitrary remote references during validation.
    # CPE/text product forms are self-contained; external forms require pinned schemas.
    validator=Draft7Validator(json.loads(raw),format_checker=FormatChecker(),registry=Registry())
    try:errors=[dict(path='/'.join(map(str,e.absolute_path)),message=e.message) for e in validator.iter_errors(document)]
    except Exception as exc:return dict(valid=False,errors=[dict(path='',message='Unresolved external schema: '+str(exc))],semantic_accuracy_verified=False)
    return dict(valid=not errors,errors=errors,semantic_accuracy_verified=False,
        schema_commit='62f75fd989c947eba063f0908975c08e7193043e')
