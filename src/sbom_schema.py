"""Offline official-schema validation; no runtime network resolution."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]

def validate(document):
    folder=ROOT/'.tools/cyclonedx-schemas';version=document.get('specVersion')
    file=folder/('bom-'+str(version)+'.schema.json')
    if not file.is_file():return {'status':'unavailable','reason':'Official schema not cached for this version.','schema_version':version}
    from jsonschema import Draft7Validator
    from referencing import Registry,Resource
    registry=Registry()
    for p in folder.glob('*.schema.json'):
        d=json.loads(p.read_text(encoding='utf-8'));resource=Resource.from_contents(d)
        for uri in ['http://cyclonedx.org/schema/'+p.name,'https://cyclonedx.org/schema/'+p.name]:registry=registry.with_resource(uri,resource)
        if d.get('$id'):registry=registry.with_resource(d['$id'],resource)
    schema=json.loads(file.read_text(encoding='utf-8'))
    try:errors=sorted(Draft7Validator(schema,registry=registry).iter_errors(document),key=lambda e:str(list(e.path)))
    except Exception as e:return {'status':'unavailable','reason':str(e),'schema_version':version}
    return {'status':'valid' if not errors else 'invalid','schema_version':version,
        'errors':[{'path':list(e.path),'message':e.message} for e in errors[:20]],'total_errors':len(errors),'network_resolution':False}
