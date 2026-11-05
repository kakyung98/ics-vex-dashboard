"""Pinned official CWE hierarchy. Research routing rules live separately."""
from pathlib import Path
from functools import lru_cache
import hashlib,json
ROOT=Path(__file__).resolve().parents[1]


def snapshot_hash_matches(blob, expected):
    """Allow Git text EOL normalization only; changed catalog contents still fail."""
    lf=blob.replace(b'\r\n',b'\n')
    return expected in {hashlib.sha256(b).hexdigest() for b in (blob,lf,lf.replace(b'\n',b'\r\n'))}


@lru_cache(maxsize=1)
def load():
    pointer=json.loads((ROOT/'data/cwe_taxonomy/current.json').read_text(encoding='utf-8'))
    path=(ROOT/pointer['path']).resolve()
    if not path.is_relative_to((ROOT/'data/cwe_taxonomy').resolve()):raise ValueError('Taxonomy path escapes snapshot directory.')
    blob=path.read_bytes()
    if not snapshot_hash_matches(blob,pointer['sha256']):raise ValueError('Taxonomy snapshot hash mismatch.')
    record=json.loads(blob)
    if not record.get('records'):raise ValueError('Empty taxonomy snapshot.')
    return record


def ancestry(cwe,taxonomy=None):
    taxonomy=taxonomy or load();records=taxonomy['records'];found=set();pillars=set();paths=[];errors=[]
    stack=[(cwe,[])];steps=0
    while stack:
        cid,path=stack.pop();steps+=1
        if steps>10000:errors.append('ancestry_expansion_limit');break
        if cid in path:errors.append('ancestry_cycle');continue
        rec=records.get(cid)
        if not rec:errors.append('weakness_not_in_snapshot:'+cid);continue
        found.add(cid);trail=path+[cid]
        if rec.get('abstraction')=='Pillar':
            pillars.add(cid)
            if len(paths)<128:paths.append(trail)
        else:
            for parent in rec.get('parents_view_1000',[]):stack.append((parent,trail))
    return {'cwe':cwe,'name':records.get(cwe,{}).get('name'),'abstraction':records.get(cwe,{}).get('abstraction'),
        'ancestors':sorted(found),'pillars':sorted(pillars),'paths':paths,'errors':sorted(set(errors)),
        'taxonomy_version':taxonomy['version'],'taxonomy_xml_sha256':taxonomy.get('xml_sha256')}
