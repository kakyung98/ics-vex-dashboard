"""Lossless ID transport: keep source facts, shorten opaque IDs and response keys."""
from copy import deepcopy
from src.identification_agent_contracts import SYSTEMS, schema

KEYS={'ranked_candidate_ids':'rank','version_observation_ids':'versions',
      'model_observation_ids':'models','evidence_refs':'refs','candidate_id':'pick','status':'status'}


def _path(parts):
    return '/'.join(str(p).replace('~','~0').replace('/','~1') for p in parts)


def _leaves(value,path=()):
    for key,item in value.items():
        if isinstance(item,dict) and item:yield from _leaves(item,path+(key,))
        else:yield _path(path+(key,)),item


def pack_records(records):
    """Columnar JSON without dropping values, missing fields, order or duplicates."""
    groups={}
    for index,record in enumerate(records):
        leaves=list(_leaves(record));columns=tuple(k for k,_ in leaves)
        table=groups.setdefault(columns,{'columns':['$row',*columns],'rows':[]})
        table['rows'].append([index,*[value for _,value in leaves]])
    return list(groups.values())


def unpack_records(tables):
    indexed={}
    for table in tables:
        for row in table['rows']:
            record={}
            for column,value in zip(table['columns'][1:],row[1:]):
                parts=[p.replace('~1','/').replace('~0','~') for p in column.split('/')]
                target=record
                for part in parts[:-1]:target=target.setdefault(part,{})
                target[parts[-1]]=value
            indexed[row[0]]=record
    return [indexed[i] for i in range(len(indexed))]


def encode(task,packet,*,tabular=False):
    wire=deepcopy(packet);mapping={}
    for i,c in enumerate(wire.get('candidates',[])):
        original=c['candidate_id'];alias='c'+str(i);mapping[original]=alias
        mapping['dictionary:'+original]='dictionary:'+alias;c['candidate_id']=alias
    for i,o in enumerate(wire.get('observations',[])):
        original=o['id'];alias='o'+str(i);mapping[original]=alias;o['id']=alias
    for evidence in wire['evidence']:evidence['id']=mapping.get(evidence['id'],evidence['id'])
    system=SYSTEMS[task]
    for full,short in KEYS.items():system=system.replace(full,short)
    output=schema(task,wire)
    output['properties']={KEYS.get(k,k):v for k,v in output['properties'].items()}
    output['required']=[KEYS.get(k,k) for k in output['required']]
    if task in {'L2','L4'} and len(wire['evidence'])>=2:
        output['properties']['refs']['minItems']=2
        system += '\nFor a positive decision, refs MUST include BOTH an input:* ID and dictionary:<chosen ID>. Never return only one kind. Example: ["input:name","dictionary:c0"]. Copy actual supplied IDs; do not invent citations.'
    if tabular:
        for field in ('candidates','evidence','observations'):
            if field in wire:
                original=wire[field];packed=pack_records(original)
                if unpack_records(packed)!=original:raise ValueError('Lossless table roundtrip failed: '+field)
                wire[field]=packed
        system += '\nInput record lists use lossless column tables: columns are JSON field paths, each rows entry gives their values, and $row is the original row order. A slash denotes a nested field. Read every candidate/evidence row as the corresponding object. Cite the id column values; $row is not an evidence ID.'
    return wire,system,output,{v:k for k,v in mapping.items()}


def decode(value,reverse):
    if not isinstance(value,dict):return None
    keys={v:k for k,v in KEYS.items()}
    def restore(item):
        if isinstance(item,str):return reverse.get(item,item)
        if isinstance(item,list):return [restore(v) for v in item]
        return item
    return {keys.get(k,k):restore(v) for k,v in value.items()}
