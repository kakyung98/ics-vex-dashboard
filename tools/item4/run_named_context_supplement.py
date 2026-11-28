"""Correct the context fixture without changing the frozen CVE cohorts."""
import sys,json,hashlib,copy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
OUT=ROOT/'results/item4_goldfree_expanded_20261126'


def prepare():
    from src.item4.assets.asset_observations import catalogue
    data=json.loads((OUT/'inputs.json').read_text(encoding='utf-8'));types=catalogue()['asset_types'];items=[]
    for original in data['v3']:
        row=copy.deepcopy(original);aid=row['packet']['asset_classification'].get('asset_type_id')
        row['named_context_available']=aid in types
        if aid in types:row['packet']['asset_classification']['asset']=dict(id=aid,name=types[aid][0]['asset_name'])
        items.append(row)
    path=OUT/'named_context_inputs.json'
    if path.exists():raise ValueError('Named-context fixtures already frozen')
    path.write_text(json.dumps(items,ensure_ascii=False,indent=2),encoding='utf-8')
    amendment=dict(reason='Original fixture provided opaque asset IDs but omitted names available to the actual web V3 packet. Add a separate named-context arm, never overwrite earlier results.',
        unique_cves=len(items),named_context_cases=sum(r['named_context_available'] for r in items),unknown_context_cases=sum(not r['named_context_available'] for r in items),
        input_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),selection='Determined by source-side asset-type availability, not by output success. Never fall back from a failed named-context generation to an earlier successful output.')
    (OUT/'protocol_amendment_named_context.json').write_text(json.dumps(amendment,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(amendment))


if __name__=='__main__':prepare()
