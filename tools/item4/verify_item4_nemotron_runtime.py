"""Exercise each evidence-review contract on a clearly fictional fixture before a population run."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.models import scenario_review_experts as moe
from src.item4.models.nemotron_inference_provider import NemotronBatch


def verify(manifest,port=18128):
    provider=NemotronBatch(port,manifest,concurrency=4)
    requests=[]
    def capture(system,packet,**kwargs):
        requests.append(dict(system=system,packet=packet))
        return {}
    observation=dict(scope='current_single',deployment='running',runtime='bom',complete_inventory=False,
                     component_ref='fixture-component',version='1.0')
    rows={
        'supplier':[('supplier-fixture',dict(product_key='fixture-product',source_version='1.0',
                       status='known_affected',version_membership='true'))],
        'inventory':[('operator-fixture',observation)],
        'conditions':[('condition-fixture',dict(expression='a',conditions=[
            dict(atom_id='a',observation='o',quote='The affected option is enabled.')]))],
        'crosscheck':[('operator-fixture',observation)]}
    for role in moe.PROMPTS:
        moe._expert(role,rows[role],capture,None)
    outputs=provider(requests)
    for role,result in zip(moe.PROMPTS,outputs):
        if isinstance(result,Exception):
            raise RuntimeError(role+': '+str(result)) from result
        print(role,json.dumps(result['prediction']),flush=True)
    receipt=dict(kind='inference_contract_smoke_only',fixture_cases=4,human_review_count=0,
                 completed_at=datetime.now(timezone.utc).isoformat(),
                 model=provider.identity['model'],revision=provider.identity['revision'],
                 responses=[dict(role=role,output=result) for role,result in zip(moe.PROMPTS,outputs)])
    target=manifest.parent/'smoke.json'
    target.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--port',type=int,default=18128)
    a=p.parse_args()
    verify(a.manifest,a.port)
