"""Validate balanced input schemas and actual operator quotas; select smoke cases."""
from pathlib import Path
from urllib.parse import urlsplit
from collections import Counter
import hashlib
import json
import fastjsonschema

ROOT=Path(__file__).resolve().parents[2]

def main():
    dataset=ROOT/'benchmark/item3_advisory_inputs_v5'
    manifest=json.loads((dataset/'manifest.json').read_bytes())
    folder=ROOT/'data/standards/cyclonedx-1.7'
    schemas={p.name:json.loads(p.read_bytes()) for p in folder.glob('*.json') if p.name!='cryptography-defs.source.json'}
    def lookup(uri):return schemas[Path(urlsplit(uri).path).name]
    validate=fastjsonschema.compile(schemas['bom-1.7.schema.json'],handlers={'http':lookup,'https':lookup},use_default=False)
    counts={};scenarios={};selected=[]
    for fold in ('train','test'):
        files=list((dataset/fold/'sboms').glob('*.json'))
        for p in files:validate(json.loads(p.read_bytes()))
        counts[fold]=len(files)
        labels=[json.loads(s) for s in (dataset/fold/'gold.jsonl').read_text(encoding='utf-8').splitlines()]
        scenarios[fold]=dict(Counter(r['scenario'] for r in labels if r['scenario']!='control'))
        assert scenarios[fold]==manifest['scenarios_by_fold'][fold]
        if fold=='test':
            for style in ('_mask','_noise'):
                candidates=[r for r in labels if r['axis']=='I1' and r['scenario'].endswith(style)]
                chosen=min(candidates,key=lambda r:(len(r['gold']['components']),r['id']))
                selected.extend(r['id'] for r in labels if r['pair_id']==chosen['pair_id'])
    for axis in ('component','version','CPE'):
        assert sum(c[axis+'_mask'] for c in scenarios.values())==1554
        assert sum(c[axis+'_noise'] for c in scenarios.values())==1554
    report=dict(passed=True,validated=counts,schema=str(folder/'bom-1.7.schema.json'),defaults_inserted=False,
                actual_scenarios=scenarios,scope='JSON schema conformance and actual annotation operator quotas')
    (ROOT/'results/item3_balanced_v5_schema_20261125.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (dataset/'smoke_selection.json').write_text(json.dumps(selected,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
