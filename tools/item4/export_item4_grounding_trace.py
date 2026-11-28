"""Export a reviewable CVE source/product/role/question/case trace from sealed Gold."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.evaluation.source_context_simulation import DATA; from src.item4.evaluation.source_context_simulation import model_packet
from src.common.runtime.training_progress_io import atomic_json
from src.item4.decision.scoped_vex_review import digest


def export(data,cve,output):
    data=Path(data)
    index=next(r for r in map(json.loads,(data/'cve_index.jsonl').open(encoding='utf-8')) if r['cve']==cve)
    record=next(r for r in map(json.loads,(data/'cve_source_records.jsonl').open(encoding='utf-8')) if r['cve']==cve)
    assert digest({k:v for k,v in record.items() if k!='record_digest'})==record['record_digest']
    fold=index['fold'];labels={r['id']:r for r in map(json.loads,(data/fold/'labels.jsonl').open(encoding='utf-8')) if r['cve']==cve}
    rows=[r for r in map(json.loads,(data/fold/'inputs.jsonl').open(encoding='utf-8')) if r['packet']['cve']==cve]
    assert {r['id'] for r in rows}==set(index['cases'])==labels.keys()
    spec=rows[0]['packet'].get('spec')
    source=next(s for s in record['sources'] if spec and s['id']==spec['source']['id']) if spec else None
    result=dict(cve=cve,scope='Source-grounded conditional synthetic test; not a real asset impact assessment',
        source_record_digest=record['record_digest'],source=source,
        selected_product=spec['product'] if spec else None,
        asset_type=spec['asset_type'] if spec else None,
        product_scope=spec['product_scope_validation'] if spec else None,
        conditions_and_questions=spec['conditions'] if spec else [],
        expression=spec['expression'] if spec else None,
        operator_answers_collected=False,independent_human_semantic_validation=False,
        other_product_scopes=index['product_grounding'],
        cases=[dict(id=r['id'],variation=labels[r['id']]['variation'],model_input=model_packet(r['packet']),
            separate_gold=labels[r['id']]) for r in rows])
    atomic_json(output,result)
    print(json.dumps(dict(output=str(output),cve=cve,cases=len(rows)),ensure_ascii=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,default=DATA)
    parser.add_argument('--cve',default='CVE-2015-8214')
    parser.add_argument('--output',type=Path,default=ROOT/'results/item4_source_context_v3_grounded_full_population/examples/CVE-2015-8214.json')
    args=parser.parse_args();export(args.data,args.cve,args.output)
