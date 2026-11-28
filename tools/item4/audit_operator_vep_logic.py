"""Strict signed-prerequisite equivalence against reviewed held-out annotations.

This checks annotated logic, not independent real-world exploitability accuracy.
"""
from pathlib import Path
import argparse,itertools,json,re,sys,hashlib
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.analysis import exploitation_prerequisites as V
from src.common.data.prerequisite_research_schema import enrich

def atom_key(item):
    words=re.findall(r'[a-z0-9]+',item['target'].casefold())
    stop={'the','a','an','service','feature','option','interface','deprecated'}
    return item['predicate'],tuple(w for w in words if w not in stop),item.get('observation',{}).get('quantifier','single')

def equivalent(expected,actual):
    ek={p['id']:atom_key(p) for p in expected['prerequisites']};ak={p['id']:atom_key(p) for p in actual['prerequisites']}
    if set(ek.values())!=set(ak.values()):return False
    keys=sorted(set(ek.values()))
    if len(keys)>8:raise ValueError('Equivalence audit is bounded to eight annotated atoms')
    def evaluate(expr,mapping,facts):
        if 'condition' in expr:return facts[mapping[expr['condition']]]
        values=[evaluate(c,mapping,facts) for c in expr['args']]
        if expr['op']=='not':return {'true':'false','false':'true','unknown':'unknown'}[values[0]]
        if expr['op']=='and':return 'false' if 'false' in values else 'true' if all(v=='true' for v in values) else 'unknown'
        return 'true' if 'true' in values else 'false' if all(v=='false' for v in values) else 'unknown'
    def routes(draft,mapping,facts):
        values=[evaluate(s['expression'],mapping,facts) for s in draft['scenarios']]
        return 'unknown' if not values else 'true' if 'true' in values else 'false' if all(v=='false' for v in values) else 'unknown'
    return all(routes(expected,ek,dict(zip(keys,values)))==routes(actual,ak,dict(zip(keys,values)))
               for values in itertools.product(('true','false','unknown'),repeat=len(keys)))

def audit(dataset,predictions,output):
    rows=[json.loads(l) for l in Path(dataset).read_text(encoding='utf-8').splitlines()]
    predictions_path=Path(predictions)
    predictions=json.loads(predictions_path.read_text(encoding='utf-8'))
    if [p['id'] for p in predictions]!=[r['id'] for r in rows]:raise ValueError('Every held-out case must be present in order')
    results=[]
    for row,pred in zip(rows,predictions):
        if row['family'] not in ('negative','and_not'):continue
        reason=None;matched=False
        try:
            actual=V.resolve_references(enrich(json.loads(pred['text'])),row['packet'])
            V.validate(actual,{k:row['packet'][k] for k in ('cve','sources','products')})
            matched=equivalent(row['target'],actual)
            if not matched:reason='Missing, extra or logically inequivalent signed prerequisite(s)'
        except Exception as e:reason=type(e).__name__+': '+str(e)
        results.append(dict(id=row['id'],synthetic=row['synthetic'],equivalent=matched,reason=reason))
    evaluation_path=Path(output).parent/'evaluation.json'
    evaluation=json.loads(evaluation_path.read_text(encoding='utf-8'))
    report=dict(state='complete',adapter_sha256=evaluation['adapter_sha256'],predictions_sha256=hashlib.sha256(predictions_path.read_bytes()).hexdigest(),dataset_test_sha256=hashlib.sha256(Path(dataset).read_bytes()).hexdigest(),total_heldout_cases=len(rows),negative_cases=len(results),
        equivalent_negative_cases=sum(r['equivalent'] for r in results),passed=bool(results) and all(r['equivalent'] for r in results),
        method='Three-valued logic equivalence over normalized annotated atom names; conservative exact atom coverage',
        expert_gold=False,independent_real_asset_accuracy_verified=False,cases=results)
    Path(output).write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in report.items() if k!='cases'}));return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dataset',type=Path,required=True);p.add_argument('--predictions',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();audit(a.dataset,a.predictions,a.output)
