"""Validate blinded ratings, compute pre-adjudication kappa, export gold and score."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
import json
from pathlib import Path

from src.item4.evaluation.synthetic_vex_benchmark import JUSTIFICATIONS; from src.item4.evaluation.synthetic_vex_benchmark import STATUSES; from src.item4.evaluation.synthetic_vex_benchmark import agreement; from src.item4.evaluation.synthetic_vex_benchmark import affected_precision; from src.item4.evaluation.synthetic_vex_benchmark import csaf_vex

DEFAULT = Path(__file__).resolve().parents[2]/'benchmark/item4_evaluation/csaf_vex_v2'
REASONS = ['reason_'+j for j in JUSTIFICATIONS]
FIELDS = ['status','source_binding_valid','scenario_logic_valid','evidence_sufficient']+REASONS


def load(path):
    result={}
    with Path(path).open(encoding='utf-8-sig') as f:
        for row in map(json.loads,f):
            if row['id'] in result:
                raise ValueError('Duplicate ID: '+row['id'])
            result[row['id']]=row
    return result


def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        raise FileExistsError('Preserve existing result; choose a new --output: '+str(path))
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def complete(row):
    return bool(row.get('reviewer_id') and row.get('reviewed_at') and row.get('rationale')
        and row.get('evidence_refs') and all(row.get(f) is not None for f in FIELDS)
        and isinstance(row.get('justifications'),list))


def validate(row):
    if row['status'] not in STATUSES:
        raise ValueError('Invalid status: '+row['id'])
    expected={'affected':True,'not_affected':False,'under_investigation':None}[row['status']]
    if row.get('actual_affected') is not expected:
        raise ValueError('Status and actual_affected disagree: '+row['id'])
    just=row['justifications']
    if len(just)!=len(set(just)) or any(j not in JUSTIFICATIONS for j in just):
        raise ValueError('Invalid justification: '+row['id'])
    if (row['status']=='not_affected') != bool(just):
        raise ValueError('not_affected must have a reason; other statuses cannot: '+row['id'])
    for field in FIELDS[1:]:
        if row[field] not in ('yes','no','unknown'):
            raise ValueError('Review fields use yes/no/unknown: '+field)
    positives={j for j in JUSTIFICATIONS if row['reason_'+j]=='yes'}
    if set(just)!=positives:
        raise ValueError('Reason flags and justifications disagree: '+row['id'])
    if row['status']!='under_investigation' and any(row[f]!='yes' for f in
            ['source_binding_valid','scenario_logic_valid','evidence_sufficient']):
        raise ValueError('Definite status requires valid source, logic and sufficient evidence: '+row['id'])


def paired(data,a_path,b_path):
    packets=load(data/'review/packets.jsonl');a=load(a_path);b=load(b_path)
    if set(a)!=set(packets) or set(b)!=set(packets):
        raise ValueError('Both rating files must retain all evaluation IDs, including blank entries')
    rows=[];pending=[]
    for key,p in packets.items():
        for rating in (a[key],b[key]):
            if rating['cve']!=p['cve'] or rating['advisory_id']!=p['advisory_id']:
                raise ValueError('Scope changed: '+key)
        if not (complete(a[key]) and complete(b[key])):
            pending.append(key);continue
        validate(a[key]);validate(b[key])
        if a[key]['reviewer_id']==b[key]['reviewer_id']:
            raise ValueError('Raters must be independent people: '+key)
        rows.append(dict(id=key,advisory_id=p['advisory_id'],a=a[key],b=b[key]))
    if rows and (len({r['a']['reviewer_id'] for r in rows})!=1 or
                 len({r['b']['reviewer_id'] for r in rows})!=1):
        raise ValueError('Cohen kappa requires the same two raters across the reviewed sample')
    return packets,rows,pending


def kappa_report(args):
    _,rows,pending=paired(args.data,args.a,args.b)
    reports={field:agreement(rows,field,args.bootstrap) for field in FIELDS}
    approved=bool(rows) and not pending and all(reports[f]['kappa'] is not None and
        reports[f]['kappa']>=.8 for f in ['status']+REASONS)
    write(args.output,dict(stage='pre_adjudication',paired_cases=len(rows),pending_cases=len(pending),
        complete=not pending,agreement=reports,proposed_project_threshold=.8,
        threshold_is_project_rule_not_universal_standard=True,agreement_gate_met=approved,
        expert_gold_created=False,real_asset_validation=False))


def adjudicate(args):
    _,pairs,pending=paired(args.data,args.a,args.b)
    if pending:
        raise ValueError('Complete both independent ratings before final gold; pending='+str(len(pending)))
    ratings={r['id']:r for r in pairs};decisions=load(args.decisions)
    if set(decisions)!=set(ratings):
        raise ValueError('Adjudications must cover the full expert sample')
    gold=load(args.data/'gold.jsonl')
    for key,row in decisions.items():
        if not complete(row) or row.get('independent_ratings_locked') is not True or not row.get('resolution'):
            raise ValueError('Incomplete or unlocked adjudication: '+key)
        validate(row)
        r=ratings[key]
        if row['cve']!=gold[key]['cve'] or row['advisory_id']!=r['advisory_id']:
            raise ValueError('Adjudication changed scope: '+key)
        disagreement=any(r['a'][f]!=r['b'][f] for f in FIELDS)
        consensus_override=any(row[f]!=r['a'][f] for f in FIELDS)
        if disagreement or consensus_override:
            if not row.get('adjudicator_id') or row['adjudicator_id'] in {r['a']['reviewer_id'],r['b']['reviewer_id']}:
                raise ValueError('Disagreement/override requires independent third adjudicator: '+key)
        gold[key].update(actual_affected=row['actual_affected'],status=row['status'],
            justifications=row['justifications'],expert_validated=True,
            adjudication=row)
    output=Path(args.output)
    if output.exists():raise FileExistsError(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('w',encoding='utf-8') as f:
        for key in sorted(gold):f.write(json.dumps(gold[key],ensure_ascii=False)+'\n')


def score(args):
    predictions=load(args.predictions)
    if args.reference=='candidate':
        candidates=load(args.data/'candidate_labels.jsonl')
        gold={k:dict(r,actual_affected=r['candidate_actual_affected']) for k,r in candidates.items()}
        scope='full_population_conditional_synthetic_reference_NOT_expert_gold'
    else:
        gold=load(args.gold)
        scope='full_population_expert_ledger_with_unreviewed_unknowns'
    metrics=affected_precision(predictions,gold)
    sample={k:r for k,r in gold.items() if r['fold']=='evaluation'}
    sample_complete=bool(sample) and all(r.get('expert_validated') for r in sample.values())
    expert_metric=(affected_precision({k:predictions[k] for k in sample},sample)
                   if args.reference=='expert' and sample_complete else None)
    write(args.output,dict(reference_scope=scope,all_cases=metrics,
        expert_sample_complete=sample_complete if args.reference=='expert' else False,
        expert_sample=expert_metric,full_population_expert_validated=(args.reference=='expert' and
            all(r.get('expert_validated') for r in gold.values())),
        note='A 30% ICSA expert sample does not supply expert truth for the remaining 70%.'))


def export(args):
    gold=load(args.gold);packets=load(args.data/'inputs.jsonl')
    if set(gold)!=set(packets):raise ValueError('Gold population mismatch')
    output=Path(args.output)
    if output.exists():raise FileExistsError(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('w',encoding='utf-8') as f:
        for key,p in packets.items():
            g=gold[key]
            status=g['status'] if g.get('expert_validated') else 'under_investigation'
            reasons=g['justifications'] if g.get('expert_validated') else []
            text=(g.get('adjudication') or {}).get('rationale') or 'Expert review pending; no final not-affected assertion.'
            doc=csaf_vex(key,p['cve'],p['target']['name']+' / '+p['target']['version'],status,reasons,
                'Synthetic benchmark scenario; not a supplier statement. '+text)
            f.write(json.dumps(dict(id=key,document=doc),ensure_ascii=False)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data',type=Path,default=DEFAULT)
    commands=parser.add_subparsers(dest='command',required=True)
    for command,func in [('kappa',kappa_report),('adjudicate',adjudicate),('score',score),('export-csaf',export)]:
        sub=commands.add_parser(command);sub.set_defaults(func=func)
        sub.add_argument('--output',type=Path,required=True)
        if command in {'kappa','adjudicate'}:
            sub.add_argument('--a',type=Path,required=True);sub.add_argument('--b',type=Path,required=True)
        if command=='kappa':sub.add_argument('--bootstrap',type=int,default=1000)
        if command=='adjudicate':sub.add_argument('--decisions',type=Path,required=True)
        if command in {'score','export-csaf'}:sub.add_argument('--gold',type=Path,default=DEFAULT/'gold.jsonl')
        if command=='score':
            sub.add_argument('--predictions',type=Path,required=True)
            sub.add_argument('--reference',choices=['expert','candidate'],default='expert')
    args=parser.parse_args();args.func(args)


if __name__=='__main__':main()
