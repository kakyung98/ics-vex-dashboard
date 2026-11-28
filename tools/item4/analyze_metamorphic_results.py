"""Local, prediction-only analysis after frozen TEST evaluation has completed."""
import sys,json,random
from pathlib import Path
from collections import defaultdict,Counter
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import metamorphic_synthetic as E


def percentile(values,p):
    values=sorted(values);return values[round((len(values)-1)*p)]


def main(folder):
    folder=Path(folder);artifacts=folder/'artifacts'
    inputs=json.loads((folder/'inputs.json').read_text());gold={r['id']:r['gold'] for r in json.loads((folder/'gold.json').read_text())}
    cases={r['id']:dict(r,gold=gold[r['id']]) for r in inputs}
    groups=defaultdict(dict)
    for p in (artifacts/'predictions').glob('*/*/*.json'):
        row=json.loads(p.read_text());groups[row['phase'],row['arm']][row['id']]=row
    output={};examples=[]
    for (phase,arm),predictions in groups.items():
        selected=[c for c in cases.values() if c['split']=='test']
        if not all(c['id'] in predictions for c in selected):continue
        scores={c['id']:E.judge(c,predictions[c['id']].get('draft'),valid=predictions[c['id']]['valid']) for c in selected}
        clusters=defaultdict(lambda:Counter())
        admitted=Counter();families=defaultdict(Counter);original=Counter();noop=0;mr=defaultdict(Counter);health=Counter()
        for c in selected:
            r=scores[c['id']];cl=clusters[c['base_id']]
            for k in ('tp','fp','fn','logic_correct','case_correct'):cl[k]+=r[k]
            cl['cases']+=1
            families[str(c['family'])]['cases']+=1;families[str(c['family'])]['correct']+=r['case_correct']
            if c['variant']=='original':
                for k in ('tp','fp','fn','logic_correct','case_correct'):original[k]+=r[k]
                original['cases']+=1
            row=predictions[c['id']];draft=row.get('draft') or {};kept=[]
            artifact=row.get('artifact') or {};review=artifact.get('coverage_review') or {}
            if review:
                health['review_cases']+=1;health['review_failed']+=review.get('status')=='failed'
            health['logical_generation_calls']+=len(row.get('trace',[]))
            health['exact_duplicate_normalizations']+=sum(len(t.get('normalizations',[])) for t in row.get('trace',[]))
            for event in artifact.get('execution_history',[]):
                if event.get('failure'):health['rejected_'+event['failure'].get('stage','unknown')]+=1
            for atom in draft.get('prerequisites',[]) if row['valid'] else []:
                score=atom.get('extraction_confidence')
                if type(score) in (int,float) and .8<score<=1 and atom.get('review_status')!='rejected':kept.append(atom)
            filtered=dict(draft,prerequisites=kept)
            f=E.judge(c,filtered,valid=row['valid'])
            for k in ('tp','fp','fn'):admitted[k]+=f[k]
            admitted['predicted_atoms']+=len(draft.get('prerequisites',[]));admitted['kept_atoms']+=len(kept)
            if not r['case_correct'] and len([e for e in examples if e['phase']==phase and e['arm']==arm and e['family']==c['family']])<2:
                examples.append(dict(phase=phase,arm=arm,id=c['id'],family=c['family'],variant=c['variant'],
                    source=c['record']['sources'][0]['text'],gold=c['gold'],judgement=r,error=row.get('error'),
                    prediction=draft,artifact_path=str(artifacts/'predictions'/phase/arm/(c['id']+'.json'))))
            if c['variant']=='original':continue
            base=cases[c['base_id']+'__original'];b=scores[base['id']]
            if [s['text'] for s in c['record']['sources']]==[s['text'] for s in base['record']['sources']]:
                noop+=1;continue
            valid=r['valid'] and b['valid']
            if c['variant']=='remove_evidence':
                relation=valid and not draft.get('prerequisites') and not draft.get('scenarios') and bool(draft.get('unknowns'))
            else:
                relation=valid and b['found']==r['found'] and E.equivalent(b['expression'],r['expression'],sorted(set(b['found'])|set(r['found'])))
                base_nr=bool((predictions[base['id']].get('draft') or {}).get('nonrequirements'))
                relation=relation and base_nr==bool(draft.get('nonrequirements'))
            mr[c['variant']]['total']+=1;mr[c['variant']]['relation_passed']+=relation
            mr[c['variant']]['grounded_passed']+=b['case_correct'] and r['case_correct']
            cl['mr_total']+=1;cl['mr_grounded']+=b['case_correct'] and r['case_correct'];cl['mr_relation']+=relation
        def metrics(count):
            den=2*count['tp']+count['fp']+count['fn']
            return dict(f1=2*count['tp']/den if den else 0,
                logic_accuracy=count['logic_correct']/count['cases'],case_accuracy=count['case_correct']/count['cases'],
                grounded_mr_rate=count['mr_grounded']/count['mr_total'] if count['mr_total'] else 0,
                relation_mr_rate=count['mr_relation']/count['mr_total'] if count['mr_total'] else 0)
        total=sum(clusters.values(),Counter());point=metrics(total)
        rng=random.Random(20261127);draws=defaultdict(list);keys=list(clusters)
        for _ in range(2000):
            resampled=sum((clusters[rng.choice(keys)] for _ in keys),Counter())
            for k,v in metrics(resampled).items():draws[k].append(v)
        def prf(count):
            tp,fp,fn=count['tp'],count['fp'],count['fn']
            return dict(precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,counts=dict(count))
        output[phase+'/'+arm]=dict(point=point,cluster_bootstrap_95ci={k:[percentile(v,.025),percentile(v,.975)] for k,v in draws.items()},
            independent_base_worlds=len(clusters),test_cases=len(selected),excluded_noop_mr=noop,
            mr={k:dict(v) for k,v in mr.items()},original_only=prf(original),admitted=prf(admitted),families={k:dict(v) for k,v in families.items()})
        output[phase+'/'+arm]['pipeline_health']=dict(health,review_failure_rate=health['review_failed']/health['review_cases'] if health['review_cases'] else None)
    (folder/'analysis.json').write_text(json.dumps(dict(results=output,bootstrap='2000 resamples of source-world clusters; variants are not independent samples.',
        no_op_policy='Exact unchanged source variants excluded from MR denominators only; all extraction cases remain scored.'),ensure_ascii=False,indent=2),encoding='utf-8')
    (folder/'failure_examples.json').write_text(json.dumps(examples,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v['point'] for k,v in output.items()}))


if __name__=='__main__':main(sys.argv[1])
