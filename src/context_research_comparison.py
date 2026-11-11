"""Question-cost comparison across CVEs for one identical asset scope."""
from collections import Counter,defaultdict
from .semantic_condition_contract import digest
from .context_vex_pipeline import approved,leaves,evaluate_review


def question_groups(reviews):
    groups={};required=set()
    for review in reviews:
        cve=review['cve'];conditions={c['id']:c for c in review['conditions']}
        needed=leaves(review['formula']['expression']) if review.get('formula') else {c['id'] for c in conditions.values() if c.get('necessity') in ('required_for_path','required_all_paths')}
        required.update((cve,c) for c in needed)
        for q in review['questions']:
            if not approved(q):continue
            mapped=[m for m in q.get('mappings',[]) if approved(m) and m['coverage']=='FULL' and
                    approved(conditions[m['condition_id']]) and conditions[m['condition_id']].get('operator_observable') is True]
            if not mapped:continue
            signature=digest([q['text'],q['target'],sorted((conditions[m['condition_id']]['predicate'],conditions[m['condition_id']]['target'],tuple(sorted(m['answers'].items()))) for m in mapped)])
            group=groups.setdefault(signature,dict(id=signature,members=[],member_costs={},covers=set(),cost=q.get('cost',1)))
            group['members'].append((cve,q['id']))
            group['member_costs'][(cve,q['id'])]=q.get('cost',1)
            group['covers'].update((cve,m['condition_id']) for m in mapped)
            group['cost']=max(group['cost'],q.get('cost',1))
    return groups,required


def plan_arm(reviews,arm):
    groups,required=question_groups(reviews)
    if arm=='individual':
        chosen=[]
        for group in groups.values():
            for member in group['members']:
                chosen.append(dict(group,members=[member],cost=group['member_costs'][member],covers={c for c in group['covers'] if c[0]==member[0]}))
    elif arm=='common_only':
        chosen=[g for g in groups.values() if len({m[0] for m in g['members']})>1]
    elif arm=='proposed':
        remaining=set(required);chosen=[]
        while True:
            candidates=[g for g in groups.values() if g['covers']&remaining]
            if not candidates:break
            group=min(candidates,key=lambda g:(g['cost']/len(g['covers']&remaining),g['id']))
            chosen.append(group);remaining-=group['covers']
    else:raise ValueError('Unknown comparison arm')
    covered=set().union(*(g['covers'] for g in chosen)) if chosen else set()
    return dict(arm=arm,question_count=len(chosen),cost=sum(g['cost'] for g in chosen),
        question_ids_by_cve={r['cve']:sorted({qid for g in chosen for cve,qid in g['members'] if cve==r['cve']}) for r in reviews},
        unresolved_conditions=sorted(required-covered))


def compare(reviews,cases,reference_kind='unlabeled'):
    bycve={r['cve']:r for r in reviews}
    # Never reuse answers or count savings across different deployments/modes/times.
    batches=defaultdict(list)
    for case in cases:
        b=case['binding']
        key=tuple(b.get(k) for k in ('asset_ref','product','build','config_baseline','mode','evaluated_at'))
        batches[key].append(case)
    outputs={}
    for arm in ('individual','common_only','proposed'):
        count=0;cost=0;results=[];matrix=Counter()
        for same_scope in batches.values():
            selected_reviews=[bycve[c] for c in sorted({c['binding']['cve'] for c in same_scope})]
            plan=plan_arm(selected_reviews,arm)
            count+=plan['question_count'];cost+=plan['cost']
            for case in same_scope:
                cve=case['binding']['cve'];allowed=set(plan['question_ids_by_cve'][cve])
                result=evaluate_review(bycve[cve],{**case,'answers':[a for a in case.get('answers',[]) if a['question_id'] in allowed]})
                results.append(dict(cve=cve,binding=case['binding'],status=result['status'],formula_value=result['formula_value']))
                if case.get('reference_status'):matrix[(case['reference_status'],result['status'])]+=1
        precision={}
        for state in ('affected','not_affected','fixed','under_investigation'):
            predicted=sum(n for (gold,pred),n in matrix.items() if pred==state)
            precision[state]=matrix[(state,state)]/predicted if predicted else None
        outputs[arm]=dict(question_count=count,declared_cost=cost,results=results,
            confusion=[dict(reference=g,prediction=p,count=n) for (g,p),n in matrix.items()],
            precision=precision if reference_kind!='unlabeled' else None)
    return dict(reference_kind=reference_kind,results=outputs,
        caution='Synthetic references verify behavior only. Real VEX precision requires independently reviewed asset-specific reference labels.')
