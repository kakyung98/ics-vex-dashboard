"""Score structured extraction only against explicitly independent, source-pinned gold."""
from itertools import product
from src.item4.analysis.cvss_operational_questions import digest
from src.item4.decision.condition_logic_evaluation import logic


def signature(item):
    return digest([item['predicate'],' '.join(item['target'].casefold().split()),
        ' '.join(item.get('value','').casefold().split()),item.get('operator'),item.get('expected'),
        item.get('operational_quote'),sorted((r['source_id'],r['quote']) for r in item.get('source_refs',[]))])


def expression(draft):
    mapping={p['id']:signature(p) for p in draft.get('prerequisites',[])}
    def convert(node):
        return dict(condition=mapping[node['condition']]) if 'condition' in node else dict(op=node['op'],args=[convert(a) for a in node['args']])
    paths=[convert(s['expression']) for s in draft.get('scenarios',[])]
    return paths[0] if len(paths)==1 else dict(op='or',args=paths) if paths else None


def equivalent(left,right,variables):
    if left is None or right is None:return left==right
    if len(variables)>8:return True if left==right else None
    for states in product(('true','false','unknown'),repeat=len(variables)):
        facts=dict(zip(variables,states))
        if logic(left,facts)!=logic(right,facts):return False
    return True


def score(rows,gold_rows=()):
    gold={}
    for row in gold_rows:
        if row['cve'] in gold:raise ValueError('Duplicate CVE gold label')
        if row.get('review_method')!='independent_human' or not row.get('reviewer') or not row.get('source_record_sha256'):
            raise ValueError('Gold requires independent human review and a pinned source digest')
        gold[row['cve']]=row
    counts=dict(cves=0,failed=0,independently_judged_cves=0,unjudged_cves=0,source_mismatches=0,TP=0,FP=0,FN=0,
                logic_judged=0,logic_correct=0,logic_unjudged=0)
    seen=set()
    for row in rows:
        cve=row['cve']
        if cve in seen:raise ValueError('Duplicate extraction CVE')
        seen.add(cve);counts['cves']+=1;counts['failed']+=row.get('status')!='extracted'
        reference=gold.get(cve)
        if reference is None:counts['unjudged_cves']+=1;continue
        if row.get('source_record_sha256')!=reference['source_record_sha256']:
            counts['source_mismatches']+=1;counts['unjudged_cves']+=1;continue
        predicted=(row.get('artifact') or {}).get('draft',{})
        expected=reference['draft']
        p={signature(x) for x in predicted.get('prerequisites',[])};g={signature(x) for x in expected.get('prerequisites',[])}
        counts['independently_judged_cves']+=1;counts['TP']+=len(p&g);counts['FP']+=len(p-g);counts['FN']+=len(g-p)
        same=equivalent(expression(predicted),expression(expected),sorted(p|g)) if row.get('status')=='extracted' else False
        if same is None:counts['logic_unjudged']+=1
        else:counts['logic_judged']+=1;counts['logic_correct']+=same
    return dict(counts,precision=counts['TP']/(counts['TP']+counts['FP']) if counts['TP']+counts['FP'] else None,
        recall=counts['TP']/(counts['TP']+counts['FN']) if counts['TP']+counts['FN'] else None,
        gold_cves_without_prediction=len(set(gold)-seen),
        scope='Strict structured source-quote/atom matching and three-valued logic equivalence on independently reviewed CVEs; no field exploitability claim.')
