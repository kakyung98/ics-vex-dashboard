"""Explicit assistant-reference agreement, separate from independent gold scoring."""
from src.item4.evaluation.cvss_extraction_scoring import signature,expression,equivalent
from src.item4.analysis.exploitation_prerequisites import digest


def score(results,labels):
    refs={r['id']:r for r in labels}
    counts=dict(cases=0,extracted=0,failed=0,source_mismatches=0,TP=0,FP=0,FN=0,
        logic_judged=0,logic_matching=0,logic_unjudged=0)
    rows=[]
    for row in results:
        ref=refs[row['reference_id']];counts['cases']+=1
        if row.get('source_sha256')!=ref['source_record_sha256']:
            counts['source_mismatches']+=1
            rows.append(dict(id=ref['id'],status='source_mismatch'));continue
        ok=row.get('v2_status')=='validated';counts['extracted']+=ok;counts['failed']+=not ok
        draft=(row.get('v2') or {}).get('draft',{})
        p={signature(a) for a in draft.get('prerequisites',[])};g={signature(a) for a in ref['draft']['prerequisites']}
        tp=len(p&g);fp=len(p-g);fn=len(g-p)
        counts['TP']+=tp;counts['FP']+=fp;counts['FN']+=fn
        same=equivalent(expression(draft),expression(ref['draft']),sorted(p|g)) if ok else False
        if same is None:counts['logic_unjudged']+=1
        else:counts['logic_judged']+=1;counts['logic_matching']+=same
        rows.append(dict(id=ref['id'],cve=ref['cve'],status='extracted' if ok else 'failed',TP=tp,FP=fp,FN=fn,
            exact_logic_match=same,reference_completeness=ref['completeness']))
    return dict(version='item4-assistant-reference-agreement/1',counts=counts,rows=rows,
        exact_atom_precision=counts['TP']/(counts['TP']+counts['FP']) if counts['TP']+counts['FP'] else None,
        exact_atom_recall=counts['TP']/(counts['TP']+counts['FN']) if counts['TP']+counts['FN'] else None,
        independent_expert_labels=0,independent_semantic_accuracy=None,actual_exploitability_accuracy=None,
        reference_labels_digest=digest(labels),
        scope='Strict atom/quote identity and Boolean agreement with assistant reference labels. Wording variants can fail strict matching. Failed empty extractions do not count as correct negatives.')
