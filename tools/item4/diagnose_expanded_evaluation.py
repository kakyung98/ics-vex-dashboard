"""Post-test diagnostics only. Never change the frozen scores or GT."""
from pathlib import Path
from collections import Counter
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation.sealed_source_gt import fact_match

def read(p):return json.loads(p.read_text(encoding='utf-8'))
def main():
    r=ROOT/'results/item4_expanded_evaluation_20261127';d=ROOT/'data/item4_synthetic_gt_expanded_v1'
    report=read(r/'reports/test_candidate.json');inputs={c['id']:c for c in read(d/'test_candidate/inputs.json')};gold={g['id']:g for g in read(d/'test_candidate/gold.json')}
    rows={p.stem:read(p) for p in (r/'collected/item4/predictions').glob('*.json')};stats=Counter();examples={};details=[]
    for f in report['failures']:
        cid=f['id'];c=inputs[cid];g=gold[cid]['gold'];p=rows[cid];j=f['judgement'];flags=set()
        if not p['valid']:
            stats['fn_in_native_rejection_cases']+=j.get('fn',0);flags.add('native_rejection')
        else:
            pred=p['prediction'];atoms={a['id']:a for a in pred['conditions']};scenarios={s['id']:s for s in pred['scenarios']};mapping={}
            for a in atoms.values():
                fs=[fact for fact in g['facts'] if fact_match(a,fact)]
                if len(fs)==1:mapping[a['id']]=fs[0]['id']
            for error in j['errors']:
                if error['reason']=='unsupported_atom_quote':
                    a=atoms[error['id']];q=a['quote'];src=c['passages'].get(a['source'],'')
                    if q and q in src:flags.add('exact_atom_quote_rejected_by_full_span_or_budget_rule')
                    else:flags.add('noncontiguous_or_wrong_source_atom_quote')
                elif error['reason']=='unsupported_relation_quote_or_branch':
                    s=scenarios[error['id']];q=s['quote'];src=c['passages'].get(s['source'],'');ids={mapping.get(i) for i in s['conditions']}
                    if q and q in src and any(set(b['facts'])==ids and b['source']==s['source'] for b in g['branches']):flags.add('branch_matches_but_exact_relation_quote_rejected_by_full_span_rule')
                    elif not q or q not in src:flags.add('noncontiguous_or_wrong_source_relation_quote')
                    else:flags.add('relation_branch_mapping_mismatch')
                elif error['reason']=='unmatched_or_duplicate_fact':
                    a=atoms[error['id']]
                    if a['necessity']=='contextual' and a['quote'] in c['passages'].get(a['source'],''):flags.add('source_quoted_context_not_annotated_in_gt')
                    elif a['necessity']=='required':flags.add('unmatched_required_claim_semantic_or_lexical')
            stats['fn_in_native_accepted_cases']+=j.get('fn',0)
        for flag in flags:
            stats[flag+'_cases']+=1
            examples.setdefault(flag,dict(id=cid,challenge=f['challenge'],input=c,gold=gold[cid],prediction=p,judgement=j))
        details.append(dict(id=cid,flags=sorted(flags)))
    timing=[json.loads(l) for l in (r/'collected/item4/native_cache/inference_timing.jsonl').read_text(encoding='utf-8').splitlines()]
    execution=dict(raw_recorded_inferences=len(timing),format_retry_records=sum(bool(x['usage'].get('format_retry')) for x in timing),prefix_disagreement_records=sum(bool(x['usage'].get('prefix_disagreement')) for x in timing))
    span=max(x['timestamp'] for x in timing)-min(x['timestamp']-x['seconds'] for x in timing)
    assert stats['native_rejection_cases']==report['cases']-report['counts']['valid']
    assert stats['fn_in_native_rejection_cases']+stats['fn_in_native_accepted_cases']==report['counts']['fn']
    result=dict(test_candidate_counts=dict(stats),run_execution_counts=execution,failure_flags_overlap=True,inference_elapsed_seconds=round(span,2),
        interpretation=['32.8125 percent is strict contract compliance, not independent semantic accuracy.','Exact source quotations can fail the entire-preannotated-span rule, including omission of articles. No post-test relaxation or rescoring.','Source-quoted optional contextual claims omitted by GT are not by themselves hallucinations.','28 of 32 test FN belong to 11 native rejection cases. Remaining FN may include lexical mismatches.','Native format failures stay in every headline denominator; no successful-only alternative score is substituted.','Construction families shared across splits, so test_candidate is a controlled synthetic holdout, not independent external validation.'],
        recommended_order=['Repair and DEV-validate structured decoding/format failures.','Independently adjudicate source-supported paraphrases, context and minimal sufficient relation spans; freeze a revised oracle before another final test.','Use DEV-only extraction/logic tuning after those measurement/runtime problems are resolved.','Create a new untouched independently worded final test after changes; these evaluated documents are now exposed.'],
        score_sha256_before_diagnostics=hashlib.sha256((r/'final_summary.json').read_bytes()).hexdigest(),failures=details)
    for name,x in [('post_test_diagnostics.json',result),('diagnostic_examples.json',examples)]:
        (r/name).write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf-8')
    assert result['score_sha256_before_diagnostics']==hashlib.sha256((r/'final_summary.json').read_bytes()).hexdigest()
    print(json.dumps({k:v for k,v in result.items() if k!='failures'},ensure_ascii=True))

if __name__=='__main__':main()
