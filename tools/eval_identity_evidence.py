"""Evaluate identity retrieval separately from CVE applicability and VEX.

Legacy CPE-pair references are conflicted/partially weak: results are agreement,
not independent real-SBOM accuracy. Never inject expected IDs into retrieval.
"""
import argparse,json,sys,time,hashlib
from pathlib import Path
from collections import defaultdict,Counter
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.identity_retrieval import get_index
from src.identity_versions import version_info
from src.identity_evidence import validate_identity,rerank,digest
from src.training_io import atomic_json
from ics_agent_matcher_full.ics_agent_matcher.matcher import norm,ALIAS

def main():
    p=argparse.ArgumentParser();p.add_argument('--limit',type=int,default=0)
    p.add_argument('--llm',action='store_true');p.add_argument('--output',type=Path,default=ROOT/'results/identity_evidence_v3_evaluation.json')
    p.add_argument('--gold',type=Path,default=ROOT/'data/cpe_match_eval.jsonl');a=p.parse_args()
    if a.llm and not 1<=a.limit<=20:raise ValueError('LLM development evaluation is bounded to 20 cases; freeze a separately budgeted run for larger comparisons.')
    grouped={}
    for line in a.gold.read_text(encoding='utf-8').splitlines():
        r=json.loads(line);raw=r.get('_sut_input')
        if not raw:continue
        key=digest([raw.get('name'),raw.get('version'),raw.get('publisher'),raw.get('cpe')])
        entry=grouped.setdefault(key,{'input':raw,'positive_identities':set(),'reference_rows':0})
        entry['reference_rows']+=1
        if r.get('applicable') is True:
            c=r.get('component') or {}
            if c.get('vendor') and c.get('product'):entry['positive_identities'].add((c['vendor'],c['product']))
    code_files=[ROOT/'src'/name for name in ['identity_retrieval.py','identity_versions.py','identity_evidence.py','identity_calibration.py']]
    code_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in code_files}
    selected=sorted(grouped.items())[:a.limit or None];index=get_index();records=[];counts=Counter();start=time.time()
    status_file=a.output.with_suffix('.status.json')
    atomic_json(status_file,{'phase':'running','total':len(selected),'done':0,'pid':__import__('os').getpid()})
    for i,(key,row) in enumerate(selected):
        raw=row['input'];c={'name':raw.get('name') or '','version':raw.get('version') or '',
            'supplier':raw.get('publisher') or '','manufacturer':'','cpes':[raw['cpe']] if raw.get('cpe') else [],'purl':None}
        c['evidence']=[{'id':'input:'+k,'value':c[k]} for k in ['name','version','supplier'] if c[k]]
        versions=version_info(c,synthetic=True);retrieval=index.search(c,versions);candidates=retrieval['candidates']
        agent=None
        if a.llm:
            agent=rerank(c,retrieval)
            if agent['guard_accepted']:
                order={rid:i for i,rid in enumerate(agent['prediction']['ranked_candidate_ids'])}
                candidates=sorted(candidates,key=lambda r:order.get(r['candidate_id'],len(order)))
        got=validate_identity(c,candidates);refs=row['positive_identities'];unique=len(refs)==1
        expected=next(iter(refs)) if unique else None
        ranked=[(r['vendor'],r['product']) for r in candidates]
        rank=ranked.index(expected)+1 if expected in ranked else None
        base_name=ALIAS.get(norm(c['name']),norm(c['name']));base={
            (index.docs[rid]['vendor'],index.docs[rid]['product']) for rid in index.by_product.get(base_name,set())}
        baseline=next(iter(base)) if len(base)==1 else None
        chosen=(got['vendor'],got['product']) if got['status']=='validated' else None
        counts['reference_unique']+=unique;counts['reference_missing_or_conflicting']+=not unique
        counts['identity_selected']+=chosen is not None
        if unique:
            counts['recall_at_20']+=rank is not None and rank<=20
            counts['top1_agreement']+=bool(ranked and ranked[0]==expected)
            counts['selected_scorable']+=chosen is not None
            counts['selected_agrees']+=chosen==expected
            counts['baseline_selected_scorable']+=baseline is not None
            counts['baseline_agrees']+=baseline==expected
        records.append({'id':key,'input':c,'reference_identities':sorted(refs),'reference_unique':unique,
            'rank_of_reference':rank,'top_candidates':[{k:r[k] for k in ['candidate_id','vendor','product','ranking_score','conflicts']} for r in candidates[:20]],
            'decision':got,'baseline_identity':baseline,'model_ranking':agent})
        if (i+1)%100==0:atomic_json(status_file,{'phase':'running','total':len(selected),'done':i+1,'elapsed_seconds':round(time.time()-start,1)})
    n=counts['reference_unique'];scored=counts['selected_scorable'];bs=counts['baseline_selected_scorable']
    report={'scope':'Legacy synthetic CPE-pair reference agreement, identity retrieval only; NOT independent real-SBOM or CVE/VEX accuracy.',
        'complete':True,'cases':len(records),'counts':dict(counts),'reference_recall_at_20':counts['recall_at_20']/n if n else None,
        'top1_reference_agreement':counts['top1_agreement']/n if n else None,
        'selected_reference_agreement':counts['selected_agrees']/scored if scored else None,
        'identity_selection_coverage':counts['identity_selected']/len(records) if records else None,
        'baseline_selected_reference_agreement':counts['baseline_agrees']/bs if bs else None,
        'baseline_selection_coverage':bs/n if n else None,'independent_calibration_performed':False,
        'evaluation_usage':'development_reference_audit','independent_heldout_test':False,
        'fuzzy_acceptance_enabled':False,'test_labels_used_for_tuning':False,'llm_used':a.llm,
        'source_sha256':hashlib.sha256(a.gold.read_bytes()).hexdigest(),'dictionary_sha256':index.snapshot_hash,
        'code_hashes_at_start':code_hashes,'code_changed_during_run':any(hashlib.sha256(p.read_bytes()).hexdigest()!=code_hashes[p.name] for p in code_files),
        'elapsed_seconds':round(time.time()-start,1),'records':records}
    atomic_json(a.output,report);atomic_json(status_file,{'phase':'complete','cases':len(records),'elapsed_seconds':report['elapsed_seconds']})
    print(json.dumps({k:v for k,v in report.items() if k!='records'},indent=2))

if __name__=='__main__':main()
