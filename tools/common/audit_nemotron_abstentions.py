"""Read-only audit of frozen synthetic inputs and completed Nemotron receipts."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import zlib

ROOT=Path(__file__).resolve().parents[2]
RUN='nemotron-20261122T121210Z-534c666308'
OUT=ROOT/'results/nemotron_abstention_audit_20261123'

def main():
    OUT.mkdir(exist_ok=True)
    source=next((Path(tempfile.gettempdir())/'ICS-VEX/moe-inputs').glob('5015fc6685d533343f6aa86d0341dcf152bd40b3cc52bdac0eab8d5f77024cb3.sqlite3'))
    db=sqlite3.connect(source.as_uri()+'?mode=ro&immutable=1',uri=True)
    cases={}; packets={}; packet_hashes={}; inputs=Counter(); contexts=defaultdict(Counter)
    extraction=Counter(); upstream_errors=Counter(); extraction_models=Counter()
    for cve,blob in db.execute('SELECT cve,packet FROM packets'):
        raw=zlib.decompress(blob);p=json.loads(raw); packets[cve]=p
        packet_hashes[cve]=hashlib.sha256(raw).hexdigest()
        cond=p['job']['conditions'][0];pre=cond.get('prerequisite') or {}
        extraction[str(cond.get('status'))]+=1
        if cond.get('status')=='unresolved':upstream_errors[cond.get('reason','')]+=1
        else:extraction_models[str(pre.get('model',{}).get('model'))]+=1
        inputs['cves_extracted_without_scenarios']+=cond.get('status')=='extracted' and not bool((pre.get('draft') or {}).get('scenarios'))
        inputs['cves']+=1
        inputs['cves_without_questions']+=not bool(p['job']['questions'])
        inputs['cves_with_frozen_source_path']+=bool(p['generation']['independent_source_path_available'])
        inputs['cves_with_source_bindings']+=bool(p['generation']['source_condition_bindings'])
        for case in p['cases']:
            cases[case['id']]=case; inputs['cases']+=1
            inputs['cases_missing_inventory_coverage']+='inventory_coverage' not in case['context']
            inputs['cases_empty_answers']+=not bool(case['answers'])
            for k,v in case['context'].items():contexts[k][v]+=1
    counts=Counter(); expert=defaultdict(Counter); reasons=defaultdict(Counter)
    samples={}; products={}; rule_cves=set(); all_o=[]; inventory_mismatch=[]
    digest=hashlib.sha256()
    file=ROOT/'results/item4_scenario_moe'/RUN/'candidates.jsonl'
    for line in file.open('rb'):
        digest.update(line);r=json.loads(line);case=cases[r['id']];p=packets[r['cve']]
        assert r['packet_sha256']==packet_hashes[r['cve']]
        products[r['cve']]=r['verified_product']
        rule=bool(r['source_rule_identities'])
        if rule:rule_cves.add(r['cve'])
        counts['cases_with_bound_rule']+=rule
        for e in r['experts']:expert[e['expert']][str(e['verdict'])]+=1
        for reason in r['reasons']:
            reasons[reason]['cases']+=1
            reasons[reason]['with_bound_rule']+=rule
            reasons[reason]['no_questions']+=not bool(p['job']['questions'])
            reasons[reason]['no_frozen_source_path']+=not p['generation']['independent_source_path_available']
            reasons[reason]['empty_answers']+=not bool(case['answers'])
            reasons[reason]['runtime_'+case['context']['runtime']]+=1
            if reason not in samples or reason=='crosscheck_did_not_corroborate':
                samples[reason+(':'+r['id'] if reason=='crosscheck_did_not_corroborate' else '')]=dict(case=case,candidate=r,
                    job_questions=p['job']['questions'],generation=p['generation'],input_bom=p['job']['input_bom'])
        if rule and case['answers'] and set(case['answers'].values())=={'o'}:
            all_o.append(dict(id=r['id'],cve=r['cve'],context=case['context'],reasons=r['reasons'],experts=r['experts']))
        ctx=case['context'];expected=ctx['scope']=='current_single' and ctx['deployment']=='running' and ctx['runtime']=='bom'
        ie=next(e for e in r['experts'] if e['expert']=='inventory')
        if expected and ie['verdict']!='installed_exact':inventory_mismatch.append(r['id'])
    counts.update({'unique_cves':len(products),'cves_with_bound_rule':len(rule_cves),'all_o_rule_cases':len(all_o),
                   'inventory_model_disagrees_with_exact_context':len(inventory_mismatch)})
    product_states=Counter(p['state'] for p in products.values())
    versions=Counter(str(p['version']) for p in products.values())
    ledger=sqlite3.connect(ROOT/'results/item4_run_ledger/runs.sqlite3')
    saved=json.loads(ledger.execute('SELECT snapshot FROM runs WHERE run_id=?',(RUN,)).fetchone()[0])
    assert saved['status']=='completed' and saved['result']['candidates_sha256']==digest.hexdigest()
    assert len(cases)==97553 and len(products)==12418
    report=dict(run_id=RUN,created_at=datetime.now(timezone.utc).isoformat(),candidates_sha256=digest.hexdigest(),
        input_packet_hashes_match_receipts=True,completed_candidates_hash_matches_ledger=True,
        upstream_extraction_statuses=dict(extraction),upstream_extraction_errors=dict(upstream_errors),upstream_extraction_models=dict(extraction_models),
        inputs=dict(inputs),context_counts=dict(contexts),counts=dict(counts),product_states=dict(product_states),
        top_versions=versions.most_common(15),expert_verdicts=dict(expert),hold_breakdown=dict(reasons),
        all_o_bound_rule_cases=all_o,inventory_disagreement_ids=inventory_mismatch)
    (OUT/'audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (OUT/'samples.json').write_text(json.dumps(samples,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
