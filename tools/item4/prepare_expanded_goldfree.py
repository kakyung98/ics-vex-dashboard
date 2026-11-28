"""Freeze larger, reproducible gold-free cohorts before model inference."""
import sys,json,re,random,hashlib,math
from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.workflow.source_analysis_jobs import description_packet
from src.item4.analysis import asset_operating_question_generation as V3
OUT=ROOT/'results/item4_goldfree_expanded_20261126'
SEED=2026112601


def main():
    OUT.mkdir(exist_ok=True)
    if (OUT/'inputs.json').exists():raise ValueError('Frozen cohort exists; do not silently resample')
    home=ROOT/'results/item4_source_condition_question_links'
    pop=json.loads((home/'source_population.json').read_text(encoding='utf-8'))
    if len(pop)!=12418:raise ValueError('Expected complete 12,418-CVE sampling frame')
    old=json.loads((ROOT/'results/item4_qwen_reference_20261126/manifest.json').read_text(encoding='utf-8'))
    development={c['id'] for c in old['cases']}
    flags={};records={};groups=defaultdict(list);ledger=[]
    for i,cve in enumerate(sorted(pop)):
        record=description_packet(cve)
        text=' '.join(s['text'] for s in record.get('sources',[]))
        tags=dict(source_missing=not bool(text),
            negative_or_quantified=bool(re.search(r'\b(not|never|without|disabled|all|every|only)\b',text,re.I)),
            and_or=bool(re.search(r'\b(and|or|either|both)\b',text,re.I)),
            default_or_mitigation=bool(re.search(r'\b(default|mitigat\w*|recommend\w*|should)\b',text,re.I)),
            explicit_condition=bool(re.search(r'\b(if|when|requires?|must|enabled|configured|access to)\b',text,re.I)))
        order=['source_missing','default_or_mitigation','negative_or_quantified','explicit_condition','and_or']
        stratum=next((s for s in order if tags[s]),'no_explicit_marker')
        flags[cve]=dict(stratum=stratum,tags=tags,development=cve in development)
        ledger.append(dict(cve=cve,**flags[cve],source_count=len(record.get('sources',[]))))
        records[cve]=record
        if cve not in development:groups[stratum].append(cve)
        if (i+1)%2000==0:print('Indexed',i+1,flush=True)
    rng=random.Random(SEED)
    allocation={s:min(20,len(ids)) for s,ids in groups.items()}
    while sum(allocation.values())<500:
        s=max((s for s in groups if allocation[s]<len(groups[s])),key=lambda s:len(groups[s])/(allocation[s]+1))
        allocation[s]+=1
    selected=[]
    for s in sorted(groups):
        ids=rng.sample(sorted(groups[s]),allocation[s]);selected+=ids
    rng.shuffle(selected)
    robust=set(rng.sample(sorted(selected),100))
    cases=[dict(id=cve,record=records[cve],asset_type_id=None,**flags[cve],
                robustness_selected=cve in robust,inclusion_probability=allocation[flags[cve]['stratum']]/len(groups[flags[cve]['stratum']])) for cve in selected]
    units=json.loads((home/'proposals.json').read_text(encoding='utf-8'))['units']
    eligible=defaultdict(list)
    for a in units:
        c=a.get('original_condition',{});statement=c.get('statement','');quote=c.get('source_quote','');text=a.get('text','')
        if a['cve'] in development:continue
        if c.get('necessity')!='required' or not a.get('verified') or a.get('source_subject_ambiguous'):continue
        if c.get('axis') not in ('AC','UI','AV') or c.get('actor') not in ('system','victim','user','legitimate user'):continue
        if not quote or text.count(quote)!=1 or len(statement)>400:continue
        if not re.search(r'\b(enabled|configured|opens?|running|maintenance|local access|network access)\b',quote,re.I):continue
        if re.search(r'\b(not|never|without|disabled|unspecified|undefined)\b',statement,re.I):continue
        if re.search(r'\b(long|crafted|malformed|payload|buffer|function|member)\b',quote,re.I):continue
        if hashlib.sha256(text.encode()).hexdigest()!=a['source_sha256']:continue
        eligible[a['cve']].append(a)
    v3=[]
    q_cves=rng.sample(sorted(eligible),min(180,len(eligible)))
    for cve in q_cves:
        a=rng.choice(sorted(eligible[cve],key=lambda a:a['id']));c=a['original_condition']
        fact=re.sub(r'^[^:]+:\s*','',c['statement'])
        axis=c['axis'];kind='configuration' if axis=='AC' else 'operating_workflow' if axis=='UI' else 'network_access'
        record='configuration_export' if axis=='AC' else 'operating_procedure' if axis=='UI' else 'firewall_acl'
        source=dict(id=a['source_id'],text=a['text'],text_sha256=a['source_sha256'],url=a.get('source_url'),product_keys=[],scope_binding='unresolved')
        assets=pop[cve].get('asset_candidates',[]);aid=assets[0] if len(assets)==1 else None
        job=dict(conditions=[dict(cve=cve,sources=[source],prerequisite=dict(sha256=V3.digest(a),draft=dict(scenarios=[dict(id='candidate',expression=dict(condition='p0'))])))],
            components=[dict(ref='asset',name='Assessment asset')],representative=dict(ref='asset'),
            asset_classification=dict(status='classified' if aid else 'unresolved',asset_type_id=aid,provisional=True))
        q=dict(condition_id='p0',label=fact,scope_kind=c['target'],observation=dict(kind=kind,record_type=record,check='Inspect '+record+' for '+fact),source_refs=[dict(source_id=source['id'],quote=c['source_quote'])],operational_quote=c['source_quote'])
        payload=V3.packet(job,dict(cve=cve,id='candidate:'+a['id'],declared_ref='asset'),[q],[])
        v3.append(dict(id=cve,kind='real_source_candidate',packet=payload,candidate_unit_id=a['id'],input_semantics_independently_validated=False))
    prior=json.loads((ROOT/'results/item4_goldfree_h200_20261126/inputs.json').read_text(encoding='utf-8'))
    data=dict(cases=cases,v3=v3,hashes=prior['hashes'],seed=SEED)
    (OUT/'inputs.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    with (OUT/'population_ledger.jsonl').open('w',encoding='utf-8') as f:
        for r in ledger:f.write(json.dumps(r,ensure_ascii=False)+'\n')
    manifest=dict(version='expanded-goldfree-cohort/1',created_at=datetime.now(timezone.utc).isoformat(),seed=SEED,
        population=12418,development_cases_excluded_from_fresh_sample=len(development),
        sampling_frame_by_stratum={s:len(v) for s,v in groups.items()},allocation=allocation,
        extraction_cves=len(cases),robustness_cves=len(robust),v2_expected_runs=len(cases)+2*len(robust),
        question_unique_cves=len(v3),question_atoms=len(v3),v3_expected_runs=2*len(v3),
        candidate_input_bank_unique_cves=len(eligible),question_axis_counts=dict(Counter(eligible[c][0]['original_condition']['axis'] for c in q_cves)),
        sampling='Stratified random CVE sampling with known inclusion probabilities; 100 robustness CVEs chosen before inference.',
        v3_sampling='Random unique CVEs from lexically eligible pre-existing source-condition candidates; not filtered by current V2 success.',
        question_input_limit='Candidate atoms are test inputs, not semantic gold. Their input grounding must be evaluated separately.',
        gold_used=False,independent_expert_labels=0,inputs_sha256=hashlib.sha256((OUT/'inputs.json').read_bytes()).hexdigest(),
        limitations=['Development examples excluded, but prior project/model training exposure is not fully known.',
            'V3 eligible input bank is limited to positive configuration/access/workflow candidates; not all question types.',
            'Sampling weights apply to V2 frame estimates, not V3 candidate-bank estimates.'])
    (OUT/'cohort_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(manifest,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
