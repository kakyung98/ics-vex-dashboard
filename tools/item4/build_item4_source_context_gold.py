"""Real CVE identifiers and source-conditioned synthetic worlds, label separated."""
from collections import Counter,defaultdict
from copy import deepcopy
import hashlib,itertools,json,sys
from io import StringIO
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.decision.scoped_vex_review import DATA as SOURCES; from src.item4.decision.scoped_vex_review import digest
from src.item4.evaluation.source_context_simulation import DATA; from src.item4.evaluation.source_context_simulation import AT; from src.item4.evaluation.source_context_simulation import source_spec
from src.common.runtime.training_progress_io import atomic_json
from tools.item3.item3_precision_pipeline import sha
from src.research.item4_source_recovery import recover,unresolved_evidence,VERSION as RECOVERY_VERSION
from src.item4.evaluation.ground_truth_evidence import GroundingIndex; from src.item4.evaluation.ground_truth_evidence import VERSION as GROUNDING_VERSION

# Four operator-context cases; observation-quality faults are outside this Gold.
VARIATIONS=('observed_true','observed_false','hidden_true','hidden_false')

def write_jsonl(path,text):
    # Publish complete files; avoid exposing partially written JSONL to readers.
    temporary=path.with_suffix('.jsonl.tmp')
    temporary.write_bytes(text.encode('utf-8'))
    temporary.replace(path)

def dnf(expr,negated=False):
    """Independent oracle compiler: Boolean DNF, never production ternary logic."""
    if 'condition' in expr:return [{expr['condition']:not negated}]
    op=expr['op']
    if op=='not':return dnf(expr['args'][0],not negated)
    if negated:op={'and':'or','or':'and'}[op]
    children=[dnf(a,negated) for a in expr['args']]
    if op=='or':return [t for child in children for t in child]
    result=[{}]
    for child in children:
        result=[{**a,**b} for a in result for b in child if all(k not in a or a[k]==v for k,v in b.items())]
        if len(result)>512:raise ValueError('Oracle formula budget exceeded')
    return result

def plant(terms,state):return any(all(state[k]==v for k,v in term.items()) for term in terms)

def boundary(spec):
    observable=[c['id'] for c in spec['conditions'] if c['operator_observable']]
    fixed={k:True for k in spec['simulation_assumptions']['unobserved_requirements_satisfied']}
    if not observable or len(observable)>10:raise ValueError('No bounded observable state space')
    terms=dnf(spec['expression'])
    for values in itertools.product((False,True),repeat=len(observable)):
        true_state={**fixed,**dict(zip(observable,values))}
        if not plant(terms,true_state):continue
        for pivotal in observable:
            false_state={**true_state,pivotal:not true_state[pivotal]}
            if not plant(terms,false_state):return terms,true_state,false_state,pivotal
    raise ValueError('No observable change can discriminate the selected simulated path')

def expected_code(terms,spec,observations,binding):
    # Independent possible-world oracle. Invalid observations convey no facts.
    known={k:True for k in spec['simulation_assumptions']['unobserved_requirements_satisfied']}
    observable=[c['id'] for c in spec['conditions'] if c['operator_observable']]
    for cid in observable:
        values={o['value']=='true' for o in observations if o['condition_id']==cid and o['binding']==binding
            and o['observed_at']<=AT<=o['valid_until'] and o['value'] in ('true','false')}
        if len(values)==1:known[cid]=next(iter(values))
    missing=[k for k in observable if k not in known]
    possible=[plant(terms,{**known,**dict(zip(missing,values))}) for values in itertools.product((False,True),repeat=len(missing))]
    return 'A' if possible and all(possible) else 'U'

def build(output=None):
    global DATA
    if output is not None:DATA=Path(output)
    if DATA.exists():raise FileExistsError(DATA)
    DATA.mkdir(parents=True)
    assignments={r['cve']:r for r in map(json.loads,(ROOT/'results/item4_condition_clusters_v1/cve_assignments.jsonl').open(encoding='utf-8'))}
    records={}
    for path in sorted(SOURCES.glob('records_*.json')):records.update(json.loads(path.read_text(encoding='utf-8')))
    assert len(assignments)==len(records)==12418 and assignments.keys()==records.keys()
    grounder=GroundingIndex(ROOT)
    handles={};counts=Counter();reasons=Counter();case_index=[];support=defaultdict(set)
    for fold in ('train','evaluation'):
        (DATA/fold).mkdir()
        for kind in ('inputs','labels'):handles[fold,kind]=StringIO()
    with StringIO() as evidence:
        for cid in sorted(records):
            record=records[cid];assert digest({k:v for k,v in record.items() if k!='record_digest'})==record['record_digest']
            record=grounder.prepare(record)
            fold=assignments[cid]['fold'];selected=None;failures=[]
            sources={s['id']:s for s in record['sources']}
            ordered=sorted(record.get('scenarios',[]),key=lambda s:(
                sources[s['source_ref']['source_id']].get('product_scope_validation',{}).get('basis')!='exact_product_family_note_title',
                min(s['product_keys'],default='~'),s['id']))
            for scenario in ordered:
                try:
                    spec=source_spec(record,scenario);terms,true_state,false_state,pivotal=boundary(spec)
                    selected=(spec,terms,true_state,false_state,pivotal);break
                except (ValueError,KeyError) as exc:failures.append(str(exc))
            evidence.write(json.dumps(record,ensure_ascii=False)+'\n')
            cid_cases=[]
            if selected:
                counts['CVEs_with_conditional_worlds']+=1;counts[fold+':CVEs_with_conditional_worlds']+=1
                spec,terms,true_state,false_state,pivotal=selected
                variations=VARIATIONS
            else:
                variations=('unknown_source',);spec=None
                counts['CVEs_source_unknown']+=1
                reasons.update(set(failures) or {'No source scenario draft'})
            for variation in variations:
                identity='CTX-'+hashlib.sha256(('source-context-v5|'+cid+'|'+variation).encode()).hexdigest()[:32]
                packet=dict(mode='source_conditioned_simulation',synthetic=True,cve=cid,evaluated_at=AT,
                    spec=deepcopy(spec),observations=[])
                label=dict(id=identity,cve=cid,synthetic=True,real_CVE_identifier=True,actual_affected=None,
                    expected_code='U',source_semantic_accuracy_verified=False,scope='conditional_selected_path_synthetic_world',
                    label_method='Independent DNF plant simulator and all-completions observation oracle',fold=fold)
                if spec:
                    latent=false_state if variation in ('observed_false','hidden_false') else true_state
                    binding=dict(cve=cid,asset_ref='hypothetical-'+hashlib.sha256(cid.encode()).hexdigest()[:16],
                        product=spec['product']['name'],build='assumed-affected-synthetic-build',
                        config_baseline='cfg-'+identity,mode='hypothetical-operations',actor_origin='hypothetical-assessed-origin')
                    packet['binding']=binding
                    for c in spec['conditions']:
                        if not c['operator_observable']:continue
                        k=c['id']
                        if variation in ('hidden_true','hidden_false') and k==pivotal:continue
                        packet['observations'].append(dict(condition_id=k,value=str(latent[k]).lower(),binding=dict(binding),
                            observed_at='2026-11-15T00:00:00+09:00',valid_until='2026-12-16T00:00:00+09:00',
                            evidence_type='synthetic_operator_record',source='simulation://observation/'+identity))
                    label.update(actual_affected=plant(terms,latent),expected_code=expected_code(terms,spec,packet['observations'],binding),
                        latent_state=latent,variation=variation,source_record_digest=record['record_digest'])
                    label.update(source_grounding_contract_validated=True,real_asset_impact_verified=False)
                    if label['expected_code']=='A' and not label['actual_affected']:
                        raise ValueError('Observation oracle contradicts latent world')
                    if fold=='train':
                        for c in spec['conditions']:
                            if c['operator_observable']:support[(c['kind'],c['statement'],c['question'])].add(cid)
                else:
                    packet['unknown_source_reasons']=sorted(set(failures)) or ['No source scenario draft']
                    packet['source_evidence']=unresolved_evidence(record)
                    label['variation']='unknown_source'
                handles[fold,'inputs'].write(json.dumps(dict(id=identity,packet=packet),ensure_ascii=False)+'\n')
                handles[fold,'labels'].write(json.dumps(label,ensure_ascii=False)+'\n')
                counts[fold+':cases']+=1;counts['cases']+=1;counts[fold+':expected_'+label['expected_code']]+=1
                counts['known_latent_labels']+=label['actual_affected'] is not None;cid_cases.append(identity)
            case_index.append(dict(cve=cid,fold=fold,cluster=assignments[cid]['cluster'],cases=cid_cases,
                source_record_digest=record['record_digest'],conditional_world_available=bool(selected),
                selected_product=spec['product']['key'] if spec else None,
                selected_asset_type=spec['asset_type'] if spec else None,
                product_grounding=[dict(key=p['key'],name=p['name'],asset_type=p.get('asset_type'),
                    version_scope=p.get('version_scope'),source_product_ref=p.get('source_product_ref')) for p in record['products']],
                unknown_source_reasons=[] if selected else sorted(set(failures)) or ['No source scenario draft']))
        write_jsonl(DATA/'cve_source_records.jsonl',evidence.getvalue())
    for (fold,kind),h in handles.items():
        write_jsonl(DATA/fold/(kind+'.jsonl'),h.getvalue())
        h.close()
    write_jsonl(DATA/'cve_index.jsonl',''.join(json.dumps(row)+'\n' for row in case_index))
    templates=[dict(kind=k[0],source_proposition=k[1],source_question=k[2],training_CVE_support=len(v),
        meaning='Question reuse only; not universal prerequisites or sufficient exploitability') for k,v in sorted(support.items(),key=lambda kv:(-len(kv[1]),str(kv[0])))]
    atomic_json(DATA/'train_question_support.json',dict(count_unit='distinct TRAIN CVEs',test_used=False,templates=templates))
    atomic_json(DATA/'manifest.json',dict(schema='source-context-gold/5',population=12418,counts=dict(counts),unknown_reasons=dict(reasons),
        variations=list(VARIATIONS),excluded_variations=['conflict_true','stale_false'],
        previous_dataset='benchmark/item4_source_context_gold_v4',grounding_version=GROUNDING_VERSION,
        change_reason='Product-specific source scope, explicit asset-role evidence, typed operator questions and formula checks; unresolved evidence stays unknown',
        operator_answers_collected=False,independent_human_semantic_validation=False,
        evaluation_unit='One deterministically selected validated product/path per CVE; all other product scopes retained in the index',
        fixed18_taxonomy_unchanged=True,model_estimated_asset_types_used=False,unobserved_requirements_assumed_true=False,
        require_model_inference_for_every_CVE=True,unknown_source_actual_affected_is_null=True,
        original_real_CVE_ids_preserved=True,split='Existing shared-source connected groups: 8406 train CVEs / 4012 evaluation CVEs',
        simulation_assumptions=['Selected described path is complete within this simulation only','Selected source-linked product scope applies in simulation',
            'Unobservable or unsupported predicates block the path; no missing requirements assigned true','Other attack paths excluded only from this hypothetical world'],
        no_human_semantic_approval_fabricated=True,source_semantics_verified=False,real_asset_accuracy_verified=False,
        target_precision_strictly_greater_than=.85,unknown_CVEs_retained=True,IDs_are_opaque=True,
        artifacts={p.relative_to(DATA).as_posix():sha(p) for p in DATA.rglob('*.jsonl')}))
    print(json.dumps(dict(population=12418,counts=dict(counts),unknown_reasons=dict(reasons))),flush=True)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=DATA)
    build(parser.parse_args().output)
