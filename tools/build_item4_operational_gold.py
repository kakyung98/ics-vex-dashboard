"""Fictional ICS simulation Gold and prediction-blind real-asset worksheets."""
import itertools
import hashlib
import json
from pathlib import Path
import sys
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.training_io import atomic_json
from src.operational_assessment import assess, affected_precision

OUT = ROOT/'benchmark/item4_operational_gold_v2'
AT = '2026-11-16T00:00:00+09:00'


def evidence(binding, source, quote, **extra):
    return dict(binding=dict(binding), source=source, quote=quote, reviewer='fictional-fixture-author',
        observed_at='2026-11-15T00:00:00+09:00', valid_until='2026-12-16T00:00:00+09:00',
        integrity_verified=True, **extra)


def expression(family):
    a,b,c = ({'condition':k} for k in ('network','feature','interlock'))
    notc = {'op':'not','args':[c]}
    return [dict(op='and',args=[a,b]), dict(op='or',args=[a,b]),
        dict(op='and',args=[a,b,notc]), dict(op='or',args=[dict(op='and',args=[a,b]),notc])][family]


def simulation_oracle(family, n, f, i):
    # Independent simulator: Boolean latent plant state, never the production AST.
    return [(n and f), (n or f), (n and f and not i), ((n and f) or not i)][family]


def build():
    if OUT.exists(): raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    handles={}
    for fold in ('train','evaluation'):
        (OUT/fold).mkdir()
        for kind in ('inputs','labels'):
            handles[fold,kind]=(OUT/fold/(kind+'.jsonl')).open('w',encoding='utf-8',newline='\n')
    counts=Counter(); predicted=[]; labels=[]
    try:
        for group in range(100):
            fold='train' if group%10<7 else 'evaluation';family=group%4
            for state in itertools.product((False,True),repeat=3):
                for fault in ('complete','missing','stale','wrong_scope','conflict','unreviewed','inapplicable','unobservable'):
                    # Opaque identifiers prevent missing observations from being
                    # reconstructed from state bits embedded in case/source IDs.
                    seed=json.dumps([group,state,fault],separators=(',',':'))
                    case_id='SYN-'+hashlib.sha256(('case-v2:'+seed).encode()).hexdigest()[:32]
                    binding=dict(cve=f'CVE-2099-{10000+group}',asset_ref='fictional-plc-'+str(group),
                        product='fictional-controller-'+str(group),build='1.0',config_baseline='cfg-'+case_id,
                        mode='operations',actor_origin='fictional-engineering-network')
                    specs=[dict(id=k,operator_observable=True,predicate=k,target=binding['asset_ref']) for k in ('network','feature','interlock')]
                    source=evidence(binding,'fixture://scenario/'+str(group),
                        'Fictional complete vulnerability scenario; not a claim about a real CVE.')
                    scenario=dict(id='scenario-'+str(group),product=binding['product'],
                        semantic_reviewed=True,sufficiency_reviewed=True,source_evidence=source,
                        conditions=specs,expression=expression(family))
                    observations=[evidence(binding,'fixture://observation/'+case_id,k+'='+str(v),condition_id=k,value=str(v).lower()) for k,v in zip(('network','feature','interlock'),state)]
                    packet=dict(binding=binding,synthetic=True,fictional_cve=True,
                        attack_asset_ids=[f'A{group%18+1:04}'],attack_techniques=[],scenarios=[scenario],
                        applicability=evidence(binding,'fixture://inventory','Fictional product and running build match',value='true'),
                        observations=observations,action_statement='Apply the fictional supplier correction after operational review.')
                    if fault=='missing': packet['observations']=observations[1:]
                    elif fault=='stale':
                        for o in observations:o['valid_until']='2026-11-15T01:00:00+09:00'
                    elif fault=='wrong_scope':
                        for o in observations:o['binding']={**binding,'build':'other-build'}
                    elif fault=='conflict':
                        packet['observations'] += [evidence(binding,'fixture://conflict','Conflicting network observation',condition_id='network',value=str(not state[0]).lower())]
                    elif fault=='unreviewed': scenario['sufficiency_reviewed']=False
                    elif fault=='inapplicable':packet['applicability']['value']='false'
                    elif fault=='unobservable':
                        for s in specs:s['operator_observable']=False
                    actual=bool(simulation_oracle(family,*state)) if fault!='inapplicable' else False
                    gold=dict(id=case_id,binding=binding,actual_affected=actual,synthetic=True,
                        fictional_cve=True,label_method='independent_boolean_plant_simulator',
                        latent_state=dict(zip(('network','feature','interlock'),state)),family=family,group=group,fault=fault)
                    handles[fold,'inputs'].write(json.dumps(dict(id=case_id,packet=packet),ensure_ascii=False)+'\n')
                    handles[fold,'labels'].write(json.dumps(gold,ensure_ascii=False)+'\n')
                    counts[fold]+=1;counts['fault:'+fault]+=1
                    if fold=='evaluation':
                        result=assess(packet,AT)
                        predicted.append(dict(id=case_id,binding=binding,status=result['status'],fault=fault))
                        labels.append(gold)
    finally:
        for f in handles.values():f.close()
    from tools.item3_precision_pipeline import sha
    atomic_json(OUT/'manifest.json',dict(schema='synthetic-ICS-operational-gold/2',counts=dict(counts),
        identifier_policy='Opaque SHA256 identifiers; latent state and fault labels occur only in separate labels',
        training_compatibility='Frozen adapter used 32 v1 training records with complete observations only; v2 evaluation identifiers sanitized before any v2 predictions',
        split_unit='fictional vulnerability/product family',train_groups=70,evaluation_groups=30,
        metric='TP/(TP+FP) among automatically affected asset/CVE scopes',threshold_strictly_greater_than=.85,
        synthetic=True,independent_real_asset_validation=False,
        oracle='Separate latent-state Boolean simulator; no production prediction used as a label',
        limitation='Designed simulation coverage, not extracted-CVE semantic accuracy or field accuracy',
        evaluated_at=AT,artifacts={str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*.jsonl')}))
    result=ROOT/'results/item4_operational_v2';result.mkdir(parents=True,exist_ok=True)
    with (result/'predictions.jsonl').open('w',encoding='utf-8') as f:
        for row in predicted:f.write(json.dumps(row)+'\n')
    report=affected_precision(predicted,labels)
    report['by_fault']={fault:affected_precision([r for r in predicted if r['fault']==fault],[r for r in labels if r['fault']==fault])
        for fault in sorted({r['fault'] for r in labels})}
    atomic_json(result/'precision_report.json',report)
    blank=dict(record_type='real_asset_impact_work_item',synthetic=False,asset_case_verified=False,
        binding={k:'' for k in ('cve','asset_ref','product','build','config_baseline','mode','actor_origin','evaluated_at')},
        rater_a=dict(name='',actual_affected=None,source='',quote=''),
        rater_b=dict(name='',actual_affected=None,source='',quote=''),
        prediction_blind_review=False,actual_affected=None,adjudication=None)
    atomic_json(OUT/'real_asset_annotation_blank.json',blank)
    atomic_json(OUT/'annotation_guidance.json',dict(
        instructions=['Record the exact asset/CVE/product/build/configuration/operating-mode/attack-origin/time scope.',
            'Two reviewers independently examine inventory, vendor records, configuration and operational evidence before predictions are revealed.',
            'Label actual_affected true, false or null; missing or stale evidence is null.',
            'Record evidence and reconcile disagreements with a third reviewer.',
            'Change record_type to real_asset_impact_gold only after verified independent annotation.',
            'Simulation scores cannot be reported as real ICS asset accuracy.']))
    print(json.dumps(report,ensure_ascii=False),flush=True)


if __name__=='__main__':build()
