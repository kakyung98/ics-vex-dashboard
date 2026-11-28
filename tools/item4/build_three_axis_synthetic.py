"""Freeze a labelled synthetic holdout before executing the VEX evaluator.

Ground truth is assigned from the scenario narrative table below, independently
of assessment outputs. All records are fictional, including source statements.
One deliberately semantically false, structurally valid supplier claim per asset
tests the engine's inability to authenticate an attested record's truth.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from datetime import datetime,timezone
from copy import deepcopy
import gzip,hashlib,json,random
from tools.item4 import serve_nist_operational_vex as S
from tools.item4.nist_three_axis_fixtures import case,bundle,proof,condition,add
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'results/nist_three_axis_experiment_20261118'
# ID, actual status, repetitions per each of the original 18 asset types.
MANIFEST=[
 ('affected_current','affected',5),('affected_network_blocked','affected',5),
 ('affected_condition_unknown','affected',5),('affected_governance_present','affected',5),
 ('affected_identity_unavailable','affected',5),('fixed_running','fixed',5),
 ('fix_documented_not_running','affected',5),('supplier_no_impact','not_affected',5),
 ('complete_structural_exclusion','not_affected',5),('blocked_without_product_proof','not_affected',5),
 ('different_source_product','not_affected',5),('different_running_build','not_affected',5),
 ('contradictory_source_status','not_affected',5),('governance_cannot_refute','not_affected',5),
 ('semantically_false_supplier_attestation','not_affected',1),
]
NARRATIVES={
 'affected_current':'The installed build is vulnerable. Exact supplier and inventory evidence is available.',
 'affected_network_blocked':'The installed build remains vulnerable despite a scoped blocked path. Mitigation is not a fixed product.',
 'affected_condition_unknown':'The installed build is vulnerable; attacker-path observations are unavailable.',
 'affected_governance_present':'The installed build is vulnerable even though a security budget is documented.',
 'affected_identity_unavailable':'The installed build is vulnerable, but the assessor lacks a selected product/build identity proof.',
 'fixed_running':'The vendor fixed this CVE and the fixed build is actually executing.',
 'fix_documented_not_running':'A vendor fix exists, but the old vulnerable build is still running; no installation proof is supplied.',
 'supplier_no_impact':'The exact product/configuration is outside the CVE impact scope, established by a qualified source.',
 'complete_structural_exclusion':'The fictional vulnerability has a single exhaustive route that qualified analysis structurally excludes.',
 'blocked_without_product_proof':'This fictional deployed scope is not affected; the available packet observation alone cannot establish that ground truth.',
 'different_source_product':'The real deployed product is not affected. The submitted affected finding belongs to another source product.',
 'different_running_build':'The real deployed build is not affected. The submitted affected finding concerns another build.',
 'contradictory_source_status':'Ground truth is no impact, but available records contain conflicting status claims.',
 'governance_cannot_refute':'Ground truth is no impact. A budget record is incorrectly offered as non-execution proof.',
 'semantically_false_supplier_attestation':'Ground truth is no impact, but a formally valid, falsely attested supplier finding claims affected. The engine cannot verify this semantic deception from codes and hashes.',
}
def dump(x):return json.dumps(x,ensure_ascii=False,separators=(',',':'))
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'protocol.json').exists():raise SystemExit('Frozen dataset already exists; refusing to relabel or overwrite it.')
    now=datetime.now(timezone.utc);rows=[];truth=[]
    for asset in range(18):
        for family,label,reps in MANIFEST:
            for rep in range(reps):
                cid=f'A{asset+1:04}-{family}-{rep:02}'
                p,r=case(asset,now)
                # Unique asset identities prevent accidental cross-case reuse.
                old=p['scope']['asset_ref'];p['scope']['asset_ref']=cid
                for e in p['evidence'].values():e['asset_ref']=cid
                for v in p['reference_values'].values():v['asset_ref']=cid
                plan=S.V.plan(r['cve'],p,'fictional-product',r)
                affected=family.startswith('affected_') or family in ('different_source_product','different_running_build','contradictory_source_status','semantically_false_supplier_attestation')
                status='affected' if affected else 'fixed' if family in ('fixed_running','fix_documented_not_running') else 'not_affected' if family=='supplier_no_impact' else None
                b=bundle(plan,p,status)
                if family=='affected_current':add(b,'network',condition(plan,p))
                if family=='affected_network_blocked':add(b,'network',condition(plan,p,'false'))
                if family=='affected_identity_unavailable':b['selected_ids'].remove('identity')
                if family=='fixed_running':add(b,'runtime',proof(plan,p,'installation','running_fixed_build','runtime_installation','inventory'))
                if family in ('complete_structural_exclusion','governance_cannot_refute'):
                    add(b,'nonexec',condition(plan,p,'false',True));add(b,'closure',proof(plan,p,'route_coverage','complete','exhaustive_route_analysis','analysis'))
                    if family=='governance_cannot_refute':b['records']['nonexec']['field_ids']=['C12-01.01']
                if family=='blocked_without_product_proof':add(b,'network',condition(plan,p,'false'))
                if family=='different_source_product':b['records']['status']['product_key']='another-source-product'
                if family=='different_running_build':b['records']['status']['scope']['build']='another-build'
                if family=='contradictory_source_status':add(b,'no-impact',proof(plan,p,'product_status','not_affected','supplier_statement','vendor'))
                rows.append(dict(case_id=cid,family=family,record=r,profile=p,typed_review=b,approved_scenarios=['fictional-route']))
                truth.append(dict(case_id=cid,actual_status=label,actual_affected=label=='affected',narrative=NARRATIVES[family]))
    random.Random(882901).shuffle(rows)
    with gzip.open(OUT/'holdout_inputs.jsonl.gz','wt',encoding='utf-8') as f:
        for row in rows:f.write(dump(row)+'\n')
    (OUT/'holdout_ground_truth.jsonl').write_text('\n'.join(dump(row) for row in truth)+'\n',encoding='utf-8')
    hashes={name:hashlib.sha256((OUT/name).read_bytes()).hexdigest() for name in ['holdout_inputs.jsonl.gz','holdout_ground_truth.jsonl']}
    protocol=dict(version=1,frozen_at=now.isoformat(),positive_label='affected',formula='TP / (TP + FP)',target_precision=.90,seed=882901,total=len(rows),asset_types=18,families=MANIFEST,excluded_cases=0,labels_independent_of_assessment_outputs=True,training_cases=0,parameter_tuning_on_holdout=False,repeat_cases_are_template_replications_not_independent_real_world_observations=True,semantic_false_attestation_cases=18,limitations=['Synthetic source/evidence assumptions do not validate real CVE prerequisite extraction, product matching, or operator truthfulness.','The scenario mix is predeclared and is not an estimate of field prevalence.','Repeated templates across 18 types are not independent evidence of semantic accuracy.','Qualified expert review of the questionnaire and real assets remains outstanding.'],sha256=hashes)
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf-8')
    print(dump(dict(frozen_cases=len(rows),hashes=hashes)))
if __name__=='__main__':main()
