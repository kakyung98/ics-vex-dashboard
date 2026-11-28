"""Final measured Qwen, label-provenance and live-workflow report."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from datetime import datetime,timezone
import json
from shutil import copyfile
from src.item4.analysis import exploitation_prerequisites as V2
from src.item4.analysis import asset_operating_question_generation as V3


def read(name):return json.loads((ROOT/name).read_text(encoding='utf-8'))


def main():
    adapter=read('results/item4_qwen_reference_20261126/report.json')
    base=read('results/item4_qwen_base_reference_20261126/report.json')
    isolated=read('results/item4_qwen_v3_isolated_20261126/report.json')
    labels=read('benchmark/item4_evaluation/current_reference_v1/manifest.json')
    critical=read('results/item4_qwen_critical_guard9_20261126/report.json')
    live=read('results/item4_live_bom_20261126/report.json')
    critical_outputs={}
    for cve in ['CVE-2020-15782','CVE-2018-13806']:
        row=read('results/item4_qwen_critical_guard9_20261126/'+cve+'.json')
        draft=(row.get('v2') or {}).get('draft',{})
        critical_outputs[cve]=dict(status=row['v2_status'],error=row.get('error'),
            positive_facts=[p['statement'] for p in draft.get('prerequisites',[])],unknowns=draft.get('unknowns',[]))
    def variant(folder,summary):
        a=read(folder+'/reference-agreement.json')
        return dict(source=folder,recorded_validation_policy=read(folder+'/manifest.json')['operator_policy'],
            cases=summary['real_cases'],structural_admissions=summary['v2_valid'],
            failed=summary['real_cases']-summary['v2_valid'],generated_question_cases=summary['v3_generated_cases'],
            skipped_question_cases=summary['v3_no_special_cases'],
            recorded_inference_attempts=summary['llm_calls'],strict_reference_agreement=a,
            independent_semantic_accuracy=None,model=summary['measured_model'])
    report=dict(version='item4-llm-validity-review/2',created_at=datetime.now(timezone.utc).isoformat(),
        review_method='assistant_source_audit_and_assistant_reference_agreement_not_independent_human',
        prompts=dict(v2=V2.digest(V2.SYSTEM),v3=V3.digest(V3.SYSTEM)),operator_policy=V2.OP.POLICY,
        deployed_model_evaluated=True,provider_selection_changed=False,
        labels=labels,
        qwen_adapter=variant('results/item4_qwen_reference_20261126',adapter),
        qwen_base_ablation=variant('results/item4_qwen_base_reference_20261126',base),
        qwen_v3_isolated=isolated,critical_regressions=critical,critical_outputs=critical_outputs,live_bom=live,
        positive_fixture=read('results/item4_live_positive_fixture_20261126/report.json'),
        positive_fixture_cache=read('results/item4_live_positive_fixture_20261126/cache-verification.json'),
        interpretation=[
            'The deployed extraction adapter admitted 18/18 outputs but produced special questions in only 1 case. Seventeen skips are not successful V3 measurements.',
            'The base ablation admitted 10/18 outputs and produced special questions in 4 cases. More surfaced conditions does not establish a better or independently validated model.',
            'Strict atom agreement is zero for both variants. This includes differences in exact quotation spans and structured fields; it is not a semantic precision/recall estimate.',
            'The adapter recovered the OSPF-enabled fact but missed other explicit reference conditions. The base also surfaced Basic128Rsa15, factory-reset mode and WDB-agent state; the factory-reset predicate was incorrectly typed as interface_reachable and needs semantic review.',
            'The final object-scope guard rejects directory-write access being replaced by file writability or access by an unspecified actor. Remaining source-condition omissions are recorded in critical_outputs.',
            'The final default-state parser separates an explicit exploitation setting from a separate default-state comment. This was developed on audit examples; original runs are preserved without relabelling their results.',
            'A legacy training label (CVE-2023-0345) elevates a default SSH state into a required prerequisite. It was flagged for review; the original training data and weights were not changed.',
            'V3 isolated Qwen preserves ten supplied positive facts across seven cases. Record sufficiency, operator usability and benefit from asset context remain unestablished.',
            'No automatic provider fallback or adapter activation change was introduced based on this small development audit.',
            'The live BOM workflow uses unknown-only observations and verifies safe under-investigation exports, not actual exploitability.'],
        independent_expert_labels=0,actual_exploitability_labels=0,
        independent_semantic_accuracy=None,field_exploitability_accuracy=None,
        limitations=['82 assistant reference labels are not independent expert gold or whole-population labels.',
            'Eighteen real sources are disjoint from recorded adapter training, but audit examples were used during development. This is not an untouched blind test.',
            'Pretraining overlap, independent source completeness, same-actor relations and operator usability remain unverified.',
            'Qwen V2 prerequisite recall remains inadequate for autonomous confident exploitability claims. Preserve Unknown and inspect the evidence.'])
    report['web_summary']='Qwen V2 adapter: 18 / 18 structurally admitted, but special questions in only 1 / 18 cases. Base ablation: 10 / 18 admitted, questions in 4 cases. Isolated Qwen V3: 7 / 7 cases, 10 locked facts preserved. Extraction validity remains unestablished.'
    report['web_limit']='Assistant-reference development audit; independent expert labels: 0. Failed extractions and skipped generation remain explicit. Live BOM observations are Unknown only; exports do not establish actual exploitability.'
    folder=ROOT/'results/item4_llm_validity_20261126';folder.mkdir(exist_ok=True)
    path=folder/'report.json'
    archive=ROOT/'research_records/item4_pre_qwen_audit_20261126';archive.mkdir(exist_ok=True)
    if path.exists() and not (archive/'report.json').exists():copyfile(path,archive/'report.json')
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(report['web_summary']);print('Live BOM:',live['cves'],'CVEs;',live['vex_statements'],'under-investigation statements')


if __name__=='__main__':main()
