"""Prediction-blind synthetic baseline for the unified #4 package.

This exercises source-bound version comparison and operational_assessment,
not the deployed extraction model or end-to-end Agent 3/4 pipeline.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from collections import Counter, defaultdict
from copy import deepcopy
import json
from pathlib import Path

from src.item4.decision.evidence_based_vex import registry; from src.item4.decision.evidence_based_vex import version_state
from src.item4.decision.operating_scenario_assessment import assess; from src.item4.decision.operating_scenario_assessment import valid_evidence; from src.item4.decision.operating_scenario_assessment import affected_precision
from tools.item4.consolidate_item4_evaluation import AT, sha, write, evidence

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'benchmark/item4_evaluation'
OUT = ROOT / 'results/item4_unified_evaluation_20261120'


def predict(inputs, rules):
    if inputs is None:
        return dict(status='under_investigation', binding=None, reason='No exact asset operational information')
    from src.item4.decision.evidence_review_gate import instant
    binding = inputs['binding']
    rule = rules[binding['cve']]
    packet = dict(binding=binding, synthetic=True, action_statement=inputs['action_statement'],
                  applicability=deepcopy(inputs['inventory']), observations=[], scenarios=[])
    packet['applicability']['value'] = 'true'
    at = instant(inputs['evaluated_at'])
    if not valid_evidence(inputs['inventory'], binding, at):
        return dict(status='under_investigation', binding=binding, reason='Unknown installed version')
    state = version_state(rule, binding['build'])
    if state == 'unknown':
        return dict(status='under_investigation', binding=binding, reason='Unresolved supplier release')
    if state == 'unaffected':
        return dict(status='not_affected', binding=binding, reason='Supplier unaffected release branch')
    if state == 'fixed':
        packet['fix_evidence'] = evidence(binding, 'SYNTHETIC installed release matches supplier fix',
                                         running_fixed_build_verified=True)
    else:
        conditions = []
        for question in rule['questions']:
            qid = question['id']
            conditions.append(dict(id=qid, operator_observable=True))
            for observation in inputs['observations']:
                if observation['question_id'] != qid:
                    continue
                value = observation['selected_value']
                mapped = ('true' if value in question['true_values'] else
                          'false' if value in question['false_values'] else 'unknown')
                packet['observations'].append(dict(observation, condition_id=qid, value=mapped))
        # Review flags apply to this explicit synthetic contract only.
        packet['scenarios'] = [dict(id='supplier-synthetic-path', product=binding['product'],
            expression=deepcopy(rule['expression']), conditions=conditions,
            semantic_reviewed=True, sufficiency_reviewed=True,
            source_evidence=evidence(binding, rule['source']['quote'],
                                     source_ref=deepcopy(rule['source'])))]
    return assess(packet, inputs['evaluated_at'])


def main():
    if (DATA / 'full_population_manifest.json').exists():
        raise SystemExit('The former 991-case baseline is historical. Use tools.item4.run_item4_full_actual for the frozen full-population evaluation.')
    summary = json.loads((DATA / 'summary.json').read_bytes())
    assert sha((DATA / 'gold.jsonl').read_bytes()) == summary['gold_jsonl_sha256']
    reg = registry()
    assert reg['sha256'] == summary['source_registry_sha256']
    OUT.mkdir(parents=True, exist_ok=True)
    predictions = []
    # Only IDs and inputs are retained for the prediction loop. Never pass gold,
    # source_rule copied into annotations, latent state, or variant to predict().
    inputs = []
    for p in sorted((DATA / 'annotations').glob('*.json')):
        row = json.loads(p.read_bytes())
        assert sha((DATA / row['sbom_file']).read_bytes()) == row['sbom_file_sha256']
        inputs.append((row['id'], row['inputs']))
    for case_id, packet in inputs:
        result = predict(packet, reg['rules'])
        predictions.append(dict(id=case_id, binding=result['binding'], status=result['status']))
    # Publish predictions before opening the gold ledger for scoring.
    with (OUT / 'predictions.jsonl').open('w', encoding='utf-8') as f:
        for row in predictions:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')
    gold = [json.loads(s) for s in (DATA / 'gold.jsonl').read_text(encoding='utf-8').splitlines()]
    assert len(gold) == len(predictions) == summary['case_count']
    labels = [dict(id=r['id'], synthetic=True,
                   binding=r['inputs']['binding'] if r['inputs'] else None,
                   actual_affected=r['gold']['actual_affected']) for r in gold]
    by_id = {r['id']: r for r in predictions}
    def score(rows):
        ids = {r['id'] for r in rows}
        return affected_precision([by_id[r['id']] for r in rows],
                                  [r for r in labels if r['id'] in ids])
    synthetic = [r for r in gold if r['inputs'] is not None]
    per_variant = defaultdict(list)
    per_cve = defaultdict(list)
    for row in synthetic:
        per_variant[row['gold']['variant']].append(row)
        per_cve[row['inputs']['binding']['cve']].append(row)
    baseline = score(synthetic)
    predicted_affected = baseline['TP'] + baseline['FP'] + baseline['unjudged_predicted_affected']
    interval = None
    if predicted_affected:
        from math import sqrt
        z = 1.95996398454
        p = baseline['TP'] / predicted_affected
        den = 1 + z*z/predicted_affected
        mid = (p + z*z/(2*predicted_affected))/den
        half = z*sqrt(p*(1-p)/predicted_affected + z*z/(4*predicted_affected**2))/den
        interval = [100*(mid-half), 100*(mid+half)]
    report = dict(evaluation_kind='source-bound-operational-assessment-synthetic-baseline',
        population_cases=len(gold), retained_advisory_sboms=3881,
        declared_unique_cves=summary['declared_unique_cves'],
        synthetic_scenario_unique_cves=len(per_cve), synthetic_baseline=baseline,
        synthetic_precision_percent=None if baseline['precision'] is None else 100*baseline['precision'],
        nominal_wilson_95_percent=interval,
        uncertainty_limit='Scenarios share CVEs and configurations; nominal interval is not independent field-sample confidence.',
        per_cve={k: score(v) for k,v in sorted(per_cve.items())},
        per_variant={k: score(v) for k,v in sorted(per_variant.items())},
        all_case_status_counts=dict(Counter(r['status'] for r in predictions)),
        unknown_context_original_cases=3881, original_cases_excluded=0,
        full_population_precision_percent=None, full_population_target_met=None,
        deployed_model_precision_percent=None, llm_used=False,
        independent_real_asset_validation=False,
        prediction_gold_separated=True,
        gold_jsonl_sha256=summary['gold_jsonl_sha256'], source_registry_sha256=reg['sha256'])
    write(OUT / 'report.json', report)
    summary['evaluation'] = dict(report_file=(OUT / 'report.json').relative_to(ROOT).as_posix(),
        synthetic_baseline_precision_percent=report['synthetic_precision_percent'],
        synthetic_baseline_target_met=baseline['target_met'],
        synthetic_TP=baseline['TP'], synthetic_FP=baseline['FP'],
        synthetic_recall=baseline['recall'], synthetic_abstention_fraction=baseline['abstention_fraction'],
        scope='7 source-backed CVEs, synthetic operating scenarios; not deployed-model or whole-population accuracy')
    write(DATA / 'summary.json', summary)
    readme = DATA / 'README.txt'
    marker = '\n5. 합성 기준선 실행 결과\n'
    body = readme.read_text(encoding='utf-8').split(marker)[0]
    percent = report['synthetic_precision_percent']
    readme.write_text(body + marker +
        f"합성 사례 {len(synthetic):,}건, 실제 CVE {len(per_cve)}개 범위. "
        f"TP={baseline['TP']}, FP={baseline['FP']}, 정밀도={percent:.2f}%.\n"
        f"85% 초과 기준선 통과={baseline['target_met']}. "
        f"재현율={baseline['recall']*100:.2f}%, 보류율={baseline['abstention_fraction']*100:.2f}%.\n"
        '잘못 입력된 운영 기록으로 발생한 FP도 포함했습니다. CVE별로는 미통과 대상이 있습니다.\n'
        '명목 95% Wilson 하한은 85%보다 낮습니다. 반복 시나리오는 독립 현장 표본이 아닙니다.\n'
        '전체 12,418개 CVE의 정밀도와 배포 모델의 정밀도는 미측정입니다.\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
