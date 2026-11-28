"""Recount saved Qwen outputs; no inference and no independent-gold claim.

The sole semantic match below is an explicit assistant source review, not an
automatic fuzzy matcher. Partial references cannot establish true negatives.
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.analysis import exploitation_prerequisites as V2
from src.item4.analysis import asset_operating_question_generation as V3
from src.item4.evaluation.assistant_reference_scoring import score
from src.item4.models.review_adapter_config import selected


def read(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    provenance = {}

    def pinned(path):
        path = Path(path)
        provenance[path.as_posix()] = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        return read(path)

    label_path = Path('benchmark/item4_evaluation/current_reference_v1/labels.jsonl')
    raw = (ROOT / label_path).read_bytes()
    provenance[label_path.as_posix()] = hashlib.sha256(raw).hexdigest()
    refs = [json.loads(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
    refs = [r for r in refs if not r['synthetic']]
    label_manifest = pinned('benchmark/item4_evaluation/current_reference_v1/manifest.json')
    if hashlib.sha256(raw).hexdigest() != label_manifest['labels_sha256']:
        raise ValueError('Reference label file no longer matches its manifest')
    by_cve = {r['cve']: r for r in refs}
    variants = {}
    adapter_rows = []
    for folder in ['item4_qwen_reference_20261126', 'item4_qwen_base_reference_20261126']:
        home = Path('results') / folder
        manifest = pinned(home / 'manifest.json')
        rows, errors = [], []
        positive_cases = []
        for case in manifest['cases']:
            row = pinned(home / (case['id'] + '.json'))
            ref = by_cve[case['id']]
            if V2.digest(case['record']) != ref['source_record_sha256']:
                raise ValueError('Evaluation/reference source mismatch: ' + case['id'])
            row['reference_id'] = ref['id']
            rows.append(row)
            if row.get('v2_status') == 'validated':
                try:
                    V2.validate(row['v2']['draft'], case['record'])
                except Exception as exc:
                    errors.append(dict(cve=case['id'], error=str(exc)))
            if ref['draft']['prerequisites']:
                positive_cases.append(dict(cve=case['id'],
                    reference_facts=[a['statement'] for a in ref['draft']['prerequisites']],
                    predicted_facts=[a['statement'] for a in row.get('v2', {}).get('draft', {}).get('prerequisites', [])],
                    status=row['v2_status']))
        agreement = score(rows, refs)
        if agreement['counts']['source_mismatches']:
            raise ValueError('Saved output/reference source mismatch')
        variants[folder] = dict(cases=len(rows),
            structurally_admitted=sum(r['v2_status'] == 'validated' for r in rows),
            current_policy_revalidation_errors=errors,
            nonempty_extractions=sum(bool(r.get('v2', {}).get('draft', {}).get('prerequisites')) for r in rows),
            recorded_policy=manifest['operator_policy'],
            prompts_match_current=manifest['prompts'] == dict(v2=V2.digest(V2.SYSTEM), v3=V3.digest(V3.SYSTEM)),
            strict_reference_agreement=agreement,
            reference_positive_cases=positive_cases)
        if folder == 'item4_qwen_reference_20261126':
            adapter_rows = rows
            adapter_identity = manifest['model_identities']['exploitation-prerequisites']['adapter']

    # Manual, transparent source review. Do not infer equivalence from lexical
    # overlap or silently relabel the strict scorer's FP as an exact TP.
    semantic_reviews = []
    recovered = question_delivered = 0
    for row in adapter_rows:
        ref = by_cve[row['id']]
        for expected in ref['draft']['prerequisites']:
            predictions = row.get('v2', {}).get('draft', {}).get('prerequisites', [])
            match = None
            reason = 'No prerequisite returned; required fact remains unresolved.'
            if row['id'] == 'CVE-2020-28393':
                matches = [a for a in predictions if a['statement'] == 'OSPF is enabled'
                           and a['predicate'] == 'feature_enabled' and a['target'] == 'OSPF'
                           and a['value'] == 'enabled' and a['expected'] is True]
                if len(matches) != 1 or expected['statement'] != 'OSPF is enabled':
                    raise ValueError('Saved OSPF output changed; renew manual semantic review')
                match = matches[0]
                reason = 'Same OSPF-enabled fact and target; exact scorer differs on quotation span.'
            elif predictions:
                raise ValueError('New nonempty output requires manual semantic review')
            recovered += match is not None
            delivered = bool(match and any(
                a.get('status') == 'generated' and a.get('llm_used') is True and
                a.get('prediction', {}).get('questions', {}).get(match['id'], {}).get('positive_fact') == match['statement']
                for a in row.get('v3', {}).values()))
            question_delivered += delivered
            semantic_reviews.append(dict(cve=row['id'], reference_id=expected['id'],
                fact=expected['statement'], recovered=match is not None,
                question_delivered=delivered, reason=reason))

    isolated = []
    home = Path('results/item4_qwen_v3_isolated_20261126')
    isolated_summary = pinned(home / 'report.json')
    for path in sorted((ROOT / home).glob('*.json')):
        if path.name == 'report.json':
            continue
        row = pinned(home / path.name)
        artifact, payload = row['artifact'], row['packet']
        valid = V3.accepted(artifact, payload)
        for key, atom in payload['atoms'].items():
            q = artifact['prediction']['questions'][key]
            isolated.append(dict(case=row['id'], kind=row['kind'], atom=key,
                accepted_current_contract=valid,
                fact_preserved=q['positive_fact'] == atom['positive_fact'],
                record_type_preserved=q['record_type'] == atom['observation']['record_type'],
                check_copied_verbatim=q['check'] == atom['observation']['check'],
                question_equals_template=q['question'] == 'For this asset, is the following true: ' + atom['positive_fact']))
    if len(isolated) != isolated_summary['questions']:
        raise ValueError('Isolated report/question count mismatch')
    installed = selected('exploitation-prerequisites')
    positives = len(semantic_reviews)
    report = dict(version='saved-llm-validity-quantitative-audit/1',
        created_at=datetime.now(timezone.utc).isoformat(), new_inference=False,
        review_method='assistant_source_review_not_independent_expert',
        current_policy=V2.OP.POLICY,
        installed_adapter_matches_recorded=installed['sha256'] == adapter_identity['sha256'],
        current_adapter_evaluation_passed=installed['evaluation_passed'],
        variants=variants,
        adapter_known_reference_condition_audit=dict(reference_conditions=positives,
            recovered=recovered, missed=positives-recovered,
            reference_condition_recovery_rate=recovered/positives,
            source_condition_to_question_rate=question_delivered/positives,
            semantic_precision=None, independent_semantic_f1=None,
            explanation='Known-positive recovery only. Partial assistant labels cannot establish all FP/TN or population accuracy.',
            rows=semantic_reviews),
        isolated_v3=dict(cases=isolated_summary['cases'], questions=len(isolated),
            accepted_questions=sum(r['accepted_current_contract'] for r in isolated),
            facts_preserved=sum(r['fact_preserved'] for r in isolated),
            checks_copied_verbatim=sum(r['check_copied_verbatim'] for r in isolated),
            questions_equal_fixed_template=sum(r['question_equals_template'] for r in isolated),
            operator_answerability_rate=None, asset_context_benefit=None,
            rows=isolated),
        independent_expert_labels=label_manifest['independent_expert_labels'],
        actual_exploitability_labels=label_manifest['actual_exploitability_labels'],
        limitations=[
            'Saved development outputs were revalidated, not newly generated under current policy.',
            'Original generation policy 7 differs from current policy 9; prompt hashes match.',
            'Small purposive sample with partial assistant references, not an independent blind test.',
            'No true-negative accuracy, population confidence interval or field exploitability claim.',
            'V3 contract preservation does not establish record sufficiency or an advantage over templates.'],
        input_sha256=provenance)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(output=str(output.resolve()), reference_conditions=positives,
        recovered=recovered, recovery_rate=recovered/positives,
        question_delivery_rate=question_delivered/positives,
        v3_questions=len(isolated), v3_preserved=report['isolated_v3']['facts_preserved'],
        v3_copied_checks=report['isolated_v3']['checks_copied_verbatim'],
        adapter_identity_matches=report['installed_adapter_matches_recorded']), ensure_ascii=False))


if __name__ == '__main__':
    main()
