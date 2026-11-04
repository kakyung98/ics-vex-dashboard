"""New-contract controlled-curriculum checks; never independent CVE accuracy."""
from src.item4_questions import validate
from src.operational_questions import _validate_questions
from src.operational_role_tasks import check_assessment


def check(role, packet, pred):
    if role == 'item4-questions':
        valid, rows, errors, normalizations = validate({'prediction': pred}, packet['sources'], packet, _validate_questions)
        return {'contract_valid': valid, 'strict_no_normalization': valid and not normalizations,
                'common_specific_present': valid and {q['scope'] for q in rows} == {'common', 'specific'},
                'source_route_eligible': packet['analysis_route']['requirement'] == 'operational_review'}
    result = check_assessment(packet, pred)
    usable = any(q['answer']['value'] != 'unknown' and q['answer']['evidence'].strip()
                 for q in packet['questions_and_answers'])
    if isinstance(pred, dict):
        result['unknown_version_safety'] = packet.get('version_decided') is True or pred.get('assessment') == 'likely_cannot_determine'
        result['concise_explanation'] = isinstance(pred.get('explanation'), str) and 0 < len(pred['explanation']) <= 700
        result['unknown_answer_safety'] = usable or pred.get('assessment') == 'likely_cannot_determine'
    else:
        result.update(unknown_version_safety=False, concise_explanation=False, unknown_answer_safety=False)
    return result


def evaluate(role, rows, texts):
    from src.grounded_role_tasks import parse
    if len(rows) != len(texts):raise ValueError('Prediction count mismatch')
    records = []
    for row, text in zip(rows, texts):
        pred = parse(text);checks = check(role, row['packet'], pred)
        records.append({'id': row['id'], 'checks': checks, 'prediction': pred, 'raw': text,
                        'reference': row['target'], 'reference_exact_agreement': pred == row['target'],
                        'advisory_label_agreement': isinstance(pred, dict) and pred.get('assessment') == row['target'].get('assessment')
                        if role == 'operation-assessment' else None})
    metrics = {key: sum(bool(r['checks'][key]) for r in records)/len(records) for key in records[0]['checks']} if records else {}
    metrics.update(examples=len(records), reference_exact_agreement=sum(r['reference_exact_agreement'] for r in records)/len(records) if records else None,
                   expert_semantic_accuracy_evaluated=False, interpretation='New-contract controlled synthetic curriculum only; not independently labelled CVE accuracy.')
    if role == 'operation-assessment':metrics['advisory_label_agreement'] = sum(r['advisory_label_agreement'] for r in records)/len(records) if records else None
    return metrics, records
