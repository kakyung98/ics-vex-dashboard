"""Pure scoring rules: errors stay in denominators; abstention is explicit."""
from src.identification_tasks import valid_output


def score(task, rows, predictions):
    if len(rows) != len(predictions): raise ValueError('Prediction count mismatch')
    if any(not valid_output(task,row['gold']) for row in rows):
        raise ValueError('Invalid ground-truth schema')
    active = {'L2': 'resolved', 'L3': 'present', 'L4': 'validated'}[task]
    correct = decided = correct_decided = invalid = false_resolved = revision_loss = 0
    gold_decidable = sum(r['gold']['status'] == active for r in rows)
    decisions = []
    for row, pred in zip(rows, predictions):
        valid = valid_output(task, pred)
        exact = valid and pred == row['gold']
        is_decided = valid and pred['status'] == active
        invalid += not valid; correct += exact; decided += is_decided
        correct_decided += bool(exact and is_decided)
        false_resolved += bool(is_decided and row['gold']['status'] != active)
        if task == 'L3' and is_decided and row['gold']['normalized']:
            expected = row['gold']['normalized']
            actual = pred['normalized']
            revision_loss += actual != expected and len(actual) < len(expected) and expected.startswith(actual)
        decisions.append({'id': row['id'], 'gold': row['gold'], 'prediction': pred,
                          'schema_valid': valid, 'exact': bool(exact)})
    n = len(rows)
    return {'total': n, 'exact_accuracy': correct/n if n else None,
            'schema_valid_rate': (n-invalid)/n if n else None,
            'decision_precision': correct_decided/decided if decided else None,
            'decision_recall': correct_decided/gold_decidable if gold_decidable else None,
            'coverage': decided/n if n else None,
            'abstention_rate': (n-invalid-decided)/n if n else None,
            'invalid_outputs': invalid, 'false_resolved': false_resolved,
            'revision_prefix_truncations': revision_loss if task == 'L3' else None,
            'cases': decisions}


def score_cve_pairs(gold, predictions):
    """gold[(component,CVE)] = bool; unlabeled predictions are never guessed false."""
    predictions = set(predictions)
    tp = sum(gold.get(p) is True for p in predictions)
    fp = sum(gold.get(p) is False for p in predictions)
    unknown = sum(p not in gold for p in predictions)
    fn = sum(label is True and pair not in predictions for pair, label in gold.items())
    return {'TP': tp, 'FP': fp, 'FN': fn, 'unlabelled_predictions': unknown,
            'precision': tp/(tp+fp) if tp+fp else None,
            'recall_on_labelled_positives': tp/(tp+fn) if tp+fn else None,
            'labelled_prediction_share': (tp+fp)/len(predictions) if predictions else None}
