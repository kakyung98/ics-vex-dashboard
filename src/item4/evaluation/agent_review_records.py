"""Publish completed, blinded AI reviews separately from generated candidates and human ratings."""
from contextlib import closing
import json
import re

from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs


METHOD = 'scenario_blind_agent_review'
ARTIFACTS = {
    'report.ko.html': 'text/html',
    'report.json': 'application/json',
    'comparisons.jsonl': 'application/x-ndjson',
    'reviewer_a.json': 'application/json',
    'reviewer_b.json': 'application/json',
    'ballot_receipts.json': 'application/json',
}
FIELD_TYPES = {
    'asset_scope', 'deployment_inventory', 'inventory_completeness', 'running_build',
    'configuration_state', 'change_history', 'supplier_scope',
}


def _validate_review(review, total):
    fields = {
        'packet_id', 'source_run_id', 'agent_reviewed_scenarios', 'agent_ratings', 'agreements',
        'disagreements', 'human_reviewed_scenarios', 'verified_field_records', 'field_record_type_counts',
        'status_pairs',
    }
    if not isinstance(review, dict) or set(review) != fields or type(total) is not int or total < 1:
        raise ValueError('Invalid blinded review summary.')
    if any(not isinstance(review[k], str) or not review[k].strip() for k in ('packet_id', 'source_run_id')):
        raise ValueError('The review must identify its packet and source run.')
    counts = fields - {'packet_id', 'source_run_id', 'status_pairs', 'field_record_type_counts'}
    if (any(type(review[k]) is not int or review[k] < 0 for k in counts)
            or review['agent_reviewed_scenarios'] != total or review['agent_ratings'] != 2 * total
            or review['human_reviewed_scenarios'] != 0 or review['agreements'] + review['disagreements'] != total):
        raise ValueError('Two AI ballots per scenario and a separate human review count are required.')

    def bounded_counts(values, allowed):
        return (isinstance(values, dict) and set(values) <= allowed
                and all(type(n) is int and 0 <= n <= total for n in values.values()))

    pairs = review['status_pairs']
    if (not isinstance(pairs, dict) or set(pairs) - ledger.CANDIDATE
            or not all(bounded_counts(dest, ledger.CANDIDATE) for dest in pairs.values())
            or sum(sum(dest.values()) for dest in pairs.values()) != total
            or sum(dest.get(status, 0) for status, dest in pairs.items()) != review['agreements']):
        raise ValueError('AI agreement counts differ from the paired status matrix.')
    needs = review['field_record_type_counts']
    if not bounded_counts(needs, FIELD_TYPES):
        raise ValueError('Invalid requested field evidence counts.')


def publish_agent_review(run_id, *, total, code_hashes, data_hashes, agent_review):
    """Seal the artifact fingerprints and the two-agent summary in one idempotent write."""
    if (not isinstance(run_id, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}', run_id)
            or run_id in ledger.ARCHIVES):
        raise ValueError('Invalid or reserved evaluation run ID.')
    _validate_review(agent_review, total)
    row = dict(run_id=run_id, schema_version=1, status='completed', generation_method=METHOD,
               unit='scenarios', total=total, completed=total, candidate_count=0, prediction_count=0,
               expert_reviewed_count=0, candidate_origin='review_only', error=None, archived=False,
               code_hashes=ledger._hashes(code_hashes), model_hashes={},
               data_hashes=ledger._hashes(data_hashes), agent_review=agent_review)
    if not ARTIFACTS.keys() <= row['data_hashes'].keys():
        raise ValueError('Missing agent review artifact fingerprints.')
    for name in ARTIFACTS:
        if runs.file_sha(runs.OUTPUT / run_id / name) != row['data_hashes'][name]:
            raise ValueError('Agent review artifact differs from its fingerprint: ' + name)
    with closing(ledger._connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        existing = db.execute('SELECT snapshot FROM runs WHERE run_id=?', (run_id,)).fetchone()
        if existing:
            saved = json.loads(existing[0])
            if any(saved.get(k) != v for k,v in row.items()):
                raise ValueError('This run ID has already been published with different content.')
            return saved
        stamp = ledger.now()
        row.update(created_at=stamp, updated_at=stamp)
        db.execute('INSERT INTO runs VALUES (?,?)', (run_id, json.dumps(row, ensure_ascii=False)))
    return row
