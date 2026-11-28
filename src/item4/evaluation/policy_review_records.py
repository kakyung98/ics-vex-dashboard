"""Publish a policy rereview and its comparison with a completed blinded review."""
from collections import Counter
from contextlib import closing
import json
import re

from src.item4.evaluation import agent_review_records as reviews
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs


def _valid_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}', value))


def _check_transitions(policy, agent_review, total):
    fields = {'previous_run_id', 'prior_not_affected_count', 'prior_not_affected_pairs',
              'prior_disagreement_count', 'prior_disagreement_pairs', 'prior_disagreements_now_agree',
              'absence_policy_violations'}
    if not isinstance(policy, dict) or set(policy) != fields or not _valid_id(policy['previous_run_id']):
        raise ValueError('Invalid policy rereview summary or previous run ID.')
    for name in ('prior_not_affected_count', 'prior_disagreement_count',
                 'prior_disagreements_now_agree', 'absence_policy_violations'):
        if type(policy[name]) is not int or not 0 <= policy[name] <= total:
            raise ValueError('Invalid policy rereview count: ' + name)
    if policy['absence_policy_violations']:
        raise ValueError('The rereview contains an absence-policy violation.')

    current = {a + ' / ' + b: n for a, values in agent_review['status_pairs'].items()
               for b, n in values.items()}
    combined = Counter()
    for group in ('prior_not_affected', 'prior_disagreement'):
        pairs = policy[group + '_pairs']
        if (not isinstance(pairs, dict) or not pairs.keys() <= current.keys()
                or any(type(n) is not int or n < 0 for n in pairs.values())
                or sum(pairs.values()) != policy[group + '_count']):
            raise ValueError('Invalid current A/B status pairs for ' + group)
        combined.update(pairs)
    if any(n > current[pair] for pair, n in combined.items()):
        raise ValueError('Transition counts exceed the current A/B status matrix.')
    now_agree = sum(policy['prior_disagreement_pairs'].get(f'{s} / {s}', 0) for s in ledger.CANDIDATE)
    if now_agree != policy['prior_disagreements_now_agree']:
        raise ValueError('The count of prior disagreements now in agreement differs.')


def publish_policy_review(run_id, *, total, code_hashes, data_hashes, agent_review, policy_rereview):
    """Seal the six artifacts, both AI ballots' aggregate counts and prior transitions together."""
    if not _valid_id(run_id) or run_id in ledger.ARCHIVES:
        raise ValueError('Invalid or reserved evaluation run ID.')
    reviews._validate_review(agent_review, total)
    _check_transitions(policy_rereview, agent_review, total)
    previous_id = policy_rereview['previous_run_id']
    if previous_id == run_id:
        raise ValueError('The previous run must have a distinct ID.')

    row = dict(run_id=run_id, schema_version=1, status='completed', generation_method=reviews.METHOD,
               unit='scenarios', total=total, completed=total, candidate_count=0, prediction_count=0,
               expert_reviewed_count=0, candidate_origin='review_only', error=None, archived=False,
               code_hashes=ledger._hashes(code_hashes), model_hashes={}, data_hashes=ledger._hashes(data_hashes),
               agent_review=agent_review, policy_rereview=policy_rereview)
    if not reviews.ARTIFACTS.keys() <= row['data_hashes'].keys():
        raise ValueError('Missing policy rereview artifact fingerprints.')
    for name in reviews.ARTIFACTS:
        if runs.file_sha(runs.OUTPUT / run_id / name) != row['data_hashes'][name]:
            raise ValueError('Policy rereview artifact differs from its fingerprint: ' + name)

    with closing(ledger._connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        record = db.execute('SELECT snapshot FROM runs WHERE run_id=?', (previous_id,)).fetchone()
        previous = json.loads(record[0]) if record else {}
        if (previous.get('generation_method') != reviews.METHOD or previous.get('status') != 'completed'
                or previous.get('completed') != total or previous.get('total') != total):
            raise ValueError('A completed previous agent review of the same population is required.')
        prior = previous['agent_review']
        if (prior['source_run_id'] != agent_review['source_run_id']
                or prior['status_pairs'].get('not_affected', {}).get('not_affected', 0)
                != policy_rereview['prior_not_affected_count']
                or prior['disagreements'] != policy_rereview['prior_disagreement_count']):
            raise ValueError('The transition summary differs from the previous agent review.')
        # Readers and exact retries of historical runs do not insert a new snapshot.
        db.execute("""
            CREATE TRIGGER IF NOT EXISTS require_policy_for_new_blind_reviews
            BEFORE INSERT ON runs
            WHEN json_extract(NEW.snapshot, '$.generation_method') = 'scenario_blind_agent_review'
             AND json_type(NEW.snapshot, '$.policy_rereview') IS NOT 'object'
            BEGIN
                SELECT RAISE(ABORT, 'New blind A/B reviews require the current v2 policy review publisher.');
            END
        """)
        record = db.execute('SELECT snapshot FROM runs WHERE run_id=?', (run_id,)).fetchone()
        if record:
            saved = json.loads(record[0])
            if any(saved.get(k) != value for k, value in row.items()):
                raise ValueError('This run ID has already been published with different content.')
            return saved
        stamp = ledger.now()
        row.update(created_at=stamp, updated_at=stamp)
        db.execute('INSERT INTO runs VALUES (?,?)', (run_id, json.dumps(row, ensure_ascii=False)))
    return row
