"""Publish a follow-up AI decision against one disagreement in a sealed policy review."""
from contextlib import closing
from hashlib import sha256
import json
import re
from urllib.parse import urlsplit

from src.item4.evaluation import agent_review_records as reviews
from src.item4.evaluation import policy_review_records as policy
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs


METHOD = 'scenario_evidence_adjudication'
ARTIFACTS = {
    'report.ko.html': 'text/html',
    'report.json': 'application/json',
    'decision.json': 'application/json',
    'field_audit.json': 'application/json',
    'supplier_evidence.json': 'application/json',
    'source_receipt.json': 'application/json',
}


def _check_summary(summary, run_id):
    fields = {'previous_run_id', 'review_id', 'cve', 'previous_statuses', 'status', 'reviewer_kind',
              'human_reviewed_scenarios', 'verified_field_records', 'running_release_verified',
              'portal_installation_verified', 'supplier_advisory'}
    if not isinstance(summary, dict) or set(summary) != fields:
        raise ValueError('Expected a single evidence adjudication summary.')
    if (not policy._valid_id(summary['previous_run_id']) or summary['previous_run_id'] == run_id
            or not policy._valid_id(summary['review_id']) or not isinstance(summary['cve'], str)
            or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', summary['cve'])):
        raise ValueError('A distinct previous run and a valid case ID and CVE are required.')
    pair = summary['previous_statuses']
    if (not isinstance(pair, dict) or set(pair) != {'reviewer_a', 'reviewer_b'}
            or not all(isinstance(s, str) and s in ledger.CANDIDATE for s in pair.values())
            or pair['reviewer_a'] == pair['reviewer_b'] or not isinstance(summary['status'], str)
            or summary['status'] not in ledger.CANDIDATE):
        raise ValueError('Expected the two disagreeing prior statuses and one VEX decision.')
    if (summary['reviewer_kind'] != 'ai_agent' or type(summary['human_reviewed_scenarios']) is not int
            or summary['human_reviewed_scenarios'] != 0 or type(summary['verified_field_records']) is not int
            or summary['verified_field_records'] < 0
            or any(type(summary[k]) is not bool for k in ('running_release_verified', 'portal_installation_verified'))):
        raise ValueError('Invalid reviewer identity, field record count or verification flags.')
    release, portal = summary['running_release_verified'], summary['portal_installation_verified']
    if not summary['verified_field_records'] and (release or portal or summary['status'] != 'under_investigation'):
        raise ValueError('Asset verification or a definitive decision requires a verified field record.')
    if summary['status'] in ('affected', 'fixed') and not (release and portal):
        raise ValueError('An affected or fixed decision needs verification of the running release and portal installation.')
    if summary['status'] == 'not_affected' and not (release or portal):
        raise ValueError('A not-affected decision needs verified evidence of release or installation scope.')
    url = summary['supplier_advisory']
    if not isinstance(url, str) or not url.startswith('https://') or not urlsplit(url).hostname:
        raise ValueError('A supplier advisory HTTPS URL is required.')


def _pinned_content(run_id, name, hashes):
    try:
        content = (runs.OUTPUT / run_id / name).read_bytes()
    except FileNotFoundError as exc:
        raise ValueError('Missing published artifact: ' + name) from exc
    if sha256(content).hexdigest() != hashes.get(name):
        raise ValueError('Artifact differs from its ledger fingerprint: ' + name)
    return content


def _check_predecessor(db, summary):
    previous_id = summary['previous_run_id']
    record = db.execute('SELECT snapshot FROM runs WHERE run_id=?', (previous_id,)).fetchone()
    previous = json.loads(record[0]) if record else {}
    if (previous.get('generation_method') != reviews.METHOD or previous.get('status') != 'completed'
            or not previous.get('policy_rereview') or previous['completed'] != previous['total']):
        raise ValueError('A completed previous policy rereview is required.')
    content = _pinned_content(previous_id, 'comparisons.jsonl', previous['data_hashes'])
    comparisons = (json.loads(line) for line in content.splitlines())
    matches = [item for item in comparisons if item['review_id'] == summary['review_id']]
    if len(matches) != 1:
        raise ValueError('The previous policy rereview must identify the case exactly once.')
    case = matches[0]
    if (case['agreement'] is not False or case['cve'] != summary['cve']
            or any(case[role]['status'] != status for role, status in summary['previous_statuses'].items())):
        raise ValueError('The case or its A/B disagreement differs from the previous policy rereview.')


def publish_adjudication(run_id, *, code_hashes, data_hashes, adjudication):
    """Publish once, with one reviewed case and zero generated candidates, predictions or human reviews."""
    if not policy._valid_id(run_id) or run_id in ledger.ARCHIVES:
        raise ValueError('Invalid or reserved evaluation run ID.')
    _check_summary(adjudication, run_id)
    row = dict(run_id=run_id, schema_version=1, status='completed', generation_method=METHOD,
               unit='scenarios', total=1, completed=1, candidate_count=0, prediction_count=0,
               expert_reviewed_count=0, candidate_origin='review_only', error=None, archived=False,
               code_hashes=ledger._hashes(code_hashes), model_hashes={},
               data_hashes=ledger._hashes(data_hashes), adjudication=adjudication)
    for name in ARTIFACTS:
        content = _pinned_content(run_id, name, row['data_hashes'])
        if name in ('report.json', 'decision.json'):
            document = json.loads(content)
            if not isinstance(document, dict) or document.get('adjudication') != adjudication:
                raise ValueError('The adjudication summary differs from ' + name)
            _check_summary(document['adjudication'], run_id)
    with closing(ledger._connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        _check_predecessor(db, adjudication)
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
