"""Durable provenance and per-scenario counts for defensive evaluations."""
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import psutil

ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / 'results'
DB = RESULTS / 'item4_run_ledger' / 'runs.sqlite3'
REPLAY = 'item4_fixed_world_replay_20261121'
V3 = 'item4_extracted_ox_v3_20261120'
EARLY = 'item4_full_actual_20261120'
ARCHIVES = (REPLAY, V3, EARLY)
COUNTERS = ('completed', 'candidate_count', 'expert_reviewed_count')
GENERATION = {'completed', 'partial', 'failed'}
CANDIDATE = {'affected', 'not_affected', 'fixed', 'under_investigation'}
REASON_KEYS = {'hold_reasons', 'product_hold_reasons', 'generation_failure_reasons'}
COUNT_KEYS = {'generation_statuses', 'candidate_statuses'} | REASON_KEYS


class ProgressCounts:
    """Count each status once and each distinct applicable reason once per scenario."""

    def __init__(self):
        self.counts = {key: Counter() for key in sorted(COUNT_KEYS)}

    @staticmethod
    def _entries(row):
        generation = row['generation_status']
        if generation not in GENERATION:
            raise ValueError('Unrecognized generation status.')
        if generation == 'completed':
            status = row['candidate_status']
            if status not in CANDIDATE:
                raise ValueError('Unrecognized candidate status.')
            yield 'candidate_statuses', status
            if status == 'under_investigation':
                reasons = set(row.get('reasons') or ['reason_not_recorded'])
                for reason in reasons:
                    yield 'hold_reasons', reason
                if 'supplier_evidence_conflicting_or_unresolved' in reasons:
                    for reason in set(row.get('product_reasons', [])):
                        yield 'product_hold_reasons', reason
        else:
            errors = {e.get('reason_code') or e.get('error') or 'reason_not_recorded'
                      for e in row.get('experts', []) if e.get('execution') == 'error'}
            for code in errors or {'reason_not_recorded'}:
                yield 'generation_failure_reasons', code
        yield 'generation_statuses', generation

    def add(self, row):
        for key, code in self._entries(row):
            self.counts[key][code] += 1

    def remove(self, row):
        entries = list(self._entries(row))
        if any(self.counts[key][code] <= 0 for key, code in entries):
            raise ValueError('Cannot remove an uncounted scenario outcome.')
        for key, code in entries:
            self.counts[key][code] -= 1
            if not self.counts[key][code]:
                del self.counts[key][code]

    def snapshot(self):
        return {key: dict(values) for key, values in self.counts.items()}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def _connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=15)
    db.execute('CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, snapshot TEXT NOT NULL)')
    return db


def _hashes(mapping):
    if not isinstance(mapping, dict) or not mapping or not all(
        isinstance(k, str) and k and isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
        for k, v in mapping.items()
    ):
        raise ValueError('Supply named SHA-256 fingerprints for the exact evaluation inputs.')
    return dict(mapping)


def start_run(run_id, *, generation_method, total, code_hashes, model_hashes, data_hashes, resumable=False):
    if not isinstance(run_id, str) or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}', run_id) or run_id in ARCHIVES:
        raise ValueError('Invalid or reserved evaluation run ID.')
    if type(total) is not int or total < 1 or not isinstance(generation_method, str) or not generation_method.strip():
        raise ValueError('Supply the generation method and a positive scenario count.')
    stamp = now()
    owner = psutil.Process()
    row = dict(run_id=run_id, schema_version=1, status='running', generation_method=generation_method,
               total=total, completed=0, candidate_count=0, expert_reviewed_count=0, prediction_count=0,
               candidate_origin='generated_in_this_run', unit='scenarios', created_at=stamp, updated_at=stamp,
               code_hashes=_hashes(code_hashes), model_hashes=_hashes(model_hashes),
               data_hashes=_hashes(data_hashes), error=None, archived=False,
               owner_pid=owner.pid, owner_started_at=owner.create_time())
    if resumable:
        row.update(resumable=True, resume_count=0, progress=ProgressCounts().snapshot())
    with closing(_connect()) as db, db:
        try:
            db.execute('INSERT INTO runs VALUES (?,?)', (run_id, json.dumps(row)))
        except sqlite3.IntegrityError as exc:
            raise ValueError('Evaluation run ID already exists.') from exc
    return row


def _check_distributions(summary, completed, candidate_count):
    for key, allowed, expected in (
        ('generation_statuses', GENERATION, completed),
        ('candidate_statuses', CANDIDATE, candidate_count),
    ):
        counts = summary[key]
        if (not isinstance(counts, dict) or set(counts) - allowed
                or any(type(n) is not int or n < 0 for n in counts.values()) or sum(counts.values()) != expected):
            raise ValueError('Inconsistent result distribution: ' + key)
    if summary['generation_statuses'].get('completed', 0) != candidate_count:
        raise ValueError('Completed generation count must match the number of generated candidates.')
    if not REASON_KEYS.issubset(summary):
        return
    if any(not isinstance(summary[k], dict) for k in REASON_KEYS):
        raise ValueError('Reason counts must be mappings.')
    held = summary['candidate_statuses'].get('under_investigation', 0)
    errors = completed - candidate_count
    for key, limit, required in (('hold_reasons', held, True),
                                 ('generation_failure_reasons', errors, True),
                                 ('product_hold_reasons', summary['hold_reasons'].get('supplier_evidence_conflicting_or_unresolved', 0), False)):
        counts = summary[key]
        if (not isinstance(counts, dict) or any(not isinstance(code, str) or not code or
                type(n) is not int or not 0 < n <= limit for code, n in counts.items()) or
                (required and sum(counts.values()) < limit)):
            raise ValueError('Inconsistent reason counts: ' + key)


def _check_result(result, completed, candidate_count):
    if not isinstance(result, dict) or set(result) not in (
            {'candidates_sha256', 'generation_statuses', 'candidate_statuses'}, COUNT_KEYS | {'candidates_sha256'}):
        raise ValueError('Expected a candidate file SHA-256 and result distributions.')
    _hashes({'candidates.jsonl': result['candidates_sha256']})
    _check_distributions(result, completed, candidate_count)


def _check_inventory_review(review, total, result):
    def counts(values, allowed=None):
        if (not isinstance(values, dict) or (allowed is not None and set(values) - allowed) or
                any(not isinstance(k, str) or not k or type(n) is not int or not 0 <= n <= total
                    for k, n in values.items())):
            raise ValueError('Invalid inventory review counts.')
        return Counter(values)

    if not isinstance(review, dict) or set(review) != {
        'previous_candidate_statuses', 'transitions', 'prior_not_affected_review',
        'absence_evidence_review', 'additional_model_calls',
    } or type(review['additional_model_calls']) is not int or review['additional_model_calls'] != 0:
        raise ValueError('Invalid inventory review metadata.')
    previous = counts(review['previous_candidate_statuses'], CANDIDATE)
    transitions = review['transitions']
    if not isinstance(transitions, dict) or set(transitions) - CANDIDATE:
        raise ValueError('Invalid inventory review transitions.')
    after = Counter()
    for old in CANDIDATE:
        dest = counts(transitions.get(old, {}), CANDIDATE)
        if sum(dest.values()) != previous[old]:
            raise ValueError('Inventory review transitions differ from the previous candidate counts.')
        after.update(dest)
    if after != Counter(result['candidate_statuses']) or sum(after.values()) != total:
        raise ValueError('Inventory review transitions differ from the final candidate counts.')
    cohort = review['prior_not_affected_review']
    required = {'reviewed', 'retained', 'changed_to_under_investigation', 'coverage_values', 'source_runs'}
    if not isinstance(cohort, dict) or set(cohort) != required:
        raise ValueError('Invalid prior not-affected review cohort.')
    scores = counts({k: cohort[k] for k in ('reviewed', 'retained', 'changed_to_under_investigation')})
    prior = transitions.get('not_affected', {})
    if (scores['reviewed'] != previous['not_affected'] or scores['retained'] != prior.get('not_affected', 0) or
            scores['changed_to_under_investigation'] != prior.get('under_investigation', 0) or
            scores['reviewed'] != scores['retained'] + scores['changed_to_under_investigation'] or
            any(sum(counts(cohort[k]).values()) != scores['reviewed'] for k in ('coverage_values', 'source_runs'))):
        raise ValueError('Prior not-affected review counts do not reconcile.')
    keys = {'reviewed', 'explicit_complete', 'partial', 'missing', 'other',
            'already_under_investigation', 'prior_crosscheck_holds_replaced'}
    absence = counts(review['absence_evidence_review'], keys)
    if (set(absence) != keys or absence['reviewed'] != sum(absence[k] for k in ('explicit_complete', 'partial', 'missing', 'other'))
            or not absence['prior_crosscheck_holds_replaced'] <= absence['already_under_investigation'] <= absence['reviewed']):
        raise ValueError('Undeployed inventory review counts do not reconcile.')


def _current_owner(row):
    owner = psutil.Process()
    return row.get('owner_pid') == owner.pid and row.get('owner_started_at') == owner.create_time()


def _owner_alive(row):
    try:
        return psutil.Process(row['owner_pid']).create_time() == row['owner_started_at']
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        return True


def resume_run(run_id, *, generation_method, total, code_hashes, model_hashes, data_hashes):
    """Claim an unfinished checkpoint after confirming its inputs and previous owner."""
    expected = dict(generation_method=generation_method, total=total, code_hashes=_hashes(code_hashes),
                    model_hashes=_hashes(model_hashes), data_hashes=_hashes(data_hashes))
    with closing(_connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        record = db.execute('SELECT snapshot FROM runs WHERE run_id=?', (run_id,)).fetchone()
        if not record:
            raise KeyError(run_id)
        row = json.loads(record[0])
        if not row.get('resumable') or row['status'] == 'completed':
            raise ValueError('This run cannot be resumed.')
        if any(row[k] != v for k, v in expected.items()):
            raise ValueError('The resume request differs from the frozen run.')
        if not _current_owner(row) and _owner_alive(row):
            raise ValueError('Another process owns this run.')
        owner = psutil.Process()
        row.pop('result', None)
        row.update(status='running', error=None, owner_pid=owner.pid, owner_started_at=owner.create_time(),
                   resume_count=row['resume_count'] + 1, updated_at=now())
        db.execute('UPDATE runs SET snapshot=? WHERE run_id=?', (json.dumps(row), run_id))
    return row


def update_run(run_id, *, completed, candidate_count, expert_reviewed_count=0, status='running',
               error=None, result=None, progress=None, inventory_review=None):
    if status not in {'running', 'partial', 'failed', 'completed'}:
        raise ValueError('Invalid evaluation run status.')
    values = (completed, candidate_count, expert_reviewed_count)
    with closing(_connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        record = db.execute('SELECT snapshot FROM runs WHERE run_id=?', (run_id,)).fetchone()
        if not record:
            raise KeyError(run_id)
        row = json.loads(record[0])
        changes = dict(zip(COUNTERS, values), status=status, error=error)
        if progress is not None:
            if not isinstance(progress, dict) or set(progress) != COUNT_KEYS:
                raise ValueError('Incomplete progress distributions.')
            _check_distributions(progress, completed, candidate_count)
            changes['progress'] = progress
        if result is not None:
            if status == 'running':
                raise ValueError('The artifact fingerprint is recorded only when closing a run.')
            _check_result(result, completed, candidate_count)
            changes['result'] = result
            if REASON_KEYS.issubset(result):
                final_progress = {k: result[k] for k in COUNT_KEYS}
                if progress is not None and progress != final_progress:
                    raise ValueError('Final result and progress differ.')
                changes['progress'] = final_progress
        if inventory_review is not None:
            if row['generation_method'] != 'scenario_moe_explicit_inventory_review' or status != 'completed' or result is None:
                raise ValueError('Inventory review metadata requires the completed evidence review and its result.')
            _check_inventory_review(inventory_review, row['total'], result)
            changes['inventory_review'] = inventory_review
        if row['status'] != 'running':
            if all(row.get(k) == value for k, value in changes.items()):
                return row
            raise ValueError('The evaluation run is closed.')
        if (any(type(v) is not int or not row[k] <= v <= row['total'] for k,v in zip(COUNTERS, values))
                or candidate_count > completed or expert_reviewed_count > completed
                or (status == 'completed' and completed != row['total'])):
            raise ValueError('Inconsistent evaluation counts.')
        if error is not None and not isinstance(error, str):
            raise ValueError('A run error must be text.')
        if row.get('resumable'):
            if not _current_owner(row):
                raise ValueError('Another process owns this run.')
            if status == 'completed' and (candidate_count != row['total'] or
                                         result is None or not REASON_KEYS.issubset(result)):
                raise ValueError('A completed resumable run requires its full sealed candidate report.')
            if (completed != row['completed'] or candidate_count != row['candidate_count']) and 'progress' not in changes:
                raise ValueError('A resumable checkpoint must include its cumulative distributions.')
        row.update(changes, updated_at=now())
        db.execute('UPDATE runs SET snapshot=? WHERE run_id=?', (json.dumps(row), run_id))
    return row


def _archived(run_id):
    folder = RESULTS / run_id
    if run_id not in ARCHIVES or not folder.is_dir():
        raise KeyError(run_id)
    receipts = {}

    def read(name, base=folder):
        path = base / name
        raw = path.read_bytes()
        receipts[path.relative_to(RESULTS).as_posix()] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    row = dict(run_id=run_id, schema_version=1, archived=True, unit='scenarios', created_at=None,
               updated_at=None, error=None, code_hashes={}, model_hashes={}, data_hashes={},
               total=None, completed=None, candidate_count=None, expert_reviewed_count=None,
               prediction_count=None, candidate_origin='frozen_reference', receipt_hashes=receipts)
    try:
        if run_id == EARLY:
            status = read('remote_status.json')
            config = read('run_config.json')
            progress = read('task_progress.json')
            row.update(status=status['status'], generation_method='Archived full-model evaluation',
                       total=progress['new_scenarios'], candidate_count=sum(progress['labels'].values()),
                       error=status.get('error', '').strip().splitlines()[-1] if status.get('error') else None,
                       code_hashes={**config['code_sha256'], **config['evaluation_code_sha256']},
                       data_hashes={'frozen_manifest': config['frozen_manifest_sha256']})
        elif run_id == V3:
            status = read('status.json')
            audit = read('independent_audit.json')
            config = read('protocol.json')
            row.update(status='completed' if status['status'] == 'complete' else status['status'],
                       generation_method='Archived O/X production predictions',
                       total=audit['cases'], completed=status['completed_cases'],
                       prediction_count=sum(audit['prediction_status_counts'].values()),
                       candidate_count=sum(audit['candidate_counts'].values()),
                       code_hashes={**config['code_sha256'], 'runner': config['runner_sha256']},
                       data_hashes={k: config[k] for k in ('source_input_sha256', 'source_reference_sha256')})
            # This audit explicitly counted independent reviews against the same v3 cohort.
            audit_path = RESULTS / REPLAY / 'independent_verification.json'
            if audit_path.exists():
                crosscheck = read(audit_path.name, audit_path.parent)
                if crosscheck['population']['unique_scenarios'] == row['total']:
                    row['expert_reviewed_count'] = crosscheck['population']['independently_expert_validated_scenarios']
        else:
            report = read('report.json')
            audit = read('independent_verification.json')
            if receipts[f'{REPLAY}/report.json'] != audit['verified_report_sha256']:
                raise ValueError('Archived replay report checksum mismatch.')
            config = read('protocol.json', RESULTS / V3)
            row.update(status='completed' if audit['status'] == 'verified' else 'partial',
                       generation_method='Fixed-scenario replay of archived model outputs',
                       total=audit['population']['unique_scenarios'], completed=report['counts']['cases'],
                       candidate_count=report['counts']['cases'], prediction_count=report['counts']['cases'],
                       expert_reviewed_count=audit['population']['independently_expert_validated_scenarios'],
                       code_hashes=report['code_sha256'], data_hashes={'delivery_manifest': report['source_manifest_sha256']})
        model = config['model']
        row['model_hashes'] = {**model['base_files_sha256'], model['adapter']['role']: model['adapter']['sha256']}
    except (OSError, KeyError, TypeError, ValueError):
        row.update(status='unavailable', generation_method=row.get('generation_method', 'Archived evaluation'),
                   error='A required archived receipt is unavailable or inconsistent.')
    return row


def get_run(run_id):
    if run_id in ARCHIVES:
        return _archived(run_id)
    if DB.is_file():
        with closing(_connect()) as db:
            record = db.execute('SELECT snapshot FROM runs WHERE run_id=?', (run_id,)).fetchone()
        if record:
            return _check_owner(json.loads(record[0]))
    raise KeyError(run_id)


def _check_owner(row):
    if row['status'] != 'running' or 'owner_pid' not in row or _owner_alive(row):
        return row
    with closing(_connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        current = json.loads(db.execute('SELECT snapshot FROM runs WHERE run_id=?', (row['run_id'],)).fetchone()[0])
        if current != row:
            return current
        row.update(status='partial' if row['completed'] else 'failed', updated_at=now(),
                   error='The evaluation process ended before recording its final status.')
        db.execute('UPDATE runs SET snapshot=? WHERE run_id=?', (json.dumps(row), row['run_id']))
    return row


def list_runs():
    rows = []
    if DB.is_file():
        with closing(_connect()) as db:
            rows = [json.loads(r[0]) for r in db.execute('SELECT snapshot FROM runs ORDER BY rowid DESC')]
        rows = [_check_owner(row) for row in rows]
    rows.extend(_archived(name) for name in ARCHIVES if (RESULTS / name).is_dir())
    # Fingerprint maps are available on detail and report endpoints.
    return [{k:v for k,v in row.items() if not k.endswith('_hashes')} for row in rows]
