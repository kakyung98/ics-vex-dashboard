"""Durable candidate production in frozen order. Each commit and retry covers scoped case IDs."""
from collections import Counter
from contextlib import closing
import hashlib
import json
import sqlite3
import zlib

from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs


def encoded(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.replace(path)


class ExpertCache:
    """Content-identical raw model responses, bound by the run's model and source-code pins."""
    def __init__(self, db):
        self.db = db

    def get(self, key, default=None):
        row = self.db.execute('SELECT value,response_sha FROM experts WHERE wire_sha=?', (key[1],)).fetchone()
        if row is None:
            return default
        if hashlib.sha256(row[0]).hexdigest() != row[1]:
            raise ValueError('Cached model response fingerprint mismatch.')
        return json.loads(row[0])

    def __getitem__(self, key):
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __contains__(self, key):
        return self.db.execute('SELECT 1 FROM experts WHERE wire_sha=?', (key[1],)).fetchone() is not None

    def __setitem__(self, key, value):
        raw = encoded(value)
        self.db.execute('INSERT OR IGNORE INTO experts VALUES (?,?,?)',
                        (key[1], raw, hashlib.sha256(raw).hexdigest()))


def _open(path, record):
    db = sqlite3.connect(path, timeout=30)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS metadata(run_id TEXT PRIMARY KEY, pins TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS candidates(ordinal INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
            cve TEXT NOT NULL, packet_sha TEXT NOT NULL, generation TEXT NOT NULL, row_sha TEXT NOT NULL,
            payload BLOB NOT NULL, attempts INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS prior_attempts(id TEXT, attempt INTEGER, row_sha TEXT, payload BLOB,
            PRIMARY KEY(id,attempt));
        CREATE TABLE IF NOT EXISTS experts(wire_sha TEXT PRIMARY KEY, value BLOB NOT NULL, response_sha TEXT NOT NULL);
    ''')
    pins = json.dumps({k:record[k] for k in ('run_id','generation_method','code_hashes','data_hashes',
                                             'model_hashes','total')}, sort_keys=True)
    with db:
        db.execute('INSERT OR IGNORE INTO metadata VALUES (?,?)', (record['run_id'], pins))
    if db.execute('SELECT run_id,pins FROM metadata').fetchall() != [(record['run_id'], pins)]:
        db.close()
        raise ValueError('The checkpoint belongs to different run or model/code/data fingerprints.')
    return db


def checked_bytes(payload, row_sha):
    raw = zlib.decompress(payload)
    if hashlib.sha256(raw).hexdigest() != row_sha:
        raise ValueError('Candidate checkpoint checksum mismatch.')
    return raw


def _restore(db, run_id, counts, experts):
    indexed = {}
    for seq, case, cve, packet, status, row_sha, blob in db.execute(
            'SELECT ordinal,id,cve,packet_sha,generation,row_sha,payload FROM candidates ORDER BY ordinal'):
        row = json.loads(checked_bytes(blob, row_sha))
        if (row['id'],row['cve'],row['packet_sha256'],row['generation_status'],row['run_id']) != (
                case,cve,packet,status,run_id):
            raise ValueError('Candidate checkpoint identity mismatch.')
        indexed[case] = (seq,cve,packet,status)
        counts.add(row)
        experts.update(e['execution'] for e in row['experts'])
    return indexed


def _items(plan, indexed, chunk_size):
    folder, manifest, cves, _ = plan
    seq = 0
    chunk = []
    for cve in cves:
        packet = runs.input_packet(folder, manifest, cve)
        pin = manifest[f'{runs.PREFIX}/cves/{cve}.json']
        product = None
        for case in packet['cases']:
            ordinal = seq
            seq += 1
            old = indexed.pop(case['id'], None)
            if old:
                if old[:3] != (ordinal,cve,pin):
                    raise ValueError('Stored candidate differs from the selected source case.')
                if old[3] == 'completed':
                    continue
            if product is None:
                product, rule = runs.scoped_inputs(packet)
            chunk.append((ordinal, pin, runs.scenario_input(case, product), product, rule))
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
    if indexed:
        raise ValueError('Checkpoints include cases outside the frozen selection.')
    if chunk:
        yield chunk


def _store(db, run_id, chunk, results):
    if len(results) != len(chunk):
        raise ValueError('Missing scenario batch results.')
    changes = []
    with db:
        for (seq, pin, scenario, product, rule), row in zip(chunk, results):
            if (row['id'] != scenario['id'] or row['cve'] != scenario['cve'] or
                    row['expert_validated'] is not False or row['synthetic'] is not scenario['synthetic'] or
                    row['generation_status'] not in {'completed','partial','failed'}):
                raise ValueError('The candidate result does not belong to this source scenario.')
            prior = db.execute('SELECT generation,row_sha,payload,attempts FROM candidates WHERE id=?',
                               (row['id'],)).fetchone()
            old = None
            attempts = 1
            if prior:
                status, sha, payload, attempt = prior
                if status == 'completed':
                    raise ValueError('A previously completed result cannot be replaced.')
                old = json.loads(checked_bytes(payload, sha))
                db.execute('INSERT INTO prior_attempts VALUES (?,?,?,?)', (row['id'], attempt, sha, payload))
                attempts = attempt + 1
            runs.bind_candidate(row, run_id, pin, product, rule)
            raw = encoded(row)
            db.execute('''INSERT INTO candidates VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                generation=excluded.generation,row_sha=excluded.row_sha,payload=excluded.payload,
                attempts=excluded.attempts''',
                (seq,row['id'],row['cve'],pin,row['generation_status'],hashlib.sha256(raw).hexdigest(),
                 zlib.compress(raw, 1),attempts))
            changes.append((old, row))
    return changes


def _export(db, directory):
    target = directory / 'candidates.jsonl'
    tmp = directory / 'candidates.jsonl.tmp'
    digest = hashlib.sha256()
    with tmp.open('wb') as stream:
        for payload, row_sha in db.execute('SELECT payload,row_sha FROM candidates ORDER BY ordinal'):
            line = checked_bytes(payload, row_sha) + b'\n'
            stream.write(line)
            digest.update(line)
    tmp.replace(target)
    return digest.hexdigest()


def execute(record, plan, *, chunk_size=128, batch_size=8, resume=False, provider=None, generator=None):
    if chunk_size < 1 or batch_size < 1:
        raise ValueError('Batch and checkpoint sizes must be positive.')
    if generator is None:
        from src.item4.decision.inventory_evidence_policy import generate_candidates as generator
    run_id = record['run_id']
    directory = runs.OUTPUT / run_id
    folder, manifest, selected, cohort = plan
    counts = ledger.ProgressCounts()
    experts = Counter()
    error = None
    directory.mkdir(parents=True, exist_ok=resume)
    with closing(_open(directory / 'records.sqlite3', record)) as db:
        state = dict(run_id=run_id, selected_cves=selected, cohort=cohort, batch_size=batch_size,
                     chunk_size=chunk_size, generation_method=record['generation_method'],
                     backend_identity=getattr(provider, 'identity', None))
        cfg = directory / 'setup.json'
        if not cfg.exists():
            atomic_json(cfg, state)
        else:
            prior = json.loads(cfg.read_bytes())
            if any(prior[k] != state[k] for k in ('run_id','selected_cves','cohort','generation_method','backend_identity')):
                raise ValueError('The selection differs from the resumable run.')
        indexed = _restore(db, run_id, counts, experts)
        cache = ExpertCache(db)
        try:
            for chunk in _items(plan, indexed, chunk_size):
                args = {} if provider is None else {'provider': provider}
                rows = generator([(scenario, product, rule) for _,_,scenario,product,rule in chunk],
                                 cache=cache, batch_size=batch_size, **args)
                for old, new in _store(db, run_id, chunk, rows):
                    if old:
                        counts.remove(old)
                        experts.subtract(e['execution'] for e in old['experts'])
                    counts.add(new)
                    experts.update(e['execution'] for e in new['experts'])
                progress = counts.snapshot()
                n = sum(progress['generation_statuses'].values())
                k = sum(progress['candidate_statuses'].values())
                ledger.update_run(run_id, completed=n, candidate_count=k, progress=progress)
                print(f'{run_id} processed={n}/{record["total"]} candidates={k}', flush=True)
            ids = [r[0] for r in db.execute('SELECT id FROM candidates ORDER BY id')]
            actual_sha = hashlib.sha256(json.dumps(ids, separators=(',', ':')).encode()).hexdigest()
            if len(ids) != record['total'] or actual_sha != record['data_hashes']['selected case IDs']:
                raise ValueError('The candidate file does not cover the complete frozen selection.')
        except Exception as exc:
            db.rollback()
            error = type(exc).__name__ + ': ' + str(exc)[:500]
        # SQLite is authoritative if a worker is interrupted between a batch commit and its ledger update.
        final_counts = ledger.ProgressCounts()
        experts = Counter()
        _restore(db, run_id, final_counts, experts)
        progress = final_counts.snapshot()
        attempted = sum(progress['generation_statuses'].values())
        accepted = sum(progress['candidate_statuses'].values())
        result = dict(**progress, candidates_sha256=_export(db, directory))
        complete = error is None and accepted == record['total']
        status = 'completed' if complete else 'partial' if attempted else 'failed'
        if not complete and error is None:
            error = 'Some experts did not produce valid output. Inspect generation_failure_reasons.'
        current = ledger.update_run(run_id, completed=attempted, candidate_count=accepted, status=status,
                                    error=error, result=result, progress=progress)
        report = dict(ledger=current, **result, cohort=cohort, selected_cves=selected, synthetic=True,
                      expert_validated=False, expert_executions=+experts, unique_scenario_count=attempted,
                      backend_identity=state['backend_identity'],
                      selected_cve_count=len(selected), represented_cve_count=db.execute(
                          'SELECT COUNT(DISTINCT cve) FROM candidates').fetchone()[0],
                      unique_model_wire_cache_entries=db.execute('SELECT COUNT(*) FROM experts').fetchone()[0])
        atomic_json(directory / 'report.json', report)
    return current
