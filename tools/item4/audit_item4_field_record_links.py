"""Check the frozen #4 cohort for explicit references in the three 8100 stores.

Output contains aggregate counts. Source records, private identifiers, database
paths, and submitted field values stay in their original stores.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import zlib


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / 'results/item4_extracted_ox_v3_20261120/verification.json'
PREFIX = 'benchmark/item4_evaluation/extracted_ox_v3'
MANIFEST_SHA = 'd14e596d3adff0545a53c6fb55cab102dd93db233059e45399e77dc0bca615dd'
INPUT_SHA = '9d87efe752074b4eb94975b257ad666740c1d32bbd0b21e8c5a3690597596514'
ARCHIVE_SHA = '5015fc6685d533343f6aa86d0341dcf152bd40b3cc52bdac0eab8d5f77024cb3'
STORE_DEFS = {
    'job_objects': ('identification_jobs_active.sqlite3', 'objects'),
    'workflows': ('workflows.sqlite3', 'workflows'),
    'reviews': ('reviews.sqlite3', 'reviews'),
}
JOB_KINDS = {'item4_questionnaire', 'job', 'operational-context-v1'}
# Only the known questionnaire schema can qualify as an empty synthetic replay.
# New fields may contain newly attached operations evidence and require review.
QUESTIONNAIRE_FIELDS = frozenset('''
    agents answer_provenance answers assessment assessment_cases assessment_state asset_classification
    asset_input_contract asset_key_counts asset_questions asset_state bom_sha256 catalogue_sha256 components
    condition_state conditions context_answers context_questions cves_done cves_total declared_cves
    extraction_identity id input_bom methodology_required migration_note operating_questionnaire_enabled
    plan_sha256 policy product_vex_status questions representative revision status unresolved version
'''.split())
INDEX_KEYS = ('case_id', 'input_row_sha256', 'packet_sha256', 'bom_sha256')
TOKEN = re.compile(r'(?<![a-zA-Z0-9])(?:OX3-[0-9a-f]{28}|[0-9a-f]{64})(?![a-zA-Z0-9])', re.I)


def check(ok):
    if not ok:
        raise ValueError('Frozen source or stored record is inconsistent.')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def semantic_sha(obj):
    # Same BOM serialization as the #4 questionnaire producer.
    return sha(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode('utf-8'))


def sealed(path, expected):
    raw = path.read_bytes()
    check(sha(raw) == expected)
    return json.loads(raw)


def frozen_index(delivery):
    manifest = sealed(delivery / 'delivery_manifest.json', MANIFEST_SHA)
    input_key = PREFIX + '/inputs.jsonl'
    check(manifest[input_key] == INPUT_SHA)
    idx = {k: set() for k in INDEX_KEYS}
    pending = {}
    digest = hashlib.sha256()
    input_bytes = 0
    with (delivery / input_key).open('rb') as stream:
        for line in stream:
            digest.update(line)
            input_bytes += len(line)
            row = json.loads(line)
            case_id = row['id']
            check(case_id not in pending and row['synthetic'] is True and
                  set(row) == {'id', 'cve', 'context', 'answers', 'synthetic'} and
                  set(row['context']) == {'scope', 'deployment', 'runtime', 'mode', 'origin'})
            pending[case_id] = semantic_sha(row)
            idx['input_row_sha256'].add(sha(line.rstrip(b'\r\n')))
    check(digest.hexdigest() == INPUT_SHA and len(pending) == 97553)
    idx['case_id'].update(pending)
    pop_key = PREFIX + '/population_ledger.json'
    cves = sealed(delivery / pop_key, manifest[pop_key])['cves']
    check(len(set(cves)) == len(cves) == 12418)
    spool = Path(tempfile.gettempdir()) / 'ICS-VEX/moe-inputs' / (ARCHIVE_SHA + '.sqlite3')
    conn = sqlite3.connect(spool.as_uri() + '?mode=ro&immutable=1', uri=True) if spool.is_file() else None
    counts = Counter()
    try:
        for cve in cves:
            key = f'{PREFIX}/cves/{cve}.json'
            if conn is None:
                packet = sealed(delivery / key, manifest[key])
            else:
                item = conn.execute('SELECT packet FROM packets WHERE cve=?', (cve,)).fetchone()
                check(item is not None)
                raw = zlib.decompress(item[0])
                check(sha(raw) == manifest[key])
                packet = json.loads(raw)
            check(packet['cve'] == cve and packet['cases'])
            idx['packet_sha256'].add(manifest[key])
            for case in packet['cases']:
                check(case['cve'] == cve and pending.pop(case['id']) == semantic_sha(case))
            bom = packet['job']['input_bom']
            bom_sha = semantic_sha(bom)
            check(bom_sha == packet['job']['bom_sha256'])
            idx['bom_sha256'].add(bom_sha)
            meta = bom['metadata']
            asset = meta['component']
            props = {p['name']: p['value'] for p in bom['properties']}
            counts['bom_marked_synthetic'] += props.get('dataset:synthetic-inventory') == 'true'
            counts['deployment_marked_unverified'] += props.get('dataset:deployment-verified') == 'false'
            counts['hypothetical_asset_ref'] += asset.get('bom-ref') == 'hypothetical-asset'
            counts['bom_metadata_timestamp_present'] += bool(meta.get('timestamp'))
            counts['bom_or_asset_serial_present'] += bool(bom.get('serialNumber') or asset.get('serialNumber'))
    finally:
        if conn is not None:
            conn.close()
    check(not pending)
    return idx, dict(status='complete', delivery_manifest_sha256=MANIFEST_SHA, inputs_sha256=INPUT_SHA,
                     inputs_bytes=input_bytes, delivery_manifest_bytes=(delivery / 'delivery_manifest.json').stat().st_size,
                     population_ledger_sha256=manifest[pop_key], synthetic_scenarios=len(idx['case_id']),
                     cve_packets=len(cves), **counts)


def references(obj):
    """Visit structured references, token-delimited references in notes, and exact embedded BOMs."""
    if isinstance(obj, dict):
        if obj.get('bomFormat') == 'CycloneDX':
            yield semantic_sha(obj)
        for key, value in obj.items():
            yield from references(key)
            yield from references(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from references(value)
    elif isinstance(obj, str):
        for match in TOKEN.finditer(obj):
            token = match.group().lower()
            yield 'OX3-' + token[4:] if token.startswith('ox3-') else token


def empty_questionnaire_replay(kind, record, idx):
    bom = record.get('input_bom')
    return (kind == 'item4_questionnaire' and isinstance(bom, dict)
            and not (record.keys() - QUESTIONNAIRE_FIELDS)
            and semantic_sha(bom) in idx['bom_sha256']
            and not any(record.get(k) for k in ('answers', 'context_answers', 'answer_provenance', 'assessment')))


def examine_store(path, table, idx):
    def snapshot():
        stat = path.stat()
        return (stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def active_journal():
        return any(p.is_file() and p.stat().st_size for p in
                   (Path(str(path) + '-wal'), Path(str(path) + '-journal')))

    # Immutable read-only connections also leave shared-memory files untouched.
    # Decline a journaled or changing snapshot instead of silently reading old data.
    try:
        if not path.is_file():
            return dict(status='not_examined', reason='store_missing')
        initial = snapshot()
        if active_journal():
            return dict(status='not_examined', reason='uncheckpointed_or_active_journal')
        kinds, origins = Counter(), Counter()
        matched_by_type = Counter(dict.fromkeys(INDEX_KEYS, 0))
        matched = replays = 0
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            db.row_factory = sqlite3.Row
            # The table name is supplied by STORE_DEFS, never by stored data.
            check(table in {'objects', 'workflows', 'reviews'})
            for row in db.execute('SELECT * FROM ' + table):
                record = json.loads(row['payload'])
                check(isinstance(record, dict))
                kind = row['kind'] if table == 'objects' else table
                kinds[kind if kind in JOB_KINDS or table != 'objects' else 'other'] += 1
                if kind == 'operational-context-v1':
                    packet = record.get('packet')
                    if not packet:
                        origins['empty_packet'] += 1
                    elif isinstance(packet, dict) and packet.get('synthetic') is True:
                        origins['synthetic_packet'] += 1
                    else:
                        origins['other_packet'] += 1
                tokens = set(references(record))
                for col in row.keys():
                    if col != 'payload':
                        tokens.update(references(row[col]))
                hits = {key for key, target in idx.items() if not target.isdisjoint(tokens)}
                if hits:
                    matched += 1
                    matched_by_type.update(hits)
                    if hits == {'bom_sha256'} and empty_questionnaire_replay(kind, record, idx):
                        replays += 1
        if initial != snapshot() or active_journal():
            return dict(status='not_examined', reason='store_changed_during_read')
    except (OSError, sqlite3.Error, ValueError, KeyError, IndexError, TypeError):
        return dict(status='not_examined', reason='store_unreadable_or_schema_mismatch')
    return dict(status='complete', records_examined=sum(kinds.values()), by_kind=dict(kinds),
                operating_context_origins=dict(origins), matching_records_by_reference=dict(matched_by_type),
                exact_reference_records=matched, synthetic_bom_only_records=replays,
                manual_review_records=matched - replays)


def audit(*, delivery=None, runtime=None):
    """Audit the named 8100 stores. Unavailable evidence produces null conclusions."""
    result = dict(schema='item4/field-record-link-audit/1',
                  scope='Pinned synthetic cohort and three local 8100 persistent stores. Exact case, input, packet or BOM references.',
                  status='incomplete', frozen_source={'status': 'not_examined'}, stores={}, records_examined=None,
                  exact_reference_records=None, synthetic_bom_only_records=None, manual_review_records=None,
                  verified_field_record_links=None)
    try:
        folder = Path(delivery) if delivery is not None else Path(json.loads(BASELINE.read_bytes())['artifact_directory'])
        idx, result['frozen_source'] = frozen_index(folder)
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, zlib.error):
        result['frozen_source']['reason'] = 'frozen_inputs_unavailable_or_integrity_failure'
        result['stores'] = {k: dict(status='not_examined', reason='frozen_source_unavailable') for k in STORE_DEFS}
        return result

    if runtime is None and os.environ.get('LOCALAPPDATA'):
        runtime = Path(os.environ['LOCALAPPDATA']) / 'ICS-VEX/runtime'
    for alias, (name, table) in STORE_DEFS.items():
        result['stores'][alias] = (examine_store(Path(runtime) / name, table, idx) if runtime is not None
                                   else dict(status='not_examined', reason='runtime_location_unavailable'))
    stores = list(result['stores'].values())
    if all(s['status'] == 'complete' for s in stores):
        for key in ('records_examined', 'exact_reference_records', 'synthetic_bom_only_records', 'manual_review_records'):
            result[key] = sum(s[key] for s in stores)
        result['status'] = 'requires_manual_review' if result['manual_review_records'] else 'complete'
        if result['status'] == 'complete':
            result['verified_field_record_links'] = 0
    return result


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--delivery', type=Path)
    cli.add_argument('--runtime', type=Path)
    args = cli.parse_args()
    receipt = audit(delivery=args.delivery, runtime=args.runtime)
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    raise SystemExit(0 if receipt['status'] == 'complete' else 2)
