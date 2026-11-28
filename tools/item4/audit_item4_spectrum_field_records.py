"""Read-only field-evidence audit for the single Spectrum Power review case.

Run from the project root with python -m tools.item4.audit_item4_spectrum_field_records.
Hashes for database rows cover the exact stored payload UTF-8 bytes. No intake
data, private row IDs, or source assets are exported or changed.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3

if __package__:
    from tools.item4 import audit_item4_field_record_links as shared
else:
    from tools.item4 import audit_item4_field_record_links as shared


CVE = 'CVE-2019-6579'
REVIEW = 'R-1B72A00A9560A9'
SCENARIO = 'OX3-a2e8e683c2d12be5154ce98bbdad'
PACKET = 'be1202c3319cbebac867349c274b4c4e0880b3859e8bd51f78ab05ca841cd60c'
BOM = '4a234be6f00e4a372c6064cf4a65fcdc0de6a8c632c2d4baf5def479457eb0de'
INPUT = 'bdaae40c9b919352f5d8c626faefd551139aeec76ead5e927ca6edd62382220b'
NEUTRAL = '5b839cb0ebeddc721e5309ba4542e5551c39b951cd647d58697c80a78ce2fa7f'
COMPONENT = 'component-3c0ca12b3278cb9619897aee'
RANKING_PAYLOAD = '40a306228d5e1b7db1222743e95978948627b721b8adbe431562be9f0ae08926'
INTAKE = Path('results/item4_independent_review_20261122/coordinator')
SERVICE = Path('local-service/sbom-vex/vex_operational_logic_20261117')
TEXT_FORMATS = {'.json', '.jsonl', '.txt', '.log', '.md', '.csv', '.tsv', '.xml', '.yaml', '.yml'}
PATTERNS = {
    'product': r'spectrum[\W_]*power|스펙트럼\s*파워|(?<![a-z0-9])sp4(?![a-z0-9])',
    'portal': r'web[\W_]*office[\W_]*portal|웹\s*오피스\s*포[털탈]|(?<![a-z0-9])wop(?![a-z0-9])',
    'bugfix': r'(?<![a-z0-9])bf[\W_]*47456(?:[\W_]*pe[\W_]*wop[\W_]*fix)?(?![a-z0-9])',
    'advisory': r'(?<![a-z0-9])(?:ssa[\W_]*324467|icsa[\W_]*19[\W_]*099[\W_]*02)(?![a-z0-9])',
    'cve': re.escape(CVE) + r'(?![0-9])',
    **{k: re.escape(v) for k, v in {
        'review': REVIEW, 'case': SCENARIO, 'input_sha256': INPUT, 'packet_sha256': PACKET,
        'bom_sha256': BOM, 'neutral_sha256': NEUTRAL, 'component_ref': COMPONENT,
    }.items()},
}
COMPILED = {k: re.compile(p, re.I) for k, p in PATTERNS.items()}
ATTACHMENT_KEY = re.compile(
    r'attachments?(?:_path|_url|_file)?|field_records?(?:_path|_url|_file)?|'
    r'source_record_(?:ref|path|file|url)|evidence_(?:file|path)|file_path|upload_path', re.I)
HINTS = {k: (p.lower(),) for k, p in {
    'review': REVIEW, 'case': SCENARIO, 'input_sha256': INPUT, 'packet_sha256': PACKET,
    'bom_sha256': BOM, 'neutral_sha256': NEUTRAL, 'component_ref': COMPONENT, 'cve': CVE}.items()}
HINTS.update(product=('spectrum', '스펙트럼', 'sp4'), portal=('office', '오피스', 'wop'),
             bugfix=('47456',), advisory=('324467', '099'))


def labels(s):
    lower = s.lower()
    return {k for k, words in HINTS.items()
            if any(w in lower for w in words) and COMPILED[k].search(s)}


def structured_links(obj):
    if isinstance(obj, dict):
        if obj.get('bomFormat') == 'CycloneDX' and shared.semantic_sha(obj) == BOM:
            yield 'embedded_exact_bom'
        for key, value in obj.items():
            if value and ATTACHMENT_KEY.fullmatch(key):
                yield 'attachment_reference'
            yield from structured_links(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from structured_links(value)


def file_sha(path):
    return shared.sha(path.read_bytes())


def utc_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace('+00:00', 'Z')


def case_inputs(root, delivery):
    key, request, card = (selected_row(root / INTAKE / (name + '.jsonl'))
                          for name in ('selection_key', 'field_record_requests', 'neutral_evidence'))
    case = key[0]
    shared.check(case['source_scenario_id'] == SCENARIO and case['packet_sha256'] == PACKET
                 and case['input_row_sha256'] == INPUT and case['neutral_case_sha256'] == card[1] == NEUTRAL)
    packet = shared.sealed(delivery / case['packet_path'], PACKET)
    bom = packet['job']['input_bom']
    scenario, = [r for r in packet['cases'] if r['id'] == SCENARIO]
    shared.check(shared.semantic_sha(bom) == BOM and scenario['cve'] == CVE and scenario['synthetic'] is True)
    meta = bom['metadata']
    props = {p['name']: p['value'] for p in bom['properties']}
    shared.check(props['dataset:synthetic-inventory'] == 'true' and props['dataset:deployment-verified'] == 'false')
    supplied = request[0]['supplied_record']
    shared.check(isinstance(supplied, dict) and len(supplied) >= 14)
    present = sorted(k for k, v in supplied.items() if v is not None and v != '')
    return dict(intake_path=INTAKE.as_posix(), selection_row_sha256=key[1], request_row_sha256=request[1],
                neutral_row_sha256=card[1], input_row_sha256=INPUT, packet_path=case['packet_path'],
                packet_sha256=PACKET, bom_sha256=BOM, synthetic_inventory=True, deployment_verified=False,
                scenario_synthetic=True, scenario_deployment=scenario['context']['deployment'],
                asset_reference=meta['component']['bom-ref'], asset_observation_timestamp=meta.get('timestamp'),
                intake_fields_total=len(supplied), intake_fields_populated=present,
                attached_evidence_kinds=[r['kind'] for r in card[0]['evidence']])


def selected_row(path):
    with path.open('rb') as stream:
        rows = [(r, shared.sha(line.rstrip(b'\r\n'))) for line in stream
                if (r := json.loads(line)).get('review_id') == REVIEW]
    row, = rows
    shared.check(row[0]['cve'] == CVE)
    return row


def fingerprint(path):
    stat = path.stat()
    return stat.st_ino, stat.st_size, stat.st_mtime_ns


def sidecars(path):
    return {suffix: fingerprint(p) for suffix in ('-wal', '-journal')
            if (p := Path(str(path) + suffix)).exists() and p.stat().st_size}


def inspect_store(path, *, archived=False):
    """Only known operational tables are queried, including every row/column."""
    try:
        before = fingerprint(path)
        companions = sidecars(path)
        if companions:
            # The archived source tree includes a cold 512-byte rollback-journal
            # header. It has no page frames. Require the zeroed magic and stable
            # metadata on both files; all other nonempty journals are deferred.
            if not (archived and set(companions) == {'-journal'} and companions['-journal'][1] == 512
                    and Path(str(path) + '-journal').read_bytes()[:8] == bytes(8)):
                return dict(status='incomplete', reason='uncheckpointed_or_active_journal')
        database_sha = file_sha(path)
        if archived and before[1] == 0 and fingerprint(path) == before and not companions:
            return dict(status='complete', snapshot_kind='empty_archived_file', database_sha256=database_sha,
                        database_mtime_utc=utc_timestamp(before[2]/1e9), table_counts={}, records_examined=0,
                        candidates=[])
        counts, candidates = Counter(), []
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            db.row_factory = sqlite3.Row
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            shared.check(tables and tables <= {'objects', 'reviews', 'workflows', 'sqlite_sequence'})
            for table in sorted(tables - {'sqlite_sequence'}):
                counts[table] = 0
                for row in db.execute('SELECT * FROM ' + table):
                    counts[table] += 1
                    raw = row['payload']
                    matches = set()
                    for col in row.keys():
                        if col != 'payload' and isinstance(row[col], str):
                            matches.update(labels(row[col]))
                    doc = json.loads(raw)
                    shared.check(isinstance(doc, dict))
                    matches.update(labels(json.dumps(doc, ensure_ascii=False)))
                    matches.update(structured_links(doc))
                    if not matches:
                        continue
                    digest = shared.sha(raw.encode() if isinstance(raw, str) else raw)
                    item = dict(payload_sha256=digest, matched=sorted(matches),
                                disposition='requires_record_review')
                    if (table == 'objects' and row['kind'] == 'job' and matches == {'product'}
                            and digest == RANKING_PAYLOAD):
                        # This exact payload was manually inspected. All six hits are
                        # under result/candidates for another generation of the product.
                        item.update(disposition='generated_identification_candidate_only',
                                    product_candidate='Siemens Spectrum Power 3 3.11',
                                    field_paths=['/result/components/1/' + stage + '/candidates/13/' + field
                                                 for stage in ('l2', 'l4') for field in ('product', 'cpe', 'titles/0')],
                                    job_created_utc=utc_timestamp(doc['created']), field_observation_utc=None)
                    candidates.append(item)
        shared.check(fingerprint(path) == before and sidecars(path) == companions)
        return dict(status='complete', database_sha256=database_sha, database_mtime_utc=utc_timestamp(before[2]/1e9),
                    snapshot_kind='cold_512_byte_rollback_header' if companions else 'checkpointed_snapshot',
                    table_counts=dict(counts), records_examined=sum(counts.values()), candidates=candidates)
    except (OSError, ValueError, TypeError, KeyError, IndexError, sqlite3.Error):
        return dict(status='incomplete', reason='store_missing_changed_or_unreadable')


def inspect_files(paths):
    """Read designated local intake and verification exports. Opaque files go to review."""
    results = []
    for alias, path in paths:
        try:
            before = fingerprint(path)
            raw = path.read_bytes()
            item = dict(path=alias, sha256=shared.sha(raw))
            if path.suffix.lower() not in TEXT_FORMATS:
                item.update(status='requires_record_review', reason='opaque_attachment')
            else:
                s = raw.decode('utf-8-sig')
                if path.suffix.lower() == '.json':
                    s = json.dumps(json.loads(s), ensure_ascii=False)
                terms = labels(s)
                item.update(matched=sorted(terms), status='requires_record_review' if terms else 'no_search_term')
            shared.check(fingerprint(path) == before)
        except (OSError, UnicodeError, ValueError):
            item = dict(path=alias, status='incomplete', reason='unreadable_or_changed')
        results.append(item)
    return results


def audit(*, root=shared.ROOT, runtime=None, support=Path('D:/ICS-VEX-support'), delivery=None):
    root, support = Path(root), Path(support)
    if runtime is None:
        appdata = os.environ.get('LOCALAPPDATA')
        if not appdata:
            raise ValueError('Specify the local 8100 runtime directory.')
        runtime = Path(appdata) / 'ICS-VEX/runtime'
    runtime = Path(runtime)
    out = dict(schema='item4/single-spectrum-field-audit/1', review_id=REVIEW, cve=CVE,
               source_scenario_id=SCENARIO, status='incomplete', active_store_count=0,
               records_examined=None, verified_field_records=None, running_release_verified=None,
               portal_installation_verified=None, bugfix_installation_verified=None,
               field_assessment='unknown', search_terms=PATTERNS, scope_groups={})
    try:
        if delivery is None:
            delivery = Path(json.loads((root / shared.BASELINE.relative_to(shared.ROOT)).read_bytes())['artifact_directory'])
        out['frozen_case'] = case_inputs(root, Path(delivery))
    except (OSError, KeyError, ValueError, TypeError):
        out['frozen_case'] = dict(status='incomplete', reason='case_identity_or_input_unverified')
    active = [(name, runtime / name) for name, _ in shared.STORE_DEFS.values()]
    store_groups = dict(active_8100=active,
                        prior_runtime_jobs=[('identification_jobs.sqlite3', runtime / 'identification_jobs.sqlite3')])
    snapshot_roots = {
        'service_and_test_copies': root / SERVICE,
        'local_backups': runtime.parent / 'backups',
        'support_task_backups': support / 'task-backups',
        'service_archive': support / 'archive/sbom-vex-source-20261118/vex_operational_logic_20261117',
    }
    for group, base in snapshot_roots.items():
        store_groups[group] = [(p.relative_to(base).as_posix(), p) for p in sorted(base.rglob('*.sqlite3'))
                               if p.name != 'runs.sqlite3']
    complete = True
    pending = bool(out['frozen_case'].get('intake_fields_populated'))
    for group, pairs in store_groups.items():
        stores = {alias: inspect_store(path, archived=group not in ('active_8100', 'prior_runtime_jobs'))
                  for alias, path in pairs}
        done = [r for r in stores.values() if r['status'] == 'complete']
        rows = [item for r in done for item in r['candidates']]
        base = snapshot_roots.get(group, runtime)
        out['scope_groups'][group] = dict(location_present=base.is_dir(), stores=stores,
                                          store_count=len(stores), stores_completed=len(done),
                                          row_instances_examined=sum(r['records_examined'] for r in done),
                                          candidate_row_instances=len(rows))
        complete &= len(done) == len(stores)
        pending |= any(r['disposition'] == 'requires_record_review' for r in rows)
    # Previously submitted files in named hand-off locations and known service exports.
    file_roots = {'archived_user_inputs': support / 'archive/user-inputs',
                  'workspace_service_verification': root / 'results/runtime_verification_20261119',
                  'archived_service_verification': support / 'task-backups/runtime_verification_20261119',
                  'service_example': root / 'results/item4_fixed_world_live_example_20261121'}
    for alias, base in [('runtime', runtime), ('workspace', root), ('review', (root / INTAKE).parent),
                        ('coordinator', root / INTAKE), ('data', root / 'data'), ('support', support)]:
        for name in ('attachments', 'uploads', 'field_records', 'field_evidence', 'incoming'):
            file_roots[alias + '/' + name] = base / name
    files = []
    roots_present = []
    # Allow loose service-side hand-offs while ignoring known credential,
    # service-control, and SQLite files already inventoried separately.
    for p in sorted(runtime.glob('*')):
        if (p.is_file() and p.suffix.lower() in TEXT_FORMATS
                and p.name not in ('support-migration.jsonl', 'gpu_lease.json')):
            files.append(('runtime_loose_text/' + shared.sha(p.name.encode()), p))
    for alias, base in file_roots.items():
        if base.is_dir():
            roots_present.append(alias)
            for p in sorted(base.rglob('*')):
                if p.is_file():
                    # Hash path fragments from attachment/intake locations to avoid disclosing asset names.
                    rel = p.relative_to(base).as_posix()
                    name = shared.sha(rel.encode()) if '/' in alias or alias == 'archived_user_inputs' else rel
                    files.append((alias + '/' + name, p))
    out['local_file_screen'] = dict(locations_checked=['runtime_loose_text', *file_roots],
                                    locations_present=(['runtime_loose_text'] if runtime.is_dir() else []) + roots_present,
                                    files=inspect_files(files))
    pending |= any(f['status'] == 'requires_record_review' for f in out['local_file_screen']['files'])
    complete &= not any(f['status'] == 'incomplete' for f in out['local_file_screen']['files'])
    complete &= 'packet_sha256' in out['frozen_case']
    active_group = out['scope_groups']['active_8100']
    out['active_store_count'] = active_group['stores_completed']
    if active_group['stores_completed'] == len(active):
        out['records_examined'] = active_group['row_instances_examined']
    if complete:
        out['status'] = 'requires_record_review' if pending else 'complete'
        if not pending:
            out['verified_field_records'] = 0
    out['scope_note'] = ('The active record count covers three configured 8100 stores. Legacy, test and backup '
                         'counts are row instances and may duplicate active rows. The file screen covers only the '
                         'listed local locations and terms. Unknown asset aliases, external records, unmounted '
                         'plant systems and deployment at other times are outside this result.')
    out['required_observation'] = ['Asset or component identity linked to this case and an observation time with zone',
                                   'Running Spectrum Power release/build from the same asset and observation period',
                                   'Web Office Portal installation state at that asset/time',
                                   'Applicable bugfix installation record at that asset/time',
                                   'Traceable field source, custody or recorder, and scope of inventory coverage']
    return out


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--runtime', type=Path)
    cli.add_argument('--support', type=Path, default=Path('D:/ICS-VEX-support'))
    cli.add_argument('--delivery', type=Path)
    result = audit(**vars(cli.parse_args()))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result['status'] == 'complete' else 2)
