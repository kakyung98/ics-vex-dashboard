"""Build item-3 inputs from the entire pinned ICS-CERT CVE population.

This is preprocessing, not a run of the identifier or an independent VEX oracle.
Flattened NVD conditions retain their limited product/version scope explicitly.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import unicodedata

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / 'data/item3_ics_cert_full_v1'
FIELDS = ('vendor', 'product', 'version', 'startIncl', 'startExcl', 'endIncl', 'endExcl')
SOURCES = ('data/cisa_advisories.json', 'data/nvd_cache.json',
           'data/nvd_cpe_detail.json', 'data/cpe_index.json',
           'data/cpe_dictionary.jsonl', 'data/public_corpus_freshness.json')
CVE = re.compile(r'CVE-\d{4}-\d{4,}')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def text(value):
    return ' '.join(unicodedata.normalize('NFC', str(value or '')).split())


def numbers(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+(?:\.\d+)*', value):
        return None
    return tuple(map(int, value.split('.')))


def compare(left, right):
    a, b = numbers(left), numbers(right)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def condition_truth(version, row):
    """Independent, conservative oracle for ONE flattened version condition."""
    if not version or version in {'*', '-', 'NOASSERTION'}:
        return None
    exact = row.get('version')
    if exact not in (None, '', '*', '-'):
        if any(c in exact for c in '*?'):
            return None
        if version != exact:
            compared = compare(version, exact)
            if compared is None:
                return None
            if compared != 0:
                return False
    unknown = False
    for key, signs in [('startIncl', {0, 1}), ('startExcl', {1}),
                       ('endIncl', {-1, 0}), ('endExcl', {-1})]:
        if row.get(key) is not None:
            compared = compare(version, row[key])
            if compared is None:
                unknown = True
            elif compared not in signs:
                return False
    return None if unknown else True


def select_version(row, releases):
    proposals = [(row.get('version'), 'nvd_exact_version'),
                 (row.get('startIncl'), 'nvd_inclusive_lower_bound'),
                 (row.get('endIncl'), 'nvd_inclusive_upper_bound')]
    proposals += [(v, 'official_cpe_dictionary_release') for v in sorted(releases)]
    for version, basis in proposals:
        if version and condition_truth(version, row) is True:
            return version, basis
    return None, 'no_supported_affected_version_witness'


def dictionary_identities(path, wanted):
    found = defaultdict(lambda: defaultdict(set))
    with Path(path).open(encoding='utf-8') as handle:
        for line in handle:
            row = json.loads(line)
            key = (row.get('vendor'), row.get('product'))
            if key not in wanted or row.get('deprecated'):
                continue
            cpe_fields = row.get('cpe', '').split(':')
            part = row.get('part') or (cpe_fields[2] if len(cpe_fields) > 2 else None)
            if part in {'a', 'o', 'h'}:
                found[key][part].add(row.get('version') or '')
    return found


def make_input(case_id, row, identities):
    parts = identities.get((row['vendor'], row['product']), {})
    if len(parts) != 1:
        return None, {'reason': 'dictionary_identity_missing' if not parts else 'dictionary_part_ambiguous'}
    part = next(iter(parts))
    version, basis = select_version(row, parts[part])
    component = {'type': {'a': 'application', 'o': 'operating-system', 'h': 'device'}[part],
                 'bom-ref': 'component-1', 'name': row['product'],
                 'manufacturer': {'name': row['vendor']}}
    if version:
        component['version'] = version
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.7', 'version': 1,
            'components': [component]}
    # Target CVE, ranges and expected answers are deliberately absent from this object.
    return {'id': case_id, 'sbom': sbom}, {
        'part': part, 'version': version, 'version_basis': basis,
        'condition_match': 'true' if version else 'unknown'}


def build(root=ROOT, output=None):
    root = Path(root).resolve()
    output = Path(output or root / 'data/item3_ics_cert_full_v1').resolve()
    if not output.is_relative_to(root / 'data'):
        raise ValueError('Dataset output must stay inside this workspace data directory.')
    if output.exists():
        raise FileExistsError('Choose a new dataset version; do not overwrite a completed snapshot.')
    sources = {name: {'sha256': sha(root / name), 'bytes': (root / name).stat().st_size} for name in SOURCES}
    advisories, nvd, detail, index = [read(root / name) for name in SOURCES[:4]]
    freshness = read(root / SOURCES[-1])
    links = defaultdict(list)
    invalid = []
    for advisory_id, advisory in sorted(advisories.items()):
        occurrences = Counter(str(c).strip().upper() for c in advisory.get('cves', []))
        for cve, count in sorted(occurrences.items()):
            if not CVE.fullmatch(cve):
                invalid.append({'advisory_id': advisory_id, 'raw_reference': cve, 'occurrences': count})
                continue
            links[cve].append({'advisory_id': advisory_id, 'occurrences': count,
                              'url': advisory.get('url'), 'vendor': advisory.get('vendor'),
                              'title': advisory.get('title'), 'year': advisory.get('year'),
                              'csaf_sha256': advisory.get('csaf_sha256')})
    conditions = {}
    for cve in sorted(links):
        for position, original in enumerate(detail.get(cve, [])):
            row = {k: original.get(k) for k in FIELDS}
            key = canonical([cve, row])
            if key not in conditions:
                conditions[key] = {'id': 'COND-' + hashlib.sha256(key.encode()).hexdigest()[:24],
                                   'cve': cve, **row, 'source_positions': []}
            conditions[key]['source_positions'].append(position)
    # Cross-check both caches without using the production identifier to label cases.
    indexed = Counter(canonical([row['cve'], {k: row.get(k) for k in FIELDS}])
                      for values in index['by_product'].values() for row in values if row['cve'] in links)
    detailed = Counter({key: len(row['source_positions']) for key, row in conditions.items()})
    if indexed != detailed:
        raise ValueError('CPE detail and inverted index disagree. Reconcile the source snapshots first.')
    wanted = {(row['vendor'], row['product']) for row in conditions.values()}
    identities = dictionary_identities(root / 'data/cpe_dictionary.jsonl', wanted)
    output.mkdir(parents=True)
    (output / 'inputs').mkdir()
    (output / 'gold').mkdir()
    files = ['cves.jsonl', 'advisory_cve_links.jsonl', 'conditions.jsonl',
             'inputs/sboms.jsonl', 'gold/condition_targets.jsonl',
             'unresolved.jsonl', 'invalid_references.jsonl']
    counts = Counter()
    by_cve = defaultdict(Counter)
    with ExitStack() as stack:
        handles = {name: stack.enter_context((output / name).open('w', encoding='utf-8', newline='\n')) for name in files}
        conn = sqlite3.connect(output / 'corpus.sqlite3')
        stack.callback(conn.close)
        stack.enter_context(conn)
        conn.executescript('''PRAGMA foreign_keys=ON;
            CREATE TABLE cves(cve TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE advisory_links(advisory_id TEXT, cve TEXT REFERENCES cves(cve), payload TEXT NOT NULL, PRIMARY KEY(advisory_id,cve));
            CREATE TABLE conditions(id TEXT PRIMARY KEY,cve TEXT REFERENCES cves(cve),vendor TEXT,product TEXT,payload TEXT NOT NULL);
            CREATE TABLE cases(id TEXT PRIMARY KEY,condition_id TEXT UNIQUE REFERENCES conditions(id),sbom TEXT NOT NULL,target TEXT NOT NULL);
            CREATE INDEX conditions_by_cve ON conditions(cve);
            CREATE INDEX conditions_by_product ON conditions(vendor,product);
        ''')

        def emit(name, row):
            handles[name].write(canonical(row) + '\n')
            counts[name] += 1

        for cve in sorted(links):
            meta = nvd.get(cve) or {}
            missing = []
            if not meta or meta.get('error'):
                missing.append('nvd_metadata_missing')
            if not meta.get('description'):
                missing.append('nvd_description_missing')
            if not detail.get(cve):
                missing.append('flattened_cpe_conditions_missing')
            cwes = sorted({text(w) for w in meta.get('cwes', []) if re.fullmatch(r'CWE-\d+', text(w))})
            record = {'cve': cve, 'description': text(meta.get('description')),
                      'nvd_status': meta.get('vulnStatus'), 'published': meta.get('published'),
                      'last_modified': meta.get('lastModified'), 'cvss': meta.get('metric'),
                      'cwes': cwes, 'references': sorted(set(meta.get('references') or [])),
                      'advisory_ids': [a['advisory_id'] for a in links[cve]],
                      'raw_condition_count': len(detail.get(cve, [])),
                      'missing_evidence': missing, 'full_platform_applicability': 'unknown'}
            emit('cves.jsonl', record)
            conn.execute('INSERT INTO cves VALUES (?,?)', (cve, canonical(record)))
            for link in links[cve]:
                row = {'cve': cve, **link}
                emit('advisory_cve_links.jsonl', row)
                conn.execute('INSERT INTO advisory_links VALUES (?,?,?)', (link['advisory_id'], cve, canonical(row)))
            if missing:
                emit('unresolved.jsonl', {'cve': cve, 'reasons': missing})
                counts['cves_with_missing_evidence'] += 1
            if meta.get('vulnStatus') == 'Rejected':
                counts['rejected_cves_retained'] += 1

        for row in sorted(conditions.values(), key=lambda x: (x['cve'], x['id'])):
            row['raw_occurrences'] = len(row['source_positions'])
            row['scope'] = 'one_flattened_vulnerable_product_version_condition'
            row['full_platform_logic_preserved'] = False
            emit('conditions.jsonl', row)
            conn.execute('INSERT INTO conditions VALUES (?,?,?,?,?)',
                         (row['id'], row['cve'], row['vendor'], row['product'], canonical(row)))
            by_cve[row['cve']]['unique_conditions'] += 1
            case_id = 'IC3-' + row['id'][5:]
            case, facts = make_input(case_id, row, identities)
            if case is None:
                emit('unresolved.jsonl', {'cve': row['cve'], 'condition_id': row['id'], 'reasons': [facts['reason']]})
                counts[facts['reason']] += 1
                continue
            # Rejected CVEs remain inspectable; their records are not positive gold.
            state = facts['condition_match']
            if (nvd.get(row['cve']) or {}).get('vulnStatus') == 'Rejected':
                state = 'unknown'
                emit('unresolved.jsonl', {'cve': row['cve'], 'condition_id': row['id'],
                                         'reasons': ['nvd_cve_rejected']})
            elif not facts['version']:
                emit('unresolved.jsonl', {'cve': row['cve'], 'condition_id': row['id'],
                                         'reasons': [facts['version_basis']]})
            target = {'id': case_id, 'condition_id': row['id'], 'target_cve': row['cve'],
                      'expected_product': {'vendor': row['vendor'], 'product': row['product'], 'part': facts['part']},
                      'version': facts['version'], 'version_basis': facts['version_basis'],
                      'condition_match': state, 'expected_full_cve_applicability': 'unknown',
                      'gold_scope': 'source_condition_only_not_exhaustive_identifier_output_gold',
                      'synthetic_inventory': True, 'production_predictions_used': False}
            emit('inputs/sboms.jsonl', case)
            emit('gold/condition_targets.jsonl', target)
            conn.execute('INSERT INTO cases VALUES (?,?,?,?)',
                         (case_id, row['id'], canonical(case['sbom']), canonical(target)))
            by_cve[row['cve']]['input_cases'] += 1
            counts['condition_match_' + state] += 1
        for row in invalid:
            emit('invalid_references.jsonl', row)
    coverage = output / 'coverage.jsonl'
    with coverage.open('w', encoding='utf-8', newline='\n') as handle:
        for cve in sorted(links):
            handle.write(canonical({'cve': cve, 'advisory_count': len(links[cve]),
                                    'raw_condition_count': len(detail.get(cve, [])),
                                    'unique_condition_count': by_cve[cve]['unique_conditions'],
                                    'input_cases': by_cve[cve]['input_cases']}) + '\n')
    manifest = {'schema': 'ics-vex-item3-ics-cert-corpus/1',
                'created_at_utc': datetime.now(timezone.utc).isoformat(),
                'scope': 'All valid CVE identifiers referenced by the pinned local CISA ICS/ICSA advisory snapshot',
                'upstream_refreshed_by_this_command': False,
                'snapshot_commit': freshness.get('csaf_commit'),
                'snapshot_completed_at': freshness.get('completed_at'),
                'latest_advisory_modified': freshness.get('latest_advisory_modified'),
                'sources': sources,
                'counts': {'advisories': len(advisories), 'unique_cves': len(links),
                           'advisory_reference_occurrences': sum(x['occurrences'] for v in links.values() for x in v),
                           'raw_cpe_condition_rows': sum(detailed.values()),
                           'deduplicated_cpe_conditions': len(conditions),
                           'cves_with_conditions': len({row['cve'] for row in conditions.values()}),
                           'cves_with_input_cases': sum(bool(v['input_cases']) for v in by_cve.values()),
                           'input_cases': counts['inputs/sboms.jsonl'],
                           **dict(counts)},
                'independent_human_gold': False, 'production_identifier_used_for_labels': False,
                'limitations': ['Not 120,000 unique CVEs; condition rows and CVE identities are separate units.',
                                'Flattened caches omit CPE part/platform qualifiers and AND/OR/negation logic.',
                                'Dictionary part is used only when unambiguous; unresolved conditions remain recorded.',
                                'Input versions are declared test fixtures, not observed installed product releases.',
                                'Condition-level positives are not exhaustive end-to-end CVE ground truth.'],
                'artifacts': {name: {'sha256': sha(output / name), 'bytes': (output / name).stat().st_size}
                              for name in files + ['coverage.jsonl', 'corpus.sqlite3']}}
    (output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (output / 'README.md').write_text('''# ICS-CERT 전체 참조 CVE 전처리 데이터

`manifest.json`에 모집단·중복 제거·누락·원본 지문과 산출물 해시가 있습니다. 외부 원본을 새로 다운로드한 것이 아니라 보관된 ICS-CERT/NVD 스냅샷 전체를 다시 전처리했습니다.

- `cves.jsonl`: 고유 CVE별 설명·CVSS·CWE·권고문 연결·누락 정보.
- `advisory_cve_links.jsonl`: 권고문–CVE 출처와 원본 중복 횟수.
- `conditions.jsonl`: 중복 제거한 제품·버전 조건과 원본 행 위치.
- `inputs/sboms.jsonl`: 답안이 없는 #3 시험용 SBOM 입력. 한 줄이 한 사례입니다.
- `gold/condition_targets.jsonl`: 입력 ID별 제품·버전 조건 기대값. 전체 식별 결과의 완전한 정답은 아닙니다.
- `coverage.jsonl`, `unresolved.jsonl`: CVE별 입력 커버리지와 미확정 사유.
- `corpus.sqlite3`: 위 자료를 조회할 수 있는 로컬 데이터베이스.

입력에는 대상 CVE·정답·취약 버전 범위를 넣지 않았습니다. 정보가 없는 CVE도 모집단에서 제외하지 않습니다. 평탄화된 CPE 조건에는 전체 플랫폼 AND/OR 논리가 없으므로 실제 자산 적용성은 미확정입니다. 이 데이터로 독립 성능 수치나 실제 VEX 정답을 주장하지 마세요.

개별 업로드 입력 추출: `python tools/export_item3_sbom.py IC3-<ID> --output results/item3-input.json`.
검증: `python tools/verify_item3_ics_cert.py`.
''', encoding='utf-8')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build(output=args.output)
    print(json.dumps({'output': str(args.output), 'counts': result['counts']}, ensure_ascii=False), flush=True)
