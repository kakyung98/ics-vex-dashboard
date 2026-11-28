"""Restore full NVD configurations and retain every CPE occurrence, without dictionary filtering."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import gc
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.common.runtime.training_progress_io import atomic_json; from src.common.runtime.training_progress_io import read_json
from tools.item3.preprocess_item3_ics_cert import canonical, sha, select_version, dictionary_identities


def cpe_parts(value):
    """Read source CPE 2.3 fields while preserving escapes verbatim."""
    if not isinstance(value, str) or not value.startswith('cpe:2.3:'): return []
    fields = []; field = []; escaped = False
    for char in value:
        if char == ':' and not escaped:
            fields.append(''.join(field)); field = []
        else: field.append(char)
        escaped = char == '\\' and not escaped
    fields.append(''.join(field))
    return fields if len(fields) == 13 else []


def occurrences(configurations):
    """Walk recursively; keep duplicates, false flags, malformed criteria and node paths."""
    def walk(value, path):
        if isinstance(value, dict):
            matches = value.get('cpeMatch', [])
            if not isinstance(matches, list):
                raise ValueError('Unexpected cpeMatch structure at ' + path)
            for i, match in enumerate(matches):
                yield path + f'/cpeMatch/{i}', match
            for key, child in value.items():
                if key != 'cpeMatch' and isinstance(child, (dict, list)):
                    yield from walk(child, path + '/' + key)
        elif isinstance(value, list):
            for i, child in enumerate(value):
                yield from walk(child, path + '/' + str(i))
    yield from walk(configurations, '/configurations')


def input_for_match(match, identities):
    raw = match.get('criteria') if isinstance(match, dict) else None
    parts = cpe_parts(raw)
    valid = bool(parts)
    part, vendor, product = parts[2:5] if valid else (None, None, None)
    row = {'vendor': vendor, 'product': product, 'version': parts[5] if valid else None,
           **{out: match.get(src) if isinstance(match, dict) else None for out, src in
              [('startIncl', 'versionStartIncluding'), ('startExcl', 'versionStartExcluding'),
               ('endIncl', 'versionEndIncluding'), ('endExcl', 'versionEndExcluding')]}}
    releases = identities.get((vendor, product), {}).get(part, set())
    version, basis = select_version(row, releases)
    component = {'bom-ref': 'component-1', 'name': product if valid else str(raw or '<missing-cpe-criteria>')}
    if part in {'a', 'o', 'h'}:
        component['type'] = {'a': 'application', 'o': 'operating-system', 'h': 'device'}[part]
    if vendor not in (None, '', '*', '-'):
        component['manufacturer'] = {'name': vendor}
    if version: component['version'] = version
    # The CPE answer, CVE ID, range and node logic are deliberately not supplied to the model.
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.7', 'version': 1, 'components': [component]}
    facts = {'expected_product': {'part': part, 'vendor': vendor, 'product': product},
             'version': version, 'version_basis': basis, 'criteria_valid': valid,
             'identity_scorable': valid and part in {'a', 'o', 'h'} and vendor not in ('*', '-') and product not in ('*', '-'),
             'condition_match': 'true' if version and match.get('vulnerable') is True else 'unknown',
             'vulnerable': match.get('vulnerable') if isinstance(match, dict) else None}
    return sbom, facts


def download_feed(year, folder):
    url = f'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz'
    path = folder / f'{year}.json.gz'
    record = read_json(folder / f'{year}.provenance.json')
    if record and path.is_file() and sha(path) == record.get('compressed_sha256'):
        return path, record
    headers = {'User-Agent': 'ICS-VEX-full-CPE-evaluation/1.0'}
    last_error = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url.removesuffix('.json.gz') + '.meta', headers=headers), timeout=60) as response:
                meta = dict(line.strip().split(':', 1) for line in response.read().decode().splitlines() if ':' in line)
            pending = path.with_suffix('.gz.download')
            offset = pending.stat().st_size if pending.exists() else 0
            total = int(meta['gzSize'])
            if offset > total:
                raise ValueError('Partial feed larger than current publication; choose a fresh source directory.')
            # Bounded transfers make stalled feed requests resumable.
            with pending.open('ab') as handle:
                while offset < total:
                    end = min(offset + 4*1024*1024, total) - 1
                    request = urllib.request.Request(url, headers={**headers, 'Range': f'bytes={offset}-{end}'})
                    with urllib.request.urlopen(request, timeout=60) as response:
                        if response.status == 200 and offset == 0:
                            data = response.read()
                            if len(data) != total: raise ValueError('Truncated full-feed response')
                        elif response.status == 206 and response.headers.get('Content-Range') == f'bytes {offset}-{end}/{total}':
                            data = response.read()
                            if len(data) != end-offset+1: raise ValueError('Truncated range response')
                        else:
                            raise ValueError('Feed server did not honor requested range')
                    handle.write(data); handle.flush(); offset += len(data)
            digest = hashlib.sha256(); size = 0
            with gzip.open(pending, 'rb') as handle:
                for chunk in iter(lambda: handle.read(1024*1024), b''):
                    digest.update(chunk); size += len(chunk)
            if digest.hexdigest().lower() != meta['sha256'].lower() or size != int(meta['size']):
                raise ValueError('NVD official uncompressed SHA/size mismatch; publication may have changed')
            pending.replace(path)
            record = {'year': year, 'url': url, 'downloaded_at_utc': datetime.now(timezone.utc).isoformat(),
                      'official_meta': meta, 'compressed_sha256': sha(path)}
            atomic_json(folder / f'{year}.provenance.json', record)
            print(f'Feed {year} verified ({total:,} compressed bytes)', flush=True)
            return path, record
        except Exception as exc:
            last_error = exc
            if attempt < 3: time.sleep(2*(attempt+1))
    raise RuntimeError(f'Feed {year} failed: {last_error}')


def build(output, feeds, workers=3):
    output, feeds = output.resolve(), feeds.resolve()
    if not output.is_relative_to(ROOT / 'data') or not feeds.is_relative_to(ROOT / 'data'):
        raise ValueError('Keep dataset and source downloads inside workspace data.')
    output.mkdir(parents=True, exist_ok=True); feeds.mkdir(parents=True, exist_ok=True)
    if (output / 'manifest.json').exists():
        raise FileExistsError('Completed dataset already exists; do not overwrite it.')
    population_source = ROOT / 'data/cisa_advisories.json'
    advisory = read_json(population_source)
    import re
    population = sorted({c for a in advisory.values() for c in a.get('cves', []) if re.fullmatch(r'CVE-\d{4}-\d{4,}', c)})
    years = sorted({max(2002, int(c.split('-')[1])) for c in population}, reverse=True)
    wanted = set(population)
    state = {'phase': 'downloading', 'population_cves': len(population), 'years_total': len(years), 'feeds_verified': 0}
    atomic_json(output / 'status.json', state)
    all_records = {}; provenance = []; selected_by_year = {}
    # Download concurrently, parse one feed at a time to bound memory usage.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(download_feed, year, feeds): year for year in years}
        for future in as_completed(futures):
            path, record = future.result(); provenance.append(record)
            year = futures[future]
            selected_path = output / f'selected-{year}.json'
            with gzip.open(path, 'rt', encoding='utf-8') as handle: feed = json.load(handle)
            selected = {item['cve']['id']: item['cve'] for item in feed.get('vulnerabilities', []) if item['cve']['id'] in wanted}
            atomic_json(selected_path, selected)
            selected_by_year[year] = selected_path
            all_records.update(selected)
            del feed, selected; gc.collect()
            state.update(feeds_verified=len(provenance), nvd_records_found=len(all_records), last_year=year)
            atomic_json(output / 'status.json', state)
            print(f'NVD raw {len(all_records)}/{len(population)} CVEs; {len(provenance)}/{len(years)} feeds', flush=True)
    missing = sorted(wanted - all_records.keys())
    if missing:
        atomic_json(output / 'missing_nvd_records.json', missing)
        # A successful empty API response is different from a failed download.
        # Keep such CVEs as unavailable records; never invent CPE rows for them.
        api_records = read_json(output / 'nvd_api_supplement.json')
        for cid in missing:
            if cid not in api_records:
                url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + cid
                last_error = None
                for attempt in range(4):
                    try:
                        request = urllib.request.Request(url, headers={'User-Agent': 'ICS-VEX-full-CPE-evaluation/1.0'})
                        with urllib.request.urlopen(request, timeout=60) as response: payload = json.load(response)
                        api_records[cid] = {'url': url, 'fetched_at_utc': datetime.now(timezone.utc).isoformat(), 'response': payload}
                        atomic_json(output / 'nvd_api_supplement.json', api_records)
                        print(f'NVD API {cid}: {payload.get("totalResults")} records', flush=True)
                        break
                    except Exception as exc:
                        last_error = exc
                        if attempt < 3: time.sleep(6.5*(attempt+1))
                else: raise RuntimeError(f'Unresolved acquisition failure for {cid}: {last_error}')
                time.sleep(6.5)
            items = api_records[cid]['response'].get('vulnerabilities', [])
            found = next((item['cve'] for item in items if item.get('cve', {}).get('id') == cid), None)
            if found:
                all_records[cid] = found
            elif api_records[cid]['response'].get('totalResults') == 0:
                all_records[cid] = {'id': cid, '_acquisition_status': 'nvd_record_not_found', 'configurations': []}
            else: raise RuntimeError('Unexpected API response for ' + cid)
    # Reconcile every source occurrence, not only vulnerable=true or dictionary-known products.
    wanted_products = set()
    for record in all_records.values():
        for _, match in occurrences(record.get('configurations', [])):
            parts = cpe_parts(match.get('criteria') if isinstance(match, dict) else None)
            if parts: wanted_products.add((parts[3], parts[4]))
    identities = dictionary_identities(ROOT / 'data/cpe_dictionary.jsonl', wanted_products)
    database = output / 'corpus.sqlite3'
    if database.exists():
        raise FileExistsError('Incomplete build database exists; inspect it before rebuilding.')
    db = sqlite3.connect(database)
    db.executescript('''CREATE TABLE cves(cve TEXT PRIMARY KEY,payload TEXT NOT NULL);
        CREATE TABLE cases(id TEXT PRIMARY KEY,condition_id TEXT UNIQUE,sbom TEXT NOT NULL,target TEXT NOT NULL);
        CREATE INDEX cases_by_sbom ON cases(sbom);''')
    counts = Counter(); covered = set(); unique_criteria = set(); distinct_conditions = set()
    with (output / 'cpe_occurrences.jsonl').open('w', encoding='utf-8') as rows, (output / 'coverage.jsonl').open('w', encoding='utf-8') as coverage:
        for cve in population:
            record = all_records[cve]
            db.execute('INSERT INTO cves VALUES (?,?)', (cve, canonical(record)))
            raw_count = 0
            for path, match in occurrences(record.get('configurations', [])):
                raw_count += 1
                case_id = 'ALLCPE-' + hashlib.sha256(canonical([cve, path]).encode()).hexdigest()[:24]
                sbom, facts = input_for_match(match, identities)
                target = {'id': case_id, 'target_cve': cve, 'source_path': path,
                          'raw_match': match, 'expected_full_cve_applicability': 'unknown', **facts}
                db.execute('INSERT INTO cases VALUES (?,?,?,?)', (case_id, case_id, canonical(sbom), canonical(target)))
                rows.write(canonical(target) + '\n')
                counts['raw_cpe_occurrences'] += 1
                counts['vulnerable_true' if facts['vulnerable'] is True else 'vulnerable_false' if facts['vulnerable'] is False else 'vulnerable_unspecified'] += 1
                counts['criteria_valid' if facts['criteria_valid'] else 'criteria_invalid'] += 1
                counts['identity_scorable' if facts['identity_scorable'] else 'identity_unscorable'] += 1
                counts['version_supplied' if facts['version'] else 'version_unknown'] += 1
                if not identities.get((facts['expected_product']['vendor'], facts['expected_product']['product'])):
                    counts['dictionary_identity_missing_included'] += 1
                unique_criteria.add(str(match.get('criteria') if isinstance(match, dict) else match))
                distinct_conditions.add(canonical([cve, match]))
            absent = record.get('_acquisition_status') == 'nvd_record_not_found'
            counts['cves_nvd_record_not_found' if absent else 'cves_with_cpe' if raw_count else 'cves_without_cpe'] += 1
            if raw_count: covered.add(cve)
            coverage.write(canonical({'cve': cve, 'cpe_occurrences': raw_count,
                                      'status': 'nvd_record_not_found' if absent else 'all_occurrences_scheduled' if raw_count else 'no_assigned_cpe'}) + '\n')
    db.commit()
    case_count = db.execute('SELECT COUNT(*) FROM cases').fetchone()[0]
    unique_inputs = db.execute('SELECT COUNT(DISTINCT sbom) FROM cases').fetchone()[0]
    assert case_count == counts['raw_cpe_occurrences']
    assert len(population) == counts['cves_with_cpe'] + counts['cves_without_cpe'] + counts['cves_nvd_record_not_found']
    db.close()
    artifacts = ['corpus.sqlite3', 'cpe_occurrences.jsonl', 'coverage.jsonl'] + [p.name for p in selected_by_year.values()]
    if (output / 'nvd_api_supplement.json').is_file(): artifacts.append('nvd_api_supplement.json')
    sources = ['data/cisa_advisories.json', 'data/cpe_dictionary.jsonl', 'data/cpe_index.json', 'data/nvd_cache.json', 'data/nvd_cpe_detail.json']
    manifest = {'schema': 'ics-vex-item3-all-assigned-cpe-occurrences/1', 'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'population_fixed_to_local_ics_cert_references': True, 'counts': {'unique_cves': len(population),
            'input_cases': case_count, 'unique_sbom_inputs': unique_inputs, 'cves_with_input_cases': len(covered),
            'unique_cpe_criteria_strings': len(unique_criteria), 'unique_cve_match_records': len(distinct_conditions), **dict(counts)},
        'all_cpe_occurrences_included': True, 'dictionary_based_exclusions': 0,
        'non_vulnerable_platform_cpes_included': True, 'full_configuration_trees_preserved': True,
        'full_cpe_criteria_preserved_in_targets': True, 'input_mode': 'identifier_blind_product_version_inventory',
        'sources': {name: {'sha256': sha(ROOT / name), 'bytes': (ROOT / name).stat().st_size} for name in sources},
        'feeds': sorted(provenance, key=lambda x: x['year']),
        'artifacts': {name: {'sha256': sha(output / name), 'bytes': (output / name).stat().st_size} for name in artifacts},
        'limitations': ['Fresh NVD feeds with a fixed ICS-CERT CVE population; differs in snapshot date from the earlier flattened baseline.',
            'Every assigned cpeMatch occurrence is covered, including duplicates and vulnerable=false context; wildcard criteria are not expanded into all matching dictionary releases.',
            'Original CPE answers are withheld from SBOM input. Unknown versions remain unknown; version witnesses are synthetic declarations.',
            'CPE-less CVEs and successfully queried CVEs absent from NVD are recorded separately, not fabricated CPE test cases.',
            'Preserving full configuration trees does not establish full platform applicability from a one-component SBOM.']}
    atomic_json(output / 'manifest.json', manifest)
    state.update(phase='complete', counts=manifest['counts']); atomic_json(output / 'status.json', state)
    print(json.dumps(manifest['counts'], ensure_ascii=False), flush=True)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'data/item3_all_assigned_cpes_v1')
    parser.add_argument('--feeds', type=Path, default=ROOT / 'data/nvd_all_cpe_source_feeds_v1')
    parser.add_argument('--workers', type=int, choices=range(1, 5), default=3)
    args = parser.parse_args()
    build(args.output, args.feeds, args.workers)
