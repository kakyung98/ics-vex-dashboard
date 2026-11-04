"""Refresh public CISA ICS records and their NVD metadata, never training labels.

CISA is pinned to an immutable upstream commit. NVD yearly JSON 2.0 feeds
provide a complete refresh of corpus CVEs, including changes to old CVEs.
Downloads are retained for provenance and recovery. Existing HTML-only legacy
advisories are preserved when not represented in the official CSAF archive.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import gc
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
from src.training_io import atomic_json, read_json
from fetch_nvd import parse as nvd_parse
from build_cpe_index import detail

DATA = ROOT / 'data'
REPORT = ROOT / 'results/public_corpus_refresh.json'


def branches(nodes):
    for node in nodes:
        yield node
        yield from branches(node.get('branches', []))


def csaf_record(doc, source, commit):
    document = doc['document']
    aid = document['tracking']['id'].lower()
    if not re.fullmatch(r'icsa?-\d{2}-\d{3}-\d{2}[a-z]?', aid):
        return None
    nodes = list(branches(doc.get('product_tree', {}).get('branches', [])))
    vendors = list(dict.fromkeys(n['name'] for n in nodes if n.get('category') == 'vendor'))
    products = [n['name'] for n in nodes if n.get('category') == 'product_name']
    affected_ids = {pid for v in doc.get('vulnerabilities', []) for pid in (v.get('product_status') or {}).get('known_affected', [])}
    affected_products = [n['product']['name'] for n in nodes if n.get('product', {}).get('product_id') in affected_ids]
    vulns = []
    for v in doc.get('vulnerabilities', []):
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', v.get('cve', '')):
            continue
        metrics = {}
        for score in v.get('scores', []):
            for field, prefix in [('cvss_v3', 'cvss_v3'), ('cvss_v4', 'cvss_v4')]:
                m = score.get(field, {})
                if m.get('baseScore') is not None and m['baseScore'] >= metrics.get(prefix+'_score', -1):
                    metrics[prefix+'_score'] = m['baseScore']
                    metrics[prefix+'_vector'] = m.get('vectorString', '')
        vulns.append({'cve': v['cve'], 'cwe': (v.get('cwe') or {}).get('id', ''),
                      'description': '\n'.join(n.get('text', '') for n in v.get('notes', []) if n.get('category') in {'description', 'summary'}),
                      'product_status': v.get('product_status', {}), 'flags': v.get('flags', []), **metrics})
    notes = '\n'.join(n.get('text', '') for n in document.get('notes', []) if n.get('category') not in {'legal_disclaimer'})
    overview = '\n'.join([notes, 'Products: '+', '.join(products), 'Known affected products: '+', '.join(affected_products), *[v['cve']+': '+v['description'] for v in vulns]])
    return {'advisory_id': aid, 'url': 'https://www.cisa.gov/news-events/ics-advisories/'+aid,
            'year': 2000+int(aid.split('-')[1]), 'title': document.get('title', ''),
            'vendor': ', '.join(vendors), 'cves': sorted({v['cve'] for v in vulns}),
            'cwes': sorted({v['cwe'] for v in vulns if v['cwe']}), 'vulns': vulns,
            'affected_text': overview, 'products': products, 'affected_products': affected_products,
            'published': document['tracking'].get('initial_release_date'),
            'last_modified': document['tracking'].get('current_release_date'),
            'source': 'CISA CSAF', 'csaf_commit': commit, 'csaf_path': source,
            'csaf_sha256': hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()}


def download(url, dest):
    for attempt in range(4):
        try:
            tmp = dest.with_suffix(dest.suffix+'.download')
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'ICS-VEX-corpus-refresh/1.0'}), timeout=120) as response, tmp.open('wb') as f:
                shutil.copyfileobj(response, f)
            tmp.replace(dest)
            return
        except Exception:
            if attempt == 3:
                raise
            time.sleep(2*(attempt+1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--commit', required=True)
    args = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.commit)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = ROOT/'results/corpus_backups'/stamp
    backup.mkdir(parents=True)
    targets = ['cisa_advisories.json', 'nvd_cache.json', 'nvd_cvss.json', 'nvd_cpe_detail.json', 'cpe_index.json']
    for name in targets:
        if (DATA/name).exists():
            shutil.copy2(DATA/name, backup/name)
    advisory = read_json(DATA/'cisa_advisories.json')
    before_ids = set(advisory)
    before_cves = {c for a in advisory.values() for c in a.get('cves', [])}
    archive = DATA/'upstream_csaf_latest.zip'
    # Always fetch the requested immutable commit: no stale archive reuse.
    download('https://codeload.github.com/cisagov/CSAF/zip/'+args.commit, archive)
    imported = set()
    with zipfile.ZipFile(archive) as z:
        for name in z.namelist():
            if '/csaf_files/OT/' not in name or not re.search(r'/icsa?-\d{2}-\d{3}-\d{2}[a-z]?\.json$', name):
                continue
            doc = json.loads(z.read(name))
            record = csaf_record(doc, name.split('/', 1)[1], args.commit)
            if record:
                aid = record['advisory_id']
                # Keep best-effort HTML vendor when legacy CSAF lacks a vendor branch.
                if not record['vendor']:
                    record['vendor'] = advisory.get(aid, {}).get('vendor', '')
                advisory[aid] = record
                imported.add(aid)
    population = {c for a in advisory.values() for c in a.get('cves', [])}
    state = {'status': 'collecting_nvd', 'started_at': stamp, 'csaf_commit': args.commit,
             'scope': 'CISA ICS/ICSA advisories; legacy HTML records retained; medical ICSMA excluded',
             'advisories_before': len(before_ids), 'advisories_after': len(advisory),
             'advisories_new': len(set(advisory)-before_ids), 'csaf_records_refreshed': len(imported),
             'cves_before': len(before_cves), 'cves_after': len(population), 'cves_new': len(population-before_cves),
             'latest_advisory_modified': max(a.get('last_modified') or '' for a in advisory.values()),
             'backup': str(backup), 'feeds': [], 'nvd_records_refreshed': 0}
    atomic_json(REPORT, state)
    print(json.dumps(state), flush=True)
    cache = read_json(DATA/'nvd_cache.json')
    cvss = read_json(DATA/'nvd_cvss.json')
    cpe = read_json(DATA/'nvd_cpe_detail.json')
    feed_dir = DATA/'upstream_nvd'
    feed_dir.mkdir(exist_ok=True)
    years = sorted({max(2002, int(c.split('-')[1])) for c in population}, reverse=True)
    seen = set()
    for year in years:
        url = f'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz'
        path = feed_dir/f'{year}.json.gz'
        download(url, path)
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            feed = json.load(f)
        for item in feed['vulnerabilities']:
            c = item['cve']; cid = c['id']
            if cid not in population:
                continue
            cache[cid] = nvd_parse(c)
            cache[cid]['references'] = [r['url'] for r in c.get('references', []) if r.get('url')]
            cache[cid]['feed_timestamp'] = feed.get('timestamp')
            m = cache[cid]['metric'] or {}
            cvss[cid] = {'score': m.get('score'), 'severity': m.get('severity', ''), 'vector': m.get('vector', ''), 'ver': (m.get('method') or '').replace('CVSS', ''), 'lastModified': c.get('lastModified')}
            cpe[cid] = detail(c)
            seen.add(cid)
        state['feeds'].append({'year': year, 'url': url, 'timestamp': feed.get('timestamp'), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        state['nvd_records_refreshed'] = len(seen)
        atomic_json(REPORT, state)
        print(f'NVD {year}: refreshed {len(seen)}/{len(population)} corpus CVEs', flush=True)
        del feed
        gc.collect()
    by_product = defaultdict(list)
    vendors = {}
    for cid, entries in cpe.items():
        vendors[cid] = sorted({e['vendor'] for e in entries})
        for e in entries:
            by_product[e['product']].append(dict(e, cve=cid))
    outputs = {'cisa_advisories.json': advisory, 'nvd_cache.json': cache, 'nvd_cvss.json': cvss,
               'nvd_cpe_detail.json': cpe, 'cpe_index.json': {'generated_products': len(by_product), 'generated_cves': len(cpe), 'by_product': by_product, 'cve_vendors': vendors}}
    for name, data in outputs.items():
        atomic_json(DATA/name, data)
    state.update(status='complete', completed_at=datetime.now(timezone.utc).isoformat(),
                 nvd_missing=sorted(population-seen), nvd_coverage=len(seen)/len(population),
                 output_sha256={name: hashlib.sha256((DATA/name).read_bytes()).hexdigest() for name in outputs})
    atomic_json(REPORT, state)
    atomic_json(DATA/'public_corpus_freshness.json', {k: v for k, v in state.items() if k not in {'backup', 'output_sha256'}})
    print('COMPLETE', json.dumps({k:state[k] for k in ['advisories_after', 'cves_after', 'nvd_records_refreshed', 'nvd_missing']}), flush=True)
    # Keep the downstream live SBOM snapshot/index aligned on every refresh.
    subprocess.run([sys.executable, str(ROOT/'tools/refresh_public_sboms.py')], check=True)


if __name__ == '__main__':
    main()
