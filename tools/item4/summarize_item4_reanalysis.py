"""Independently compare parent/reanalysis deliveries and record live API checks.

Reads existing model results only. Does not execute any model or create assets.
"""
import argparse
from collections import Counter
import gzip
import hashlib
from itertools import zip_longest
import json
from pathlib import Path
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.item4.analysis.advisory_source_bundles import digest; from src.item4.analysis.advisory_source_bundles import verify_seal


def catalog(folder):
    with sqlite3.connect('file:' + str((folder/'catalog/catalog.sqlite3').resolve()) + '?mode=ro', uri=True) as db:
        return {cve: json.loads(payload) for cve, payload in db.execute('SELECT cve,payload FROM records')}


def compare(parent, current):
    previous = catalog(parent)
    corrected = catalog(current)
    assert set(previous) == set(corrected) and len(corrected) == 12418
    changes = json.loads((current/'reanalysis_report.json').read_text(encoding='utf-8'))
    byfact = {r['fact_id']: r for r in changes['previous_approved_fact_downgrades']}
    reasons = Counter()
    examples = []
    for cve, record in corrected.items():
        old, new = previous[cve]['graph'], record['graph']
        a = {c['id']: c for c in old['conditions']}
        b = {c['id']: c for c in new['conditions']}
        assert b.keys() <= a.keys()
        assert {p['id'] for p in new['paths']} <= {p['id'] for p in old['paths']}
        assert not new['coverage_complete'] or old['coverage_complete']
        for cid in a.keys() - b.keys():
            c = a[cid]
            change = byfact[c['unit_fact_id']]
            reason = ('nonrequirement_guard' if change['reasons'][0].startswith('nonrequirement')
                      else 'quote_NLI_' + change['quote_nli']['label'])
            reasons[reason] += 1
            examples.append(dict(cve=cve, condition_id=cid, condition=c['condition'],
                                 source_quote=c['evidence']['quote'], reason=reason,
                                 current_fact_state=change['state']))
    checked = 0
    with gzip.open(parent/'unit_results.jsonl.gz', 'rt', encoding='utf-8') as a, gzip.open(current/'unit_results.jsonl.gz', 'rt', encoding='utf-8') as b:
        for old_line, new_line in zip_longest(a, b):
            assert old_line is not None and new_line is not None
            old, new = json.loads(old_line), json.loads(new_line)
            verify_seal(old, 'unit_result_sha256')
            verify_seal(new, 'unit_result_sha256')
            assert old['unit_id'] == new['unit_id']
            assert old['model_responses'] == new['model_responses']
            assert old['status'] == new['status'] and old['coverage'] == new['coverage']
            assert new['reanalysis']['parent_unit_result_sha256'] == old['unit_result_sha256']
            assert len(old['facts']) == len(new['facts'])
            for f, g in zip(old['facts'], new['facts']):
                assert {k: v for k, v in f.items() if k != 'verification'} == {k: v for k, v in g.items() if k != 'verification'}
                assert f['verification'].get('nli') == g['verification'].get('nli')
                assert g['verification']['previous_verification_sha256'] == digest(f['verification'])
                if g['verification']['state'] == 'automatic_pass':
                    assert f['verification']['state'] == 'automatic_pass'
                    assert g['verification']['nli_quote']['label'] == 'entailment'
                    assert g['verification']['nli_quote']['input_sha256'] == digest([g['quote'], g['condition']])
            checked += 1
    assert checked == 31503
    return dict(passed=True, cves_preserved=len(corrected), source_units_with_unchanged_model_responses=checked,
                original_fact_contents_and_context_nli_preserved=True, no_promotions_or_new_conditions_or_paths=True,
                condition_removal_reasons=dict(reasons), removed_bound_conditions=examples,
                current_conditions=sum(len(r['graph']['conditions']) for r in corrected.values()),
                current_paths=sum(len(r['graph']['paths']) for r in corrected.values()),
                cves_with_conditions=sum(bool(r['graph']['conditions']) for r in corrected.values()),
                complete_graphs=sum(r['graph']['coverage_complete'] for r in corrected.values()),
                independent_semantic_accuracy=None)


def live_checks(base, current):
    checks = []

    def request(path, expected=200, body=None):
        wire = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base.rstrip('/')+path, data=wire, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                code, result = response.status, json.loads(response.read())
        except urllib.error.HTTPError as response:
            code, result = response.code, json.loads(response.read())
        assert code == expected, (path, code, expected)
        checks.append(dict(path=path, method='GET' if body is None else 'POST', http_status=code))
        return result

    summary = request('/api/item4/summary')
    assert summary == json.loads((current/'catalog/summary.json').read_text(encoding='utf-8'))
    record = next(r for r in catalog(current).values() if r['graph']['conditions'])
    cve = record['cve']
    assert request('/api/item4/cves/'+cve) == record
    c = record['graph']['conditions'][0]
    request('/api/item4/evidence?'+urllib.parse.urlencode({'segment_id': c['evidence']['segment_id']}))
    if c['product_ids']:
        request('/api/item4/product?'+urllib.parse.urlencode({'product_id': c['product_ids'][0]}))
    removed = request('/api/item4/cves/CVE-2015-5621')
    assert not any(c['condition'] == 'no user interaction is required' for c in removed['graph']['conditions'])
    form = request('/api/item4/inventory-form', body={'asset_type_ids': ['A0002', 'A0003']})
    assert form['input']['values'] and all(v['state'] == 'unknown' for v in form['input']['values'].values())
    request('/api/item4/assess', expected=422, body={'cve': cve})
    return dict(passed=True, base_url=base, served_catalog=str(current/'catalog'), checks=checks,
                real_assets_created=0, removed_nonrequirement_not_served=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent', type=Path, required=True)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--api')
    a = p.parse_args()
    report = compare(a.parent.resolve(), a.run.resolve())
    for label, folder in [('parent', a.parent), ('current', a.run)]:
        report[label+'_artifacts_manifest_sha256'] = hashlib.sha256((folder/'artifacts_manifest.json').read_bytes()).hexdigest()
    report['audit_script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if a.api:
        live = live_checks(a.api, a.run.resolve())
        with (a.run/'live_api_validation.json').open('x', encoding='utf-8') as stream:
            json.dump(live, stream, indent=2)
        report['live_api_checks'] = len(live['checks'])
    with (a.run/'correction_summary.json').open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in report.items() if k != 'removed_bound_conditions'}))
