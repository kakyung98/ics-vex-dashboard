import hashlib
import json
from pathlib import Path

from tools.common.build_dataset_statistics import build
from src.common.dataset_statistics import render

ROOT = Path(__file__).resolve().parents[2]


def test_unknown_zero_boundaries_and_reported_cwe():
    records = [dict(cve='a', cwe='CWE-20 CWE-20 CWE-79', cvss=0),
               dict(cve='b', cwe='NVD-CWE-noinfo', cvss=None),
               dict(cve='c', cwe='CWE-20', cvss=9),
               dict(cve='d', cwe=None, cvss='nan')]
    result = build(records, {c: dict(epss=p) for c, p in [('a', 0), ('b', .01), ('c', 1), ('d', 'nan')]}, '2026-11-16')
    assert [r['count'] for r in result['cwe']['counts']] == [2, 1]
    assert result['cvss']['available'] == result['cvss']['missing'] == 2
    assert result['cvss']['bins'][0]['count'] == 1
    assert [r['count'] for r in result['epss']['bins']] == [1, 1, 0, 1, 1]


def test_full_population_snapshot_and_render():
    snapshot = json.loads((ROOT/'site/dataset_statistics.json').read_text(encoding='utf-8'))
    assert snapshot['total_cves'] == 12418
    assert snapshot['sources']['corpus_sha256'] == hashlib.sha256((ROOT/'site/cve_index.json').read_bytes()).hexdigest()
    for metric in ['cvss', 'epss']:
        assert sum(row['count'] for row in snapshot[metric]['bins']) == 12418
        assert snapshot[metric]['available'] + snapshot[metric]['missing'] == 12418
    html = render(snapshot)
    assert '12,418' in html and snapshot['epss']['score_date'] in html
    assert html.count('role="meter"') == len(snapshot['cwe']['counts']) + 11
