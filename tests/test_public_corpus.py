from src.public_corpus import current_findings
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('refresh_public_corpus', Path(__file__).resolve().parents[1]/'tools/refresh_public_corpus.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
csaf_record = collector.csaf_record


def test_corrected_relationships_are_removed_new_ones_are_unassessed():
    prior = {'CVE-2026-1000': [{'device': 'icsa-26-001-01', 'final_vex': 'LIKELY_AFFECTED'}],
             'CVE-2026-2000': [{'device': 'icsa-26-001-02', 'final_vex': 'LIKELY_NOT_AFFECTED'}]}
    advisories = {'icsa-26-001-01': {'cves': ['CVE-2026-3000'], 'title': 'Device', 'vendor': 'Vendor'},
                  'icsa-26-001-02': {'cves': ['CVE-2026-2000']}}
    nvd = {'CVE-2026-3000': {'metric': {'severity': 'critical'}, 'cwes': ['CWE-78']}}
    result = current_findings(prior, advisories, nvd)
    assert 'CVE-2026-1000' not in result
    assert result['CVE-2026-2000'][0]['final_vex'] == 'LIKELY_NOT_AFFECTED'
    r = result['CVE-2026-3000'][0]
    assert r['final_vex'] == 'UNDER_INVESTIGATION' and r['analysis_performed'] is False
    assert r['sev'] == 'critical' and r['cwe'] == 'CWE-78'
    assert len(current_findings(result, advisories, nvd)['CVE-2026-3000']) == 1


def test_csaf_extracts_declared_cves_and_revision_without_reference_noise():
    doc = {'document': {'title': 'Controller', 'tracking': {'id': 'ICSA-26-302-03', 'current_release_date': '2026-10-29'}},
           'product_tree': {'branches': [{'category': 'vendor', 'name': 'Acme', 'branches': [{'category': 'product_name', 'name': 'Controller'}]}]},
           'vulnerabilities': [{'cve': 'CVE-2026-13162', 'cwe': {'id': 'CWE-78'},
                                'scores': [{'cvss_v3': {'baseScore': 7.5, 'vectorString': 'CVSS:3.1/test'}}],
                                'notes': [{'category': 'description', 'text': 'Command injection'}]}]}
    r = csaf_record(doc, 'path', 'a'*40)
    assert r['cves'] == ['CVE-2026-13162'] and r['vendor'] == 'Acme'
    assert r['last_modified'] == '2026-10-29' and r['vulns'][0]['cvss_v3_score'] == 7.5
    doc['document']['tracking']['id'] = 'ICSMA-26-001-01'
    assert csaf_record(doc, 'path', 'a'*40) is None
