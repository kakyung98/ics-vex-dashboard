"""Authorized API/model integration smoke; no browser or external model APIs."""
from pathlib import Path
import time
import json
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'results/item4_v3_smoke'
OUT.mkdir(exist_ok=True)
base = 'http://127.0.0.1:8100'
started = time.time()


def post(path, data=None):
    r = requests.post(base + path, json=data, timeout=900)
    r.raise_for_status()
    return r.json()


def save(name, data):
    (OUT / (name + '.json')).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


try:
    blocked = post('/api/item4/start', {'cves': [{'cve': 'CVE-2099-12345', 'cwe': ['CWE-787'],
                                                'description': 'An out-of-bounds write affects packet processing.'}]})
    save('missing_source', blocked)
    assert blocked['statements'][0]['status'] == 'under_investigation'
    assert blocked['statements'][0]['extraction']['status'] == 'not_run'
    r = requests.post(base + '/api/item4/' + blocked['review_id'] + '/questions', timeout=30)
    assert r.status_code == 400
    mixed = post('/api/item4/start', {'cves': [
        {'cve': 'CVE-2099-12345', 'cwe': ['CWE-787'], 'description': 'An out-of-bounds write affects packet processing.'},
        {'cve': 'CVE-2026-64893'}]})
    save('mixed_routes', mixed)
    assert mixed['routes']['CVE-2026-64893']['requirement'] == 'operational_review'
    save('status', {'phase': 'generating_real_model_questions', 'review_id': mixed['review_id']})
    plan = post('/api/item4/' + mixed['review_id'] + '/questions')
    save('real_model_questions', plan)
    assert [c['cve'] for c in plan['cases']] == ['CVE-2026-64893']
    generation = plan['cases'][0]['generation']
    scopes = {q.get('scope') for q in plan['cases'][0]['questions'] if q['origin'] == 'llm'}
    checks = {'blocked_case_deferred_without_extraction': True,
              'source_required_not_in_question_plan': True,
              'generation_accepted': generation['status'] == 'validated',
              'common_and_specific': scopes == {'common', 'specific'},
              'question_role': generation.get('role') == 'item4-questions',
              'no_role_adapter_claim': generation.get('fine_tuned_for_role') is False}
    save('status', {'phase': 'complete', 'elapsed_seconds': round(time.time() - started, 2),
                    'checks': checks, 'all_contract_checks_passed': all(checks.values()),
                    'semantic_accuracy_measured': False, 'external_api_calls': 0})
    print(json.dumps(checks))
except Exception as e:
    save('status', {'phase': 'failed', 'error': str(e), 'elapsed_seconds': time.time() - started})
    raise
