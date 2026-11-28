from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.item4.evaluation import agent_review_records as blind
from src.item4.evaluation import evidence_adjudication_records as evidence
from src.item4.evaluation import policy_review_records as policy
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.web import scenario_evaluation_api as api
from src.item4.web.evaluation_runs_api import router as ledger_router


@pytest.fixture
def review(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, 'DB', tmp_path / 'runs.sqlite')
    monkeypatch.setattr(ledger, 'RESULTS', tmp_path)
    monkeypatch.setattr(runs, 'OUTPUT', tmp_path / 'artifacts')
    pair = {'reviewer_a': 'under_investigation', 'reviewer_b': 'affected'}
    cve, case_id = 'CVE-2019-6579', 'case-1'

    def files(run_id, docs):
        folder = runs.OUTPUT / run_id
        folder.mkdir(parents=True)
        for name, content in docs.items():
            (folder / name).write_bytes(content)
        return {name: sha256(content).hexdigest() for name, content in docs.items()}

    comparison = dict(cve=cve, review_id=case_id, agreement=False,
                      reviewer_a={'status': pair['reviewer_a']}, reviewer_b={'status': pair['reviewer_b']})
    matrix = {pair['reviewer_a']: {pair['reviewer_b']: 1}}
    previous = dict(packet_id='fixture', source_run_id='sample', agent_reviewed_scenarios=1, agent_ratings=2,
                    agreements=0, disagreements=1, human_reviewed_scenarios=0, verified_field_records=0,
                    field_record_type_counts={}, status_pairs=matrix)
    code = {'code': 'a' * 64}
    docs = {name: b'{}' for name in blind.ARTIFACTS}
    docs['comparisons.jsonl'] = json.dumps(comparison).encode() + b'\n'
    blind.publish_agent_review('blind', total=1, code_hashes=code, data_hashes=files('blind', docs),
                               agent_review=previous)
    policy_row = policy.publish_policy_review(
        'policy', total=1, code_hashes=code, data_hashes=files('policy', docs), agent_review=previous,
        policy_rereview=dict(previous_run_id='blind', prior_not_affected_count=0, prior_not_affected_pairs={},
                             prior_disagreement_count=1, prior_disagreement_pairs={'under_investigation / affected': 1},
                             prior_disagreements_now_agree=0, absence_policy_violations=0))
    summary = dict(previous_run_id='policy', review_id=case_id, cve=cve, previous_statuses=pair,
                   status='under_investigation', reviewer_kind='ai_agent', human_reviewed_scenarios=0,
                   verified_field_records=0, running_release_verified=False, portal_installation_verified=False,
                   supplier_advisory='https://vendor.example/advisory')
    docs = {name: b'{}' for name in evidence.ARTIFACTS}
    docs['decision.json'] = docs['report.json'] = json.dumps({'adjudication': summary}).encode()
    docs['report.ko.html'] = b'<html lang="ko"></html>'
    return policy_row, dict(code_hashes=code, data_hashes=files('adjudicated', docs), adjudication=summary)


def test_atomic_followup_and_artifact_delivery(review):
    previous, inputs = review
    with ThreadPoolExecutor(2) as pool:
        first, retry = pool.map(lambda _: evidence.publish_adjudication('adjudicated', **inputs), range(2))
    assert first == retry == ledger.get_run('adjudicated')
    assert first['generation_method'] == evidence.METHOD and first['completed'] == first['total'] == 1
    assert first['candidate_count'] == first['prediction_count'] == first['expert_reviewed_count'] == 0
    assert first['adjudication'] == inputs['adjudication']
    assert ledger.get_run('policy') == previous
    assert [r['run_id'] for r in ledger.list_runs() if not r['archived']] == ['adjudicated', 'policy', 'blind']
    with pytest.raises(ValueError, match='different content'):
        evidence.publish_adjudication('adjudicated', **dict(inputs, code_hashes={'other': 'e' * 64}))

    app = FastAPI()
    app.include_router(ledger_router)
    app.include_router(api.router)
    client = TestClient(app)
    base = '/api/item4/evaluation-runs/adjudicated/'
    assert client.get(base + 'report').json() == first
    assert client.get(base + 'candidates').status_code == 404
    for name, mime in evidence.ARTIFACTS.items():
        url = base + 'evidence-adjudication/' + name
        body = (runs.OUTPUT / 'adjudicated' / name).read_bytes()
        response = client.get(url)
        assert response.status_code == 200 and response.content == body
        assert response.headers['content-type'].split(';')[0] == mime
        assert response.headers['cache-control'] == 'no-store'
        head = client.head(url)
        assert head.status_code == 200 and not head.content
        assert head.headers['content-length'] == str(len(body))
        (runs.OUTPUT / 'adjudicated' / name).write_bytes(b'changed')
        assert client.get(url).status_code == client.head(url).status_code == 409
        (runs.OUTPUT / 'adjudicated' / name).unlink()
        assert client.get(url).status_code == 404
    assert client.get(base + 'evidence-adjudication/unknown').status_code == 404
    assert client.get('/api/item4/evaluation-runs/policy/evidence-adjudication/report.json').status_code == 404
    assert ledger.get_run('adjudicated') == first


@pytest.mark.parametrize('changes, reason', [
    ({'previous_run_id': 'blind'}, 'completed previous policy rereview'),
    ({'previous_run_id': 'missing'}, 'completed previous policy rereview'),
    ({'previous_run_id': 'adjudicated'}, 'distinct previous'),
    ({'cve': 'CVE-2099-4321'}, 'disagreement differs'),
    ({'review_id': 'not-in-run'}, 'identify the case exactly once'),
    ({'previous_statuses': {'reviewer_a': 'fixed', 'reviewer_b': 'affected'}}, 'disagreement differs'),
    ({'previous_statuses': {'reviewer_a': 'affected', 'reviewer_b': 'affected'}}, 'two disagreeing'),
    ({'reviewer_kind': 'human'}, 'reviewer identity'),
    ({'human_reviewed_scenarios': False}, 'reviewer identity'),
    ({'running_release_verified': 0}, 'verification flags'),
    ({'verified_field_records': -1}, 'field record count'),
    ({'portal_installation_verified': True}, 'verified field record'),
    ({'status': 'not_affected'}, 'verified field record'),
    ({'status': 'affected', 'running_release_verified': True, 'verified_field_records': 1}, 'portal installation'),
    ({'status': 'fixed', 'portal_installation_verified': True, 'verified_field_records': 1}, 'running release'),
    ({'status': 'not_affected', 'verified_field_records': 1}, 'release or installation scope'),
    ({'supplier_advisory': 'javascript:alert(1)'}, 'HTTPS URL'),
])
def test_refuses_unsubstantiated_summary(review, changes, reason):
    previous, inputs = review
    inputs['adjudication'].update(changes)
    for name in ('report.json', 'decision.json'):
        path = runs.OUTPUT / 'adjudicated' / name
        path.write_text(json.dumps({'adjudication': inputs['adjudication']}), encoding='utf-8')
        inputs['data_hashes'][name] = runs.file_sha(path)
    with pytest.raises(ValueError, match=reason):
        evidence.publish_adjudication('adjudicated', **inputs)
    assert ledger.get_run('policy') == previous
    with pytest.raises(KeyError):
        ledger.get_run('adjudicated')


def test_refuses_changed_predecessor_and_mismatching_receipts(review):
    _, inputs = review
    path = runs.OUTPUT / 'policy' / 'comparisons.jsonl'
    original = path.read_bytes()
    path.write_bytes(original + b' ')
    with pytest.raises(ValueError, match='fingerprint: comparisons.jsonl'):
        evidence.publish_adjudication('adjudicated', **inputs)
    path.write_bytes(original)
    (runs.OUTPUT / 'adjudicated' / 'decision.json').write_bytes(b'{}')
    with pytest.raises(ValueError, match='fingerprint: decision.json'):
        evidence.publish_adjudication('adjudicated', **inputs)
    inputs['data_hashes']['decision.json'] = sha256(b'{}').hexdigest()
    with pytest.raises(ValueError, match='summary differs from decision.json'):
        evidence.publish_adjudication('adjudicated', **inputs)
    with pytest.raises(KeyError):
        ledger.get_run('adjudicated')


def test_ui_shows_one_decision_and_links_from_previous_review(review):
    playwright = pytest.importorskip('playwright.sync_api')
    chrome = next((path for path in [
        os.environ.get('CHROME_PATH'), shutil.which('chromium'), shutil.which('google-chrome'),
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    ] if path and Path(path).is_file()), None)
    if not chrome:
        pytest.skip('Chromium unavailable')
    previous, inputs = review
    current = evidence.publish_adjudication('adjudicated', **inputs)
    markup = (ledger.ROOT / 'src/item4/web/asset_vex_questionnaire.html').read_text(encoding='utf-8')
    source = (ledger.ROOT / 'src/item4/web/evaluation_runs_ui.js').read_text(encoding='utf-8')
    assert source == (ledger.ROOT / 'site/item4-run-ledger.js').read_text(encoding='utf-8')

    def serve(route):
        url = route.request.url.split('?')[0]
        if url.endswith('item4.html'):
            route.fulfill(content_type='text/html', body=markup + '<script>' + source + '</script>')
        elif url.endswith('/evaluation-runs'):
            route.fulfill(json={'runs': [current, previous]})
        elif url.endswith('/adjudicated'):
            route.fulfill(json=current)
        elif url.endswith('/policy'):
            route.fulfill(json=previous)
        else:
            route.fulfill(status=404)

    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=chrome, headless=True)
        page = browser.new_page()
        page.route('**/*', serve)
        page.goto('http://review.test/item4.html?run_id=policy#evaluation-runs')
        record = page.locator('#evaluation-record')
        record.get_by_role('link', name='CVE-2019-6579 · case-1 · 조사 보류').click()
        record.get_by_role('heading', name='CVE-2019-6579 · 불일치 1건 근거 재판정').wait_for()
        assert record.get_by_text('조사 보류 (under_investigation)').is_visible()
        assert record.get_by_text('현장 미확인', exact=True).count() == 2
        assert record.locator("dt:text-is('사람이 검토한 시나리오') + dd").inner_text() == '0건'
        assert record.get_by_role('link', name='A 조사 보류 / B 영향 있음').get_attribute('href').endswith(
            '/policy/agent-review/report.ko.html#case-1')
        for name, file in [('근거 재판정 보고서', 'report.ko.html'), ('현장 기록 대조 내역', 'field_audit.json'),
                           ('공급사 제품·버전 근거', 'supplier_evidence.json')]:
            assert record.get_by_role('link', name=name, exact=True).get_attribute('href').endswith(
                '/adjudicated/evidence-adjudication/' + file)
        assert record.get_by_role('link', name='공급사 권고문 원문').get_attribute('href') == inputs['adjudication']['supplier_advisory']
        browser.close()
