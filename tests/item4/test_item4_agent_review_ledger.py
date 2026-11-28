from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.item4.evaluation import agent_review_records as reviews
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.web import scenario_evaluation_api as api
from src.item4.web.evaluation_runs_api import router as ledger_router


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, 'DB', tmp_path/'ledger.sqlite3')
    monkeypatch.setattr(runs, 'OUTPUT', tmp_path/'artifacts')
    folder = runs.OUTPUT/'fixture'
    folder.mkdir(parents=True)
    for name in reviews.ARTIFACTS:
        (folder/name).write_bytes(b'{}\n' if name.endswith(('.json', '.jsonl')) else b'<p>fixture</p>')
    summary = dict(packet_id='blind-packet', source_run_id='parent', agent_reviewed_scenarios=2,
                   agent_ratings=4, agreements=1, disagreements=1, human_reviewed_scenarios=0,
                   verified_field_records=0, field_record_type_counts={'running_build': 2},
                   status_pairs={'affected': {'affected': 1, 'under_investigation': 1}})
    return dict(total=2, code_hashes={'implementation': 'a'*64},
                data_hashes={name: runs.file_sha(folder/name) for name in reviews.ARTIFACTS}, agent_review=summary)


def test_concurrent_publish_is_idempotent_and_preserves_ai_and_human_counts(inputs):
    with ThreadPoolExecutor(2) as pool:
        a, b = pool.map(lambda _: reviews.publish_agent_review('fixture', **inputs), range(2))
    assert a == b == ledger.get_run('fixture')
    assert a['completed'] == a['total'] == 2 and a['agent_review']['agent_ratings'] == 4
    assert a['expert_reviewed_count'] == a['prediction_count'] == a['candidate_count'] == 0
    assert not a['model_hashes'] and a['candidate_origin'] == 'review_only'
    with pytest.raises(ValueError, match='already been published'):
        reviews.publish_agent_review('fixture', **dict(inputs, code_hashes={'implementation': 'b'*64}))


@pytest.mark.parametrize('change', [
    {'agreements': 3}, {'human_reviewed_scenarios': 2}, {'agent_ratings': 2},
    {'status_pairs': {'fixed': {'affected': 2}}}, {'status_pairs': {'other': {'affected': 2}}},
    {'field_record_type_counts': {'running_build': 3}},
])
def test_rejects_inconsistent_review_summary(inputs, change):
    inputs['agent_review'].update(change)
    with pytest.raises(ValueError):
        reviews.publish_agent_review('fixture', **inputs)
    with pytest.raises(KeyError):
        ledger.get_run('fixture')


def test_serves_exact_recorded_artifacts_and_refuses_mismatch(inputs):
    app = FastAPI()
    app.include_router(api.router)
    app.include_router(ledger_router)
    client = TestClient(app)
    base = '/api/item4/evaluation-runs/fixture'
    artifacts = base+'/agent-review/'
    assert client.get(artifacts+'report.ko.html').status_code == 404
    wrong = dict(inputs['data_hashes'], **{'comparisons.jsonl': 'e'*64})
    with pytest.raises(ValueError, match='fingerprint'):
        reviews.publish_agent_review('fixture', **dict(inputs, data_hashes=wrong))
    row = reviews.publish_agent_review('fixture', **inputs)
    assert client.get(base).json() == row == client.get(base+'/report').json()
    assert client.get(base+'/candidates').status_code == 404
    for filename in reviews.ARTIFACTS:
        raw = (runs.OUTPUT/'fixture'/filename).read_bytes()
        r = client.get(artifacts+filename)
        assert r.content == raw and r.status_code == 200
        assert ('content-disposition' in r.headers) == (filename != 'report.ko.html')
        head = client.head(artifacts+filename)
        assert head.status_code == 200 and not head.content and head.headers['content-length'] == str(len(raw))
    assert client.get(artifacts+'unlisted.json').status_code == 404
    path = runs.OUTPUT/'fixture'/'report.json'
    path.write_bytes(b'{"different":true}')
    assert client.get(artifacts+'report.json').status_code == client.head(artifacts+'report.json').status_code == 409
    assert ledger.get_run('fixture') == row


def test_panel_loads_case_agreement_details_only_when_opened(inputs):
    playwright = pytest.importorskip('playwright.sync_api')
    chrome = next((path for path in [
        os.environ.get('CHROME_PATH'), shutil.which('chromium'), shutil.which('google-chrome'),
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    ] if path and Path(path).is_file()), None)
    if not chrome:
        pytest.skip('Chromium is unavailable')
    cases = []
    for i, b_status in enumerate(('affected', 'under_investigation')):
        a = dict(status='affected', evidence_ids=['O01'], rationale='Agent A judgement', needed_records='Asset inventory')
        b = dict(status=b_status, evidence_ids=['O01'], rationale='Agent B judgement', needed_records='Running build')
        cases.append(dict(review_id='blind-'+str(i), cve='CVE-2099-1111', agreement=a['status']==b['status'],
                          reviewer_a=a, reviewer_b=b))
    path = runs.OUTPUT/'fixture'/'comparisons.jsonl'
    path.write_text(''.join(json.dumps(case) + '\n' for case in cases), encoding='utf-8')
    inputs['data_hashes'][path.name] = runs.file_sha(path)
    row = reviews.publish_agent_review('fixture', **inputs)
    markup = (ledger.ROOT/'src/item4/web/asset_vex_questionnaire.html').read_text(encoding='utf-8')
    source = (ledger.ROOT/'src/item4/web/evaluation_runs_ui.js').read_text(encoding='utf-8')
    requests = []
    def serve(route):
        url = route.request.url.split('?')[0]
        if url.endswith('item4.html'):
            route.fulfill(content_type='text/html', body=markup + '<script>' + source + '</script>')
        elif url.endswith('/evaluation-runs'):
            route.fulfill(json={'runs': [row]})
        elif url.endswith('/fixture'):
            route.fulfill(json=row)
        elif url.endswith('/comparisons.jsonl'):
            requests.append(url)
            route.fulfill(content_type='application/x-ndjson', body=path.read_bytes())
        else:
            route.fulfill(status=404)
    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=chrome, headless=True)
        page = browser.new_page()
        page.route('**/*', serve)
        page.goto('http://review.test/item4.html?run_id=fixture#evaluation-runs')
        page.get_by_text('사람이 검토한 시나리오').wait_for()
        assert not requests and page.locator('#evaluation-candidates').is_hidden()
        page.get_by_text('사례별 일치·불일치 및 현장 근거 요청 보기').click()
        page.get_by_text('불일치 1건', exact=True).wait_for()
        assert page.get_by_text('일치 1건', exact=True).is_visible()
        page.locator('summary').filter(has_text='blind-1').click()
        assert page.get_by_text('Running build', exact=True).first.is_visible()
        assert len(requests)==1 and '/fixture/agent-review/' in requests[0]
        assert len(page.locator('a[href*="/fixture/agent-review/"]').all()) == 6
        browser.close()
