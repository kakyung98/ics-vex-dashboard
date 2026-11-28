from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import sqlite3
from urllib.parse import urljoin

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.item4.evaluation import agent_review_records as historical
from src.item4.evaluation import policy_review_records as policy
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.web import scenario_evaluation_api as api
from src.item4.web.evaluation_runs_api import router as ledger_router


@pytest.fixture
def records(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, 'DB', tmp_path/'runs.sqlite')
    monkeypatch.setattr(runs, 'OUTPUT', tmp_path/'artifacts')
    prior = [('not_affected', 'not_affected'), ('affected', 'under_investigation')]
    current = [('under_investigation', 'under_investigation'), ('affected', 'affected')]

    def inputs(run_id, states):
        cases = []
        matrix = {}
        for i, (a, b) in enumerate(states):
            counts = matrix.setdefault(a, {})
            counts[b] = counts.get(b, 0) + 1
            rating = dict(rationale='Case evidence', evidence_ids=['O01'], needed_records='Running build')
            case = dict(review_id=f'case-{i}', cve=f'CVE-2099-{1111+i}', agreement=a == b,
                        reviewer_a=dict(rating, status=a), reviewer_b=dict(rating, status=b))
            if run_id == 'current':
                case.update(previous_statuses=dict(reviewer_a=prior[i][0], reviewer_b=prior[i][1]),
                            prior_groups=[('prior_not_affected', 'prior_disagreement')[i]])
            cases.append(case)
        folder = runs.OUTPUT/run_id
        folder.mkdir(parents=True)
        for name in historical.ARTIFACTS:
            (folder/name).write_bytes(b'{}')
        (folder/'comparisons.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in cases), encoding='utf-8')
        agreements = sum(a == b for a, b in states)
        summary = dict(packet_id='packet-'+run_id, source_run_id='source', agent_reviewed_scenarios=2,
                       agent_ratings=4, agreements=agreements, disagreements=2-agreements,
                       human_reviewed_scenarios=0, verified_field_records=0, field_record_type_counts={},
                       status_pairs=matrix)
        return dict(total=2, agent_review=summary, code_hashes={'code': 'a'*64},
                    data_hashes={name: runs.file_sha(folder/name) for name in historical.ARTIFACTS})

    previous = historical.publish_agent_review('prior', **inputs('prior', prior))
    output = inputs('current', current)
    output['policy_rereview'] = dict(
        previous_run_id='prior', prior_not_affected_count=1, prior_disagreement_count=1,
        prior_not_affected_pairs={'under_investigation / under_investigation': 1},
        prior_disagreement_pairs={'affected / affected': 1}, prior_disagreements_now_agree=1,
        absence_policy_violations=0)
    return previous, output


def test_publication_is_atomic_repeatable_and_linked(records):
    prior, inputs = records
    with ThreadPoolExecutor(2) as pool:
        first, second = pool.map(lambda _: policy.publish_policy_review('current', **inputs), range(2))
    assert first == second == ledger.get_run('current')
    assert first['agent_review'] == inputs['agent_review'] and first['policy_rereview'] == inputs['policy_rereview']
    assert first['expert_reviewed_count'] == first['prediction_count'] == first['candidate_count'] == 0
    assert first['generation_method'] == prior['generation_method'] == historical.METHOD
    assert prior == ledger.get_run('prior') and 'policy_rereview' not in prior
    with pytest.raises(ValueError, match='different content'):
        policy.publish_policy_review('current', **dict(inputs, code_hashes={'code': 'b'*64}))

    app = FastAPI()
    app.include_router(ledger_router)
    app.include_router(api.router)
    client = TestClient(app)
    prefix = '/api/item4/evaluation-runs/'
    assert client.get(prefix+'current/report').json() == first
    assert client.get(prefix+'current/candidates').status_code == 404
    for name in historical.ARTIFACTS:
        current = prefix+'current/agent-review/'+name
        previous = prefix+'prior/agent-review/'+name
        response = client.get(current)
        assert response.status_code == 200 and response.content == (runs.OUTPUT/'current'/name).read_bytes()
        assert urljoin(current, response.links['predecessor-version']['url']) == previous
        assert client.head(current).headers['link'] == response.headers['link']
        assert 'link' not in client.head(previous).headers
    (runs.OUTPUT/'current'/'report.json').write_bytes(b'changed')
    assert client.get(prefix+'current/agent-review/report.json').status_code == 409
    assert ledger.get_run('current') == first


@pytest.mark.parametrize('change', [
    {'previous_run_id': 'missing'}, {'previous_run_id': 'current'}, {'prior_disagreements_now_agree': 0},
    {'prior_not_affected_pairs': {'under_investigation/under_investigation': 1}},
    {'prior_disagreement_pairs': {'under_investigation / under_investigation': 1}},
    {'prior_disagreement_count': 0, 'prior_disagreement_pairs': {}, 'prior_disagreements_now_agree': 0},
    {'absence_policy_violations': 1}, {'unknown': 0},
])
def test_rejects_inconsistent_transitions_without_saving(records, change):
    prior, inputs = records
    inputs['policy_rereview'].update(change)
    with pytest.raises(ValueError):
        policy.publish_policy_review('current', **inputs)
    with pytest.raises(KeyError):
        ledger.get_run('current')
    assert ledger.get_run('prior') == prior


def test_after_first_policy_publication_legacy_can_replay_but_cannot_insert(records):
    prior, inputs = records
    policy.publish_policy_review('current', **inputs)
    legacy = {k: prior[k] for k in ('total', 'code_hashes', 'data_hashes', 'agent_review')}
    assert historical.publish_agent_review('prior', **legacy) == prior
    shutil.copytree(runs.OUTPUT/'prior', runs.OUTPUT/'another-legacy')
    with pytest.raises(sqlite3.IntegrityError, match='current v2 policy review publisher'):
        historical.publish_agent_review('another-legacy', **legacy)
    with pytest.raises(KeyError):
        ledger.get_run('another-legacy')
    other = ledger.start_run('another-method', generation_method='scenario_moe_local_llm', total=1,
                             code_hashes={'code': 'a'*64}, model_hashes={'model': 'b'*64},
                             data_hashes={'data': 'c'*64})
    assert ledger.get_run('another-method') == other


def test_conflicting_first_policy_publication_rolls_back_insert_trigger(records):
    prior, inputs = records
    historical.publish_agent_review('current', **{k: v for k, v in inputs.items() if k != 'policy_rereview'})
    with pytest.raises(ValueError, match='different content'):
        policy.publish_policy_review('current', **inputs)
    legacy = {k: prior[k] for k in ('total', 'code_hashes', 'data_hashes', 'agent_review')}
    shutil.copytree(runs.OUTPUT/'prior', runs.OUTPUT/'another-legacy')
    assert historical.publish_agent_review('another-legacy', **legacy)['run_id'] == 'another-legacy'


def test_ui_shows_transition_counts_and_case_links(records):
    playwright = pytest.importorskip('playwright.sync_api')
    chrome = next((path for path in [
        os.environ.get('CHROME_PATH'), shutil.which('chromium'), shutil.which('google-chrome'),
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    ] if path and Path(path).is_file()), None)
    if not chrome:
        pytest.skip('Chromium unavailable')
    prior, inputs = records
    current = policy.publish_policy_review('current', **inputs)
    markup = (ledger.ROOT/'src/item4/web/asset_vex_questionnaire.html').read_text(encoding='utf-8')
    source = (ledger.ROOT/'src/item4/web/evaluation_runs_ui.js').read_text(encoding='utf-8')
    assert source == (ledger.ROOT/'site/item4-run-ledger.js').read_text(encoding='utf-8')
    requested_cases = []

    def serve(route):
        url = route.request.url.split('?')[0]
        if url.endswith('item4.html'):
            route.fulfill(content_type='text/html', body=markup+'<script>'+source+'</script>')
        elif url.endswith('/evaluation-runs'):
            route.fulfill(json={'runs': [current, prior]})
        elif url.endswith('/current'):
            route.fulfill(json=current)
        elif url.endswith('/current/agent-review/comparisons.jsonl'):
            requested_cases.append(url)
            route.fulfill(body=(runs.OUTPUT/'current'/'comparisons.jsonl').read_bytes())
        else:
            route.fulfill(status=404)

    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(executable_path=chrome, headless=True)
        page = browser.new_page()
        page.route('**/*', serve)
        page.goto('http://review.test/item4.html?run_id=current#evaluation-runs')
        fields = page.locator('#evaluation-record')
        fields.get_by_text('이전 A·B 모두 미영향 1건의 재검토 판정').wait_for()
        assert fields.get_by_text('이전 A·B 불일치 1건의 재검토 판정').is_visible()
        assert fields.locator("dt:text-is('사람이 검토한 시나리오') + dd").inner_text() == '0건'
        assert fields.get_by_text('A 조사 보류 / B 조사 보류 · 1건').is_visible()
        assert not requested_cases
        fields.get_by_text('사례별 이전·재검토 판정과 현장 근거 요청 보기').click()
        table = fields.get_by_role('table', name='이전 A·B 모두 미영향 · 1건')
        table.wait_for()
        assert len(requested_cases) == 1
        assert table.get_by_role('link', name='A 미영향 / B 미영향').get_attribute('href').endswith(
            '/prior/agent-review/report.ko.html#case-0')
        assert table.get_by_role('link', name='A 조사 보류 / B 조사 보류').get_attribute('href').endswith(
            '/current/agent-review/report.ko.html#case-0')
        second = fields.get_by_role('table', name='이전 A·B 불일치 · 1건')
        assert second.get_by_role('link', name='A 영향 있음 / B 영향 있음').get_attribute('href').endswith(
            '/current/agent-review/report.ko.html#case-1')
        browser.close()
