"""Blinding, offline review recovery and role isolation for a synthetic specimen."""
import json
import os
from pathlib import Path
import shutil

import pytest

from tools.item4.render_item4_blind_sample import render_review_forms


def specimens():
    return [
        dict(review_id=identifier, cve='CVE-2099-9001', component=dict(name='Fixture', version='1.0'), evidence=[
            dict(evidence_id='O01', kind='simulation', title='동결 입력',
                 facts=dict(context={'scope': 'current_single'}, literal='</script><script>throw 42</script>'),
                 source=dict(file='frozen.json', pointer='/context')),
        ])
        for identifier in ('blind-x', 'blind-y')
    ]


def test_rejects_multiple_case_identities_and_leaked_fields(tmp_path):
    cases = specimens()
    cases[1]['candidate_status'] = 'affected'
    with pytest.raises(ValueError, match='neutral'):
        render_review_forms(tmp_path, cases, packet_id='fixture')
    cases[1].pop('candidate_status')
    cases[1]['review_id'] = cases[0]['review_id']
    with pytest.raises(ValueError, match='unique blind'):
        render_review_forms(tmp_path, cases, packet_id='fixture')
    cases[1]['review_id'] = 'different'
    cases[0]['evidence'].append(cases[0]['evidence'][0].copy())
    with pytest.raises(ValueError, match='unique evidence'):
        render_review_forms(tmp_path, cases, packet_id='fixture')


def test_offline_review_lifecycle(tmp_path):
    playwright = pytest.importorskip('playwright.sync_api')
    chrome = next((path for path in [
        os.environ.get('CHROME_PATH'), shutil.which('chromium'), shutil.which('google-chrome'),
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    ] if path and Path(path).is_file()), None)
    a, b = render_review_forms(tmp_path, specimens(), packet_id='fixture-1')
    assert '</script><script>throw 42' not in a.read_text('utf-8')
    with playwright.sync_playwright() as pw:
        if not chrome and not Path(pw.chromium.executable_path).is_file():
            pytest.skip('No local Chromium installation')
        browser = pw.chromium.launch(executable_path=chrome, headless=True)
        profile = browser.new_context(accept_downloads=True, offline=True)
        page = profile.new_page()
        failures, network = [], []
        page.on('pageerror', lambda err: failures.append(str(err)))
        page.on('request', lambda req: network.append(req.url) if req.url.startswith(('http:', 'https:')) else None)
        page.goto(a.resolve().as_uri())
        assert page.locator('#phase').inner_text() == '미검토'
        assert page.locator('#status').input_value() == ''
        assert page.locator('#progress').inner_text() == '검토 완료 0 / 2건'
        assert 'throw 42' in page.locator('#evidence').inner_text()
        page.locator('#finish').click()
        assert '검토자 식별자' in page.locator('#feedback').inner_text()
        page.locator('#who').fill('fixture-reviewer')
        page.locator('#status').select_option('under_investigation')
        page.locator('#why').fill('동결 시나리오의 현장 확인 자료가 없습니다.')
        page.locator('#evidence input').check()
        page.locator('#finish').click()
        assert '추가 근거' in page.locator('#feedback').inner_text()
        page.locator('#need').fill('해당 범위의 배포 재고와 기록 일자')
        page.locator('#finish').click()
        assert page.locator('#phase').inner_text() == '검토 완료'
        assert not page.locator('#who').is_editable()
        page.locator('#todo').click()
        page.locator('#why').fill('두 번째 사례 작성 중')
        page.reload()
        assert page.locator('#progress').inner_text() == '검토 완료 1 / 2건'
        page.locator('#next').click()
        assert page.locator('#why').input_value() == '두 번째 사례 작성 중'
        with page.expect_download() as event:
            page.locator('#download').click()
        backup = tmp_path / 'backup.json'
        event.value.save_as(backup)
        data = json.loads(backup.read_bytes())
        assert data['reviewer_slot'] == 'reviewer_a'
        assert [row['review_id'] for row in data['ratings']] == ['blind-x']
        assert data['ratings'][0]['evidence_ids'] == ['O01']
        assert data['drafts'][0]['reviewed_at'] is None
        page.locator('#prev').click()
        page.locator('#need').fill('수정한 추가 근거')
        assert page.locator('#phase').inner_text() == '작성 중'
        page.goto(b.resolve().as_uri())
        assert page.locator('#who').input_value() == ''
        assert page.locator('#progress').inner_text() == '검토 완료 0 / 2건'
        page.locator('#file').set_input_files(backup)
        page.wait_for_function("document.getElementById('persist').textContent.includes('불러오기 실패')")
        assert page.locator('#who').input_value() == ''
        page.goto(a.resolve().as_uri())
        page.once('dialog', lambda dialog: dialog.accept())
        page.locator('#file').set_input_files(backup)
        page.wait_for_function("document.getElementById('persist').textContent.includes('파일을 불러왔습니다')")
        assert page.locator('#who').input_value() == 'fixture-reviewer'
        assert page.locator('#phase').inner_text() == '검토 완료'
        assert not failures and not network
        browser.close()
