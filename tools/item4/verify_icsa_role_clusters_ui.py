"""Verify the original 18 asset names and advisory-first navigation."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse,json
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2]

def verify(base):
    folder=ROOT/'site/asset_vulntology'
    nav=json.loads((folder/'icsa_asset_navigation.json').read_text(encoding='utf-8'))
    source=json.loads((folder/'icsa_role_groups.json').read_text(encoding='utf-8'))
    if nav['settings']['variant']=='source_v3':
        source=json.loads((ROOT/'results/icsa_fixed18_reclassification/source_advisories_fulltext_v3.json').read_text(encoding='utf-8'))
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True)
        page=browser.new_page(viewport=dict(width=1600,height=1100))
        errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(base+'/vex-decision.html',wait_until='networkidle')
        page.wait_for_selector('#av-assets button')
        assert page.locator('#av-assets button').count()==18
        assert page.locator('#av-assets button span').all_inner_texts()==[c['name'] for c in nav['categories']]
        assert 'A0001' not in page.locator('#av-assets').inner_text()
        assert 'All CVEs' not in page.locator('#av-assets').inner_text()
        assert f"{nav['metrics']['full_svd_cosine_silhouette']:.4f}" in page.locator('#av-cluster-metrics').text_content()
        assert ('target: met' if nav['metrics']['target_silhouette_met'] else 'target: not met') in page.locator('#av-cluster-metrics').text_content()
        for category in nav['categories']:
            page.locator('[data-group="'+category['id']+'"]').click()
            assert page.locator('#av-list-count').inner_text()==f"{category['cve_count']:,} distinct CVEs"
            visible=page.locator('[data-cve]').evaluate_all('(els)=>els.map(e=>e.dataset.cve)')
            assert set(visible)<=set(category['cves'])
            assert len(visible)==min(40,category['cve_count'])
        page.locator('[data-group="A0008"]').click()
        assert page.locator('#av-related-count').inner_text()=='8 related definitions'
        assert 'File Server' in page.locator('#av-related-definitions').text_content()
        for status in ['source_phrase','model_estimate','unassigned']:
            aid,d=next((aid,d) for aid,d in nav['assignment_details'].items() if d['status']==status)
            if d['asset_id']:page.locator('[data-group="'+d['asset_id']+'"]').click()
            else:page.locator('#av-unassigned').click()
            page.locator('#av-advisory').select_option(aid)
            text=page.locator('#av-advisory-info').inner_text()
            assert status.replace('_',' ') in text
            if status!='unassigned':
                assert page.locator('#av-advisory-info mark').count()>0
                source_text=next(a['feature_text'] for a in source['advisories'] if a['id']==aid)
                for quote in page.locator('#av-advisory-info mark').all_inner_texts():assert quote in source_text
            if status=='model_estimate':page.locator('#av-advisory-info').screenshot(path=str(ROOT/'results/icsa_fixed18_reclassification/explanation.png'))
        selected=next(c for c in nav['categories'] if c['cve_count']>40 and any(len(a['cves'])>2 for a in source['advisories'] if a['id'] in c['advisory_ids']))
        advisory=next(a for a in source['advisories'] if a['id'] in selected['advisory_ids'] and len(a['cves'])>2)
        page.locator('[data-group="'+selected['id']+'"]').click()
        page.locator('#av-next').click();assert page.locator('#av-page').inner_text().startswith('41')
        page.locator('#av-advisory').select_option(advisory['id'])
        assert page.locator('#av-list-count').inner_text()==f"{len(advisory['cves']):,} distinct CVEs"
        page.locator('#av-search').fill(advisory['cves'][0]);page.locator('#av-search-form button').click()
        assert page.locator('[data-cve]').count()==1
        page.locator('[data-cve]').click();page.wait_for_selector('#av-detail:not([hidden])')
        assert page.locator('#av-cve-title').inner_text()==advisory['cves'][0]
        page.locator('#av-search').fill('');page.locator('#av-unassigned').click()
        assert page.locator('#av-list-count').inner_text()==f"{nav['unassigned']['cve_count']:,} distinct CVEs"
        assert page.locator('#av-advisory option').count()==len(nav['unassigned']['advisory_ids'])+1
        page.locator('[data-group="'+selected['id']+'"]').click()
        page.evaluate("""fixture=>{const original=window.fetch;window.fetch=(input,options)=>String(input).endsWith('/api/cve-match/jobs/ui-fixture/vex')?Promise.resolve(new Response(JSON.stringify(fixture),{headers:{'Content-Type':'application/json'}})):original(input,options)}""",dict(job_id='ui-fixture',cves=[dict(cve=advisory['cves'][0],mappings=[])]))
        page.locator('#av-job').fill('ui-fixture');page.locator('#av-load-job').click();page.wait_for_selector('#av-detail:not([hidden])')
        assert page.locator('#av-list-count').inner_text()=='1 distinct CVEs in identification results'
        page.locator('#av-clear-job').click()
        page.wait_for_function("!document.getElementById('av-list-count').textContent.includes('identification results')")
        page.locator('#av-assets').screenshot(path=str(ROOT/'results/icsa_role_clusters_k18/asset_type_cards.png'))
        page.set_viewport_size(dict(width=390,height=844));assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        assert not errors,errors
        browser.close()
    print('Verified',base,': original 18 names, 43 related definitions, actual scores, source/estimated/unassigned explanations, all counts and filters, mobile width')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--base',required=True);verify(p.parse_args().base.rstrip('/'))
