import json
from src.source_inventory import inventory,public_summary


def test_collection_and_compiler_attempts_have_distinct_scopes(tmp_path):
    folder=tmp_path/'data/source_snapshots'
    for c in ['CVE-2099-1000','CVE-2099-2000','CVE-2099-3000']:
        p=folder/c;p.mkdir(parents=True)
        if c!='CVE-2099-3000':(p/'code.c').write_text('int target(void){return 1;}')
    results=tmp_path/'results';(results/'campaign').mkdir(parents=True)
    (results/'current_source_campaign.json').write_text(json.dumps({'path':'results/campaign'}))
    (results/'campaign/summary.json').write_text(json.dumps({'results':[
        {'cve':'CVE-2099-1000','analysis_state':'blocked'},
        {'cve':'CVE-2099-4000','analysis_state':'partial'}]}))
    value=inventory(tmp_path,{'CVE-2099-1000','CVE-2099-3000','CVE-2099-4000'})
    assert value['snapshots_total']==2 and value['snapshots_in_corpus']==1
    assert value['no_local_snapshot']==2 and value['snapshots_outside_corpus']==1
    assert value['analysis_attempted_in_corpus']==1 and value['analysis_state_in_corpus']=={'blocked':1}
    assert value['snapshot_presence_verifies_complete_product'] is False
    assert 'analysis_records' not in public_summary(value)


def test_legacy_verdicts_cannot_create_collection_and_missing_campaign_cannot_erase_it(tmp_path):
    results=tmp_path/'results';results.mkdir()
    (results/'vex_v2_summary.json').write_text(json.dumps({'cves':[{'cve':'CVE-2099-1000'}]}))
    assert inventory(tmp_path,{'CVE-2099-1000'})['snapshots_in_corpus']==0
    p=tmp_path/'data/source_snapshots/CVE-2099-1000';p.mkdir(parents=True);(p/'code.c').write_text('code')
    value=inventory(tmp_path,{'CVE-2099-1000'})
    assert value['snapshots_in_corpus']==1 and value['analysis_attempted_in_corpus']==0


def test_inventory_page_uses_observed_counts_and_cwe_route_explanation():
    from src.api_server import STORE,make_page
    value=STORE.source_inventory
    assert value['snapshots_in_corpus']+value['no_local_snapshot']==len(STORE.by_cve)
    assert STORE.cve_level['by_source_class'].get('code-available',0)==value['snapshots_in_corpus']
    assert STORE.tier_a['code_collected']==value['snapshots_in_corpus']
    page=make_page('dataset')
    assert 'source-unobtainable' not in page and 'source cannot be obtained at all' not in page
    assert 'Source snapshot availability and analysis coverage' in page
    assert 'snapshots_in_corpus' in page and 'Eligible operational cases' in page
