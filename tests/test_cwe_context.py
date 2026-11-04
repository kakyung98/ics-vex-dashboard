from src.cwe_context import context
from src import cve_requirements as REQ,oc_vex_judge as JUDGE


def test_multiple_sources_and_placeholder_ids():
    c=context('CVE-2020-12345',nvd={'cwes':['CWE-78','NVD-CWE-noinfo']},corpus_cwe='CWE-20',supplied=['CWE-78','CWE-787'])
    assert [e['id'] for e in c['entries']]==['CWE-20','CWE-78','CWE-787']
    assert all(e['can_refute'] is False for e in c['entries'])
    assert c['entries'][0]['mapping_specificity']=='broad'


def test_cwe_only_never_creates_exploitation_conditions_or_clears_cve():
    for cwe in ['CWE-78','CWE-287','CWE-787','CWE-999999',None]:
        c=context('CVE-2020-12345',supplied=cwe)
        req=REQ.extract('CVE-2020-12345',cwe_context=c)
        result=JUDGE.judge_many([{'cve':'CVE-2020-12345','requirements':req,'asset':{'no_network_interface':True}}])
        assert result['statements'][0]['status']=='under_investigation'
        assert result['statements'][0]['cwe_context']==c


def test_adding_cwe_does_not_change_existing_context_decision():
    vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    base=REQ.extract('CVE-2020-12345',vector)
    added=REQ.extract('CVE-2020-12345',vector,cwe_context=context('CVE-2020-12345',supplied='CWE-78'))
    asset={'no_network_interface':True}
    assert JUDGE.judge('CVE-2020-12345',base,asset)['status']==JUDGE.judge('CVE-2020-12345',added,asset)['status']


def test_context_api_preserves_cwe_provenance_without_clearance():
    from fastapi.testclient import TestClient
    from src.api_server import app
    result=TestClient(app).post('/api/oc/judge',json={'asset':{'no_network_interface':True},
        'cves':[{'cve':'CVE-2099-12345','cwes':['CWE-78','CWE-787']}]})
    assert result.status_code==200,result.text
    statement=result.json()['statements'][0]
    assert statement['status']=='under_investigation'
    assert [e['id'] for e in statement['cwe_context']['entries']]==['CWE-78','CWE-787']
    assert statement['cwe_context']['entries'][0]['sources'][0]['source']=='request'
