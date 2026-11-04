import json
from src.candidate_snapshot import SnapshotNVD
from ics_agent_matcher_full.ics_agent_matcher.matcher import CVE_API


def test_explicit_evaluation_index_is_used_instead_of_live_corpus(tmp_path):
    path=tmp_path/'frozen.json'
    path.write_text(json.dumps({'by_product':{'test_product':[{'vendor':'test_vendor','cve':'CVE-2000-1234'}]}}),encoding='utf-8')
    nvd=SnapshotNVD(index_path=path)
    result=nvd.get_all(CVE_API,{'virtualMatchString':'cpe:2.3:a:test_vendor:test_product:*:*:*:*:*:*:*:*'},'vulnerabilities')
    assert [r['cve']['id'] for r in result['vulnerabilities']]==['CVE-2000-1234']
    assert result['vulnerabilities'][0]['cve']['configurations']==[]
