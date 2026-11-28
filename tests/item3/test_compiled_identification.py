import hashlib
import json
import pytest
from src.item3.evidence.local_vulnerability_lookup import SourceCPELookup
from src.item3.matching.product_version_cve_matching import identify,identify_compiled
from src.item3.evidence.version_evidence import declared_interval


@pytest.mark.parametrize('version,raw,expected',[
    ('1.5',None,'true'),('3.0',None,'false'),(None,'vers:intdot/>=1|<2','true'),
    (None,'vers:intdot/>=1|<3','unknown'),(None,None,'unknown')])
def test_preparsed_source_conditions_preserve_general_match_semantics(tmp_path,version,raw,expected):
    conditions=[{'vulnerable':True,'criteria':'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
                 'versionStartIncluding':'1','versionEndExcluding':'2'},
                {'vulnerable':True,'criteria':'cpe:2.3:a:other:product:3.0:*:*:*:*:*:*:*'}]
    record={'id':'CVE-2099-0001','configurations':[{'cpeMatch':conditions}]}
    data=(json.dumps(record)+'\n').encode();(tmp_path/'cves.jsonl').write_bytes(data)
    (tmp_path/'manifest.json').write_text(json.dumps({'sha256':hashlib.sha256(data).hexdigest()}))
    source=SourceCPELookup(tmp_path)
    actual=['a','vendor','product',version,*([None]*7)]
    interval=declared_interval(raw) if raw else None
    compiled=source.identification_conditions(record['id'],tuple(actual[:3]))
    assert len(compiled)==1
    assert identify(record['configurations'],actual,'intdot',interval)==expected
    assert identify_compiled(compiled,actual,'intdot',interval)==expected


def test_identity_filter_retains_matching_wildcard_conditions(tmp_path):
    record={'id':'CVE-2099-0002','configurations':[{'cpeMatch':[
        {'vulnerable':True,'criteria':'cpe:2.3:a:vendor:product:9:*:*:*:*:*:*:*'},
        {'vulnerable':True,'criteria':'cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*'}]}]}
    data=(json.dumps(record)+'\n').encode();(tmp_path/'cves.jsonl').write_bytes(data)
    (tmp_path/'manifest.json').write_text(json.dumps({'sha256':hashlib.sha256(data).hexdigest()}))
    source=SourceCPELookup(tmp_path);actual=['a','vendor','product','1',*([None]*7)]
    compiled=source.identification_conditions(record['id'],tuple(actual[:3]))
    assert len(compiled)==2 and identify_compiled(compiled,actual)=='true'
