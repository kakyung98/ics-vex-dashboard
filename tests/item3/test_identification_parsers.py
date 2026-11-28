"""Source bindings and ranges must survive identification without invented releases."""
import json,hashlib
import pytest
from src.item3.matching.sbom_matching_engine import cpe_parts
from src.item3.evidence.version_evidence import version_info; from src.item3.evidence.version_evidence import declared_interval
from src.item3.matching.product_version_cve_matching import identify; from src.item3.matching.product_version_cve_matching import atom
from src.item3.evidence.product_candidate_search import ProductIndex


@pytest.mark.parametrize('product',[r'logo\!_soft_comfort',r'console\:edition',r'literal\*name',r'path\\name'])
def test_quoted_cpe_attributes_are_preserved(product):
    text='cpe:2.3:a:vendor:'+product+':1.2:*:*:*:*:*:*:*'
    fields=cpe_parts(text)
    assert len(fields)==13 and fields[4]==product
    assert ':'.join(fields)==text


@pytest.mark.parametrize('value',[
    'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*',
    'cpe:2.3:a:vendor::1:*:*:*:*:*:*:*',
    'cpe:2.3:a:vendor:product name:1:*:*:*:*:*:*:*',
    r'cpe:2.3:a:vendor:product\a:1:*:*:*:*:*:*:*',
    'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:'+chr(92),
])
def test_malformed_cpe_is_not_repaired(value):assert cpe_parts(value)==[]


def test_literal_escaped_wildcard_does_not_become_a_pattern():
    assert atom(r'name\*',r'name\*') is True
    assert atom(r'name\*','name_other') is False


def test_logo_product_is_in_the_dictionary_candidates():
    index=ProductIndex([{'cpe':r'cpe:2.3:a:siemens:logo\!_soft_comfort:8.3:*:*:*:*:*:*:*','title':'Siemens LOGO! Soft Comfort'}])
    component={'name':'LOGO! Soft Comfort','version':'vers:intdot/<9','manufacturer':'Siemens','supplier':'',
               'component_type':'application','cpes':[],'purl':None}
    result=index.search(component,version_info(component))
    assert result['candidates'][0]['product']==r'logo\!_soft_comfort'
    assert result['candidates'][0]['features']['exact_product']


def condition(raw,target,qualifier='*'):
    versions=version_info({'name':'fixture','version':raw,'cpes':[]})
    match={'criteria':f'cpe:2.3:a:vendor:fixture:*:*:*:*:*:{qualifier}:*:*','vulnerable':True,**target}
    return identify([{'cpeMatch':[match]}],['a','vendor','fixture',None,*([None]*7)],versions['scheme'],versions['declared_range'])


@pytest.mark.parametrize('target,expected',[
    ({'versionEndExcluding':'9'},'true'),
    ({'versionEndIncluding':'9'},'true'),
    ({'versionEndExcluding':'8.3'},'unknown'),
    ({'versionStartIncluding':'9'},'false'),
    ({'versionStartExcluding':'9'},'false'),
])
def test_whole_declared_range_is_compared_not_a_selected_version(target,expected):
    versions=version_info({'name':'fixture','version':'vers:intdot/<9','cpes':[]})
    assert versions['normalized'] is None and versions['comparison_version'] is None
    assert versions['status']=='declared_range' and versions['scheme']=='intdot'
    assert condition('vers:intdot/<9',target)==expected


def test_unknown_platform_attribute_remains_unknown_for_a_range():
    assert condition('vers:intdot/<9',{'versionEndExcluding':'9'},'linux')=='unknown'


def test_union_and_exclusions_are_kept_as_multiple_intervals():
    parsed=declared_interval('vers:intdot/>=1|!=2|<3')
    assert parsed is not None and len(parsed['intervals'])==2
    assert condition('vers:intdot/>=1|!=2|<3',{'versionStartIncluding':'1','versionEndExcluding':'3'})=='true'
    assert condition('vers:intdot/<1|>=2|<3',{'versionEndExcluding':'1'})=='unknown'


@pytest.mark.parametrize('value',['vers:intdot/>=9|<3','vers:intdot/<3|<4','vers:unknown/<9','vers:none/*','vers:intdot/=1.0'])
def test_unsupported_or_invalid_ranges_do_not_become_releases(value):
    info=version_info({'name':'fixture','version':value,'cpes':[]})
    assert info['normalized'] is None and info['declared_range'] is None


def test_concrete_version_outside_declared_range_is_a_conflict():
    info=version_info({'name':'fixture','version':'vers:intdot/<9',
                       'cpes':['cpe:2.3:a:vendor:fixture:10:*:*:*:*:*:*:*']})
    assert info['normalized'] is None and info['status']=='conflict'
    assert 'version_outside_declared_range' in info['conflicts']


def test_csaf_family_match_handles_punctuation_without_accepting_another_product():
    from src.item3.evidence.cisa_advisory_lookup import structured_product_match
    assert structured_product_match('LOGO! Soft Comfort','siemens','LOGO! Soft Comfort')
    assert structured_product_match('Siemens LOGO! Soft Comfort vers:intdot/<9','siemens','LOGO! Soft Comfort')
    assert not structured_product_match('LOGO! Soft Comfort Professional','siemens','LOGO! Soft Comfort')
    assert not structured_product_match('WinCC Runtime Comfort','siemens','LOGO! Soft Comfort')


def test_verified_local_csaf_is_used_and_modified_bytes_are_rejected(tmp_path,monkeypatch):
    from src.common.data import cve_evidence_catalog as evidence
    raw=b'{"document":{},"vulnerabilities":[{"cve":"CVE-2099-0001"}]}'
    (tmp_path/'data').mkdir();path=tmp_path/'data/case.json';path.write_bytes(raw)
    monkeypatch.setattr(evidence,'ROOT',tmp_path)
    row={'cves':['CVE-2099-0001'],'csaf_path':'case.json','local_csaf_file':'data/case.json','url':'https://example.test',
         'source_raw_sha256':hashlib.sha256(raw).hexdigest(),
         'csaf_sha256':hashlib.sha256(json.dumps(json.loads(raw),sort_keys=True).encode()).hexdigest()}
    monkeypatch.setattr(evidence,'advisories',lambda:{'case':row})
    evidence.documents.cache_clear()
    try:
        assert len(evidence.documents('CVE-2099-0001'))==1
        path.write_bytes(raw+b' ');evidence.documents.cache_clear()
        assert evidence.documents('CVE-2099-0001')==[]
    finally:evidence.documents.cache_clear()


def test_cisa_candidates_follow_verified_affected_relations_and_remain_unknown(tmp_path,monkeypatch):
    from src.item3.evidence import cisa_advisory_lookup as cisa
    (tmp_path/'data').mkdir()
    document={'product_tree':{'branches':[{'category':'vendor','name':'Siemens','branches':[
        {'category':'product_name','name':'LOGO! Soft Comfort','branches':[
            {'category':'product_version_range','name':'vers:intdot/<9',
             'product':{'product_id':'p1','name':'LOGO! Soft Comfort <9'}}]}]}]},
        'vulnerabilities':[{'cve':'CVE-2099-0001','product_status':{'known_affected':['p1']}}]}
    raw=json.dumps(document).encode();(tmp_path/'data/case.json').write_bytes(raw)
    row={'source':'CISA CSAF','vendor':'Siemens','vendors':['Siemens'],'products':['LOGO! Soft Comfort'],
         'affected_products':['LOGO! Soft Comfort <9'],'url':'https://www.cisa.gov/news-events/ics-advisories/case',
         'local_csaf_file':'data/case.json','source_raw_sha256':hashlib.sha256(raw).hexdigest(),
         'csaf_sha256':hashlib.sha256(json.dumps(document,sort_keys=True).encode()).hexdigest()}
    index=json.dumps({'case':row}).encode();(tmp_path/'data/cisa_advisories.json').write_bytes(index)
    (tmp_path/'data/cisa_reference_manifest.json').write_text(json.dumps({'index_sha256':hashlib.sha256(index).hexdigest()}))
    monkeypatch.setattr(cisa,'ROOT',tmp_path)
    caches=[cisa.source_records,cisa.structured_relations,cisa.advisory_index,cisa.family_index]
    for cache in caches:cache.cache_clear()
    try:
        result=cisa.retrieve({'name':'LOGO! Soft Comfort','manufacturer':'Siemens'})
        assert len(result)==1 and result[0]['cve_id']=='CVE-2099-0001'
        assert result[0]['match_status']=='unknown' and result[0]['evidence']['version_confirmed'] is False
        assert cisa.retrieve({'name':'WinCC Runtime Comfort','manufacturer':'Siemens'})==[]
    finally:
        for cache in caches:cache.cache_clear()
