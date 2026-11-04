from matcher import extract, norm, criterion_state, evaluate_nodes, run, NVD, CVE_API, CPE_API
import json

def test_cyclonedx():
    x=extract({'bomFormat':'CycloneDX','components':[{'name':'curl','version':'8.1.0'}]})
    assert x[0]['name']=='curl'

def test_version_ranges():
    c={'criteria':'cpe:2.3:a:example:controller:*:*:*:*:*:*:*:*',
       'vulnerable':True,'versionStartIncluding':'2.0','versionEndExcluding':'3.0'}
    assert criterion_state(c,'example','controller','2.5')=='true'
    assert criterion_state(c,'example','controller','3.0')=='false'
    assert criterion_state(c,'example','controller','vendor-revision')=='unknown'

def test_other_platform_condition_not_assumed():
    nodes=[{'operator':'AND','cpeMatch':[
      {'criteria':'cpe:2.3:a:example:controller:*:*:*:*:*:*:*:*','vulnerable':True},
      {'criteria':'cpe:2.3:o:other:os:*:*:*:*:*:*:*:*','vulnerable':False}]}]
    assert evaluate_nodes(nodes,'example','controller','1.0')=='unknown'

def test_missing_identity_no_crash():
    out=run({'bomFormat':'CycloneDX','components':[{'name':'','version':'1.0'}]},NVD(offline=True))
    assert out['components'][0]['validation']['status']=='unresolved'

def test_offline_no_fake_match():
    out=run({'bomFormat':'CycloneDX','components':[{'name':'libssl','version':'1.1.1g'}]},NVD(offline=True))
    assert out['components'][0]['cves']==[]
    assert out['components'][0]['validation']['status']=='unresolved'


def fixture_key(path, params):
    return json.dumps([path, params], sort_keys=True)


def test_verified_input_cpe_and_real_nvd_configuration_shape():
    cpe='cpe:2.3:a:curl:curl:8.1.0:*:*:*:*:*:*:*'
    fixtures={
        fixture_key(CPE_API, {'keywordSearch':'curl','resultsPerPage':100}):
            {'products':[{'cpe':{'cpeName':cpe}}]},
        fixture_key(CVE_API, {'cpeName':cpe,'resultsPerPage':2000}):
            {'vulnerabilities':[{'cve':{'id':'CVE-TEST-1','configurations':[
                {'nodes':[{'operator':'OR','cpeMatch':[{
                    'criteria':'cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*',
                    'vulnerable':True,'versionEndExcluding':'8.2.0'}]}]}]}}]},
    }
    result=run({'bomFormat':'CycloneDX','components':[
        {'name':'curl','version':'8.1.0','cpe':cpe}]}, NVD(offline=True,fixtures=fixtures))
    component=result['components'][0]
    assert component['validation']['status']=='validated'
    assert component['cves'][0]['match_status']=='match'
    assert component['cves'][0]['patch_status']=='not_checked'


def test_ambiguity_on_second_dictionary_page_is_rejected():
    params={'keywordSearch':'curl','resultsPerPage':100}
    fixtures={fixture_key(CPE_API,params):{'totalResults':2,'products':[
        {'cpe':{'cpeName':'cpe:2.3:a:curl:curl:8.1.0:*:*:*:*:*:*:*'}}]},
        fixture_key(CPE_API,dict(params,startIndex=1)):{'totalResults':2,'products':[
        {'cpe':{'cpeName':'cpe:2.3:a:another:curl:1.0:*:*:*:*:*:*:*'}}]}}
    result=run({'bomFormat':'CycloneDX','components':[{'name':'curl','version':'8.1.0'}]},
               NVD(offline=True,fixtures=fixtures))
    assert result['components'][0]['validation']['status']=='unresolved'


def test_nvd_failure_is_not_a_negative_match():
    class FailedNVD(NVD):
        def get(self, path, params):
            raise RuntimeError('service unavailable')
    result=run({'bomFormat':'CycloneDX','components':[{'name':'curl','version':'8.1.0'}]},FailedNVD())
    assert 'nvd_lookup_failure' in result['components'][0]['validation']['reasons']
    assert result['components'][0]['cves']==[]


def test_spdx_preserves_vendor_version():
    result=extract({'spdxVersion':'SPDX-2.3','packages':[{
        'SPDXID':'SPDXRef-1','name':'controller','versionInfo':'V4.6.2 HF3',
        'supplier':'Organization: Device Manufacturer'}]})
    assert result[0]['version']=='V4.6.2 HF3'
    assert result[0]['supplier']=='Organization: Device Manufacturer'
