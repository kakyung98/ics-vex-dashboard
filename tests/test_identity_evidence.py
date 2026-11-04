
from src.dataset_paths import public_sbom_file
from copy import deepcopy
import pytest
from src.identity_retrieval import ProductIndex
from src.identity_versions import version_info,compare_versions,evaluate_configurations,purl_parts
from src.identity_evidence import run_evidence,validate_identity
from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD,CPE_API

def index():
    def row(v,p,version='1.0',part='a'):
        return {'cpe':f'cpe:2.3:{part}:{v}:{p}:{version}:*:*:*:*:*:*:*','title':v+' '+p+' '+version}
    return ProductIndex([row('acme','controller'),row('other','controller'),row('haxx','curl'),row('haxx','curl','2.0'),row('openssl','openssl')],snapshot_hash='fixture')

def component(**kw):return {'name':'curl','version':'1.0','supplier':'','manufacturer':'','cpes':[],**kw}

def sbom(**kw):return {'bomFormat':'CycloneDX','components':[component(**kw)]}

def test_vendor_collision_cannot_be_resolved_by_supplier_alone():
    idx=index();c=component(name='controller',supplier='acme')
    candidates=idx.search(c,version_info(c))['candidates']
    assert validate_identity(c,candidates)['identity_status']=='ambiguous'
    c['manufacturer']='acme';candidates=idx.search(c,version_info(c))['candidates']
    assert validate_identity(c,candidates)['vendor']=='acme'

def test_explicit_vendor_name_and_duplicate_releases():
    idx=index();c=component(name='Acme Controller')
    r=idx.search(c,version_info(c));assert validate_identity(c,r['candidates'])['vendor']=='acme'
    c=component();r=idx.search(c,version_info(c));v=validate_identity(c,r['candidates'])
    assert v['product']=='curl' and v['status']=='validated'
    assert next(c for c in r['candidates'] if c['product']=='curl')['release_count']==2

def test_fuzzy_candidate_is_retrieved_without_auto_accepting():
    idx=index();c=component(name='curll')
    r=idx.search(c,version_info(c));assert any(x['product']=='curl' for x in r['candidates'])
    assert validate_identity(c,r['candidates'])['status']=='unresolved'
    assert r['ranking_scores_are_probabilities'] is False

def test_conflicting_name_and_verified_cpe_do_not_silently_override_each_other():
    idx=index();c=component(name='openssl',cpes=['cpe:2.3:a:haxx:curl:1.0:*:*:*:*:*:*:*'])
    r=idx.search(c,version_info(c));assert validate_identity(c,r['candidates'])['identity_status']=='conflicting_evidence'

def test_manufacturer_is_not_collapsed_into_supplier():
    r=run_evidence(sbom(name='controller',supplier={'name':'distributor'},manufacturer={'name':'acme'}),NVD(offline=True),index=index())
    c=r['components'][0]
    assert c['component']['supplier']=='distributor' and c['validation']['vendor']=='acme'

def test_name_version_is_provisional_and_synthetic_field_is_not_deployment_proof():
    r=version_info(component(name='EC Controller V3.3b63',version='NOASSERTION'))
    assert r['normalized'] is None and r['provisional_values']==['3.3b63']
    assert r['observations'][0]['evidence']=='V3.3b63'
    assert version_info(component(version='1.2'),synthetic=True)['normalized'] is None

@pytest.mark.parametrize('value',['<v2.1.7','1.2 and earlier','all'])
def test_ranges_or_opaque_text_are_not_installed_versions(value):
    assert version_info(component(version=value))['normalized'] is None

def test_version_conflicts_and_revision_preservation():
    r=version_info(component(version='v1.2.3-vendor4',purl='pkg:generic/curl@1.2.4'))
    assert r['status']=='conflict' and r['normalized'] is None
    r=version_info(component(version=' v1.2.3-vendor4 '))
    assert r['normalized']=='1.2.3-vendor4'
    assert compare_versions('1.2.3-vendor4','1.2.3-vendor5','unknown') is None
    assert compare_versions('1.0.0-alpha.9','1.0.0-alpha.10','semver')==-1
    assert compare_versions('1.0.0-rc.1','1.0.0','semver')==-1
    assert compare_versions('1.0.0+build.1','1.0.0+build.2','semver')==0
    assert compare_versions('1:2.3-1','2.3','debian')==1

@pytest.mark.parametrize('a,b,expected',[
    ('1.0~rc1','1.0',-1),('2.0^150825','2.0',1),('2.0^150825','2.0.1',-1),
    ('1.0','1+.+0',0),('abc123','abc.000123',0),('1.xyz','1.0',-1),
    ('1.0-5','1.0-1',1),('5:3.0-1','4:6.0-1',1),('1.0~beta1','1.0~rc1',-1)])
def test_rpm_documented_ordering(a,b,expected):
    assert compare_versions(a,b,'rpm')==expected
    assert compare_versions(b,a,'rpm')==-expected

def test_purl_parse_does_not_equate_namespace_to_vendor():
    p=purl_parts('pkg:maven/org.example/library@1.0.0?arch=x86_64#src/main')
    assert p['namespace']=='org.example' and p['name']=='library' and p['qualifiers']['arch']=='x86_64'
    assert 'vendor' not in p

def test_platform_and_or_and_unsupported_ordering_remain_unknown():
    m={'criteria':'cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*','vulnerable':True,'versionEndExcluding':'2.0.0'}
    platform={'criteria':'cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*','vulnerable':False}
    nodes=[{'operator':'AND','cpeMatch':[m,platform]}]
    assert evaluate_configurations(nodes,'haxx','curl','1.0.0','semver')=='unknown'
    assert evaluate_configurations([{'cpeMatch':[m]}],'haxx','curl','1.0.0','unknown')=='unknown'
    assert evaluate_configurations([{'cpeMatch':[m]}],'haxx','curl','1.0.0','semver')=='true'
    assert evaluate_configurations([{'cpeMatch':[m]}],'haxx','curl','1.0.0','semver','h')=='unknown'

def test_llm_cannot_invent_candidates_or_force_ambiguous_acceptance():
    calls=[]
    def bad(*args):calls.append(args);raise AssertionError('No model')
    r=run_evidence(sbom(name='controller'),NVD(offline=True),index=index(),use_llm=True,infer=bad)['components'][0]
    assert not calls and r['l2']['agent'] is None and r['validation']['status']=='unresolved'

def test_nonliteral_llm_version_span_is_rejected():
    r=version_info(component(name='Controller version build-12',version='NOASSERTION'),llm_spans=[{'source':'name','start':0,'end':5,'value':'9.9'}])
    assert r['rejected_spans']==['unsupported_llm_span'] and r['normalized'] is None

def test_unknown_version_still_queries_verified_product():
    class Fixture(NVD):
        def get_all(self,path,params,field):
            assert 'virtualMatchString' in params
            return {'vulnerabilities':[{'cve':{'id':'CVE-2099-12345','configurations':[]}}]}
    r=run_evidence(sbom(version='NOASSERTION'),Fixture(offline=True),index=index())['components'][0]
    assert r['validation']['status']=='validated' and r['cves'][0]['match_status']=='unknown'

def test_input_vulnerability_answers_are_not_used():
    data=sbom();data['vulnerabilities']=[{'id':'CVE-1999-999999'}]
    r=run_evidence(data,NVD(offline=True),index=index())
    assert not r['components'][0]['cves']

def test_dictionary_cpe_alone_does_not_prove_an_unknown_name():
    idx=index();c=component(name='Unidentified library',cpes=['cpe:2.3:a:haxx:curl:1.0:*:*:*:*:*:*:*'])
    assert validate_identity(c,idx.search(c,version_info(c))['candidates'])['status']=='unresolved'

def test_reviewed_alias_requires_vendor_scope_and_a_source():
    records=[{'cpe':'cpe:2.3:a:acme:control_app:1.0:*:*:*:*:*:*:*','title':'Acme Control App'}]
    alias={'kind':'product_alias','alias':'Control Suite','vendor':'acme','product':'control_app',
        'review_status':'reviewed','reviewer':'fixture-only','source':'https://example.invalid/vendor-record'}
    idx=ProductIndex(records,aliases=[alias]);c=component(name='Control Suite',manufacturer='acme')
    assert validate_identity(c,idx.search(c,version_info(c))['candidates'])['status']=='validated'
    c['manufacturer']='';assert validate_identity(c,idx.search(c,version_info(c))['candidates'])['status']=='unresolved'
    alias['review_status']='pending';idx=ProductIndex(records,aliases=[alias]);c['manufacturer']='acme'
    assert validate_identity(c,idx.search(c,version_info(c))['candidates'])['status']=='unresolved'

def test_component_type_constrains_cpe_part():
    idx=ProductIndex([{'cpe':'cpe:2.3:o:acme:control:1.0:*:*:*:*:*:*:*','title':'Acme Control OS'}])
    c=component(name='control',component_type='library')
    assert validate_identity(c,idx.search(c,version_info(c))['candidates'])['status']=='unresolved'

def test_calibration_cannot_use_test_or_weak_labels():
    from src.identity_calibration import calibrate
    with pytest.raises(ValueError):calibrate([{'split':'test'}])
    assert calibrate([])['runtime_fuzzy_acceptance'] is False
    rows=[{'split':'validation','review_status':'adjudicated','annotation_basis':'human_reviewed_identity','reviewers':['a','b'],
           'top1_correct':True,'score':.2,'margin':.1} for i in range(100)]
    result=calibrate(rows)
    assert result['status']=='no_threshold_meets_requirement' # zero errors/100 is insufficient for a 99% lower bound
    result=calibrate(rows,minimum_precision=.95)
    assert result['status']=='validation_threshold_proposed' and result['runtime_fuzzy_acceptance'] is False

def test_compatibility_cpu_job_handoff_preserves_provenance():
    from pathlib import Path
    import json,time
    from fastapi.testclient import TestClient
    from src.api_server import app
    data=json.loads((public_sbom_file('icsa-26-274-04_SBOM-CVE.json')).read_text(encoding='utf-8'))
    data['vulnerabilities']=[{'id':'CVE-1999-999999'}]
    client=TestClient(app);r=client.post('/api/cve-match/jobs',json={'sbom':data,'lookup_mode':'local','agent_mode':'evidence'})
    assert r.status_code==202,r.text
    jid=r.json()['id'];deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        job=client.get('/api/cve-match/jobs/'+jid).json()
        if job['status'] in {'completed','failed'}:break
        time.sleep(.05)
    assert job['status']=='completed',job
    result=job['result'];assert result['architecture']=='deterministic-identification-v1' and result['agent_mode']=='deterministic'
    assert result['summary']['unique_cves']==2 and result['summary']['errors']==0
    assert all(c['l2']['agent'] is None for c in result['components'])
    handoff=client.get('/api/cve-match/jobs/'+jid+'/vex').json()
    assert {c['cve'] for c in handoff['cves']}=={'CVE-2026-64892','CVE-2026-64893'}
    for case in handoff['cves']:
        assert case['version_decided'] is False
        assert all(m['identification_evidence']['architecture'] in {'evidence-v3','deterministic-identification-v1'} for m in case['mappings'])
