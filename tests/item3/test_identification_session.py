from copy import deepcopy

from src.item3.evidence.product_candidate_search import ProductIndex
from src.item3.evidence.product_identity_evidence import grounded_versions,prepare_candidates
from src.item3.agents.agent_routing import conditions
from src.item3.matching.identification_pipeline import run_unified
from src.item3.matching.identification_session import IdentificationSession


CPE='cpe:2.3:a:fixture_vendor:fixture_product:1.0:*:*:*:*:*:*:*'


class Lookup:
    def __init__(self):self.calls=0
    def get_all(self,*args):
        self.calls+=1
        return {'vulnerabilities':[{'cve':{'id':'CVE-2099-0001','configurations':[{
            'cpeMatch':[{'criteria':CPE.replace(':1.0:',':*:'),'vulnerable':True,
                         'versionStartIncluding':'1.0','versionEndExcluding':'2.0'}]}]}}]}


def bom(ref='a',version='1.3',cpe=True):
    component={'bom-ref':ref,'type':'application','name':'fixture_product','version':version,
               'manufacturer':{'name':'fixture_vendor'}}
    if cpe:component['cpe']=CPE.replace(':1.0:',':'+version+':')
    return {'bomFormat':'CycloneDX','components':[component]}


def index():return ProductIndex([{'cpe':CPE,'title':'Fixture product'}])


def reject_model(*args):raise AssertionError('Independent exact evidence needs no model')


def test_declared_release_uses_cve_bounds_without_a_registry_release_or_model():
    result=run_unified(bom(),Lookup(),index=index(),agents=reject_model,mode='agents',mapping_scope='identification')
    row=result['components'][0]
    assert row['validation']['status']=='validated'
    assert row['cves'][0]['match_status']=='match'
    assert row['routing']['executed_agents']==[]
    assert row['i1']['retrieval']['indexes']['vector'] is False


def test_exact_vendor_product_does_not_require_an_invented_identifier():
    result=run_unified(bom(cpe=False),Lookup(),index=index(),agents=reject_model,mode='agents',mapping_scope='identification')
    assert result['components'][0]['cves'][0]['match_status']=='match'
    assert result['components'][0]['routing']['executed_agents']==[]


def test_model_review_can_defer_an_otherwise_confirmed_match():
    calls = []
    def defer(task, packet):
        calls.append(task)
        if task=='I1':
            candidate=next(c for c in packet['candidates'] if not c['conflicts'])
            return dict(prediction=dict(ranked_candidate_ids=[candidate['candidate_id']],status='ranked',
                evidence_refs=['input:name','dictionary:'+candidate['candidate_id']]),llm_used=True)
        return dict(prediction=dict(candidate_id=None, status='unresolved',
                                    evidence_refs=['input:name']), llm_used=True)
    defer.require_identity_review = True
    result = run_unified(bom(), Lookup(), index=index(), agents=defer,
                         mode='agents', mapping_scope='identification')
    row = result['components'][0]
    assert calls == ['I1','I3']
    assert row['i3']['agent']['status'] == 'abstained'
    assert row['validation']['status'] == 'unresolved'
    assert row['cves'] == []


def test_default_service_provider_requires_model_review(monkeypatch):
    from src.item3.matching import identification_pipeline as pipeline
    calls=[]
    def tuned(task,packet):
        calls.append(task)
        if task=='I1':
            candidate=next(c for c in packet['candidates'] if not c['conflicts'])
            return dict(prediction=dict(ranked_candidate_ids=[candidate['candidate_id']],status='ranked',
                evidence_refs=['input:name','dictionary:'+candidate['candidate_id']]),
                llm_used=True,model_mode='fine_tuned')
        candidate=next(c for c in packet['candidates'] if c['eligible_for_selection'])
        return dict(prediction=dict(candidate_id=candidate['candidate_id'],status='validated',
            evidence_refs=['input:name','dictionary:'+candidate['candidate_id']]),
            llm_used=True,model_mode='fine_tuned')
    tuned.require_identity_review=True
    assert pipeline.infer_agent.require_identity_review is True
    monkeypatch.setattr(pipeline,'infer_agent',tuned)
    result=pipeline.run_unified(bom(),Lookup(),index=index(),mode='agents',mapping_scope='identification')
    assert calls==['I1','I3'] and result['llm_used']
    assert result['trained_identity_roles']==['I1','I3']
    assert result['components'][0]['cves'][0]['match_status']=='match'


def test_required_model_failure_does_not_fall_back_to_confirmed_rules():
    def unavailable(task,packet):
        raise RuntimeError('model unavailable')
    unavailable.require_identity_review=True
    result=run_unified(bom(),Lookup(),index=index(),agents=unavailable,mode='agents',mapping_scope='identification')
    assert result['components'][0]['validation']['status']=='unresolved'
    assert not result['components'][0]['cves']


def test_i1_without_actual_model_use_cannot_confirm_identity():
    def structural_rank(task,packet):
        if task=='I1':
            candidate=next(c for c in packet['candidates'] if not c['conflicts'])
            return dict(prediction=dict(ranked_candidate_ids=[candidate['candidate_id']],status='ranked',
                evidence_refs=['input:name','dictionary:'+candidate['candidate_id']]),llm_used=False)
        return dict(prediction=dict(candidate_id=None,status='unresolved',evidence_refs=['input:name']),llm_used=True)
    structural_rank.require_identity_review=True
    result=run_unified(bom(),Lookup(),index=index(),agents=structural_rank,mode='agents',mapping_scope='identification')
    assert 'I1' in result['components'][0]['routing']['executed_agents']
    assert result['components'][0]['validation']['status']=='unresolved'
    assert not result['components'][0]['cves']


def test_manufacturer_conflict_is_deferred_without_a_useless_model_choice():
    c=dict(name='fixture_product',version='1.3',supplier='',manufacturer='different_vendor',
           component_type='application',purl=None,cpes=[CPE])
    ix=index();versions=grounded_versions(c,ix,allow_declared_cpe_version=True)
    _,prepared=prepare_candidates(c,versions,ix)
    decisions=conditions(c,versions,prepared,ix)
    assert not decisions['I1']['required'] and not decisions['I3']['required']
    assert decisions['I1']['reasons']==['no_independently_supported_identity']
    result=run_unified({'bomFormat':'CycloneDX','components':[{
        'type':'application','name':'fixture_product','version':'1.3',
        'manufacturer':{'name':'different_vendor'},'cpe':CPE.replace(':1.0:',':1.3:')}]},
        Lookup(),index=ix,agents=reject_model,mode='agents',mapping_scope='identification')
    assert result['components'][0]['validation']['status']=='unresolved'
    assert result['components'][0]['cves']==[]


def test_session_rebinds_references_and_isolates_mutation_and_versions():
    ix=index();source=Lookup();session=IdentificationSession(compact=True)
    options=dict(index=ix,mode='rules',mapping_scope='identification',component_cache=session)
    a=run_unified(bom('a'),source,**options)
    a['components'][0]['cves'][0]['match_status']='caller_mutation'
    b=run_unified(bom('b'),source,**options)
    assert b['components'][0]['component']['id']=='b'
    assert b['components'][0]['cves'][0]['match_status']=='match'
    assert source.calls==1 and session.hits==1
    c=run_unified(bom('c','3.0'),source,**options)
    assert source.calls==2 and not c['components'][0]['cves']
    assert c['components'][0]['nonmatching_cve_count']==1


def test_session_does_not_mix_vulnerability_sources():
    ix=index();session=IdentificationSession();first=Lookup();second=Lookup()
    for source in (first,second):
        run_unified(bom(),source,index=ix,mode='rules',mapping_scope='identification',component_cache=session)
    assert first.calls==second.calls==1 and session.hits==0


def test_catalog_model_digits_do_not_override_explicit_release_or_hide_conflicts():
    cpe=CPE.replace('fixture_product','controller_v2')
    ix=ProductIndex([{'cpe':cpe,'title':'Controller V2'}])
    component=dict(name='Controller V2',version='1.3',manufacturer='fixture_vendor',
                   supplier='',component_type='application',purl=None,cpes=[cpe.replace(':1.0:',':1.3:')])
    versions=grounded_versions(component,ix,allow_declared_cpe_version=True)
    assert versions['normalized']=='1.3' and not versions['conflicts']
    assert versions['catalog_model_observations']
    component['version']='3.0'
    versions=grounded_versions(component,ix,allow_declared_cpe_version=True)
    assert versions['normalized'] is None and versions['conflicts']
    component.update(version='',cpes=[])
    versions=grounded_versions(component,ix,allow_declared_cpe_version=True)
    assert versions['normalized'] is None


def test_fast_identity_proof_still_checks_cve_edition_conditions():
    class EditionLookup(Lookup):
        def get_all(self,*args):
            result=super().get_all(*args)
            fields=CPE.replace(':1.0:',':*:').split(':');fields[7]='enterprise'
            result['vulnerabilities'][0]['cve']['configurations'][0]['cpeMatch'][0]['criteria']=':'.join(fields)
            return result
    source=bom();fields=source['components'][0]['cpe'].split(':');fields[7]='community'
    source['components'][0]['cpe']=':'.join(fields)
    result=run_unified(source,EditionLookup(),index=index(),agents=reject_model,
                       mode='agents',mapping_scope='identification')
    assert result['components'][0]['validation']['status']=='validated'
    assert result['components'][0]['cves'][0]['match_status']=='no_match'
