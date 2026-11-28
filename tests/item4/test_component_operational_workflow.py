"""Architecture handoffs and unsafe language-context regression checks."""
from copy import deepcopy
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.item4.workflow import component_review_workflow as W
from src.item4.decision import evidence_based_vex as E; from src.item4.models import operating_record_review_model as O
from src.item4.analysis import exploitation_prerequisites as V; from src.item4.decision import attack_graph_builder as G; from src.item4.models import json_inference_client as L
from tools.item4.auto_vex_fixture_support import profile, request
from tools.item4 import serve_nist_operational_vex as S


class WorkflowContract(unittest.TestCase):
    def setUp(self):
        # Source-bound synthetic inference and structural graph fixture: these
        # assertions verify handoffs without loading a GPU or external MulVAL.
        original=E.registry()['rules']['CVE-2014-0198']
        def infer(record):
            ref=dict(source_id=record['sources'][0]['id'],quote=original['questions'][0]['source']['quote'])
            draft=dict(format=V.VERSION,cve=record['cve'],prerequisites=[dict(id='buffers',predicate='feature_enabled',target='SSL_MODE_RELEASE_BUFFERS',value='',statement='SSL_MODE_RELEASE_BUFFERS must be enabled',operator_observable=True,source_refs=[ref],operator='eq',expected=True,operational_quote='SSL_MODE_RELEASE_BUFFERS is\nenabled',observation=dict(kind='configuration',record_type='configuration_export',check='Check the applied SSL_MODE_RELEASE_BUFFERS configuration'))],scenarios=[dict(id='route',product_keys=[record['products'][0]['key']],expression=dict(condition='buffers'),source_refs=[ref])],nonrequirements=[],unknowns=[])
            return V.extract(record,runner=lambda *a,**k:dict(prediction=draft,model={'name':'synthetic'},llm_used=True))
        def graph(*args):
            value=G.source_contract(*args);value['generation_status']='complete'
            value['sha256']=G.digest({k:v for k,v in value.items() if k!='sha256'});return value
        for target,name,effect in [(V,'resolve',infer),(G,'build',graph)]:
            mock=patch.object(target,name,side_effect=effect);mock.start();self.addCleanup(mock.stop)

    def test_query_links_retain_source_and_graph_binding(self):
        p=E.plan('CVE-2014-0198',profile())
        links=p['workflow_contract']['query_graph_links']
        self.assertEqual({x['question_id'] for x in links},{q['id'] for q in p['questions']})
        for link in links:
            self.assertTrue(link['graph_node_present'])
            self.assertTrue(link['exploit_source']['source_sha256'])
            self.assertTrue(all(f['nist_basis'] for f in link['fields']))
        self.assertIn('llm_vep_operating_record_review',p['workflow_contract']['stages'])
        self.assertEqual(p['workflow_contract']['exports'],['OpenVEX','CycloneDX VEX'])

    def test_asset_changes_guidance_without_dropping_cve_conditions(self):
        ap=profile(asset_index=0);bp=profile(asset_index=2)
        for key in ('observed_at','valid_until'):bp['scope'][key]=ap['scope'][key]
        a=E.plan('CVE-2014-0198',ap)
        b=E.plan('CVE-2014-0198',bp)
        self.assertEqual(a['questions'],b['questions'])
        self.assertNotEqual(a['workflow_contract']['asset_context']['type_specific_collection_topics'],
                            b['workflow_contract']['asset_context']['type_specific_collection_topics'])
        self.assertFalse(a['workflow_contract']['asset_context']['supplies_condition_truth'])

    def test_advisory_estimate_cannot_become_product_bound_fact(self):
        record={'products':[{'key':'icsa-25-001-01:CSAFPID-1','aliases':['Widget']}],
                'sources':[{'id':'nvd:CVE-2025-12345','url':'https://nvd.nist.gov/vuln/detail/CVE-2025-12345'}]}
        nav={'advisory_asset_ids':{'icsa-25-001-01':['A0003']},
             'assignment_details':{'icsa-25-001-01':{'status':'model_estimate'}},
             'advisory_product_evidence':{'icsa-25-001-01':[{'product_key':'icsa-25-001-01:OTHER','asset_id':'A0003'}]}}
        with patch.object(W.P,'get',return_value=record),patch.object(W.A,'asset_navigation',return_value=nav):
            out=W.source_context('CVE-2025-12345','Widget')
            suggestion=out['asset_type_suggestions'][0]
            self.assertEqual(suggestion['scope'],'advisory_context_only')
            self.assertTrue(suggestion['requires_confirmation'])
            self.assertEqual(suggestion['product_bindings'],[])
            self.assertEqual(out['cross_references'][0]['cve'],'CVE-2025-12345')
            self.assertEqual(W.source_context('CVE-2025-12345','Different')['asset_type_suggestions'],[])

    def test_raw_bom_enters_existing_identification_not_import_only(self):
        from src.item3.web import identification_jobs_api as candidate_web
        bom={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,
             'components':[{'bom-ref':'x','type':'library','name':'OpenSSL','version':'1.0.1g'}]}
        with patch.object(candidate_web,'submit',return_value={'id':'test','status':'queued'}) as submit:
            r=TestClient(S.app).post('/api/bom-vex/start',json=bom)
        self.assertEqual(r.status_code,200,r.text)
        submit.assert_called_once_with(bom,agent_mode='unified',lookup_mode='local')


class ContextRegression(unittest.TestCase):
    def question(self):
        return O.annotate(dict(id='buffers',label='Is the feature enabled?',source={},options={}),dict(origin='workstation'))

    def test_noncurrent_excerpts_never_load_model_or_claim_safe(self):
        for text in ['Historical record: the feature is disabled.',
                     'Proposed change: disable the feature; implementation pending.']:
            with patch.object(L,'generate',side_effect=AssertionError('Noncurrent state must abstain')):
                result=O.compare(self.question(),[dict(id='r',excerpt=text)],'complete')
            self.assertEqual(result['value'],'unknown');self.assertFalse(result['executed'])

    def test_unknown_record_cannot_be_overridden_by_confident_record(self):
        evidence=[dict(id='a',excerpt='Current complete inspection: the feature is disabled.'),
                  dict(id='b',excerpt='The running feature state could not be verified.')]
        prediction=dict(records=[dict(evidence_id='a',value='false',quote_evidence_id='a',current_applied_state=True,scope_matches=True,reason='Current complete negative'),
                                 dict(evidence_id='b',value='unknown',quote_evidence_id='',current_applied_state=True,scope_matches=True,reason='Missing state')])
        result=O.compare(self.question(),evidence,'complete',runner=lambda *a,**k:dict(prediction=prediction,model={'name':'synthetic'},llm_used=True))
        self.assertEqual(result['value'],'unknown');self.assertTrue(result['executed'])

    def test_current_record_negating_a_proposal_reaches_model_review(self):
        text='Current applied configuration: the feature is disabled. This is not a proposed change.'
        prediction=dict(records=[dict(evidence_id='r',value='false',quote_evidence_id='r',
            current_applied_state=True,scope_matches=True,reason='Current complete inspection')])
        result=O.compare(self.question(),[dict(id='r',excerpt=text)],'complete',
                         runner=lambda *a,**k:dict(prediction=prediction,model={'name':'synthetic'},llm_used=True))
        self.assertTrue(result['executed']);self.assertEqual(result['value'],'false')

if __name__=='__main__':unittest.main()
