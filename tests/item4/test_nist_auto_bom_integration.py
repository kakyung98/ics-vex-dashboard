"""HTTP integration for BOM import, case-scoped inputs, exports and retained review data."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
from src.item4.workflow import source_analysis_jobs as Q; from src.item4.decision import asset_vex_assessment as E
from tests.item4.test_item4_asset_key_workflow import fixture_job, graph_fixture
from tools.item4 import serve_nist_operational_vex as S
from tools.item4.auto_vex_fixture_support import profile


class AutomaticBomIntegration(unittest.TestCase):
    start_url = '/api/item4/analyses/start'

    def setUp(self):
        self.client = TestClient(S.app)
        self.addCleanup(self.client.close)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.w = S.service.bom_vex_workflow
        self.patch(Q.store, 'DB', Path(temp.name) / 'sessions.sqlite3')
        self.patch(self.w, 'DB', Path(temp.name) / 'workflows.sqlite3')
        self.patch(S.service.operational_vex_api, 'DB', Path(temp.name) / 'reviews.sqlite3')
        self.patch(Q, 'JOBS', {})
        self.patch(Q, 'extraction_identity', return_value='fixture')
        self.submit = self.patch(Q.QUEUE, 'submit')
        self.example, self.packet = fixture_job()
        from src.item4.analysis import asset_operating_question_generation as V3
        run_questions=V3.run_job
        def model(system,wire,**kwargs):
            return dict(llm_used=True,model=dict(model='integration-fixture'),prediction=dict(questions={
                key:dict(positive_fact=atom['positive_fact'],question=atom['question_contract']['question'],
                    check=atom['observation']['check'],record_type=atom['observation']['record_type'],confidence=95)
                for key,atom in wire['atoms'].items()}))
        self.patch(V3,'run_job',side_effect=lambda job,progress=None,**kw:run_questions(job,progress,runner=model))
        self.bom = deepcopy(self.example['input_bom'])

    def patch(self, obj, name, *args, **kwargs):
        p = patch.object(obj, name, *args, **kwargs)
        result = p.start()
        self.addCleanup(p.stop)
        return result

    def post(self, path, payload):
        response = self.client.post(path, json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def start(self, bom, **kwargs):
        queued = self.post(self.start_url, dict(bom=bom, **kwargs))
        self.url = '/api/item4/analyses/jobs/' + queued['id']
        return queued

    def complete(self):
        def extract(cve, _components, **kwargs):
            if cve == self.packet['cve']:
                return deepcopy(self.example['conditions'][0])
            return dict(cve=cve, status='unresolved', reason='No fixture source')
        with patch.object(Q, 'classify', return_value=self.example['asset_classification']), \
                patch.object(Q, 'extract_declared', side_effect=extract):
            run, *args = self.submit.call_args.args
            run(*args)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.text)
        job = response.json()
        self.assertEqual(job['status'], 'completed', job.get('error'))
        return job

    @staticmethod
    def token(job):
        return dict(revision=job['revision'], plan_sha256=job['plan_sha256'])

    def test_identification_handoff_preserves_multiple_cves_without_prior_verdict(self):
        component = {'id':'component','name':'Fixture Library','version':'1.0'}
        ids = ['CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10003']
        findings = dict(components=[dict(component=component, validation=dict(status='validated'),
                               cves=[dict(cve_id=c, match_status='match') for c in ids])])
        imported = self.w.create_from_json(findings)
        self.assertTrue(all(c['match_status']=='unknown' for c in imported['cases']))
        bom = self.w.export(imported['id'], 'bom')
        key = 'a' * 32
        job = self.start(bom, request_id=key)
        repeat = self.start(bom, request_id=key)
        self.assertEqual(repeat['id'], job['id'])
        self.submit.assert_called_once()
        self.assertEqual([d['cve'] for d in job['declared_cves']], ids)
        self.assertEqual(job['components'][0]['version'], '1.0')
        changed = deepcopy(bom)
        changed['components'][0]['version'] = '2.0'
        self.assertEqual(self.client.post(self.start_url, json=dict(bom=changed, request_id=key)).status_code, 422)

    def test_upload_preserves_component_ref_and_disregards_embedded_verdict(self):
        self.bom['vulnerabilities'][0]['analysis'] = {'state':'not_affected'}
        self.start(self.bom)
        job = self.complete()
        self.assertEqual(job['assessment_cases'][0]['declared_ref'], 'asset')
        self.assertEqual(job['product_vex_status'], 'under_investigation')
        self.assertIsNone(job.get('assessment'))
        self.assertEqual(self.client.get(self.url+'/export/openvex').status_code, 422)

    def test_unsupported_malformed_and_unidentified_input(self):
        for bom in [{}, [], {'components':[{'name':'invalid'}]}, dict(self.bom, vulnerabilities=[])]:
            with self.subTest(bom=bom):
                self.assertEqual(self.client.post(self.start_url, json={'bom':bom}).status_code, 422)
        self.assertEqual(self.client.post(self.start_url, content='{broken').status_code, 422)
        self.submit.assert_not_called()

    def test_operational_pages_use_asset_key_workflow_and_hide_manual_verdict(self):
        for url in ['/bom-vex.html?legacy=1', '/vex-decision.html', '/item4.html']:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            doc = BeautifulSoup(response.text, 'html.parser')
            self.assertEqual(doc.select_one('#bom-file')['type'], 'file')
            self.assertIsNotNone(doc.select_one('#questions-section #save-inputs'))
            self.assertIsNotNone(doc.select_one('#questions-section #assess'))
            self.assertIsNotNone(doc.select_one('#assessment-result #download-openvex'))
            self.assertFalse(doc.select('#bw-job,#ov-finding-status,#ov-proof-builder,#ov-new-conclusion'))
            self.assertLess(len(response.content), 2_000_000)

    def test_profile_and_verdict_cannot_override_target_or_decision(self):
        self.start(self.bom)
        job = self.complete()
        for target, field in [('answers','profile'), ('answers','component_ref'), ('assess','bindings'),
                              ('assess','typed_review'), ('assess','product_finding'), ('assess','status')]:
            with self.subTest(field=field):
                response = self.client.post(self.url+'/'+target, json=dict(self.token(job), **{field:'not_affected'}))
                self.assertEqual(response.status_code, 422)
        self.assertIsNone(self.client.get(self.url).json()['assessment'])

    def test_historical_mismatched_profile_cannot_authorize_a_saved_review(self):
        findings = dict(components=[dict(component=dict(id='asset',name='DifferentProduct',version='1.0'),
            cves=[dict(cve_id='CVE-2014-0198',match_status='match')])])
        w = self.w.create_from_json(findings)
        case = w['cases'][0]
        p = profile()
        # Retain the historical internal-store safeguard; an exported document
        # must not reuse a saved assessment for another product.
        w['profiles']['asset'] = dict(profile=p)
        payload = dict(cve=case['cve'], profile=p)
        rid = S.service.operational_vex_api.save(payload, dict(reviewed_at='2026-01-01T00:00:00Z',
                                                               assessment_sha256='a'*64))
        w['reviews'][case['id']] = dict(review_id=rid,profile_sha256=self.w.digest(p),
                                        bom_sha256=w['bom_sha256'],mapping_review={})
        self.w.store(w)
        with self.assertRaisesRegex(ValueError,'[Pp]roduct'):
            self.w.assess(w['id'],case['id'], dict(revision=w['revision'],bom_sha256=w['bom_sha256'],assessment=payload))
        self.assertEqual(self.w.export(w['id'],'openvex',case['id'])['statements'][0]['status'], 'under_investigation')
        vex = self.w.export(w['id'],'bom-vex',case['id'])
        self.assertEqual(vex['vulnerabilities'][0]['analysis']['state'], 'in_triage')

    def test_case_specific_inputs_and_calculated_exports(self):
        unknown = 'CVE-2099-99999'
        self.bom['vulnerabilities'].append(dict(id=unknown,affects=[dict(ref='asset')]))
        self.start(self.bom)
        job = self.complete()
        question, = job['questions']
        self.assertEqual(question['cve'], self.packet['cve'])
        self.assertEqual({c['cve'] for c in job['assessment_cases']}, {self.packet['cve'],unknown})
        context = dict(scope='current_single',mode='normal',origin='same_zone')
        for case in job['assessment_cases']:
            context[case['prefix']+'deployment'] = 'running'
            context[case['prefix']+'runtime'] = 'bom'
        saved = self.post(self.url+'/answers',dict(self.token(job),answers={question['id']:'o'},
                                                    context_answers=context))
        def binding(cve, component, result):
            bound = cve == self.packet['cve']
            return dict(state='vulnerable' if bound else 'unknown', product_bound=bound,
                        condition_product_bound=bound, sources=[])
        with patch.object(Q,'description_packet',return_value=self.packet), \
                patch.object(E,'version_binding',side_effect=binding), patch.object(E.G,'build',side_effect=graph_fixture):
            result = self.post(self.url+'/assess',self.token(saved))
            response = self.client.get(self.url+'/export/openvex')
        self.assertEqual(response.status_code, 200, response.text)
        expected = {self.packet['cve']:'affected', unknown:'under_investigation'}
        self.assertEqual({r['cve']:r['status'] for r in result['assessment']['decisions']}, expected)
        self.assertEqual({s['vulnerability']['name']:s['status'] for s in response.json()['statements']}, expected)

    def test_stale_source_plan_returns_conflict_and_preserves_saved_input(self):
        self.start(self.bom)
        job = self.complete()
        current = self.post(self.url+'/answers',dict(self.token(job),answers={job['questions'][0]['id']:'o'}))
        for action in ('answers','assess'):
            for token in (self.token(job), dict(self.token(current),plan_sha256='0'*64)):
                response = self.client.post(self.url+'/'+action, json=token)
                self.assertEqual(response.status_code, 409)
        self.assertEqual(self.client.get(self.url).json()['answers'], current['answers'])

    def test_prior_benchmark_is_labelled_historical_for_the_corrected_engine(self):
        for url in ['/nist-population-vex-method.html','/bom-vex-method.html']:
            response = self.client.get(url)
            self.assertEqual(response.status_code,200)
            self.assertIn('id="benchmark-history-notice"',response.text)
            self.assertIn(S.V.VERSION,response.text)

    def test_population_registry_exposes_sources_outside_specializations(self):
        cve = 'CVE-2011-4051'
        manifest = dict(version='fixture',population_count=12418,population_sha256='a'*64,sha256='b'*64,counts={})
        record = dict(cve=cve,products=[dict(key='product')],compiled={'fixture':True})
        with patch.object(S.population,'manifest',return_value=manifest), patch.object(S.population,'get',return_value=record):
            registry = self.client.get('/nist-auto-vex-rules.json').json()
            self.assertNotIn(cve, registry['rules'])
            self.assertEqual(registry['population'], manifest)
            source = self.client.get('/api/operational-vex/compiled-source/'+cve)
            self.assertEqual(source.status_code, 200)
            self.assertEqual(source.json()['products'], record['products'])
            self.assertEqual(source.json()['historical_compilation'], record['compiled'])
            self.assertFalse(source.json()['historical_compilation_used_for_current_decisions'])
            self.assertEqual(self.client.get('/api/operational-vex/compiled-source/not-a-cve').status_code,400)

    def test_fixed_version_requires_confirmation_of_the_running_build(self):
        cve = 'CVE-2010-5298'
        self.bom['metadata']['component'].update(name='OpenSSL', version='1.0.1h')
        self.bom['vulnerabilities'][0]['id'] = cve
        self.start(self.bom)
        job = self.complete()
        case, = job['assessment_cases']
        context = dict(scope='current_single',mode='normal',origin='same_zone')
        context[case['prefix']+'deployment'] = 'running'
        with patch.object(E.A,'detail',return_value={}), patch.object(E.G,'build',side_effect=graph_fixture):
            saved = self.post(self.url+'/answers', dict(self.token(job),context_answers=context))
            row = self.post(self.url+'/assess', self.token(saved))['assessment']['decisions'][0]
            self.assertEqual(row['status'], 'under_investigation')
            saved = self.post(self.url+'/answers', dict(self.token(saved),context_answers={case['prefix']+'runtime':'bom'}))
            row = self.post(self.url+'/assess', self.token(saved))['assessment']['decisions'][0]
            self.assertEqual(row['status'], 'fixed')

if __name__=='__main__':
    unittest.main()
