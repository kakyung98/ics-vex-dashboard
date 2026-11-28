"""Questionnaire routing, source isolation and attributed choice contracts."""
from copy import deepcopy
import hashlib
import json
import re
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
from src.item4.workflow import source_analysis_jobs as Q
from tools.item4 import serve_nist_operational_vex as S


def bom():
    return dict(bomFormat='CycloneDX',specVersion='1.6',version=1,
        metadata=dict(component={'bom-ref':'asset','type':'device','name':'Test Controller'}),
        components=[{'bom-ref':'library','type':'library','name':'Test Library','version':'1.0'}],
        vulnerabilities=[dict(id='CVE-2026-12345',affects=[dict(ref='library')]),
                         dict(id='CVE-2026-12345',affects=[dict(ref='asset')]),
                         dict(id='CVE-2026-54321',affects=[dict(ref='asset')])])


def extracted(cve):
    item=dict(id='feature',predicate='feature_enabled',target='FTP',value='enabled',
              category='OTHER',extraction_confidence=0.95,
              statement='FTP is enabled',operator_observable=True,
              operator='eq',expected=True,operational_quote='Exploitation requires FTP enabled.',
              observation=dict(kind='configuration',record_type='configuration_export',check='Read the applied FTP setting.'),
              source_refs=[dict(source_id='nvd:'+cve,quote='Exploitation requires FTP enabled.')])
    draft=dict(prerequisites=[item],scenarios=[dict(expression={'condition':'feature'})],unknowns=[])
    return dict(cve=cve,status='extracted',source_kind='CVE description',source_policy='cve-description-special/1',cvss_assessments=[],prerequisite=dict(sha256='a'*64,draft=draft),sources=[])


class SourceAnalysis(unittest.TestCase):
    def setUp(self):
        from src.item4.analysis import asset_operating_question_generation as V3
        p=patch.object(V3,'run_job',return_value={});p.start();self.addCleanup(p.stop)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        for name,value in [('DB',Path(temp.name)/'jobs.sqlite3')]:
            mock=patch.object(Q.store,name,value);mock.start();self.addCleanup(mock.stop)
        mock=patch.object(Q,'JOBS',{});mock.start();self.addCleanup(mock.stop)
        self.client=TestClient(S.app)

    def complete(self,jid):
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            value=Q.get(jid)
            if value['status'] in ('completed','failed'):return value
            time.sleep(.01)
        self.fail('Source analysis did not finish')

    def test_v1_precedes_v2_and_keeps_failed_cves_with_asset_key_inputs(self):
        order=[]
        def classify(*args):
            order.append('V1')
            return dict(status='classified',asset_type_id='A0003',asset=dict(id='A0003',name='PLC'))
        def extract(cve,**kwargs):
            self.assertTrue(order)
            self.assertEqual(kwargs['asset_context']['components'][0]['asset_type_id'],'A0003')
            if cve=='CVE-2026-12345':
                return extracted(cve)
            raise ValueError('missing source')
        with patch.object(Q,'classify',side_effect=classify),patch.object(Q,'extract_description',side_effect=extract):
            response=self.client.post('/api/item4/analyses/start',json={'bom':bom()})
            self.assertEqual(response.status_code,200,response.text)
            result=self.complete(response.json()['id'])
        self.assertEqual(result['status'],'completed');self.assertEqual(result['cves_done'],2)
        self.assertEqual(len(result['conditions']),2)
        self.assertEqual([a['number'] for a in result['agents']],[1,2,3,4])
        self.assertTrue(result['operating_questionnaire_enabled'])
        self.assertTrue(result['questions']);self.assertTrue(result['question_generation_required']);self.assertEqual(result['answers'],{})
        self.assertTrue(any(u['cve']=='CVE-2026-54321' for u in result['unresolved']))
        self.assertEqual(result['assessment_state'],'awaiting_inputs')
        self.assertEqual(result['product_vex_status'],'under_investigation')

    def test_inventory_deduplicates_only_declared_cves(self):
        components,declared=Q.inventory(bom())
        self.assertEqual([d['cve'] for d in declared],['CVE-2026-12345','CVE-2026-54321'])
        self.assertEqual(declared[0]['component_refs'],['asset','library'])
        self.assertEqual(components[0]['pointer'],'/metadata/component')

    def test_description_extraction_is_isolated_from_asset_inference(self):
        text='Exploitation requires FTP enabled.'
        source=dict(id='nvd:CVE-2026-12345',text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),product_keys=['p'])
        record=dict(products=[dict(key='p')],sources=[source,dict(id='icsa:other',text='Upgrade firmware.')])
        with patch.object(Q.descriptions,'detail',return_value=dict(description=text)),patch.object(Q.population,'get',return_value=record),patch.object(Q.vep,'resolve',return_value={'sha256':'x','draft':{'prerequisites':[]}}) as infer:
            result=Q.extract_description('CVE-2026-12345')
        packet=infer.call_args.args[0]
        self.assertEqual(packet['sources'],[source]);self.assertEqual(packet['products'],[])
        self.assertEqual(result['source_kind'],'CVE description')

    def test_english_upload_shell_has_four_stages_and_asset_input_section(self):
        reference=BeautifulSoup(self.client.get('/index.html').text,'html.parser')
        for path in ['/item4.html','/bom-vex.html','/vex-decision.html']:
            response=self.client.get(path);self.assertEqual(response.status_code,200)
            doc=BeautifulSoup(response.text,'html.parser')
            self.assertEqual(doc.html.get('lang'),'en');self.assertEqual(doc.html.get('translate'),'no')
            self.assertIsNone(re.search('[\uac00-\ud7a3]',doc.get_text()))
            self.assertEqual([n.get_text() for n in doc.select('.agent-grid .ov-pill')],['V1','V2','V3','V4'])
            self.assertIsNotNone(doc.select_one('#questions-section'))
            self.assertIsNotNone(doc.select_one('#assessment-result'))
            self.assertIsNone(doc.select_one('textarea'))
            self.assertEqual(doc.find(id='start').get_text(),'Analysis Exploitability →')
            self.assertIsNotNone(doc.find(id='bom-dropzone'))
            self.assertEqual(str(doc.select_one('main.main > .workspace-topbar')),
                             str(reference.select_one('main.main > .workspace-topbar')))
            self.assertEqual(str(doc.select_one('main.main > .foot')),
                             str(reference.select_one('main.main > .foot')))
            self.assertIsNotNone(doc.select_one('main.main > h1'))
            selected=doc.select('aside a.navtab.on')
            self.assertEqual(len(selected),1)
            self.assertEqual(selected[0].get('href'),'/item4.html')
            self.assertEqual(selected[0].get('aria-current'),'page')
        self.assertEqual(self.client.get('/item4-questionnaire.js').status_code,200)

    def test_question_endpoints_are_retired_including_legacy_paths(self):
        for path in ['/api/item4/questionnaires/start','/api/item4/questionnaires/jobs/old/answers',
                     '/api/item4/questionnaires/jobs/old/assess','/api/operational-vex/plan',
                     '/api/operational-vex/assess','/api/operational-vex/batch',
                     '/api/bom-vex/from-json','/api/bom-vex/workflows/old/profiles',
                     '/api/bom-vex/workflows/old/cases/old/assess',
                     '/api/item4/start','/api/item4/old/questions',
                     '/api/item4/old/questions/CVE-2026-12345/generate','/api/item4/old/answers',
                     '/api/oc/questions','/api/oc/answers','/api/cluster-questions/compile',
                     '/api/question-mining/reviews','/api/operational-workflow/compile']:
            self.assertEqual(self.client.post(path,json={}).status_code,410,path)
        self.assertEqual(self.client.get('/api/operational-vex/question-relevance').status_code,410)

    def test_new_start_rejects_answers_and_self_supplied_verdict(self):
        for field in ['answers','context_answers','status']:
            response=self.client.post('/api/item4/analyses/start',json=dict(bom=bom(),**{field:{}}))
            self.assertEqual(response.status_code,422)

if __name__=='__main__':unittest.main()
