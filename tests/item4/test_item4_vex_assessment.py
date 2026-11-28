"""Old questionnaire state never bypasses the new asset-key contract."""
from copy import deepcopy
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.item4.workflow import analysis_job_state as A; from src.item4.workflow import source_analysis_jobs as Q; from src.item4.decision import asset_vex_assessment as E
from tools.item4 import serve_nist_operational_vex as S

class AssetKeyMigration(unittest.TestCase):
    def test_migration_invalidates_legacy_answers_and_decisions(self):
        job=dict(id='job',status='completed',declared_cves=[],bom_sha256='a'*64,conditions=[],asset_classification={},
                 questions=[{'id':'q'}],answers={'q':'absent'},context_questions=[{}],
                 context_answers={'runtime':'bom'},assessment={'status':'not_affected'},
                 assessment_cases=[{}],product_vex_status='not_affected')
        self.assertTrue(A.prepare(job,Q.digest))
        self.assertEqual(job['answers'],{});self.assertEqual(job['context_answers'],{})
        self.assertIsNone(job['assessment']);self.assertEqual(job['product_vex_status'],'under_investigation')
        self.assertEqual(job['assessment_state'],'awaiting_inputs')
        self.assertEqual([a['number'] for a in job['agents']],[1,2,3,4])
        self.assertFalse(A.prepare(job,Q.digest),'State migration must be idempotent')
        self.assertTrue(callable(E.evaluate),'V4 assessment engine must be retained')

    def test_vex_export_requires_a_current_assessment(self):
        job=dict(id='job',status='completed',assessment_state='awaiting_inputs',assessment=None)
        client=TestClient(S.app)
        with patch.object(Q,'get',return_value=job):
            for kind in ['analysis']:
                self.assertEqual(client.get('/api/item4/analyses/jobs/job/export/'+kind).json(),job)
            for kind in ['review','openvex','cyclonedx']:
                self.assertEqual(client.get('/api/item4/analyses/jobs/job/export/'+kind).status_code,422)
            state=client.get('/api/item4/analyses/jobs/job/assessment').json()
            self.assertTrue(state['engine_retained']);self.assertTrue(state['operating_questionnaire_enabled'])
            self.assertEqual(state['state'],'awaiting_inputs')

if __name__=='__main__':unittest.main()
