"""Durable CVE checkpoints and idempotent submission across lost connections."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import threading
import tempfile
import unittest
from unittest.mock import patch
from src.item4.workflow import source_analysis_jobs as Q
from tests.item4.test_item4_questionnaire import bom, extracted
from src.item4.assets.question_record_context import extraction_context


def pin_unknown_context(row,job):
    components,_=Q.inventory(job['input_bom'])
    linked=[c for c in components if c['ref'] in row['bom_declaration']['component_refs']]
    row['asset_type_context_sha256']=Q.digest(extraction_context(job,linked))


class Recovery(unittest.TestCase):
    def test_restart_retains_unprocessed_source_checkpoints(self):
        from copy import deepcopy
        job=Q.start(bom());jid=job['id'];first,second=job['declared_cves']
        done=extracted(first['cve']);done.update(bom_declaration=first,extraction_policy=Q.vep.VERSION,extraction_identity=Q.extraction_identity())
        pin_unknown_context(done,job)
        pending=extracted(second['cve']);pending.update(bom_declaration=second,extraction_policy=Q.vep.VERSION,extraction_identity='prior-policy')
        job.update(status='running',conditions=[done],source_recovery_checkpoints=[pending],extraction_identity=Q.extraction_identity())
        Q._save(job);Q.JOBS.pop(jid);self.submit.reset_mock();Q.get(jid)
        with patch.object(Q,'classify',return_value=dict(status='unresolved',asset_type_id=None)), \
                patch.object(Q,'revalidate_previous',return_value=deepcopy(pending)) as revalidate, \
                patch.object(Q,'extract_declared',side_effect=AssertionError('A saved pending source must not be discarded')):
            Q._run(*self.submit.call_args.args[1:])
        self.assertEqual(revalidate.call_args.args[0]['cve'],second['cve'])
        result=Q.get(jid)
        self.assertEqual(result['cves_done'],2)
        self.assertEqual(result['source_recovery_checkpoints'],[])

    def test_v3_uses_source_conditions_without_cvss_or_get_polling(self):
        from src.item4.analysis import asset_operating_question_generation as V3
        job=Q.start(bom())
        def source(cve,components,**kwargs):
            result=extracted(cve);result.pop('cvss_assessments',None);return result
        seen=[]
        def generate(snapshot,progress=None,runner=None):
            seen.extend(snapshot['conditions'])
            self.assertTrue(all('cvss_assessments' not in r for r in snapshot['conditions']))
            return {}
        with patch.object(Q,'classify',return_value=dict(status='unresolved',asset_type_id=None)), \
                patch.object(Q,'extract_declared',side_effect=source), \
                patch.object(V3,'run_job',side_effect=generate):
            Q._run(*self.submit.call_args.args[1:])
        self.assertEqual(len(seen),2)
        self.assertEqual(Q.get(job['id'])['status'],'completed')
    def setUp(self):
        from src.item4.analysis import asset_operating_question_generation as V3
        p=patch.object(V3,'run_job',return_value={});p.start();self.addCleanup(p.stop)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        p=patch.object(Q.store,'DB',Path(temp.name)/'jobs.sqlite3');p.start();self.addCleanup(p.stop)
        p=patch.object(Q,'JOBS',{});p.start();self.addCleanup(p.stop)
        p=patch.object(Q.QUEUE,'submit');self.submit=p.start();self.addCleanup(p.stop)

    def test_duplicate_start_requests_create_one_job(self):
        key='a'*32
        first=Q.start(bom(),request_id=key)
        second=Q.start(bom(),request_id=key)
        self.assertEqual(first['id'],second['id']);self.submit.assert_called_once()
        changed=bom();changed['metadata']['component']['version']='2.0'
        with self.assertRaisesRegex(ValueError,'another BOM'):
            Q.start(changed,request_id=key)

    def test_restart_resumes_same_job_and_skips_completed_cves(self):
        job=Q.start(bom());jid=job['id']
        declaration=job['declared_cves'][0]
        done=extracted(declaration['cve']);done['bom_declaration']=declaration;done['extraction_policy']=Q.vep.VERSION
        done['extraction_identity']=Q.extraction_identity()
        pin_unknown_context(done,job)
        job.update(status='running',conditions=[done],cves_done=1,extraction_identity=Q.extraction_identity())
        Q._save(job);Q.JOBS.pop(jid);self.submit.reset_mock()
        resumed=Q.get(jid);Q.get(jid)
        self.assertEqual(resumed['id'],jid);self.assertEqual(resumed['cves_done'],1)
        self.submit.assert_called_once()
        with patch.object(Q,'classify',return_value=dict(status='unresolved',asset_type_id=None)), \
                patch.object(Q,'extract_declared',side_effect=lambda c,cs,**kw:extracted(c)) as extract:
            Q._run(*self.submit.call_args.args[1:])
        self.assertEqual([call.args[0] for call in extract.call_args_list],['CVE-2026-54321'])
        result=Q.get(jid)
        self.assertEqual(result['status'],'completed');self.assertEqual(result['cves_done'],2)
        self.assertEqual(result['conditions'][0],done)

    def test_older_restart_failure_can_resume_without_reupload(self):
        job=Q.start(bom());jid=job['id']
        job.update(status='failed',error='The server restarted before completion. Select the BOM again.')
        Q._save(job);Q.JOBS.pop(jid);self.submit.reset_mock()
        resumed=Q.get(jid)
        self.assertEqual(resumed['status'],'queued');self.submit.assert_called_once()

    def test_new_asset_model_refreshes_classification_without_reextracting_cves(self):
        job=Q.start(bom());jid=job['id']
        conditions=[extracted(d['cve']) for d in job['declared_cves']]
        job.update(status='completed',conditions=conditions,cves_done=len(conditions),
            extraction_identity=Q.extraction_identity(),asset_state='completed',
            asset_classification=dict(status='unresolved',asset_type_id=None,classification_version='old-model'))
        Q._prepare_analysis(job);old_plan=job['plan_sha256']
        job.update(answers={'old-key':'o'},assessment={'old':'verdict'})
        Q._save(job);Q.JOBS.pop(jid);self.submit.reset_mock()
        new=dict(status='classified',asset_type_id='A0015',classification_version=Q.asset_model.VERSION)
        from src.item4.analysis import asset_operating_question_generation as V3
        # This case isolates classification refresh. Missing question recovery
        # has its own tests and can independently queue V3 for this fixture.
        with patch.object(Q,'classify',return_value=new) as classify, patch.object(V3,'requires_generation',return_value=False):
            result=Q.get(jid)
        classify.assert_called_once();self.submit.assert_not_called()
        self.assertEqual(result['conditions'],conditions)
        self.assertEqual(result['cves_done'],len(conditions))
        self.assertEqual(result['asset_classification'],new)
        self.assertNotEqual(result['plan_sha256'],old_plan)
        self.assertEqual(result['answers'],{});self.assertIsNone(result['assessment'])

    def test_corrupt_snapshot_is_not_resumed(self):
        job=Q.start(bom());jid=job['id']
        job['input_bom']['version']=999;Q._save(job);Q.JOBS.pop(jid);self.submit.reset_mock()
        with self.assertRaisesRegex(ValueError,'snapshot'):
            Q.get(jid)
        self.submit.assert_not_called()

    def test_changed_adapter_identity_reextracts_instead_of_reusing_old_conditions(self):
        job=Q.start(bom());jid=job['id']
        done=extracted(job['declared_cves'][0]['cve'])
        done.update(bom_declaration=job['declared_cves'][0],extraction_policy=Q.vep.VERSION)
        job.update(status='completed',conditions=[done],extraction_identity='old-adapter')
        Q._save(job);Q.JOBS.pop(jid);self.submit.reset_mock()
        resumed=Q.get(jid)
        self.assertEqual(resumed['status'],'queued');self.submit.assert_called_once()
        with patch.object(Q,'classify',return_value=dict(status='unresolved',asset_type_id=None)), \
                patch.object(Q,'extract_declared',side_effect=lambda c,cs,**kw:extracted(c)) as extract:
            Q._run(*self.submit.call_args.args[1:])
        self.assertEqual(extract.call_count,2)
        self.assertEqual(Q.get(jid)['extraction_identity'],Q.extraction_identity())

    def test_terminal_job_releases_memory_and_obeys_durable_expiry(self):
        job = Q.start(bom())
        jid = job['id']
        with patch.object(Q, 'classify', return_value={'status': 'unresolved'}), \
                patch.object(Q, 'extract_declared', side_effect=lambda c, _, **kw: extracted(c)):
            Q._run(*self.submit.call_args.args[1:])
        self.assertNotIn(jid, Q.JOBS)
        current = Q.get(jid)
        self.assertEqual(current['status'], 'completed')
        saved = Q.save_answers(jid, dict(revision=current['revision'], plan_sha256=current['plan_sha256'],
                                         context_answers={'mode': 'normal'}))
        self.assertEqual(Q.get(jid)['context_answers'], saved['context_answers'])
        self.assertNotIn(jid, Q.JOBS)
        with Q.store.connection() as db:
            db.execute('UPDATE objects SET expires=0 WHERE kind=? AND id=?', ('item4_questionnaire', jid))
        with self.assertRaises(KeyError):
            Q.get(jid)

    def test_new_and_recovered_jobs_compete_for_the_same_final_slot(self):
        from fastapi.testclient import TestClient
        from tools.item4 import serve_nist_operational_vex as service
        client = TestClient(service.app)
        self.addCleanup(client.close)
        original = Q.start(bom())
        jid = original['id']
        Q.JOBS.clear()  # Prior server exited with a durable queued checkpoint.
        for _ in range(Q.MAX_ACTIVE_JOBS - 1):
            Q.start(bom())
        other = 'e' * 32
        base = '/api/item4/analyses'
        barrier = threading.Barrier(2)
        def request(recover):
            barrier.wait(timeout=5)
            return client.get(base + '/jobs/' + jid) if recover else client.post(
                base + '/start', json={'bom': bom(), 'request_id': other})
        with ThreadPoolExecutor(max_workers=2) as pool:
            recovered, submitted = pool.map(request, (True, False))
        self.assertEqual(sorted([recovered.status_code, submitted.status_code]), [200, 429])
        self.assertEqual(len(Q.JOBS), Q.MAX_ACTIVE_JOBS)
        if recovered.status_code == 429:
            self.assertEqual(Q.store.get('item4_questionnaire', jid), original)
            self.assertEqual(recovered.headers['Retry-After'], '2')
            Q._update(other, status='failed', extraction_identity=Q.extraction_identity())
            self.assertEqual(Q.get(jid)['recovery_count'], 1)
        else:
            self.assertIsNone(Q.store.get('item4_questionnaire', other))
            Q._update(jid, status='failed', extraction_identity=Q.extraction_identity())
            self.assertEqual(Q.start(bom(), request_id=other)['id'], other)

    def test_submission_failure_keeps_durable_checkpoint_and_releases_reservation(self):
        key = 'f' * 32
        self.submit.side_effect = RuntimeError('executor is closing')
        with self.assertRaises(RuntimeError):
            Q.start(bom(), request_id=key)
        self.assertNotIn(key, Q.JOBS)
        self.assertEqual(Q.store.get('item4_questionnaire', key)['status'], 'queued')
        self.submit.side_effect = None
        self.assertEqual(Q.start(bom(), request_id=key)['recovery_count'], 1)

    def test_write_failure_during_processing_releases_worker_and_reuses_checkpoint(self):
        job = Q.start(bom())
        with patch.object(Q, '_save', side_effect=OSError('disk full')), self.assertRaises(OSError):
            Q._run(*self.submit.call_args.args[1:])
        self.assertNotIn(job['id'], Q.JOBS)
        self.assertEqual(Q.store.get('item4_questionnaire', job['id']), job)
        self.assertEqual(Q.get(job['id'])['recovery_count'], 1)


if __name__=='__main__':unittest.main()
