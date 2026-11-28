"""Integration and failure-mode checks, using actual generated MulVAL artifacts."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import unittest
import pytest
from unittest.mock import patch

from src.item4.decision import attack_graph_builder as G
from src.item4.decision import mulval_attack_graphs as M
from src.item4.decision import evidence_based_vex as E
from tools.item4.auto_vex_fixture_support import profile,request


@pytest.mark.usefixtures('supplier_rule_fixture')
class MulvalIntegration(unittest.TestCase):
    def graph(self):
        questions=[dict(id=k,label=k,nist_fields=['C13-02.02']) for k in ('a','b','c')]
        expr=dict(op='or',args=[dict(op='and',args=[dict(condition='a'),dict(op='not',args=[dict(condition='b')])]),dict(condition='c')])
        graph=G.build('CVE-2000-1234',expr,questions,{},'A0003',True,'test')
        self.assertEqual(graph['generation_status'],'complete')
        return graph

    def test_actual_mulval_rules_preserve_unknown_and_explicit_negation(self):
        graph=self.graph()
        self.assertEqual(graph['generator'],'MulVAL/XSB')
        self.assertTrue(graph['mulval']['all_inference_steps_checked'])
        for states,expected in [(['true','false','false'],'true'),(['true','unknown','false'],'unknown'),
                                (['true','true','false'],'false'),(['unknown','unknown','true'],'true')]:
            result=G.evaluate(graph,dict(deployment='true',affected_version='true',**dict(zip('abc',states))))
            self.assertEqual(result['value'],expected)
        self.assertNotIn('execCode',graph['mulval']['program']['rules_P'])

    def test_generator_failure_has_no_python_fallback_or_path_verdict(self):
        with patch.object(M,'generate',side_effect=RuntimeError('offline')):
            req=request('CVE-2014-0198',profile(),dict(release_buffers='enabled'))
            out=E.evaluate(req)
        self.assertEqual(out['attack_graph']['nodes'],[])
        self.assertEqual(out['attack_graph']['generator'],'MulVAL/XSB')
        self.assertEqual(out['attack_graph']['generation_status'],'unavailable')
        self.assertEqual(out['decision']['status'],'under_investigation')
        self.assertFalse(out['attack_graph_evaluation']['path_found'])
        self.assertFalse(out['attack_graph_evaluation']['no_path_proven'])

    def test_import_rejects_rule_premise_tampering(self):
        graph=self.graph();program=graph['mulval']['program']
        receipt=deepcopy(M.generate(program))
        lines=receipt['files']['ARCS.CSV'].splitlines()
        receipt['files']['ARCS.CSV']='\n'.join(lines[1:])
        contract={k:v for k,v in graph.items() if k not in {'nodes','edges','sha256'}}
        contract['nodes']=graph['semantic_nodes']
        with self.assertRaises(ValueError):M.import_graph(contract,program,receipt)

    def test_cache_tampering_is_rejected(self):
        program=self.graph()['mulval']['program']
        receipt=deepcopy(M.generate(program));receipt['files']['VERTICES.CSV']='forged'
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/(program['sha256']+'.json')).write_text(json.dumps(receipt),encoding='utf-8')
            with patch.dict(M.os.environ,ICSVEX_MULVAL_CACHE=directory),self.assertRaises(ValueError):M.generate(program)

    def test_concurrent_requests_share_one_complete_generation_receipt(self):
        program=self.graph()['mulval']['program']
        raw={k:v for k,v in M.generate(program).items() if k not in {'sha256','program_sha256'}}
        barrier=threading.Barrier(2)
        def worker():
            barrier.wait(timeout=10)
            return M.generate(program)
        with tempfile.TemporaryDirectory() as directory,patch.dict(M.os.environ,ICSVEX_MULVAL_CACHE=directory):
            with patch.object(M,'execute_program',return_value=deepcopy(raw)) as runner:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    a=pool.submit(worker);b=pool.submit(worker)
                    self.assertEqual(a.result(timeout=15),b.result(timeout=15))
                self.assertEqual(runner.call_count,1)

    def test_source_rule_gap_and_step_evidence_survive_to_export(self):
        req=request('CVE-2014-3569',profile(version='1.0.1j'),dict(ssl3_build_support='disabled'))
        out=E.evaluate(req)
        self.assertEqual(out['decision']['status'],'under_investigation')
        self.assertEqual(out['condition_values']['source-ssl3-clienthello-received'],'unknown')
        self.assertFalse(out['attack_graph']['coverage_complete'])
        req=request('CVE-2010-5298',profile(),dict(multithreaded='multi',release_buffers='enabled'))
        out=E.evaluate(req);steps=out['attack_graph_evaluation']['inference_steps']
        self.assertTrue(steps)
        self.assertTrue(all(s['source_refs'] and s['rule']['clause'] and s['operating_facts'] for s in steps))
        self.assertTrue(any(f['observation'] and f['observation']['operating_records'] for s in steps for f in s['operating_facts']))
        self.assertIn(out['attack_graph']['sha256'],E.export(req)['statements'][0]['status_notes'])


if __name__=='__main__':unittest.main()
