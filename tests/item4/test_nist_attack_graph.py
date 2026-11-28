from copy import deepcopy
import unittest
import pytest

from src.item4.decision import attack_graph_builder as G
from src.item4.decision import evidence_based_vex as E
from tools.item4.auto_vex_fixture_support import profile, request


class GraphEvaluation(unittest.TestCase):
    def graph(self, expression, complete=True):
        questions=[dict(id=q, label=q, nist_fields=['C13-02.02']) for q in ('a','b','c')]
        return G.build('CVE-2000-1234', expression, questions, {'origin':'test'}, 'A0003', complete, 'test')

    def test_and_is_not_ordinary_reachability_and_or_preserves_alternatives(self):
        graph=self.graph(dict(op='or', args=[dict(op='and',args=[dict(condition='a'),dict(condition='b')]),dict(condition='c')]))
        facts=dict(deployment='true',affected_version='true',a='true',b='unknown',c='false')
        self.assertEqual(G.evaluate(graph,facts)['value'],'unknown')
        facts['c']='true';self.assertTrue(G.evaluate(graph,facts)['path_found'])
        facts.update(a='false',c='false');self.assertTrue(G.evaluate(graph,facts)['no_path_proven'])
        partial=self.graph(dict(condition='a'),False)
        self.assertFalse(G.evaluate(partial,facts)['no_path_proven'])

    def test_unmapped_operating_information_never_proves_safety_or_exposure(self):
        graph=G.build('CVE-2000-1234',dict(condition='source-known-affected'),[],{},'A0003',False,'test')
        facts=dict(deployment='true',affected_version='true',**{'source-known-affected':'true'})
        self.assertEqual(G.evaluate(graph,facts)['value'],'unknown')

    def test_tampered_or_cyclic_graph_is_rejected(self):
        graph=self.graph(dict(condition='a'));bad=deepcopy(graph);bad['coverage_complete']=False
        with self.assertRaises(ValueError):G.evaluate(bad,{})
        bad=deepcopy(graph);bad['nodes'][-1]['inputs'].append(bad['goal']);bad['sha256']=G.digest({k:v for k,v in bad.items() if k!='sha256'})
        with self.assertRaises(ValueError):G.evaluate(bad,{})


@pytest.mark.usefixtures('supplier_rule_fixture')
class OperationalGraph(unittest.TestCase):
    def answer(self, r, qid, value, evidence=('analysis',), coverage='complete'):
        r['auto_observations']['mitigation:'+qid]=dict(value=value,evidence_ids=list(evidence),coverage=coverage,
            scope_sha256=E.scope_hash(r['profile']))

    def test_graph_is_built_before_answers_and_does_not_change_with_answers(self):
        r=request('CVE-2014-0198',profile(),dict(release_buffers='enabled'))
        before=E.plan(r['cve'],r['profile'])['attack_graph']['sha256']
        self.assertTrue(E.evaluate(r)['attack_graph_evaluation']['path_found'])
        r['auto_observations']['release_buffers']['value']='disabled'
        out=E.evaluate(r);self.assertEqual(out['attack_graph']['sha256'],before)
        self.assertEqual(out['decision']['status'],'under_investigation')
        self.assertEqual(out['deployment_exploitability'],'known_paths_blocked')

    def test_verified_mitigation_keeps_product_affected_in_result_and_openvex(self):
        r=request('CVE-2014-0198',profile(),dict(release_buffers='enabled'))
        self.assertEqual(E.evaluate(r)['decision']['status'],'affected')
        self.answer(r,'release_buffers','disabled')
        out=E.evaluate(r)
        self.assertEqual(out['decision']['initial_status'],'affected')
        self.assertEqual(out['decision']['status'],'affected')
        self.assertEqual(out['decision']['resolution_basis'],'verified_path_mitigation')
        self.assertTrue(out['mitigation_review']['all_paths_blocked'])
        self.assertEqual(out['deployment_exploitability'],'known_paths_blocked')
        doc=E.export(r);self.assertEqual(doc['statements'][0]['status'],'affected')
        self.assertIn('mitigation',doc['statements'][0]['status_notes'])

    def test_applied_control_without_effectiveness_or_complete_coverage_stays_affected(self):
        for evidence,coverage in [(('configuration',),'complete'),(('analysis',),'partial'),((),'complete')]:
            with self.subTest(evidence=evidence,coverage=coverage):
                r=request('CVE-2014-0198',profile(),dict(release_buffers='enabled'))
                self.answer(r,'release_buffers','disabled',evidence,coverage)
                self.assertEqual(E.evaluate(r)['decision']['status'],'affected')

    def test_mitigation_must_block_every_or_route(self):
        r=request('CVE-2024-3400',profile('PAN-OS','10.2.4-h15'),dict(gp_gateway='configured',gp_portal='configured'))
        self.answer(r,'gp_gateway','none')
        self.assertEqual(E.evaluate(r)['decision']['status'],'affected')
        self.answer(r,'gp_portal','none')
        out=E.evaluate(r)
        self.assertEqual(out['decision']['status'],'affected')
        self.assertTrue(out['mitigation_review']['all_paths_blocked'])

    def test_missing_operating_facts_cannot_be_replaced_by_mitigation_claim(self):
        r=request('CVE-2014-0198',profile())
        self.answer(r,'release_buffers','disabled')
        self.assertEqual(E.evaluate(r)['decision']['status'],'under_investigation')

    def test_unknown_source_input_cannot_be_closed_by_build_option_mitigation(self):
        r=request('CVE-2014-3569',profile(version='1.0.1j'),dict(ssl3_build_support='disabled'))
        self.answer(r,'ssl3_build_support','enabled')
        self.assertEqual(E.evaluate(r)['decision']['status'],'under_investigation')


if __name__=='__main__':unittest.main()
