from copy import deepcopy
import unittest
from unittest.mock import patch
from tools.item4 import serve_nist_operational_vex as S
from tools.item4.nist_three_axis_fixtures import case,bundle,proof,condition,add
from src.item4.decision import scoped_proof_evaluation as T

class ThreeAxis(unittest.TestCase):
    def prepare(self,status=None,asset=2):
        p,r=case(asset);plan=S.V.plan(r['cve'],p,'fictional-product',r)
        return p,r,plan,bundle(plan,p,status)

    def run_case(self,p,r,b,approved=True,export=False):
        plan=S.V.plan(r['cve'],p,'fictional-product',r)
        payload=dict(cve=r['cve'],product_key='fictional-product',profile=p,plan_sha256=plan['plan_sha256'],approved_scenarios=['fictional-route'] if approved else [],bindings=[],typed_review=b)
        with patch('socket.socket.connect',side_effect=AssertionError('No network/model use allowed')):
            return S.V.export(payload,'openvex',r) if export else S.V.evaluate(payload,r)

    def test_affected_and_schema_valid_export(self):
        p,r,pl,b=self.prepare('affected');add(b,'network',condition(pl,p))
        result=self.run_case(p,r,b)
        self.assertEqual(result['decision']['status'],'affected');self.assertEqual(result['mappings'][0]['accepted_value'],'true')
        self.assertFalse(result['llm_used']);self.assertEqual(self.run_case(p,r,b,export=True)['statements'][0]['status'],'affected')

    def test_prerequisites_alone_do_not_establish_affected(self):
        p,r,pl,b=self.prepare();add(b,'network',condition(pl,p))
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')

    def test_blocked_path_does_not_clear_affected_product(self):
        p,r,pl,b=self.prepare('affected');add(b,'network',condition(pl,p,'false'))
        out=self.run_case(p,r,b);self.assertEqual(out['decision']['status'],'affected');self.assertEqual(out['operational_exposure'],'registered_paths_refuted')

    def test_fixed_requires_running_build(self):
        p,r,pl,b=self.prepare('fixed');self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')
        add(b,'installation',proof(pl,p,'installation','running_fixed_build','runtime_installation','inventory'))
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'fixed')
        self.assertEqual(self.run_case(p,r,b,export=True)['statements'][0]['status'],'fixed')

    def test_not_affected_supplier_proof(self):
        p,r,pl,b=self.prepare('not_affected');out=self.run_case(p,r,b)
        self.assertEqual(out['decision']['status'],'not_affected');self.assertTrue(out['decision']['impact_statement'])
        self.assertIn('impact_statement',self.run_case(p,r,b,export=True)['statements'][0])

    def test_structural_refutation_requires_complete_routes(self):
        p,r,pl,b=self.prepare();add(b,'nonexec',condition(pl,p,'false',True))
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')
        add(b,'closure',proof(pl,p,'route_coverage','complete','exhaustive_route_analysis','analysis'))
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'not_affected')
        b['records']['nonexec']['mechanism']='direct_observation'
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')

    def test_status_conflicts_never_choose_preferred_proof(self):
        p,r,pl,b=self.prepare('affected');add(b,'contradiction',proof(pl,p,'product_status','not_affected','supplier_statement','vendor'))
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')

    def test_all_18_asset_types_preserve_status_with_actual_evidence(self):
        for asset in range(18):
            p,r,pl,b=self.prepare('affected',asset)
            with self.subTest(asset=asset):self.assertEqual(self.run_case(p,r,b)['decision']['status'],'affected')

    def test_wrong_type_product_build_origin_and_source_are_rejected(self):
        for key,value in [('asset_type_id','A0001'),('product_key','other-product'),('source_digest','0'*64),('scope.build','different-build'),('scope.origin','different-origin')]:
            p,r,pl,b=self.prepare('affected')
            for item in b['records'].values():
                if '.' in key:item['scope'][key.split('.')[1]]=value
                else:item[key]=value
            with self.subTest(key=key):self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')

    def test_unreviewed_and_missing_identity_remain_unknown(self):
        p,r,pl,b=self.prepare('affected');b['records']['identity']['reviewed']=False
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')
        b['selected_ids']=['status'];self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')

    def test_governance_field_cannot_refute_network_condition(self):
        p,r,pl,b=self.prepare();c=condition(pl,p,'false',True);c['field_ids']=['C12-01.01'];add(b,'nonexec',c)
        add(b,'closure',proof(pl,p,'route_coverage','complete','exhaustive_route_analysis','analysis'))
        out=self.run_case(p,r,b);self.assertEqual(out['decision']['status'],'under_investigation');self.assertEqual(out['mappings'][0]['accepted_value'],'unknown')

    def test_unapproved_paths_and_quote_mismatch_cannot_refute(self):
        p,r,pl,b=self.prepare();add(b,'nonexec',condition(pl,p,'false',True));add(b,'closure',proof(pl,p,'route_coverage','complete','exhaustive_route_analysis','analysis'))
        self.assertEqual(self.run_case(p,r,b,False)['decision']['status'],'under_investigation')
        b['records']['nonexec']['source_quote_sha256']='0'*64
        self.assertEqual(self.run_case(p,r,b)['mappings'][0]['accepted_value'],'unknown')

    def test_arbitrary_prose_is_not_a_machine_answer(self):
        p,r,pl,b=self.prepare('affected');b['records']['status']['conclusion']='probably affected'
        with self.assertRaises(ValueError):self.run_case(p,r,b)

    def test_unresolved_source_product_never_receives_a_final_status(self):
        p,r,pl,b=self.prepare('affected');r['products'][0]['binding']='unresolved'
        new=S.V.plan(r['cve'],p,'fictional-product',r)
        for item in b['records'].values():item['source_digest']=new['source_digest']
        self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')

    def test_false_partial_coverage_does_not_refute(self):
        p,r,pl,b=self.prepare();add(b,'nonexec',condition(pl,p,'false',True));b['records']['nonexec']['coverage']='partial'
        self.assertEqual(self.run_case(p,r,b)['mappings'][0]['accepted_value'],'unknown')

    def test_three_valued_and_or_preserve_unknown_alternatives(self):
        for op,expected in [('and','not_affected'),('or','under_investigation')]:
            p,r,pl,b=self.prepare();second=deepcopy(r['scenarios'][0]['conditions'][0]);second['id']='alternative'
            r['scenarios'][0]['conditions'].append(second)
            r['scenarios'][0]['expression']=dict(op=op,args=[{'condition':'network'},{'condition':'alternative'}])
            pl=S.V.plan(r['cve'],p,'fictional-product',r);b=bundle(pl,p)
            add(b,'nonexec',condition(pl,p,'false',True));add(b,'closure',proof(pl,p,'route_coverage','complete','exhaustive_route_analysis','analysis'))
            self.assertEqual(self.run_case(p,r,b)['decision']['status'],expected)

    def test_real_cve_source_paths_without_operating_facts_stay_unknown(self):
        p=deepcopy(S.model.catalogue()['profiles'][2]['blank']);record=S.V.current_record('CVE-1999-1085')
        plan=S.V.plan(record['cve'],p,record['products'][0]['key'],record)
        request=dict(cve=record['cve'],product_key=plan['product']['key'],profile=p,plan_sha256=plan['plan_sha256'],approved_scenarios=[],bindings=[],typed_review=T.blank())
        result=S.V.evaluate(request,record)
        self.assertEqual(result['decision']['status'],'under_investigation');self.assertTrue(all(m['accepted_value']=='unknown' for m in result['mappings']))

    def test_source_rejected_and_ambiguous_override_product_claim(self):
        for key,value in [('original_nvd_status','Rejected'),('identity_ambiguous',True)]:
            p,r,pl,b=self.prepare('affected');r[key]=value;new=S.V.plan(r['cve'],p,'fictional-product',r)
            for proof in b['records'].values():proof['source_digest']=new['source_digest']
            self.assertEqual(self.run_case(p,r,b)['decision']['status'],'under_investigation')

if __name__=='__main__':unittest.main()
