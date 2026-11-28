from copy import deepcopy
from datetime import datetime,timedelta,timezone
import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from src.item4.decision import evidence_based_vex as E
from tools.item4.auto_vex_fixture_support import profile,request

class AutomaticVex(unittest.TestCase):
    def assess(self,p):
        with patch('socket.socket.connect',side_effect=AssertionError('Network/LLM forbidden')):return E.evaluate(p)
    def test_operating_choices_are_substituted_into_and_expression(self):
        p=profile();r=request('CVE-2010-5298',p,dict(multithreaded='multi',release_buffers='enabled'))
        out=self.assess(r);self.assertEqual(out['decision']['status'],'affected');self.assertEqual(out['formula_value'],'true');self.assertFalse(out['operator_selects_verdict'])
        r['auto_observations']['release_buffers']['value']='disabled';out=self.assess(r);self.assertEqual(out['formula_value'],'false');self.assertEqual(out['decision']['status'],'not_affected')
        r['auto_observations']['release_buffers']['value']='unknown';r['auto_observations']['release_buffers']['evidence_ids']=[];self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_panos_or_expression_does_not_require_both_features(self):
        for gateway,portal,status in [('configured','none','affected'),('none','configured','affected'),('none','none','not_affected'),('unknown','none','under_investigation'),('unknown','configured','affected')]:
            r=request('CVE-2024-3400',profile('PAN-OS','10.2.4-h15',15),dict(gp_gateway=gateway,gp_portal=portal))
            with self.subTest(gateway=gateway,portal=portal):self.assertEqual(self.assess(r)['decision']['status'],status)
    def test_negated_build_option_cannot_replace_unobserved_clienthello_path(self):
        for choice,status in [('disabled','under_investigation'),('enabled','under_investigation'),('unknown','under_investigation')]:
            r=request('CVE-2014-3569',profile(version='1.0.1j'),dict(ssl3_build_support=choice));self.assertEqual(self.assess(r)['decision']['status'],status)
    def test_role_and_cipher_are_different_questions(self):
        for role,cipher,status in [('client','enabled','affected'),('server','enabled','not_affected'),('both','enabled','affected'),('client','disabled','not_affected')]:
            r=request('CVE-2014-3470',profile(),dict(tls_client=role,anonymous_ecdh=cipher));self.assertEqual(self.assess(r)['decision']['status'],status)
    def test_openssl_letter_and_panos_hotfix_boundaries(self):
        matrix=[('CVE-2014-3470','0.9.8z','vulnerable'),('CVE-2014-3470','0.9.8za','fixed'),('CVE-2014-3470','0.9.8zb','fixed'),('CVE-2014-0198','1.0.1g','vulnerable'),('CVE-2014-0198','1.0.1h','fixed'),('CVE-2014-0198','1.0.1g-ubuntu','unknown'),('CVE-2014-0160','1.0.2-beta1','unknown'),('CVE-2024-3400','10.2.4-h15','vulnerable'),('CVE-2024-3400','10.2.4-h16','fixed'),('CVE-2024-3400','10.2.5-h5','vulnerable'),('CVE-2024-3400','11.0.3-h9','vulnerable'),('CVE-2024-3400','11.0.3-h10','fixed'),('CVE-2024-3400','11.1.200','unknown'),('CVE-2024-3400','10.1.9','unaffected')]
        for cve,version,expected in matrix:
            with self.subTest(cve=cve,version=version):self.assertEqual(E.version_state(E.registry()['rules'][cve],version),expected)
    def test_fixed_uses_running_version_not_a_planned_patch(self):
        r=request('CVE-2010-5298',profile(version='1.0.1h'));self.assertEqual(self.assess(r)['decision']['status'],'fixed')
        r['auto_observations']['runtime_version']['value']='unknown';r['auto_observations']['runtime_version']['evidence_ids']=[];self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_irrelevant_config_conflict_does_not_undo_verified_fix(self):
        r=request('CVE-2024-3400',profile('PAN-OS','10.2.4-h16',15),dict(gp_gateway='conflicting',gp_portal='unknown'))
        self.assertEqual(self.assess(r)['decision']['status'],'fixed')
    def test_complete_inventory_absence_is_calculated_without_a_verdict_input(self):
        r=request('CVE-2010-5298',profile(),dict(deployment='not_deployed'));self.assertEqual(self.assess(r)['decision']['status'],'not_affected')
        r['auto_observations']['deployment']['coverage']='partial';self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_negative_config_requires_complete_scope(self):
        r=request('CVE-2014-0198',profile(),dict(release_buffers='disabled'));r['auto_observations']['release_buffers']['coverage']='partial'
        self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_unreviewed_wrong_asset_stale_and_future_evidence_is_not_used(self):
        for key,value in [('reviewed',False),('asset_ref','OTHER-ASSET'),('build','other-build'),('valid_until','2000-01-01T00:00:00+00:00'),('observed_at','2099-01-01T00:00:00+00:00')]:
            r=request('CVE-2014-0198',profile(),dict(release_buffers='enabled'));r['profile']['evidence']['configuration'][key]=value
            r['plan_sha256']=E.plan(r['cve'],r['profile'])['plan_sha256']
            with self.subTest(key=key):self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_changed_scope_and_unknown_question_cannot_supply_truth(self):
        r=request('CVE-2014-0198',profile(),dict(release_buffers='enabled'));r['auto_observations']['release_buffers']['scope_sha256']='0'*64
        self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
        r['auto_observations']['telemetry']=deepcopy(r['auto_observations']['release_buffers'])
        with self.assertRaises(ValueError):self.assess(r)
    def test_user_verdict_condition_truth_and_legacy_proof_are_rejected(self):
        for field,value in [('status','affected'),('product_finding',{'status':'affected'}),('typed_review',{}),('bindings',[{'value':'true'}]),('approved_scenarios',[])]:
            r=request('CVE-2010-5298',profile());r[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.assess(r)
        for value in ['affected','true','false','not_affected']:
            r=request('CVE-2014-0198',profile());r['auto_observations']['release_buffers']['value']=value
            with self.assertRaises(ValueError):self.assess(r)
    def test_question_subset_follows_cve_source_and_never_contains_verdict_choices(self):
        p=profile();a=E.plan('CVE-2010-5298',p);b=E.plan('CVE-2014-0198',p);pan=E.plan('CVE-2024-3400',profile('PAN-OS','10.2.4-h15'))
        self.assertIn('multithreaded',{q['id'] for q in a['questions']});self.assertNotIn('multithreaded',{q['id'] for q in b['questions']})
        self.assertEqual({q['id'] for q in pan['questions']},{'deployment','runtime_version','gp_gateway','gp_portal'})
        for pl in [a,b,pan]:
            for q in pl['questions']:self.assertFalse(set(q['options'])&{'affected','fixed','not_affected','true','false'})
    def test_embedded_library_does_not_use_appliance_firmware_as_openssl_version(self):
        p=profile('Siemens fictional PLC','1.0.1h');pl=E.plan('CVE-2010-5298',p)
        self.assertTrue(pl['population_member']);self.assertEqual(pl['source_product_binding'],'unresolved')
        r=request('CVE-2010-5298',p,dict(product_family='expected',release_buffers='enabled',multithreaded='multi'))
        self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_embedded_library_record_does_not_relabel_the_bom_appliance(self):
        p=profile('Embedded PLC','5.6.7');p['reference_values']['libver']=dict(kind='version',label='1.0.1g',asset_ref=p['scope']['asset_ref'],evidence_ids=['inventory'])
        r=request('CVE-2014-0198',p,dict(product_family='expected',runtime_version='inventory:libver',release_buffers='enabled'))
        self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_a_fixed_inventory_version_cannot_override_a_vulnerable_bom_version(self):
        p=profile();p['reference_values']['other-version']=dict(kind='version',label='1.0.1h',asset_ref=p['scope']['asset_ref'],evidence_ids=['inventory'])
        r=request('CVE-2014-0198',p,dict(runtime_version='inventory:other-version',release_buffers='enabled'))
        self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_unbound_cve_has_basic_operational_questions_but_never_borrows_an_openssl_fix(self):
        p=profile();pl=E.plan('CVE-1999-1085',p);self.assertEqual({q['id'] for q in pl['questions']},{'deployment','runtime_version'})
        self.assertEqual(self.assess(request('CVE-1999-1085',p))['decision']['status'],'under_investigation')
    def test_asset_category_never_supplies_missing_operational_answers(self):
        for index in range(18):
            p=profile(asset_index=index);pl=E.plan('CVE-2010-5298',p)
            r=dict(cve=pl['cve'],profile=p,product_key=pl['product']['key'],plan_sha256=pl['plan_sha256'],auto_observations={})
            self.assertEqual(self.assess(r)['decision']['status'],'under_investigation')
    def test_current_source_or_profile_changes_require_replanning(self):
        r=request('CVE-2014-0198',profile(),dict(release_buffers='enabled'));r['profile']['scope']['mode']='maintenance'
        with self.assertRaises(ValueError):self.assess(r)
    def test_openvex_has_automatic_status_and_no_adopted_operator_conclusion(self):
        for version,choice,expected in [('1.0.1g','enabled','affected'),('1.0.1h','unknown','fixed'),('1.0.1g','disabled','not_affected'),('1.0.1g','unknown','under_investigation')]:
            r=request('CVE-2014-0198',profile(version=version),dict(release_buffers=choice))
            with patch('socket.socket.connect',side_effect=AssertionError('No network/model')):doc=E.export(r)
            self.assertEqual(doc['statements'][0]['status'],expected)

if __name__=='__main__':unittest.main()
