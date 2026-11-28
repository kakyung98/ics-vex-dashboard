"""Selection domains, scope counterexamples, and conservative VEX integration."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import hashlib,json,unittest
from unittest.mock import patch
from src.item4.assets import operating_profile_catalog as M

class SelectableAnswers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c=M.catalogue()
        cls.t=cls.c['profiles'][2]
        cls.now=datetime.now(timezone.utc)

    def blank(self):
        p=deepcopy(self.t['blank'])
        p['scope']={k:'FICTIONAL-TEST' for k in p['scope']}
        p['scope'].update(observed_at=(self.now-timedelta(minutes=10)).isoformat(),valid_until=(self.now+timedelta(hours=1)).isoformat())
        return p

    def observation(self,fid,option=None):
        f=next(f for f in self.t['definition']['fields'] if f['id']==fid)
        o=option or f['response_spec']['options'][0]
        p=self.blank()
        e=dict(source='FICTIONAL fixture source',excerpt='FICTIONAL observation; not a real asset',kind=f['response_spec']['allowed_evidence_kinds'][0],reviewed=True,
               asset_ref=p['scope']['asset_ref'],build=p['scope']['build'],config_baseline=p['scope']['config_baseline'],
               observed_at=(self.now-timedelta(hours=1)).isoformat(),valid_until=(self.now+timedelta(hours=1)).isoformat())
        p['evidence']['e']=e
        p['gates'][f['row_id']]=dict(state='present',evidence_ids=['e'],coverage_scope='assessed_asset')
        v=dict(state='recorded',evidence_ids=['e'],coverage_scope='assessed_asset',unknown_reason='',
               data=dict(choice=o['code'],coverage='complete',value_refs=[]))
        if o['requires_value_reference']:
            p['reference_values']['value-1']=dict(kind=f['response_spec']['reference_kind'],label='FICTIONAL exact source value',asset_ref=p['scope']['asset_ref'],evidence_ids=['e'])
            v['data']['value_refs']=['value-1']
        p['inventory']['values'][fid]=v
        return p

    def test_all_18_blank_profiles_preserve_unknown(self):
        for t in self.c['profiles']:
            with self.subTest(asset=t['asset']['id']):
                r=M.validate(t['blank']);self.assertEqual(r['unknown_fields'],167);self.assertFalse(r['llm_used'])

    def test_every_offered_option_is_structurally_usable_with_required_evidence(self):
        self.assertEqual(len(self.c['answer_specs']),167)
        for fid,f in self.c['answer_specs'].items():
            for o in f['options']:
                with self.subTest(field=fid,option=o['code']):
                    p=self.observation(fid,o);r=M.validate(json.loads(json.dumps(p)))
                    self.assertEqual(r['recorded_fields'],1)

    def test_each_exhaustive_choice_rejects_partial_surveys(self):
        checked=0
        for fid,f in self.c['answer_specs'].items():
            for o in f['options']:
                if o['requires_complete_scope']:
                    p=self.observation(fid,o);p['inventory']['values'][fid]['data']['coverage']='partial'
                    with self.subTest(field=fid,option=o['code']),self.assertRaisesRegex(ValueError,'complete surveyed'):
                        M.validate(p)
                    checked+=1
        self.assertGreater(checked,50)

    def test_arbitrary_prose_cannot_be_an_answer(self):
        p=self.observation('C13-08.01');p['inventory']['values']['C13-08.01']['data']='I think this is secure'
        with self.assertRaises(ValueError):M.validate(p)
        p=self.observation('C13-11.01');p['inventory']['values']['C13-11.01']['data']['choice']='probably_safe'
        with self.assertRaises(ValueError):M.validate(p)

    def test_inventory_values_are_typed_bound_and_source_linked(self):
        for mutation in ['missing','wrong_type','wrong_asset','missing_ref_evidence']:
            p=self.observation('C13-08.01')
            if mutation=='missing':p['inventory']['values']['C13-08.01']['data']['value_refs']=[]
            if mutation=='wrong_type':p['reference_values']['value-1']['kind']='identity'
            if mutation=='wrong_asset':p['reference_values']['value-1']['asset_ref']='ANOTHER-ASSET'
            if mutation=='missing_ref_evidence':p['reference_values']['value-1']['evidence_ids']=['missing']
            with self.subTest(case=mutation),self.assertRaises(ValueError):M.validate(p)

    def test_unreviewed_stale_wrong_build_evidence_cannot_establish_fact(self):
        for mutation in ['unreviewed','stale','future','wrong_build','wrong_baseline']:
            p=self.observation('C13-11.01');e=p['evidence']['e']
            if mutation=='unreviewed':e['reviewed']=False
            if mutation=='stale':e['valid_until']=(self.now-timedelta(days=1)).isoformat()
            if mutation=='future':e['observed_at']=(self.now+timedelta(days=1)).isoformat()
            if mutation=='wrong_build':e['build']='another build'
            if mutation=='wrong_baseline':e['config_baseline']='another baseline'
            with self.subTest(case=mutation),self.assertRaises(ValueError):M.validate(p)

    def test_configuration_record_cannot_substitute_for_implementation_analysis(self):
        for fid in ['C15-01.01','C15-01.03','C16-06.03']:
            p=self.observation(fid);p['evidence']['e']['kind']='configuration_record'
            with self.subTest(field=fid),self.assertRaisesRegex(ValueError,'evidence type'):M.validate(p)

    def test_unknown_unrepresented_and_conflict_do_not_assert_truth(self):
        p=self.blank();p['inventory']['values']['C13-08.01']['unknown_reason']='value_not_represented'
        self.assertEqual(M.validate(p)['unknown_fields'],167)
        p=self.observation('C13-11.01');v=p['inventory']['values']['C13-11.01'];v.update(state='conflicting',data=None)
        with self.assertRaises(ValueError):M.validate(p)
        p['evidence']['e2']=deepcopy(p['evidence']['e']);p['evidence']['e2']['excerpt']='FICTIONAL conflicting observation';v['evidence_ids'].append('e2')
        r=M.validate(p);self.assertEqual(r['conflicting_fields'],1);self.assertEqual(r['recorded_fields'],0)

    def test_type_and_empty_inventory_cannot_prove_nonapplicability(self):
        p=self.observation('C13-11.01');v=p['inventory']['values']['C13-11.01'];v.update(state='not_applicable',data=None)
        with self.assertRaises(ValueError):M.validate(p)
        p['gates']['C13-11']['state']='absent';self.assertEqual(M.validate(p)['not_applicable_fields'],1)

    def test_governance_or_control_choices_do_not_clear_a_cve(self):
        import tools.item4.serve_nist_operational_vex as S
        V=S.V
        text='A remote attacker requires network access.'
        ref=dict(source_id='fixture',span=[0,len(text)],quote=text)
        record=dict(cve='CVE-2099-90001',description='FICTIONAL TEST ONLY',original_nvd_status='Analyzed',cwes=[],asset_ids=['A0003'],
            products=[dict(key='fixture-product',name='FICTIONAL controller',binding='CSAF_known_affected',asset_ids=['A0003'])],
            sources=[dict(id='fixture',text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),url='https://example.invalid/fixture',product_keys=['fixture-product'],subject_ambiguous=False)],
            scenarios=[dict(id='route',product_keys=['fixture-product'],scope_ambiguous=False,derivation='fixture',source_ref=ref,
                expression=dict(condition='network'),conditions=[dict(id='network',kind='network_access',proposition='network access',question='Fixture network access?',operator_observable=True,source_ref=ref,context_ref=ref)])])
        for fid in ['C12-01.01','C13-11.01','C16-02.01','C13-09.02']:
            p=self.observation(fid);plan=V.plan(record['cve'],p,record=record,templates=self.c)
            request=dict(cve=record['cve'],profile=p,product_key=plan['product']['key'],plan_sha256=plan['plan_sha256'],approved_scenarios=['route'],
                bindings=[dict(question_id='route:network',field_ids=[fid],value='false',review_confirmed=True,explanation='FICTIONAL unsupported general-control mapping',absence_scope='FICTIONAL scope')])
            with self.subTest(field=fid),patch('socket.socket.connect',side_effect=AssertionError('Network/LLM call forbidden in this test')),self.assertRaises(ValueError):
                V.evaluate(request,record,self.c)

if __name__=='__main__':unittest.main()
