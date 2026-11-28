from copy import deepcopy
from datetime import datetime,timezone,timedelta
import json,unittest
from src.item4.decision import scoped_vex_review as A
from src.item4.decision import population_condition_rules as P
from src.item4.decision import evidence_based_vex as E
from tools.item4.auto_vex_fixture_support import profile,request
class FullPopulation(unittest.TestCase):
    def test_exact_original_population_without_whitelist_or_missing_members(self):
        data=P.manifest();original={c['cve'] for c in A.catalogue()['cves']}
        self.assertEqual(len(original),12418);self.assertEqual({r['cve'] for r in data['records']},original)
        self.assertEqual(data['population_sha256'],P.digest(sorted(original)))
        db=P.connection()
        try:self.assertEqual({r[0] for r in db.execute('select cve from records')},original)
        finally:db.close()
    def test_real_non_whitelisted_cve_has_source_network_question_and_automatic_status(self):
        p=profile('InduSoft Web Studio','6.1');pl=E.plan('CVE-2011-4051',p)
        self.assertTrue(pl['supported']);self.assertEqual(pl['compiler_mode'],'full_population')
        q=next(q for q in pl['questions'] if q['id'].startswith('op-'));a=request(pl['cve'],p,{q['id']:q['true_values'][0]})
        self.assertEqual(E.evaluate(a)['decision']['status'],'affected')
        a['auto_observations'][q['id']]['value']='blocked'
        self.assertEqual(E.evaluate(a)['decision']['status'],'under_investigation') # Not a universal negative proof.
    def test_source_absence_is_not_a_safety_assumption(self):
        p=profile('Unresolved source model','1.0.0');a=request('CVE-1999-1085',p)
        self.assertEqual(E.evaluate(a)['decision']['status'],'under_investigation')
        a['auto_observations']['deployment']['value']='not_deployed'
        self.assertEqual(E.evaluate(a)['decision']['status'],'not_affected')
        a['auto_observations']['deployment']['coverage']='partial'
        self.assertEqual(E.evaluate(a)['decision']['status'],'under_investigation')
    def test_exact_range_and_unknown_ordering(self):
        matrix=[('<3.1.1','3.1.0','true'),('<3.1.1','3.1.1','false'),('>=1.0 <2.0','1.5','true'),('>=1.0 <2.0','2.0','false'),('6.1|7.0','6.1','true'),('all versions','UNVERIFIED-BUILD','unknown'),('<7.4x','7.3','unknown'),('1.0 and earlier','0.9','true')]
        for source,actual,value in matrix:
            with self.subTest(source=source,actual=actual):self.assertEqual(P.membership(P.version_predicate(source),actual),value)
    def test_recommended_first_fixed_or_outside_affected_is_not_a_fix_range(self):
        rule=dict(source_product_rows=[dict(status='known_affected',version_predicate=P.version_predicate('<2.0'))])
        self.assertEqual(P.status(rule,'1.9'),'vulnerable');self.assertEqual(P.status(rule,'2.0'),'unknown')
        rule['source_product_rows'].append(dict(status='fixed',version_predicate=P.version_predicate('2.1')))
        self.assertEqual(P.status(rule,'2.1'),'fixed');self.assertEqual(P.status(rule,'2.2'),'unknown')
    def test_conflicting_supplier_statements_stay_unknown(self):
        rule=dict(source_product_rows=[dict(status=k,version_predicate=P.version_predicate('all versions')) for k in ('known_affected','known_not_affected')])
        self.assertEqual(P.status(rule,'1.0'),'conflicting')
    def test_untranslated_competing_version_status_prevents_a_definitive_status(self):
        for known in ('fixed','known_not_affected','known_affected'):
            with self.subTest(known=known):
                rule=dict(source_product_rows=[
                    dict(status=known,version_predicate=P.version_predicate('2.1')),
                    dict(status='known_affected',version_predicate=dict(op='unknown',raw='unparsed vendor range'))])
                self.assertEqual(P.status(rule,'2.1'),'unknown')

    def test_unknown_source_conditions_stay_as_expression_operands(self):
        row=P.get('CVE-1999-1085');rule=P.make_rule(row['cve'],row['products'][0]['model'])
        self.assertTrue(rule['compiled_gaps']);self.assertIn('unknown',rule['implicit_values'].values())
    def test_cached_profile_check_does_not_cache_time_or_evidence_assurance(self):
        from unittest.mock import patch
        p=profile('InduSoft Web Studio','6.1');pl=E.plan('CVE-2011-4051',p);q=next(q for q in pl['questions'] if q['id'].startswith('op-'));a=request(pl['cve'],p,{q['id']:q['true_values'][0]})
        self.assertEqual(E.evaluate(a)['decision']['status'],'affected')
        with patch.object(E,'now',return_value=datetime.now(timezone.utc)+timedelta(days=2)):
            self.assertEqual(E.evaluate(a)['decision']['status'],'under_investigation')
        bad=deepcopy(a);bad['profile']['evidence']['inventory']['asset_ref']='other'
        bad['plan_sha256']=E.plan(pl['cve'],bad['profile'])['plan_sha256']
        self.assertEqual(E.evaluate(bad)['decision']['status'],'under_investigation')
if __name__=='__main__':unittest.main()
