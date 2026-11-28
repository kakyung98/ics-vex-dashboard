"""Regression checks for products lost by the former CVE/CPE membership gate."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from tools.common.icsa_advisory_products import html_rows, product_rows, split_statement, source_vendor
from tools.common.build_icsa_advisory_sbom import build_document, validator


class AdvisoryProductTests(unittest.TestCase):
    def test_product_without_cve_or_cpe_is_preserved(self):
        csaf={'product_tree':{'branches':[{'category':'vendor','name':'Acme','branches':[
            {'category':'product_name','name':'Controller','branches':[
                {'category':'product_version_range','name':'vers:all/*','product':{
                    'name':'Controller: All versions','product_id':'P1'}}]}]}]}}
        doc,_,_=build_document('icsa-test',{'title':'Test','url':'https://example.org/advisory','cves':[]},csaf,datetime.now(timezone.utc))
        self.assertEqual([(c['name'],c['version']) for c in doc['components']],[('Controller','All versions')])
        self.assertNotIn('cpe',doc['components'][0])
        self.assertEqual(doc['metadata']['manufacturer']['name'],'unknown')
        self.assertNotIn('dependencies',doc)
        validator().validate(doc)

    def test_update_heading_does_not_hide_product_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'advisory.html'
            p.write_text('<main><h2>Affected Products</h2><h3>Begin Update A</h3><ul>'
                         '<li>Controller: All versions prior to V2.0</li><li>Panel: Version 1.2</li>'
                         '</ul><h3>End Update A</h3><h2>Mitigation</h2><p>Upgrade to 2.0</p></main>')
            rows,_,_=html_rows('test',{},p)
        self.assertEqual([(r['name'],r['version']) for r in rows],
                         [('Controller','All versions prior to V2.0'),('Panel','Version 1.2')])

    def test_source_retraction_does_not_assert_affected_edges(self):
        csaf={'document':{'notes':[{'text':'These vulnerabilities do not impact the devices.'}]},
              'product_tree':{'full_product_names':[{'name':'Panel','product_id':'P1'}]},
              'vulnerabilities':[{'cve':'CVE-2021-20602','product_status':{'known_affected':['P1']}}]}
        doc,review,_=build_document('icsa-test',{'url':'https://example.org/advisory','cves':['CVE-2021-20602']},csaf,datetime.now(timezone.utc))
        self.assertTrue(review['source_conflict_review'])
        self.assertEqual(len(doc['components']),1)
        self.assertNotIn('affects',doc['vulnerabilities'][0])

    def test_colon_takes_precedence_over_version_word(self):
        self.assertEqual(split_statement('SIMATIC Panel: All versions prior to V3.0'),
                         ('SIMATIC Panel','All versions prior to V3.0'))

    def test_manufacturer_uses_full_name_present_in_source(self):
        self.assertEqual(source_vendor({'vendor':'Rockwell'},'Rockwell Automation provides the tool.'),'Rockwell Automation')
        self.assertEqual(source_vendor({'vendor':'Rockwell'},'Rockwell is listed here.'),'Rockwell')

    def test_rslinx_executable_is_an_alias_not_a_third_product(self):
        from tools.common.build_icsa_advisory_sbom import ROOT
        rows,_,_=html_rows('icsa-10-070-01a',{'vendor':'Rockwell'},ROOT/'data/icsa_sbom_source_html/icsa-10-070-01a.html')
        self.assertEqual({r['name'] for r in rows},{'EDS Hardware Installation Tool','RSLinx Classic'})
        self.assertEqual(rows[0]['alternate_names'],['RSHWare.exe'])
        self.assertEqual(rows[0]['source_observed_versions'],['1.0.4.0'])
        self.assertTrue(all(r['vendor']=='Rockwell Automation' for r in rows))

    def test_website_preserves_cpe_less_products_and_invalidates_stale_versions(self):
        from tools.item3.icsa_cpe_dataset_web import build_cache, load_cache, sha_bytes
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);(folder/'sbom').mkdir()
            def save(version):
                doc={'components':[{'bom-ref':'p1','type':'application','name':'Panel','version':version}]}
                wire=json.dumps(doc).encode();(folder/'sbom/test.json').write_bytes(wire)
                index={'summary':{'dataset_id':'test-v2'},'advisories':[{'advisory_id':'test','file':'sbom/test.json','component_count':1,'title':'Panel advisory','declared_cves':['CVE-2021-20602'],'sha256':sha_bytes(wire)}]}
                (folder/'index.json').write_text(json.dumps(index))
            save('1.0');cache=build_cache(folder)
            self.assertEqual(cache['assets'][0]['components'][0]['name'],'Panel')
            self.assertIsNone(cache['assets'][0]['components'][0]['cpe'])
            self.assertEqual(cache['assets'][0]['cves'],[{'id':'CVE-2021-20602'}])
            save('2.0');cache=load_cache(folder)
            self.assertEqual(cache['assets'][0]['components'][0]['version'],'2.0')

    def test_unknown_manufacturer_is_not_a_conflicting_vendor(self):
        from src.item3.evidence.product_candidate_search import ProductIndex
        index=ProductIndex([{'cpe':'cpe:2.3:a:rockwellautomation:rslinx_classic:2.41.00:*:*:*:*:*:*:*','title':'Rockwell Automation RSLinx Classic'}])
        versions={'observations':[],'purl':None}
        for manufacturer in ['unknown','NOASSERTION','Rockwell Automation']:
            rows=index.search({'name':'RSLinx Classic','manufacturer':manufacturer,'supplier':'unknown'},versions)['candidates']
            self.assertNotIn('explicit_manufacturer_differs',rows[0]['conflicts'])
        rows=index.search({'name':'RSLinx Classic','manufacturer':'Different Vendor'},versions)['candidates']
        self.assertIn('explicit_manufacturer_differs',rows[0]['conflicts'])

if __name__=='__main__':unittest.main()
