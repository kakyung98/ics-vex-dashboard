"""Regression checks for product/version mistakes found in the corpus review."""
import json,sys,unittest
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
if (Path(__file__).parent/'icsa_reviewed_product_overrides.py').exists():sys.path.insert(0,str(Path(__file__).parent))
from tools.common.icsa_reviewed_product_overrides import PRODUCTS
from tools.common import icsa_advisory_products as extraction
from tools.common.build_icsa_advisory_sbom import build_document, validator

class CorpusReviewRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=json.loads((ROOT/'data/cisa_advisories.json').read_bytes())
        extraction.PRODUCTS.update(PRODUCTS)
        cls.check=validator()
    def document(self,aid):
        path=ROOT/'icsa/csaf'/(aid+'.json')
        csaf=json.loads(path.read_bytes()) if path.exists() else None
        doc,review,_=build_document(aid,self.raw[aid],csaf,datetime.now(timezone.utc))
        self.check.validate(doc)
        return doc,review
    def test_nested_versions_have_real_parent_product_names(self):
        for aid in ['icsa-14-329-02','icsa-14-329-02a','icsa-14-329-02b']:
            doc,_=self.document(aid)
            self.assertTrue(any(c['name'].startswith('TIA Portal') for c in doc['components']))
            self.assertTrue(all(not c['name'].startswith('V7.') and c['name']!='All' for c in doc['components']))
    def test_citation_page_number_is_not_a_release(self):
        doc,_=self.document('icsa-10-090-01')
        self.assertEqual([(c['name'],c['version']) for c in doc['components']],[('Windows','unknown')])
    def test_product_table_is_preserved_instead_of_exploit_framework(self):
        doc,_=self.document('icsa-11-096-01')
        names={c['name'] for c in doc['components']}
        self.assertIn('Automated Solutions Modbus/TCP OPC Server',names)
        self.assertIn('SafeNet Sentinel Protection Server',names)
        self.assertNotIn('CANVAS',names)
        self.assertNotIn('ITS scada',names)
    def test_nonproduct_notice_does_not_create_sentence_components(self):
        doc,review=self.document('icsa-11-084-01')
        self.assertFalse(doc['components'])
        self.assertTrue(review['affected_product_statements'])
    def test_mendix_has_three_products_and_source_supported_cve_links(self):
        doc,_=self.document('icsa-26-302-01')
        self.assertEqual(len(doc['components']),3)
        v=next(v for v in doc['vulnerabilities'] if v['id']=='CVE-2026-89209')
        self.assertEqual(len(v['affects']),3)
        self.assertTrue(all('scope' not in c for c in doc['components']))
        self.assertEqual(doc['metadata']['manufacturer']['name'],'unknown')
    def test_every_curated_pair_exists_in_source_and_meets_schema(self):
        for aid in PRODUCTS:
            with self.subTest(advisory=aid):self.document(aid)

if __name__=='__main__':unittest.main()