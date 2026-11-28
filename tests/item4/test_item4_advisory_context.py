"""Declared CVEs route directly to independently product-scoped ICSA evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from src.item4.analysis import product_advisory_evidence as C; from src.item4.workflow import source_analysis_jobs as Q
from tools.item4 import serve_nist_operational_vex as S


class AdvisoryContext(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); folder = self.root/'icsa/csaf'; folder.mkdir(parents=True)
        self.cve = 'CVE-2026-12345'; self.aid = 'icsa-26-001-01'; self.key = self.aid+':pid'
        self.document = dict(product_tree=dict(branches=[dict(category='vendor',name='Acme',branches=[
            dict(category='product_name',name='Control Tool',branches=[dict(category='product_version_range',name='<2.0',
                product=dict(product_id='pid', product_identification_helper=dict(cpe='cpe:2.3:a:acme:control_tool:*:*:*:*:*:*:*:*')))])])]),
            vulnerabilities=[dict(cve=self.cve,product_status=dict(known_affected=['pid']))])
        raw = json.dumps(self.document).encode(); (folder/(self.aid+'.json')).write_bytes(raw)
        text = 'Exploitation requires FTP enabled.'
        self.detail = dict(advisory_ids=[self.aid], sources=[dict(id=self.aid+':v0:n0',text=text,
            text_sha256=hashlib.sha256(text.encode()).hexdigest(),document_sha256=hashlib.sha256(raw).hexdigest(),
            url='https://www.cisa.gov/news-events/ics-advisories/'+self.aid,product_keys=[self.key])])
        self.component = dict(ref='asset',name='Control Tool',value=dict(name='Control Tool',version='1.0',manufacturer={'name':'Acme'}))
        for obj, name, kwargs in [(C.A,'ROOT',dict(new=self.root)),(C.A,'detail',dict(return_value=self.detail))]:
            p = patch.object(obj,name,**kwargs); p.start(); self.addCleanup(p.stop)

    def test_name_and_version_resolve_without_cpe_or_identification(self):
        out = C.lookup(self.cve,[self.component])
        self.assertEqual(out['matches'][0]['version_membership'],'true')
        self.assertEqual(out['products'][0]['key'],self.key)
        self.assertEqual(out['sources'],self.detail['sources'])

    def test_shared_cve_does_not_link_unrelated_product(self):
        component = deepcopy(self.component); component['name']='Different Product'
        self.assertEqual(C.lookup(self.cve,[component])['matches'],[])

    def test_unknown_vendor_is_missing_context_not_a_vendor_conflict(self):
        component=deepcopy(self.component)
        component['value']['manufacturer']={'name':'unknown'}
        component['name']='Acme Control Tool'
        self.assertEqual(len(C.lookup(self.cve,[component])['matches']),1)

    def test_unknown_and_nonaffected_versions_are_not_silently_confirmed(self):
        component = deepcopy(self.component); component['value']['version']='all versions'
        self.assertEqual(C.lookup(self.cve,[component])['matches'][0]['version_membership'],'unknown')
        component['value']['version']='3.0'; out=C.lookup(self.cve,[component])
        self.assertEqual(out['matches'][0]['version_membership'],'false')
        self.assertEqual(out['sources'],[])

    def test_cpe_identity_can_resolve_alias_without_cpe_dictionary(self):
        component=deepcopy(self.component); component['name']='Alias'
        component['value']['cpe']='cpe:2.3:a:acme:control_tool:1.0:*:*:*:*:*:*:*'
        out=C.lookup(self.cve,[component])
        self.assertEqual(out['matches'][0]['product_match'],'CPE vendor/product identity')

    def test_source_tamper_cannot_supply_context(self):
        self.detail['sources'][0]['document_sha256']='0'*64
        self.assertEqual(C.lookup(self.cve,[self.component])['sources'],[])

    def test_scenarios_cannot_cross_component_product_bindings(self):
        context=C.lookup(self.cve,[self.component])
        result=dict(advisory_context=context,prerequisite=dict(draft=dict(scenarios=[
            dict(id='right',product_keys=[self.key]),dict(id='wrong',product_keys=['other'])])))
        self.assertEqual([s['id'] for s in C.scenarios_for(result,'asset')],['right'])
        self.assertEqual(C.scenarios_for(result,'different-component'),[])

    def test_description_extraction_preserves_csaf_product_context_on_failure(self):
        with patch.object(Q,'extract_description',side_effect=OSError('model unavailable')) as inference:
            out=Q.extract_declared(self.cve,[self.component])
        inference.assert_called_once_with(self.cve)
        self.assertEqual(out['source_kind'],'CVE description')
        self.assertEqual(out['status'],'unresolved')
        self.assertEqual(len(out['advisory_context']['matches']),1)

    def test_legacy_start_bypasses_item3_for_declared_cves(self):
        from src.item3.web import identification_jobs_api as candidate_web
        bom=dict(bomFormat='CycloneDX',components=[dict(name='Control Tool',**{'bom-ref':'asset'})],
                 vulnerabilities=[dict(id=self.cve,affects=[dict(ref='asset')])])
        with patch.object(candidate_web,'submit',side_effect=AssertionError('Must bypass item #3')), \
                patch.object(Q,'start',return_value=dict(id='direct-item4',status='queued')) as start:
            response=TestClient(S.app).post('/api/bom-vex/start',json=bom)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['workflow'],'item4')
        start.assert_called_once_with(bom)

    def test_bom_classification_does_not_require_cve_to_bind_representative(self):
        bom=dict(bomFormat='CycloneDX',metadata=dict(component=dict(name='Acme Control Tool',
                 manufacturer={'name':'unknown'},**{'bom-ref':'collection'})),
                 components=[dict(name='Control Tool',version='1.0',**{'bom-ref':'asset'})],
                 vulnerabilities=[dict(id=self.cve,affects=[dict(ref='asset')])])
        selected=Q.inventory(bom)[0][0]
        with patch.object(Q.asset_model,'predict',return_value=dict(asset_type_id='A0003')):
            out=Q.classify(bom,selected)
        self.assertEqual(out['status'],'classified')
        self.assertEqual(out['evidence'],[])
        self.assertEqual(out['feature_evidence'][0]['text'],'Acme Control Tool')
        self.assertFalse(out['supplies_operating_truth'])
        self.assertEqual(Q.inventory(bom)[1][0]['component_refs'],['asset'])


    def test_collection_title_is_never_used_in_place_of_actual_product(self):
        bom=dict(bomFormat='CycloneDX',metadata=dict(component=dict(name='Unrelated advisory title (Update A)',
                 type='data',**{'bom-ref':'collection:advisory'})),
                 components=[dict(name='Control Tool',version='1.0',manufacturer={'name':'Acme'},**{'bom-ref':'asset'})],
                 vulnerabilities=[dict(id=self.cve,affects=[dict(ref='asset')])])
        components,_=Q.inventory(bom)
        self.assertEqual([c['ref'] for c in Q.representative_candidates(bom,components)],['asset'])
        with patch.object(Q.asset_model,'predict',return_value=dict(asset_type_id='A0003')) as predict:
            out=Q.classify(bom,components[0])
        self.assertEqual(predict.call_args.args[0],'Control Tool')
        self.assertEqual(out['component_classifications'][0]['component_ref'],'asset')
        self.assertEqual(out['feature_evidence'][0]['text'],'Control Tool')
        self.assertEqual(out['representative']['name'],'Control Tool')


if __name__ == '__main__':
    unittest.main()
