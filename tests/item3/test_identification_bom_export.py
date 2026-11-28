"""Exercise the download converter against the local CycloneDX schema and VEX importer."""
import json
from pathlib import Path
import subprocess
import unittest

from jsonschema import Draft7Validator, RefResolver
from src.item4.workflow.source_analysis_jobs import inventory

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT/'src/item3/web/identification_bom_export.js'


def export_bom(bom, result):
    process = subprocess.run(['node', '-e',
        "const fs=require('fs'),vm=require('vm');"
        "vm.runInThisContext(fs.readFileSync(process.argv[1],'utf8'));"
        "const p=JSON.parse(fs.readFileSync(0,'utf8'));"
        "process.stdout.write(JSON.stringify(exportIdentificationBom(p.bom,p.result)));", str(SCRIPT)],
        input=json.dumps(dict(bom=bom, result=result)), text=True, encoding='utf-8', capture_output=True,
        cwd=ROOT, check=True)
    return json.loads(process.stdout)


def row(ref, *findings):
    return dict(component=dict(id=ref), cves=[dict(cve_id=cve, match_status=status) for cve, status in findings])


class IdentificationBomExport(unittest.TestCase):
    def assert_schema(self, value):
        schema_path=ROOT/'data/standards/cyclonedx-1.7/bom-1.7.schema.json'
        schema=json.loads(schema_path.read_text(encoding='utf-8'))
        Draft7Validator(schema, resolver=RefResolver(schema_path.as_uri(), schema)).validate(value)

    def test_preserves_inventory_and_evidence_without_promoting_candidates(self):
        component={'bom-ref':'root', 'type':'firmware', 'name':'Controller', 'version':'1.0'}
        bom=dict(bomFormat='CycloneDX', specVersion='1.7', version=2,
                 metadata=dict(component={**component, 'description':'Representative inventory'}),
                 components=[component], dependencies=[dict(ref='root', dependsOn=[])])
        result=dict(components=[row('root', ('CVE-2026-12345','match'), ('CVE-2026-54321','candidate'))])
        exported=export_bom(bom, result)
        self.assert_schema(exported)
        self.assertEqual(exported['dependencies'], bom['dependencies'])
        self.assertEqual(exported['components'][0]['description'], 'Representative inventory')
        self.assertNotIn('component', exported['metadata'])
        self.assertEqual(exported['vulnerabilities'][0]['affects'], [dict(ref='root')])
        self.assertEqual([v['id'] for v in exported['vulnerabilities']], ['CVE-2026-12345'])
        self.assertNotIn('analysis', exported['vulnerabilities'][0])
        properties={p['name']:p['value'] for p in exported['properties']}
        self.assertEqual(json.loads(properties['icsvex:original-input-bom']), bom)
        self.assertEqual(json.loads(properties['icsvex:identification-result']), result)
        _, declared=inventory(exported)
        self.assertEqual(len(declared), 1)
        self.assertEqual(declared[0]['component_refs'], ['root'])

    def test_spdx_conversion_keeps_dependencies_and_original_package(self):
        bom=dict(spdxVersion='SPDX-2.3', packages=[
            dict(SPDXID='SPDXRef-a', name='A', versionInfo='1.2', licenseConcluded='NOASSERTION'),
            dict(SPDXID='SPDXRef-b', name='B')], relationships=[
            dict(spdxElementId='SPDXRef-a', relationshipType='DEPENDS_ON', relatedSpdxElement='SPDXRef-b')])
        result=dict(components=[row('SPDXRef-a', ('CVE-2026-12345','match')), row('SPDXRef-b')])
        exported=export_bom(bom,result)
        self.assert_schema(exported)
        self.assertEqual(exported['dependencies'][0], dict(ref='SPDXRef-a',dependsOn=['SPDXRef-b']))
        self.assertEqual(json.loads(exported['components'][0]['properties'][0]['value']), bom['packages'][0])

    def test_shared_cve_retains_all_component_bindings_and_existing_inventory(self):
        bom=dict(bomFormat='CycloneDX', specVersion='1.7', version=1,
                 components=[dict(type='library', name='A'), dict(type='library', name='B')])
        result=dict(components=[row('0', ('CVE-2026-12345','match')), row('1', ('CVE-2026-12345','match'))])
        exported=export_bom(bom,result)
        self.assert_schema(exported)
        self.assertEqual(exported['vulnerabilities'][0]['affects'],[dict(ref='0'),dict(ref='1')])

    def test_missing_result_target_blocks_export(self):
        with self.assertRaises(subprocess.CalledProcessError):
            export_bom(dict(bomFormat='CycloneDX',specVersion='1.7',version=1,components=[]),
                       dict(components=[row('missing', ('CVE-2026-12345','match'))]))


if __name__ == '__main__':
    unittest.main()
