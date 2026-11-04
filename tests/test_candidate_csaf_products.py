"""Advisory candidate recall must preserve product scope and uncertainty."""
import json

from src.candidate_advisories import retrieve, structured_product_match
from src.dataset_paths import public_sbom_file
from src.identity_evidence import parse_components


def test_coretec_structured_family_lookup_ignores_embedded_cve_answers():
    sbom=json.loads(public_sbom_file('icsa-26-302-03_SBOM-CVE.json').read_text(encoding='utf-8'))
    sbom['vulnerabilities']=[{'id':'CVE-1999-999999'}]
    rows=[retrieve(c) for c in parse_components(sbom)]
    assert [{v['cve_id'] for v in r} for r in rows]==[
        set(), {'CVE-2026-13162','CVE-2026-43284'},
        {'CVE-2026-13162','CVE-2026-43284'}, {'CVE-2026-13162'}]
    for row in rows:
        for v in row:
            assert v['match_status']=='unknown'
            assert v['evidence']['version_confirmed'] is False
            assert v['evidence']['document_sha256']
            assert v['evidence']['csaf_product_ids']
    component=parse_components(sbom)[1]
    component.update(manufacturer='Different Vendor',supplier='Hitachi Energy')
    assert not retrieve(component)


def test_product_boundary_and_version_suffix_are_not_fuzzy_aliases():
    for name in ['CoreTec5','Hitachi Energy CoreTec5 5.0.0',
                 'Hitachi Energy CoreTec5 vers:CoreTec5/<=3.4.0']:
        assert structured_product_match(name,'hitachi energy','CoreTec5')
    for name in ['CoreTec50','CoreTec5 unrelated controller','SuperCoreTec5',
                 'CoreTec4 5.0.0','CoreTec5 Vendor Firmware/Application extra']:
        assert not structured_product_match(name,'hitachi energy','CoreTec5')
