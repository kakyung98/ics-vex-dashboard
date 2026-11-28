from copy import deepcopy
import hashlib
import json

import pytest

from src.item4.analysis import product_advisory_evidence as C
from src.item4.analysis import exploitation_prerequisites as V


CVE = 'CVE-2099-10001'
AID = 'icsa-99-001-01'
COMPONENT = {'ref': 'asset-1', 'name': 'Device', 'value': {'version': '1.2', 'supplier': {'name': 'Acme'}}}


@pytest.fixture
def advisory(tmp_path, monkeypatch):
    folder = tmp_path / 'icsa/csaf'
    folder.mkdir(parents=True)
    path = folder / (AID + '.json')
    monkeypatch.setattr(C.A, 'ROOT', tmp_path)
    def write(statuses, other_advisories=()):
        tree = {'branches': [{'category': 'vendor', 'name': 'Acme', 'branches': [
            {'category': 'product_name', 'name': 'Device', 'branches': [
                {'category': 'product_version_range', 'name': '<2.0', 'product': {'product_id': 'p'}}]}]}]}
        doc = {'product_tree': tree, 'vulnerabilities': [
            {'cve': 'CVE-2099-10002', 'product_status': {'fixed': ['p']}},
            {'cve': CVE, 'product_status': statuses}]}
        wire = json.dumps(doc).encode()
        path.write_bytes(wire)
        passage = 'The supplier lists this product.'
        source = {'id': AID + ':v1', 'document_sha256': hashlib.sha256(wire).hexdigest(),
                  'text': passage, 'text_sha256': hashlib.sha256(passage.encode()).hexdigest(),
                  'product_keys': [AID + ':p']}
        detail = {'advisory_ids': [AID, *other_advisories], 'sources': [source]}
        monkeypatch.setattr(C.A, 'detail', lambda _: detail)
        return path
    return write


def test_selection_resolves_only_to_verified_source_and_detects_stale_bytes(advisory):
    path = advisory({'known_affected': ['p']})
    record, _ = C.packet(CVE, [COMPONENT])
    packet = V.extraction_packet(record)
    claim, = packet['product_evidence']
    binding = C.verified_version_evidence(CVE, COMPONENT)
    evidence, = binding['evidence']
    assert binding['state'] == 'known_affected'
    assert evidence['evidence_id'] == claim['product_evidence_id']
    assert evidence['status_pointer'] == '/vulnerabilities/1/product_status/known_affected/0'
    raw = {'cve': CVE, 'format': V.VERSION, 'prerequisites': [], 'scenarios': [], 'nonrequirements': [],
           'unknowns': ['No operating record.'], 'excluded_facts': [],
           'applicability_claims': [{'product_evidence_id': evidence['evidence_id']}]}
    draft = V.validate(V.resolve_references(raw, packet), record)
    assert draft['applicability_claims'] == [claim]
    path.write_bytes(path.read_bytes() + b' ')
    assert C.verified_version_evidence(CVE, COMPONENT)['state'] == 'unknown'
    with pytest.raises(ValueError, match='pinned source'):
        V.validate(draft, record)


def test_wrong_pointer_or_status_cannot_mint_a_reference(advisory):
    advisory({'known_affected': ['p']})
    record, _ = C.packet(CVE, [COMPONENT])
    packet = V.extraction_packet(record)
    for fields in [{'status_pointer': '/vulnerabilities/0/product_status/fixed/0', 'status': 'fixed'},
                   {'version': '3.1'}, {'product_pointer': '/elsewhere'}, {'key': AID + ':bad'}]:
        changed = deepcopy(record)
        changed['products'][0].update(fields)
        assert not C.verified_product_claims(changed)
    for choice in [{'product_evidence_id': 'v1-' + '0'*64}, {'product_key': AID + ':p', 'source_fields': {}},
                   dict(packet['product_evidence'][0])]:
        with pytest.raises(ValueError, match='V1'):
            V.resolve_references({'applicability_claims': [choice]}, packet)
    legacy = V.extraction_packet(record, legacy_v1=True)
    assert 'product_evidence' not in legacy
    bad = {'product_key': AID + ':p', 'source_fields': {}}
    assert V.resolve_references({'applicability_claims': [bad]}, legacy)['applicability_claims'] == [bad]


def test_uncertain_scope_and_conflicting_rows_remain_visible(advisory, monkeypatch):
    advisory({'known_affected': ['p'], 'fixed': ['p']})
    assert C.verified_version_evidence(CVE, COMPONENT)['state'] == 'conflicting'
    unresolved = deepcopy(COMPONENT)
    unresolved['value']['version'] = 'unknown'
    assert C.verified_version_evidence(CVE, unresolved)['state'] == 'unknown'
    advisory({'known_not_affected': ['p']}, ['icsa-99-002-01'])
    from src.item3.evidence import cisa_advisory_lookup as candidate_advisories
    monkeypatch.setattr(candidate_advisories, 'source_records', lambda: {})
    binding = C.verified_version_evidence(CVE, COMPONENT)
    assert binding['state'] == 'unknown'
    assert binding['source_issues'] == [{'advisory_id': 'icsa-99-002-01', 'reason': 'missing_or_unverified_source'}]
