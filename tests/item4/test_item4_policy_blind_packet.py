import json
import shutil

import pytest

from tools.item4 import build_item4_policy_blind_packet as packet


def test_sealed_forms_preserve_every_case_and_policy():
    manifest = packet.verify(packet.OUTPUT)
    source = packet.original.read_rows(packet.SOURCE / 'coordinator/neutral_evidence.jsonl')
    assert (manifest['sample_scenarios'], manifest['sample_cves'], manifest['evidence_items']) == (95, 83, 472)
    forms = []
    for slot in packet.SLOTS:
        path = packet.OUTPUT / slot / 'form.json'
        form = json.loads(path.read_bytes())
        assert set(form) == {'version', 'packet_id', 'reviewer_slot', 'instructions', 'output_contract', 'cases'}
        assert form['cases'] == source
        assert form['packet_id'] == manifest['packet_id'] != manifest['source_packet_id']
        assert form['reviewer_slot'] == slot
        assert packet.original.digest(path.read_bytes()) == manifest['files'][slot + '/form.json']
        header = form['output_contract']['ballot_fields']
        assert header['schema_version'] == 'item4-independent-agent-ballot/2'
        assert (header['reviewer_slot'], header['packet_id']) == (slot, form['packet_id'])
        assert set(form['output_contract']['rating_fields']) == {
            'review_id', 'status', 'evidence_ids', 'rationale', 'needed_records', 'field_record_types',
            'decision_basis', 'inventory_evidence_ids',
        }
        assert set(form['output_contract']['rating_fields']['decision_basis']) == set(packet.BASES)
        policy = ''.join(form['instructions'])
        assert all(term in policy for term in ('deployment=not_deployed', 'scope=current_single',
                   'inventory_coverage=complete', 'partial', 'under_investigation', '동결 관측시점'))
        forms.append(form)
    assert forms[0]['instructions'] == forms[1]['instructions']


def test_rebuild_is_reproducible_and_refuses_existing_destination(tmp_path):
    target = tmp_path / 'packet'
    assert packet.build(target) == packet.verify(packet.OUTPUT)
    with pytest.raises(FileExistsError):
        packet.build(target)
    form_file = target / 'reviewer_a/form.json'
    edited = json.loads(form_file.read_bytes())
    edited['cases'][0]['evidence'].pop()
    form_file.write_bytes(packet.encode(edited))
    with pytest.raises(ValueError, match='reviewer_a/form.json'):
        packet.verify(target)


def test_untrusted_source_manifest_is_rejected(tmp_path):
    source = tmp_path / 'source'
    shutil.copytree(packet.SOURCE, source)
    manifest = source / 'coordinator/manifest.json'
    manifest.write_bytes(manifest.read_bytes() + b' ')
    with pytest.raises(ValueError, match='manifest seal'):
        packet.build(tmp_path / 'new', source)
    assert not (tmp_path / 'new').exists()
