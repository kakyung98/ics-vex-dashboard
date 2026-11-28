import json
import sqlite3

from tools.item4 import audit_item4_spectrum_field_records as field


def test_target_terms_match_boundaries_and_advisory_fix():
    assert field.labels('bf-47456_PE_WOP_fix') == {'bugfix', 'portal'}
    assert field.labels('WEB_OFFICE_PORTAL on Spectrum Power 4.7') == {'portal', 'product'}
    assert field.labels('SSA-324467 and CVE-2019-6579') == {'cve', 'advisory'}
    assert not field.labels('CVE-2019-65790, unrelated WOPR, SSA-3244678')


def test_unverified_input_or_attachment_stays_pending_and_redacted(tmp_path):
    path = tmp_path / 'field.sqlite3'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE objects(kind TEXT, id TEXT, payload TEXT)')
        for doc in ({'text': 'Web Office Portal on private asset'},
                    {'source_record_ref': 'private path'}, {'unrelated': 10}):
            db.execute('INSERT INTO objects VALUES(?,?,?)', ('job', 'private case', json.dumps(doc)))
    before = path.read_bytes()
    result = field.inspect_store(path)
    assert result['status'] == 'complete' and result['records_examined'] == 3
    assert [x['matched'] for x in result['candidates']] == [['portal'], ['attachment_reference']]
    assert all(x['disposition'] == 'requires_record_review' for x in result['candidates'])
    assert 'private' not in json.dumps(result)
    assert before == path.read_bytes()


def test_unknown_journals_and_empty_archives(tmp_path):
    path = tmp_path / 'archive.sqlite3'
    path.touch()
    assert field.inspect_store(path, archived=True)['snapshot_kind'] == 'empty_archived_file'
    assert field.inspect_store(path)['status'] == 'incomplete'
    journal = tmp_path / 'archive.sqlite3-journal'
    journal.write_bytes(b'active')
    assert field.inspect_store(path, archived=True)['status'] == 'incomplete'
    assert journal.read_bytes() == b'active'


def test_missing_sources_cannot_produce_zero_verified_records(tmp_path):
    result = field.audit(root=tmp_path, runtime=tmp_path, support=tmp_path, delivery=tmp_path)
    assert result['status'] == 'incomplete' and result['records_examined'] is None
    assert result['verified_field_records'] is None and result['portal_installation_verified'] is None
    assert result['running_release_verified'] is None and result['bugfix_installation_verified'] is None
