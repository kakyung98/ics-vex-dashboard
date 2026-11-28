from copy import deepcopy
import json
import pytest
from src.item4.evaluation import prerequisite_consistency as E
from tools.item4.evaluate_prerequisite_consistency import main

V3 = 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H'
V4 = 'CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'


def record(*statements):
    return dict(cve='CVE-2026-10000', prerequisites=[dict(id='c'+str(i), statement=s)
                                                   for i, s in enumerate(statements)])


def reference(vector=V3):
    return dict(cve='CVE-2026-10000', vectors=[dict(vector=vector, source='vendor')], cwes=['CWE-787'])


def metric(report, key, vector=0):
    return next(m for m in report['cvss'][vector]['metrics'] if m['metric'] == key)


def test_agreement_contradiction_and_omission_are_distinct():
    r = E.evaluate(record('Attacker requires no privileges.', 'No user interaction is required.'), reference())
    assert metric(r, 'PR')['status'] == 'contradiction'
    assert metric(r, 'UI')['status'] == 'match'
    assert metric(r, 'AV')['status'] == 'not_comparable'
    assert metric(r, 'AC')['status'] == 'not_comparable'
    assert metric(r, 'AT')['status'] == 'not_comparable'
    summary = E.summarize([r])
    assert summary['agreement_rate'] == .5
    assert not summary['semantic_accuracy_proven']


def test_no_predictions_has_null_agreement():
    assert E.summarize([E.evaluate(record(), reference())])['agreement_rate'] is None


def test_original_source_and_reference_labels_do_not_fill_missing_assertions():
    row = record('HTTPS listener enabled.')
    row.update(cvss=V3, cwe='CWE-787', sources=[dict(text='Attacker requires high privileges.')])
    row['prerequisites'][0]['source_refs'] = [dict(quote='No user interaction is required.')]
    assert E.project(row)['claims'] == []
    assert 'cvss' not in E.extraction_view(row)
    assert all(m['status'] == 'not_comparable' for m in E.evaluate(row, reference())['cvss'][0]['metrics'])


@pytest.mark.parametrize('statement', [
    'Authentication enabled.', 'An authenticated user opens a file.',
    'It is false that attacker requires high privileges.',
    'If user interaction is required, the attack might work.',
    'No user interaction is required or the attacker must log in.',
])
def test_ambiguous_and_configuration_statements_not_guessed(statement):
    assert not E.project(record(statement))['claims']


def test_versions_and_providers_kept_separate():
    ref = reference()
    ref['vectors'] += [dict(vector=V4, source='other')]
    r = E.evaluate(record('User interaction is required.'), ref)
    assert metric(r, 'UI', 0)['status'] == 'contradiction'
    assert metric(r, 'UI', 1)['status'] == 'not_comparable'
    assert r['cvss'][1]['source'] == 'other'


@pytest.mark.parametrize('vector', [
    'CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C',
    V3+'/PR:N', V3.replace('PR:H', 'PR:X'), V3+'/AT:P', '9.8',
])
def test_invalid_or_unsupported_reference_retained(vector):
    r = E.evaluate(record(), reference(vector))
    assert r['cvss'][0]['status'] == 'unsupported_or_invalid_reference'
    assert E.summarize([r])['invalid_or_unsupported_vectors'] == 1


def test_multiple_paths_and_negation_not_flattened():
    for expression in [dict(op='not', args=[dict(condition='c0')]),
                       dict(op='or', args=[dict(condition='c0'), dict(condition='c1')])]:
        row = record('Attacker requires high privileges.', 'HTTPS listener enabled.')
        row['scenarios'] = [dict(expression=expression)]
        assert metric(E.evaluate(row, reference()), 'PR')['status'] == 'not_comparable'
    row['scenarios'] = [dict(expression=dict(condition='c0')), dict(expression=dict(condition='c1'))]
    assert metric(E.evaluate(row, reference()), 'PR')['status'] == 'not_comparable'


def test_structured_projection_supports_ac_at_and_validates_evidence():
    row = record('Exploitation depends on a race condition.')
    row['metric_claims'] = [dict(condition_id='c0', metric='AT', value='P', version='4.0',
                                  quote='depends on a race condition', scope='cve')]
    assert metric(E.evaluate(row, reference(V4)), 'AT')['status'] == 'match'
    row['metric_claims'][0]['quote'] = 'invented'
    with pytest.raises(ValueError):
        E.evaluate(row, reference())


def test_cwe_is_auxiliary_and_does_not_invent_conditions():
    row = record('Out-of-bounds write.')
    assert E.evaluate(row, reference())['cwe']['status'] == 'not_comparable'
    row['weakness_claims'] = [dict(condition_id='c0', cwe='CWE-787', quote='Out-of-bounds write')]
    r = E.evaluate(row, reference())
    assert r['cwe']['checks'][0]['status'] == 'exact_match'
    assert r['projection']['claims'] == []
    assert r['cwe']['auxiliary_only']
    row['weakness_claims'][0]['cwe'] = 'CWE-119'
    taxonomy = dict(records={'CWE-787': dict(parents_view_1000=['CWE-119']), 'CWE-119': {}})
    assert E.evaluate(row, reference(), taxonomy)['cwe']['checks'][0]['status'] == 'hierarchy_related'
    row['weakness_claims'][0]['cwe'] = 'CWE-78'
    taxonomy['records']['CWE-78'] = {}
    assert E.evaluate(row, reference(), taxonomy)['cwe']['checks'][0]['status'] == 'review_required'


def test_nvd_adapter_and_cli_preserve_missing_cases(tmp_path):
    inputs = tmp_path/'extractions.json'
    refs = tmp_path/'nvd.json'
    inputs.write_text(json.dumps([record('Attacker requires high privileges.'), dict(cve='CVE-2026-10001')]))
    refs.write_text(json.dumps(dict(vulnerabilities=[dict(cve=dict(id='CVE-2026-10000',
        metrics=dict(cvssMetricV31=[dict(source='nvd', cvssData=dict(vectorString=V3))]),
        weaknesses=[dict(description=[dict(value='CWE-787')])]))])))
    output = tmp_path/'report'
    assert main(['--extractions', str(inputs), '--references', str(refs), '--output', str(output)]) == 0
    report = json.loads((output/'report.json').read_bytes())
    assert report['input_records'] == 2 and report['missing_reference_records'] == 1
    assert report['metric_counts']['match'] == 1


def test_cve_mismatch_rejected_and_input_unchanged():
    row = record('Attacker requires high privileges.')
    original = deepcopy(row)
    ref = reference(); ref['cve'] = 'CVE-2026-99999'
    with pytest.raises(ValueError):
        E.evaluate(row, ref)
    E.evaluate(row, reference())
    assert row == original


def test_blinded_model_projection_and_no_reference_repair():
    row = record('Exploitation depends on a race condition.')
    row.update(cvss=V4, cwes=['CWE-362'], sources=[dict(text='Secret reference prose')])
    row['scenarios'] = [dict(expression=dict(condition='c0'),
                             source_refs=[dict(quote='Secret vector '+V4)])]
    def runner(system, packet, *, role):
        assert role == 'operating-record-review'
        serialized = json.dumps(packet)
        assert V4 not in serialized and 'CWE-362' not in serialized
        assert 'Secret' not in serialized and row['cve'] not in serialized
        return dict(prediction=dict(metric_claims=[dict(condition_id='c0', metric='AT', value='P',
            version='4.0', quote='depends on a race condition', scope='cve')], weakness_claims=[]), model='TEST DOUBLE')
    mapped, audit = E.model_projection(row, runner)
    assert 'metric_claims' not in row
    assert metric(E.evaluate(mapped, reference(V4)), 'AT')['status'] == 'match'
    assert not audit['reference_labels_used']


def test_model_hallucinated_projection_is_rejected():
    def runner(*args, **kwargs):
        return dict(prediction=dict(metric_claims=[dict(condition_id='c0', metric='PR', value='N',
            version='3.1', quote='not in extraction', scope='cve')], weakness_claims=[]))
    with pytest.raises(ValueError):
        E.model_projection(record('Authentication enabled.'), runner)


def test_conflicting_assertions_and_missing_taxonomy_do_not_become_matches():
    r = E.evaluate(record('Attacker requires high privileges.', 'Attacker requires no privileges.'), reference())
    assert metric(r, 'PR')['status'] == 'not_comparable'
    row = record('Command injection.')
    row['weakness_claims'] = [dict(condition_id='c0', cwe='CWE-78', quote='Command injection')]
    assert E.evaluate(row, reference())['cwe']['checks'][0]['status'] == 'not_comparable'


def test_nested_saved_vep_cache_can_be_evaluated():
    row = dict(cve='CVE-2026-10000', prerequisite=dict(draft=record('No user interaction is required.')))
    assert metric(E.evaluate(row, reference()), 'UI')['status'] == 'match'


def test_cli_failed_model_does_not_fallback_or_report_success(tmp_path, monkeypatch):
    from src.item4.models import json_inference_client
    def offline(*args, **kwargs):
        raise RuntimeError('model unavailable')
    monkeypatch.setattr(json_inference_client, 'generate', offline)
    inputs, refs, output = tmp_path/'input.json', tmp_path/'ref.json', tmp_path/'out'
    inputs.write_text(json.dumps(record('Attacker requires high privileges.')))
    refs.write_text(json.dumps(reference()))
    assert main(['--extractions', str(inputs), '--references', str(refs), '--output', str(output),
                 '--projection-model']) == 2
    report = json.loads((output/'report.json').read_bytes())
    assert report['records'] == 0 and report['input_records'] == 1
    assert report['agreement_rate'] is None
    assert 'model unavailable' in report['errors'][0]['error']
