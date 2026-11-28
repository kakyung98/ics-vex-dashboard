"""Verify explicit CSAF status and operator-confirmed builds through V3/V4."""
from copy import deepcopy
import hashlib
import json

import pytest

from src.item4.analysis import product_advisory_evidence as C
from src.item4.workflow import source_analysis_jobs as Q
from src.item4.decision import asset_vex_assessment as E
from src.item4.decision import mulval_attack_graphs as M

CVE = 'CVE-2099-54321'
AID = 'icsa-99-001-01'


@pytest.fixture
def setup_product(tmp_path, monkeypatch):
    folder = tmp_path / 'data/cisa_identification_csaf'
    folder.mkdir(parents=True)
    path = folder / (AID + '.json')
    monkeypatch.setattr(C.A, 'ROOT', tmp_path)
    def offline_graph(_):
        raise OSError('offline test')
    monkeypatch.setattr(M, 'generate', offline_graph)
    def fail_description(_):
        raise RuntimeError('description extraction unavailable')
    monkeypatch.setattr(Q, 'extract_description', fail_description)

    def setup(statuses, version='2.0', vendor='Acme', source_cpe=None, asset_cpe=None, name='Controller'):
        products = [
            dict(category='product_version_range', name='<2.0', product=dict(product_id='old')),
            dict(category='product_version', name='2.0', product=dict(product_id='current'))]
        if source_cpe:
            products[-1]['product']['product_identification_helper'] = dict(cpe=source_cpe)
        document = dict(product_tree=dict(branches=[dict(category='vendor', name='Acme', branches=[
            dict(category='product_name', name='Controller', branches=products)])]),
            vulnerabilities=[dict(cve=CVE, product_status=statuses)])
        raw = json.dumps(document).encode()
        path.write_bytes(raw)
        # The indexed prose only references the affected version. Fixed records
        # have their own proof in the structured product_status and product tree.
        detail = dict(advisory_ids=[AID], sources=[dict(id=AID+':v0:n0',
            document_sha256=hashlib.sha256(raw).hexdigest(), product_keys=[AID+':old'])])
        monkeypatch.setattr(C.A, 'detail', lambda _: deepcopy(detail))
        component = dict(ref='device', name=name, value=dict(version=version, manufacturer=vendor))
        if asset_cpe:
            component['value']['cpe'] = asset_cpe
        result = Q.extract_declared(CVE, [component])
        job = dict(id='test', status='completed', bom_sha256='a'*64, conditions=[result],
            revision=0, components=[C.component_identity(component)], representative=dict(ref='device'),
            asset_classification=dict(status='unresolved'), declared_cves=[dict(cve=CVE, component_refs=['device'])])
        Q._prepare_analysis(job)
        prefix = job['assessment_cases'][0]['prefix']
        job['context_answers'] = {'scope':'current_single', prefix+'deployment':'running', prefix+'runtime':'bom'}
        return job, path
    return setup


@pytest.mark.parametrize(('status', 'expected'), [('fixed','fixed'), ('known_not_affected','not_affected'),
                                                 ('under_investigation','under_investigation')])
def test_explicit_status_survives_unavailable_operational_inputs(setup_product, monkeypatch, status, expected):
    job, _ = setup_product({'known_affected':['old'], status:['current']})
    if expected != 'under_investigation':
        def unexpected_graph(*args):
            pytest.fail('A product-version decision must not start MulVAL')
        monkeypatch.setattr(E, 'build_graph', unexpected_graph)
    row = E.evaluate(job)['decisions'][0]
    assert row['status'] == expected
    assert row['attack_graph']['generation_status'] == ('unavailable' if expected == 'under_investigation' else 'not_required')
    assert row['prerequisite_status'] == 'unknown'
    source = next(s for s in row['version_binding']['sources'] if s['status'] == status)
    assert source['source_product_id'] == 'current'
    assert source['source_version'] == '2.0'
    assert source['status_pointer'] == '/vulnerabilities/0/product_status/'+status+'/0'
    assert source['product_pointer'].endswith('/branches/1/product')
    assert source['document_sha256']


@pytest.mark.parametrize(('statuses','version','vendor','expected_state'), [
    ({'known_affected':['old']}, '2.0', 'Acme', 'unknown'),
    ({'known_affected':['current'], 'fixed':['current']}, '2.0', 'Acme', 'conflicting'),
    ({'fixed':['current']}, '2.0', '', 'unknown')])
def test_clearance_needs_unambiguous_supplier_evidence(setup_product, statuses, version, vendor, expected_state):
    job, _ = setup_product(statuses, version, vendor)
    row = E.evaluate(job)['decisions'][0]
    assert row['status'] == 'under_investigation'
    assert row['version_binding']['state'] == expected_state


def test_stale_status_and_missing_operator_build_are_blocked(setup_product):
    job, path = setup_product({'fixed':['current']})
    prefix = job['assessment_cases'][0]['prefix']
    job['context_answers'][prefix+'runtime'] = 'different'
    assert E.evaluate(job)['decisions'][0]['status'] == 'under_investigation'
    job['context_answers'][prefix+'runtime'] = 'bom'
    job['assessment'] = E.evaluate(job)
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError, match='CSAF product status'):
        E.export(job, 'openvex')


def test_clearance_requires_source_cpe_edition_and_exact_product_identity(setup_product):
    source_cpe = 'cpe:2.3:a:acme:controller:2.0:*:enterprise:*:*:*:*:*'
    for supplied, expected in [(None,'under_investigation'),
                               (source_cpe.replace('enterprise', 'standard'),'under_investigation'),
                               (source_cpe,'fixed')]:
        job, _ = setup_product({'fixed':['current']}, source_cpe=source_cpe, asset_cpe=supplied)
        assert E.evaluate(job)['decisions'][0]['status'] == expected
    job, _ = setup_product({'fixed':['current']}, name='Controller 1.0')
    assert E.evaluate(job)['decisions'][0]['status'] == 'under_investigation'
    job, _ = setup_product({'fixed':['current']},
        asset_cpe='cpe:2.3:a:acme:controller:1.0:*:*:*:*:*:*:*')
    assert E.evaluate(job)['decisions'][0]['status'] == 'under_investigation'
