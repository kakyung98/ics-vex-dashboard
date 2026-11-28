"""Contract regression tests; fictional examples are not independent CVE Gold."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from src.research.item4_stage1 import (CHECKS, adjudicate, candidate, export_claims, extraction_report,
                            propose_rules, reference, review_template, validate_bundle,
                            validate_claim, validate_extraction)
from src.item4.analysis.advisory_source_bundles import VERSION; from src.item4.analysis.advisory_source_bundles import audit_sources; from src.item4.analysis.advisory_source_bundles import build_bundle; from src.item4.analysis.advisory_source_bundles import digest; from src.item4.analysis.advisory_source_bundles import seal; from src.item4.analysis.advisory_source_bundles import source_document; from src.item4.analysis.advisory_source_bundles import text_hash
from src.research.item4_stage1_evaluation import evaluate_claims, training_readiness
from src.research.item4_stage1_contracts import schemas, validate


def payload(text='The attack requires diagnostic mode to be active.', second=False):
    result = dict(document=dict(tracking=dict(id='ICSA-fixture'), notes=[dict(text='Disable all network access as a general precaution.')]),
                  product_tree=dict(full_product_names=[dict(product_id='p1', name='Fictional controller 1.0')]),
                  vulnerabilities=[dict(cve='CVE-2026-10001', notes=[dict(text=text)],
                                        product_status=dict(known_affected=['p1']))])
    if second:
        result['vulnerabilities'].append(dict(cve='CVE-2026-10002', notes=[dict(text='Only when service B is active can this flaw be triggered.')],
                                              product_status=dict(known_affected=['p1'])))
    return result


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / 'source.json'
    path.write_text(json.dumps(payload(second=True)), encoding='utf-8')
    return build_bundle([path], ['CVE-2026-10001', 'CVE-2026-10002', 'CVE-2026-10003'])


def first(bundle):
    result = propose_rules(bundle)
    return next(c for c in result['candidates'] if c['role'] == 'necessary_condition')


def approval(claim):
    row = review_template(claim, 'reviewer-A')
    row.update(decision='accepted', reviewed_at='2026-11-16T08:00:00+00:00',
               checks={k: 'supported' for k in CHECKS}, rationale='Fictional contract fixture review only.')
    return row


def test_prepare_and_source_reconstruction(bundle):
    validate_bundle(bundle)
    assert audit_sources(bundle)['passed']
    assert len(bundle['population']) == 3
    assert bundle['cve_ledger'][-1]['status'] == 'no_cve_specific_passage'
    common = bundle['segments'][0]
    assert len(common['cves']) == 2
    assert all(b['kind'] == 'advisory_membership_only' for b in bundle['bindings'] if b['segment_id'] == common['id'])


def test_source_tamper_and_resealed_scope_are_detected(bundle):
    altered = deepcopy(bundle)
    altered['segments'][1]['text'] += ' altered'
    seal(altered, 'bundle_sha256')
    with pytest.raises(ValueError, match='hash'):
        validate_bundle(altered)
    altered = deepcopy(bundle)
    altered['bindings'][0]['kind'] = 'explicit_vulnerability_scope'
    seal(altered, 'bundle_sha256')
    assert not audit_sources(altered)['passed']
    Path(bundle['documents'][0]['filename']).write_text('{}', encoding='utf-8')
    assert not audit_sources(bundle)['passed']


def test_duplicate_sources_missing_and_bad_source_are_ledgered(tmp_path):
    a, b, bad = [tmp_path / n for n in ['a.json', 'b.json', 'bad.json']]
    raw = json.dumps(payload()).encode()
    a.write_bytes(raw); b.write_bytes(raw); bad.write_text('{')
    result = build_bundle([a, b, bad, tmp_path/'missing.json'])
    assert len(result['documents']) == 1
    assert {r['status'] for r in result['source_ledger']} == {'prepared', 'duplicate_source', 'parse_failed', 'source_unavailable'}


def test_json5_and_nvd_remain_unbound_product_scopes(tmp_path):
    sources = [dict(cveMetadata=dict(cveId='CVE-2026-10001'), containers=dict(cna=dict(descriptions=[dict(value='The attack requires local access.')]))),
               dict(id='CVE-2026-10002', descriptions=[dict(value='The attack requires local access.')])]
    for i, value in enumerate(sources):
        path = tmp_path / f'{i}.json'; path.write_text(json.dumps(value))
        b = build_bundle([path]); e = propose_rules(b); c = e['candidates'][0]
        assert c['product_ids'] == []
        assert adjudicate(b, c, [approval(c)])['state'] == 'unresolved'


def test_unknown_product_is_not_fabricated(tmp_path):
    v = payload(); v['vulnerabilities'][0]['product_status']['known_affected'] = ['missing']
    p = tmp_path/'source.json'; p.write_text(json.dumps(v))
    b = build_bundle([p]); validate_bundle(b)
    assert b['source_ledger'][0]['warnings'][0]['code'] == 'unresolved_product_ref'
    c = first(b)
    assert adjudicate(b, c, [approval(c)])['state'] == 'unresolved'


def test_no_reviews_no_approved_no_vex(bundle):
    e = propose_rules(bundle); out = export_claims(bundle, e, [])
    assert out['accepted'] == []
    assert out['logic'] is None and out['coverage_complete'] is False and out['vex_eligible'] is False
    assert len(out['cve_ledger']) == 3
    assert extraction_report(bundle, e, out)['independent_semantic_precision'] is None


def test_complete_scoped_human_review_promotes_one_claim_only(bundle):
    e = propose_rules(bundle); c = first(bundle)
    out = export_claims(bundle, e, [approval(c)])
    assert len(out['accepted']) == 1
    assert out['accepted'][0]['claim']['id'] == c['id']
    assert out['vex_eligible'] is False


@pytest.mark.parametrize('field,value', [('reviewer', ''), ('method', 'model'), ('reviewed_at', None),
                                         ('reviewed_at', '2026-11-16'), ('rationale', ''), ('evidence', [])])
def test_incomplete_or_model_review_cannot_promote(bundle, field, value):
    c = first(bundle); r = approval(c); r[field] = value
    assert adjudicate(bundle, c, [r])['state'] == 'unresolved'


@pytest.mark.parametrize('check', CHECKS)
def test_every_semantic_check_is_required(bundle, check):
    c = first(bundle); r = approval(c); r['checks'][check] = 'ambiguous'
    assert adjudicate(bundle, c, [r])['state'] == 'unresolved'


def test_review_conflict_and_staleness(bundle):
    c = first(bundle); r = approval(c); rejection = deepcopy(r); rejection['decision'] = 'rejected'
    assert adjudicate(bundle, c, [r, rejection])['issues'] == ['conflicting_reviews']
    c['target'] = 'diagnostic mode'; c['normalization_evidence'] = c['evidence']
    seal(c, 'claim_sha256')
    with pytest.raises(ValueError, match='Stale'):
        adjudicate(bundle, c, [r])


def test_normalization_requires_quoted_attributes(bundle):
    c = first(bundle); c['target'] = 'TCP port 502'; seal(c, 'claim_sha256')
    with pytest.raises(ValueError, match='Normalized attribute'):
        validate_claim(bundle, c)


@pytest.mark.parametrize('field,value', [('necessity_scope', 'all_paths'), ('state', 'accepted'),
                                         ('predicate', 'invented'), ('statement', 'Invented condition')])
def test_forbidden_claim_changes(bundle, field, value):
    c = first(bundle); c[field] = value; seal(c, 'claim_sha256')
    with pytest.raises(ValueError): validate_claim(bundle, c)


def test_other_CVE_or_product_scope_cannot_promote(bundle):
    c = first(bundle); c['cve'] = 'CVE-2026-10002'; seal(c, 'claim_sha256')
    assert 'missing_structured_scope_binding' in adjudicate(bundle, c, [approval(c)])['issues']
    c = first(bundle); c['product_ids'] = []; seal(c, 'claim_sha256')
    assert adjudicate(bundle, c, [approval(c)])['state'] == 'unresolved'


def test_advisory_context_never_auto_promotes(bundle):
    s = bundle['segments'][0]
    c = candidate(bundle, s, 0, len(s['text']), 'necessary_condition', 'fixture')
    c.update(cve='CVE-2026-10001', product_ids=[bundle['products'][0]['id']]); seal(c, 'claim_sha256')
    assert 'non_CVE_specific_source' in adjudicate(bundle, c, [approval(c)])['issues']


def test_out_of_population_sources_preserved_without_wrong_assignment(bundle):
    b = deepcopy(bundle)
    b['population'] = ['CVE-2026-10003']
    b['cve_ledger'] = [r for r in b['cve_ledger'] if r['cve'] in b['population']]
    seal(b, 'bundle_sha256')
    e = propose_rules(b); validate_extraction(b, e)
    assert all(c['cve'] is None for c in e['candidates'])
    assert len(export_claims(b, e, [])['cve_ledger']) == 1


@pytest.mark.parametrize('text,role', [
    ('The vendor recommends disabling service A.', 'mitigation'),
    ('No authentication is required to trigger this issue.', 'explicit_nonrequirement'),
    ('An unauthenticated attacker can exploit this issue.', 'explicit_nonrequirement'),
    ('Controllers do not require authentication for FTP sessions.', 'explicit_nonrequirement'),
    ('The interface does not require a password.', 'explicit_nonrequirement'),
    ('Authentication is not required to exploit this issue.', 'explicit_nonrequirement'),
    ('An attacker can exploit this without any authentication.', 'explicit_nonrequirement'),
    ('If service A is enabled, the issue can occur.', 'conditional_context'),
    ('Sending a specially crafted file triggers this issue.', 'trigger'),
    ('Successful exploitation leads to code execution.', None),
    ('CVSS: AV:N/AC:L/PR:N/UI:N', None),
])
def test_rules_only_propose_roles_not_truth(tmp_path, text, role):
    p = tmp_path/'source.json'; p.write_text(json.dumps(payload(text)))
    b = build_bundle([p]); e = propose_rules(b)
    rows = [c for c in e['candidates'] if c['cve'] is not None]
    assert [c['role'] for c in rows] == ([role] if role else [])
    assert not export_claims(b, e, [])['accepted']


def test_negation_is_preserved_not_inferred_away(tmp_path):
    text = 'The attack does not require authentication, but requires diagnostic mode.'
    p = tmp_path/'source.json'; p.write_text(json.dumps(payload(text)))
    b = build_bundle([p]); e = propose_rules(b)
    c = next(c for c in e['candidates'] if c['cve'])
    assert c['statement'] == text
    assert c['role'] == 'explicit_nonrequirement'  # Mixed roles remain a review task.


def test_version_decimal_does_not_truncate_qualifiers(tmp_path):
    text = 'Product 1.2 requires diagnostic mode. Another sentence follows.'
    p = tmp_path/'source.json'; p.write_text(json.dumps(payload(text)))
    b = build_bundle([p]); c = first(b)
    assert c['statement'] == 'Product 1.2 requires diagnostic mode.'


def test_unicode_offsets_and_exact_quote(bundle):
    b = deepcopy(bundle); s = b['segments'][1]
    s['text'] = '한글 🔧 requires local access.'; s['text_sha256'] = text_hash(s['text']); seal(b, 'bundle_sha256')
    c = candidate(b, s, 3, len(s['text']), 'necessary_condition', 'fixture')
    validate_claim(b, c)
    assert c['statement'].startswith('🔧')
    c['evidence'][0]['quote'] = 'fabricated'; seal(c, 'claim_sha256')
    with pytest.raises(ValueError, match='evidence'):
        validate_claim(b, c)


@pytest.mark.parametrize('change', ['drop_segment', 'drop_candidate', 'duplicate_id', 'assert_vex', 'claim_extra'])
def test_extraction_integrity_and_complete_ledger(bundle, change):
    e = propose_rules(bundle)
    if change == 'drop_segment': e['processing_ledger'].pop()
    if change == 'drop_candidate': e['candidates'].pop()
    if change == 'duplicate_id': e['candidates'].append(e['candidates'][0])
    if change == 'assert_vex': e['vex_eligible'] = True
    if change == 'claim_extra':
        e['candidates'][0]['invented'] = True; seal(e['candidates'][0], 'claim_sha256')
    seal(e, 'extraction_sha256')
    with pytest.raises(ValueError): validate_extraction(bundle, e)


def gold_for(bundle, claim):
    return dict(contract_version=VERSION, bundle_sha256=bundle['bundle_sha256'],
                provenance='independent_human_annotation', reviewer_ids=['A', 'B'],
                model_predictions_seen=False, adjudication_note='Fictional regression fixture, not actual Gold.',
                segments=[dict(segment_id=claim['evidence'][0]['segment_id'], annotation_complete=True,
                               adjudication='resolved', rationale='Fixture expected condition.',
                               conditions=[dict(role=claim['role'], evidence=claim['evidence'][0],
                                                cve=claim['cve'], product_ids=claim['product_ids'])])])


def test_evaluation_counts_missing_predictions_and_preserves_denominators(bundle):
    e = propose_rules(bundle); c = first(bundle); g = gold_for(bundle, c)
    r = evaluate_claims(bundle, e, g, bootstrap_samples=10)
    assert r['candidate']['precision'] == r['candidate']['recall'] == 1
    assert r['unannotated_segments'] == len(bundle['segments']) - 1
    assert r['candidate_precision_interval'] is None
    sid = c['evidence'][0]['segment_id']
    e['candidates'] = [r for r in e['candidates'] if r['id'] != c['id']]
    for row in e['processing_ledger']:
        if row['segment_id'] == sid:
            row.update(status='inference_failed', candidate_ids=[], full_segment_examined=False)
    seal(e, 'extraction_sha256')
    r = evaluate_claims(bundle, e, g, bootstrap_samples=10)
    assert r['candidate']['false_negative'] == 1 and r['candidate']['precision'] is None


def test_ambiguous_gold_not_silently_scored_as_negative(bundle):
    e = propose_rules(bundle); g = gold_for(bundle, first(bundle)); g['segments'][0]['adjudication'] = 'ambiguous'
    r = evaluate_claims(bundle, e, g, bootstrap_samples=10)
    assert r['ambiguous_segments'] == 1
    assert r['candidate']['ambiguous_segment_predictions'] == 1
    assert r['candidate']['false_positive'] == 0


def test_gold_provenance_and_unknown_review_fail_closed(bundle):
    e = propose_rules(bundle); c = first(bundle); g = gold_for(bundle, c)
    g['model_predictions_seen'] = True
    with pytest.raises(ValueError): evaluate_claims(bundle, e, g)
    r = approval(c); r['claim_id'] = 'not-present'
    with pytest.raises(ValueError, match='unknown claim'): export_claims(bundle, e, [r])


def test_fictional_examples_do_not_qualify_for_training(tmp_path):
    path = tmp_path/'fictional.jsonl'
    path.write_text(json.dumps(dict(id='fictional-example', annotation_complete=True,
                                    annotator='example-not-human-gold', spans=[])) + '\n')
    r, _ = training_readiness({k:path for k in ('train', 'dev', 'test')})
    assert not r['ready']
    assert any('human provenance' in x for x in r['errors'])


def test_schemas_and_cli_end_to_end(tmp_path):
    for schema in schemas().values():
        assert schema['additionalProperties'] is False
    p = tmp_path/'source.json'; p.write_text(json.dumps(payload()))
    root = Path(__file__).resolve().parents[2]
    script = root/'tools/item4/research/item4_stage1.py'
    def run(*args):
        result = subprocess.run([sys.executable, str(script), *map(str,args)], cwd=root, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
    b, e, r, out = [tmp_path/n for n in ['bundle.json','extraction.json','reviews.json','export.json']]
    run('prepare','--input',p,'--output',b)
    run('propose','--bundle',b,'--output',e)
    run('review-template','--bundle',b,'--extraction',e,'--output',r)
    run('export','--bundle',b,'--extraction',e,'--reviews',r,'--output',out)
    assert json.loads(out.read_text())['accepted'] == []
    run('audit','--bundle',b,'--output',tmp_path/'audit.json')
    run('schemas','--output',tmp_path/'schemas')
    assert len(list((tmp_path/'schemas').glob('*.json'))) == 5
    again = subprocess.run([sys.executable,str(script),'prepare','--input',str(p),'--output',str(b)],capture_output=True)
    assert again.returncode != 0
