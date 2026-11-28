"""Evidence-scoped candidate extraction and explicit human-review promotion.

Rules and BERT propose quotations, never semantic truth. Reviews are offline input
assertions: this module does not authenticate humans or establish completeness.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime
import re

from src.item4.analysis.advisory_source_bundles import VERSION; from src.item4.analysis.advisory_source_bundles import CVE; from src.item4.analysis.advisory_source_bundles import digest; from src.item4.analysis.advisory_source_bundles import seal; from src.item4.analysis.advisory_source_bundles import text_hash; from src.item4.analysis.advisory_source_bundles import verify_seal

ROLES = ('necessary_condition', 'explicit_nonrequirement', 'conditional_context',
         'trigger', 'impact', 'mitigation', 'applicability', 'observed_context')
CHECKS = ('content', 'necessity', 'scope', 'qualifiers', 'conflicts')
PREDICATES = ('source_stated_condition', 'endpoint_reachable', 'feature_enabled',
              'required_configuration_present', 'required_operating_mode',
              'user_performs_required_action', 'attacker_is_authenticated',
              'attacker_has_required_privilege', 'attacker_has_required_artifact',
              'attacker_has_physical_or_local_access', 'unmapped')
RULES_VERSION = 'extractive-candidates/1'


def _index(rows, name):
    ids = [r['id'] for r in rows]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate ' + name)
    return {r['id']: r for r in rows}


def validate_bundle(bundle):
    from src.research.item4_stage1_contracts import validate
    validate('bundle', bundle)
    verify_seal(bundle, 'bundle_sha256')
    if bundle['contract_version'] != VERSION:
        raise ValueError('Unsupported contract')
    documents = _index(bundle['documents'], 'source')
    products = _index(bundle['products'], 'product')
    segments = _index(bundle['segments'], 'segment')
    bindings = _index(bundle['bindings'], 'binding')
    for p in products.values():
        if p['source_id'] not in documents:
            raise ValueError('Unknown product source')
    for s in segments.values():
        if s['source_id'] not in documents or text_hash(s['text']) != s['text_sha256']:
            raise ValueError('Invalid source segment/hash')
        for bid in s['binding_ids']:
            b = bindings.get(bid, {})
            if b.get('segment_id') != s['id'] or b.get('source_id') != s['source_id']:
                raise ValueError('Invalid segment binding')
        if any(p not in products for p in s['product_ids']):
            raise ValueError('Unknown product')
    for b in bindings.values():
        if b['segment_id'] not in segments or not CVE.fullmatch(b['cve']):
            raise ValueError('Invalid binding scope')
        if b['product_id'] is not None and b['product_id'] not in products:
            raise ValueError('Invalid binding product')
    population = bundle['population']
    if len(set(population)) != len(population) or any(not CVE.fullmatch(c) for c in population):
        raise ValueError('Invalid population')
    if sorted(r['cve'] for r in bundle['cve_ledger']) != sorted(population):
        raise ValueError('Population ledger mismatch')
    return bundle


def reference(segment, start, end):
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(segment['text']):
        raise ValueError('Invalid code point offsets')
    return dict(source_id=segment['source_id'], segment_id=segment['id'], start=start,
                end=end, quote=segment['text'][start:end], segment_sha256=segment['text_sha256'])


def _verify_ref(ref, segments):
    segment = segments.get(ref.get('segment_id'))
    if segment is None or reference(segment, ref['start'], ref['end']) != ref:
        raise ValueError('Invalid exact evidence reference')
    return segment


def candidate(bundle, segment, start, end, role, method):
    if role not in ROLES:
        raise ValueError('Unknown role')
    ref = reference(segment, start, end)
    unique_cve = segment['cves'][0] if (len(segment['cves']) == 1 and
        segment['source_role'] == 'cve_description' and segment['cves'][0] in bundle['population']) else None
    row = dict(bundle_sha256=bundle['bundle_sha256'], evidence=[ref], role=role,
               statement=ref['quote'], predicate='source_stated_condition',
               target=None, required_value=None, necessity_scope='described_path',
               cve=unique_cve, product_ids=list(segment['product_ids']),
               binding_ids=list(segment['binding_ids']), normalization_evidence=[],
               extractor=method, state='candidate')
    row['id'] = 'claim-' + digest(row)
    return seal(row, 'claim_sha256')


def _context(bundle):
    return (_index(bundle['segments'], 'segment'), _index(bundle['products'], 'product'),
            _index(bundle['bindings'], 'binding'))


def validate_claim(bundle, claim, context=None, *, schema_checked=False):
    """Validate provenance, not whether source text implies necessity."""
    from src.research.item4_stage1_contracts import validate
    if not schema_checked:
        validate('claim', claim)
    verify_seal(claim, 'claim_sha256')
    if claim['bundle_sha256'] != bundle['bundle_sha256']:
        raise ValueError('Claim bound to a different bundle')
    if claim['role'] not in ROLES or claim['predicate'] not in PREDICATES:
        raise ValueError('Unknown role/predicate')
    if claim['necessity_scope'] != 'described_path' or claim['state'] != 'candidate':
        raise ValueError('Stage 1 may not assert full path coverage or self-approve')
    segments, products, bindings = context or _context(bundle)
    if not claim['evidence']:
        raise ValueError('Missing condition evidence')
    refs = [_verify_ref(r, segments) for r in claim['evidence']]
    if claim['statement'] != claim['evidence'][0]['quote']:
        raise ValueError('Statement must remain extractive; no invented paraphrase')
    normalization = claim['normalization_evidence']
    for ref in normalization:
        _verify_ref(ref, segments)
    for key in ('target', 'required_value'):
        value = claim[key]
        if value is not None and (not isinstance(value, str) or not value.strip() or
                                  not any(value in r['quote'] for r in normalization)):
            raise ValueError('Normalized attribute lacks exact evidence: ' + key)
    cve = claim['cve']
    if cve is not None and (not isinstance(cve, str) or not CVE.fullmatch(cve) or cve not in bundle['population']):
        raise ValueError('Invalid/out-of-population CVE')
    if len(set(claim['product_ids'])) != len(claim['product_ids']) or any(p not in products for p in claim['product_ids']):
        raise ValueError('Invalid product scope')
    for bid in claim['binding_ids']:
        b = bindings.get(bid)
        if b is None or b['segment_id'] not in {r['id'] for r in refs}:
            raise ValueError('Binding does not support quoted segment')
    return claim


def propose_rules(bundle):
    """Transparent sentence candidates; intentionally NOT an accuracy-trained model."""
    validate_bundle(bundle)
    candidates, ledger = [], []
    for s in bundle['segments']:
        emitted = []
        # Entire sentence preserves negation, conditionals and local qualifiers.
        boundaries = [0] + [m.end() for m in re.finditer(r'(?<=[.!?])\s+|[\r\n]+', s['text'])] + [len(s['text'])]
        for a, b in zip(boundaries, boundaries[1:]):
            while a < b and s['text'][a].isspace():
                a += 1
            while b > a and s['text'][b-1].isspace():
                b -= 1
            text = s['text'][a:b]
            if not text:
                continue
            if s['source_role'] == 'mitigation' or re.search(r'\b(recommends?|should|workaround|mitigat\w*)\b', text, re.I):
                role = 'mitigation'
            elif re.search(r'\b(without (?:any )?authentication|unauthenticated|no (?:authentication|privileges?) (?:is |are )?required|(?:do|does|did) not require|authentication (?:is |was )?not required|requires? no authentication)\b', text, re.I):
                role = 'explicit_nonrequirement'
            elif re.search(r'\b(requires?|must|only (?:when|if)|in order to|prerequisite)\b', text, re.I):
                role = 'necessary_condition'
            elif re.search(r'\b(if|when|provided that)\b', text, re.I):
                role = 'conditional_context'
            elif re.search(r'\b(specially crafted|malicious file|sending a|opening a)\b', text, re.I):
                role = 'trigger'
            else:
                continue
            row = candidate(bundle, s, a, b, role, RULES_VERSION)
            candidates.append(row); emitted.append(row['id'])
        ledger.append(dict(segment_id=s['id'], status='processed_with_candidates' if emitted else 'processed_no_candidate',
                           candidate_ids=emitted, full_segment_examined=True,
                           semantic_accuracy_verified=False))
    return seal(dict(contract_version=VERSION, bundle_sha256=bundle['bundle_sha256'],
                     method=RULES_VERSION, candidates=candidates, processing_ledger=ledger,
                     logic=None, coverage_complete=False, vex_eligible=False,
                     semantic_accuracy_verified=False), 'extraction_sha256')


def validate_extraction(bundle, extraction):
    from src.research.item4_stage1_contracts import validate
    validate('extraction', extraction)
    validate_bundle(bundle)
    verify_seal(extraction, 'extraction_sha256')
    if extraction['contract_version'] != VERSION or extraction['bundle_sha256'] != bundle['bundle_sha256']:
        raise ValueError('Extraction contract/bundle mismatch')
    if extraction['logic'] is not None or extraction['coverage_complete'] is not False or extraction['vex_eligible'] is not False or extraction['semantic_accuracy_verified'] is not False:
        raise ValueError('Extraction may not assert downstream readiness')
    claims = _index(extraction['candidates'], 'claim')
    context = _context(bundle)
    for c in claims.values():
        validate_claim(bundle, c, context, schema_checked=True)
    ledger = extraction['processing_ledger']
    segs = _index(bundle['segments'], 'segment')
    if len({r['segment_id'] for r in ledger}) != len(ledger) or {r['segment_id'] for r in ledger} != set(segs):
        raise ValueError('Missing/duplicate processing ledger segments')
    seen = []
    for row in ledger:
        if row['status'] not in {'processed_with_candidates', 'processed_no_candidate', 'inference_failed', 'partial'}:
            raise ValueError('Invalid processing status')
        if row['status'] == 'processed_no_candidate' and row['candidate_ids']:
            raise ValueError('Nonempty no-candidate result')
        if row['status'] == 'processed_with_candidates' and not row['candidate_ids']:
            raise ValueError('Empty candidate result')
        if row['status'].startswith('processed_') and row['full_segment_examined'] is not True:
            raise ValueError('Incomplete source processing')
        for cid in row['candidate_ids']:
            if cid not in claims or {r['segment_id'] for r in claims[cid]['evidence']} != {row['segment_id']}:
                raise ValueError('Processing ledger claim mismatch')
            seen.append(cid)
    if Counter(seen) != Counter(claims.keys()):
        raise ValueError('Missing/duplicated claim ledger entries')
    return extraction


def review_template(claim, reviewer=''):
    return dict(claim_id=claim['id'], claim_sha256=claim['claim_sha256'],
                reviewer=reviewer, method='human', reviewed_at=None,
                decision='unresolved', checks={k: 'ambiguous' for k in CHECKS},
                rationale='', evidence=deepcopy(claim['evidence']))


def _time(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is not None:
            return parsed
    except (ValueError, TypeError, AttributeError):
        pass
    return None


def adjudicate(bundle, claim, reviews, context=None, *, schema_checked=False):
    context = context or _context(bundle)
    validate_claim(bundle, claim, context, schema_checked=schema_checked)
    issues = []
    segments, _, bindings = context
    relevant = [r for r in reviews if r.get('claim_id') == claim['id']]
    for r in relevant:
        from src.research.item4_stage1_contracts import validate
        validate('review', r)
        if r.get('claim_sha256') != claim['claim_sha256']:
            raise ValueError('Stale review for changed claim')
        if r.get('decision') not in {'accepted', 'rejected', 'unresolved'}:
            raise ValueError('Invalid review decision')
        if set(r.get('checks', {})) != set(CHECKS) or any(v not in {'supported', 'unsupported', 'ambiguous'} for v in r['checks'].values()):
            raise ValueError('Incomplete semantic review checks')
        if r.get('decision') == 'accepted':
            if (r.get('method') != 'human' or not str(r.get('reviewer', '')).strip() or
                    _time(r.get('reviewed_at')) is None or not str(r.get('rationale', '')).strip()):
                issues.append('incomplete_human_review')
            if any(r['checks'][k] != 'supported' for k in CHECKS):
                issues.append('semantic_checks_not_supported')
            if not r.get('evidence'):
                issues.append('missing_review_evidence')
        for ref in r.get('evidence', []):
            _verify_ref(ref, segments)
    if not relevant:
        return dict(state='candidate', issues=['semantic_review_required'])
    # Conflicting reviews require resolution as a new review set, never last-wins.
    if len({r['decision'] for r in relevant}) != 1:
        return dict(state='unresolved', issues=['conflicting_reviews'])
    if relevant[0]['decision'] != 'accepted':
        return dict(state=relevant[0]['decision'], issues=[])
    if claim['role'] != 'necessary_condition':
        issues.append('not_a_necessary_condition')
    if claim['cve'] is None or not claim['product_ids']:
        issues.append('unresolved_CVE_or_product_scope')
    for ref in claim['evidence']:
        segment = segments[ref['segment_id']]
        if segment['source_role'] != 'cve_description':
            issues.append('non_CVE_specific_source')
        subjects = set(re.findall(r'\bCVE-\d{4}-\d{4,}\b', ref['quote']))
        if subjects and subjects != {claim['cve']}:
            issues.append('explicit_CVE_subject_conflict')
        for pid in claim['product_ids']:
            if not any(bindings[b]['segment_id'] == segment['id'] and
                       bindings[b]['cve'] == claim['cve'] and bindings[b]['product_id'] == pid and
                       bindings[b]['kind'] == 'explicit_vulnerability_scope' for b in claim['binding_ids']):
                issues.append('missing_structured_scope_binding')
    return dict(state='unresolved' if issues else 'accepted', issues=sorted(set(issues)))


def export_claims(bundle, extraction, reviews):
    validate_extraction(bundle, extraction)
    claims = _index(extraction['candidates'], 'claim')
    if any(r.get('claim_id') not in claims for r in reviews):
        raise ValueError('Review references unknown claim')
    context = _context(bundle)
    byclaim = {}
    for r in reviews:
        byclaim.setdefault(r['claim_id'], []).append(r)
    accepted, ledger = [], []
    for c in claims.values():
        decision = adjudicate(bundle, c, byclaim.get(c['id'], []), context, schema_checked=True)
        ledger.append(dict(claim_id=c['id'], **decision))
        if decision['state'] == 'accepted':
            accepted.append(dict(claim=deepcopy(c), reviews=[deepcopy(r) for r in reviews if r['claim_id'] == c['id']],
                                 approval_basis='offline_human_assertion_not_authenticated'))
    bycve = {c: [] for c in bundle['population']}
    for c in claims.values():
        if c['cve'] in bycve:
            bycve[c['cve']].append(c['id'])
    return seal(dict(contract_version=VERSION, bundle_sha256=bundle['bundle_sha256'],
                     extraction_sha256=extraction['extraction_sha256'], accepted=accepted,
                     claim_ledger=ledger, source_processing_ledger=deepcopy(extraction['processing_ledger']),
                     cve_ledger=[dict(cve=c, candidate_ids=bycve[c], source_status=r['status'])
                                 for r in bundle['cve_ledger'] for c in [r['cve']]],
                     logic=None, coverage_complete=False, vex_eligible=False,
                     semantic_accuracy_verified=False,
                     warning='Human reviews are supplied assertions; authenticate reviewers and audit original sources separately.'),
                'export_sha256')


def extraction_report(bundle, extraction, exported):
    validate_extraction(bundle, extraction)
    return dict(contract_version=VERSION, bundle_sha256=bundle['bundle_sha256'],
                population=len(bundle['population']), source_documents=len(bundle['documents']),
                source_statuses=dict(Counter(r['status'] for r in bundle['source_ledger'])),
                cve_source_statuses=dict(Counter(r['status'] for r in bundle['cve_ledger'])),
                segments=len(bundle['segments']), candidates=len(extraction['candidates']),
                roles=dict(Counter(c['role'] for c in extraction['candidates'])),
                processing_statuses=dict(Counter(r['status'] for r in extraction['processing_ledger'])),
                approval_states=dict(Counter(r['state'] for r in exported['claim_ledger'])),
                accepted=len(exported['accepted']),
                independent_semantic_precision=None, independent_semantic_recall=None,
                not_affected_emitted=0, production_vex_emitted=False,
                method=extraction['method'])
