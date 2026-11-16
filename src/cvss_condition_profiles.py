"""Typed multi-label condition grouping and operator questions.

Exact structural grouping is not embedding clustering or evidence of equivalent
attack paths. Legacy published vectors remain legacy; unknown never equals N.
"""
from collections import defaultdict
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from src.cvss40_condition_contract import VALUES, VERSION as CONTRACT_VERSION
from src.semantic_condition_contract import digest

ROOT = Path(__file__).resolve().parents[1]
ACTIVE = ROOT/'data/cvss40_condition_runtime.json'
VERSION = 'cvss-condition-profiles/1'
QUESTIONS = {
 'AV': ('access', 'Which network segments, local execution sessions or physical interfaces can reach the source-described function, including maintenance routes?'),
 'PR': ('privileges', 'Which attacker-accessible accounts and roles have the source-described rights before the affected operation? Record authentication separately from privileges.'),
 'UI': ('trigger', 'Who performs the source-described user action, and can the same input be handled automatically, in preview, or during maintenance?'),
 'AC': ('configuration', 'Which vendor-documented exploit protections and target-specific secret controls apply to the source-described operation?'),
 'AT': ('trigger', 'Can the source-described race, on-path position or other specific execution condition occur in any assessed operating mode?'),
}
VALUE_QUESTIONS = {
 ('AV', 'N'): 'Which internal, external and maintenance network routes can deliver input to the affected service, and on which interfaces and ports?',
 ('AV', 'A'): 'Which parties can join the source-described adjacent or restricted network segment, including temporary maintenance connections?',
 ('AV', 'L'): 'Which users, processes or maintenance sessions can obtain the source-described local execution or file access on this host?',
 ('AV', 'P'): 'Which source-described physical ports or hardware interfaces exist, who can handle them, and in which maintenance modes?',
 ('PR', 'N'): 'What authentication and access boundaries exist on the affected entry point? Record them without assuming that login prevents this CVE.',
 ('PR', 'L'): 'Which available accounts or roles have the source-described limited rights before this operation, including service and maintenance accounts?',
 ('PR', 'H'): 'Which available roles have the source-described high rights before this operation? Record actual permissions rather than assuming a role named Administrator.',
 ('UI', 'N'): 'Which automatic or attacker-initiated processing paths handle the affected input without another person acting?',
 ('UI', 'P'): 'Which routine viewing, preview or other limited user interactions expose the affected processing path?',
 ('UI', 'A'): 'Who can perform the source-described conscious action such as opening a supplied file or accepting a prompt, and under which operating procedure?',
 ('UI', 'R'): 'Which other-person interactions are described and actually occur? The legacy required-interaction value does not distinguish CVSS 4.0 Passive from Active.',
}
DETAIL_QUESTIONS = {
 'access_position': ('access', 'Record the actual reachable segments, sessions or physical ports for this source-described access.'),
 'attacker_auth_or_privilege': ('privileges', 'Record the available attacker-side accounts, authentication state and rights before this operation.'),
 'victim_auth_or_privilege': ('privileges', 'Record which legitimate users are logged in and what rights their sessions have during this operation.'),
 'user_action': ('trigger', 'Record who performs this action and any automatic, preview or maintenance handling of the same input.'),
 'input_or_ingress': ('input_path', 'Record the input format, interface, origin and parties permitted to supply or modify this input.'),
 'trigger': ('trigger', 'Record whether this sequence or event can occur, using operating procedures, settings and available logs.'),
 'feature_or_configuration': ('configuration', 'Record the current feature setting, interface or port value, including maintenance exceptions.'),
 'operating_state': ('scope', 'Record the normal, boot, recovery and maintenance modes in which this operation is available.'),
 'adversary_control_or_capability': ('access', 'Record which parties can control the source-described input, communication path or resource before the operation.'),
 'affected_function': ('applicability', 'Record whether this function is installed or used, using inventory, configuration and vendor documentation.'),
}


def published_metrics(cvss):
    raw = (cvss or {}).get('vector', '')
    version = '4.0' if raw.startswith('CVSS:4.0/') else '3.1' if raw.startswith('CVSS:3.1/') else '3.0' if raw.startswith('CVSS:3.0/') else 'unsupported'
    result = dict(version=version, raw_vector=raw, metrics={}, basis='published_vector', converted_to_v4=False)
    if version != 'unsupported':
        for pair in raw.split('/'):
            if ':' not in pair: continue
            key, value = pair.split(':', 1)
            if key not in VALUES: continue
            allowed = ['N', 'R'] if key == 'UI' and version != '4.0' else VALUES[key]
            if key == 'AT' and version != '4.0': continue
            if value in allowed: result['metrics'][key] = value
    return result


def profile(row, extraction=None):
    published = published_metrics(row.get('cvss'))
    extraction = extraction or {}
    # Only current source interpretations are accepted. Older caches stay separate.
    facts = [deepcopy(f) for f in extraction.get('facts', []) if f.get('extraction_method') == CONTRACT_VERSION]
    axes = defaultdict(set)
    for f in facts:
        m, v = f['cvss40']['metric'], f['cvss40']['value']
        if m: axes[m].add(v)
    interpreted = {m: sorted(axes.get(m, {'unknown'})) for m in VALUES}
    complete = bool(extraction.get('all_packets_read'))
    # Memberships can overlap; opposite polarity/necessity/actors never collapse.
    memberships = []
    for f in facts:
        key = dict(metric=f['cvss40']['metric'], value=f['cvss40']['value'],
                   kind=f['kind'], necessity=f['necessity'], polarity=f['polarity'])
        memberships.append(dict(id='condition-type:'+digest(key)[:16], **key))
    key = dict(published_version=published['version'], published=published['metrics'],
               interpreted=interpreted, detail_types=sorted({digest(m) for m in memberships}),
               extraction_complete=complete, rejected=row.get('nvd_status') == 'Rejected')
    return dict(cve=row['cve'], schema=VERSION, cluster_id='profile:'+digest(key)[:16],
                published=published, interpreted=interpreted, memberships=list({m['id']: m for m in memberships}.values()),
                facts=facts, extraction_complete=complete, extraction_state=extraction.get('extraction_state', 'pending'),
                rejected=row.get('nvd_status') == 'Rejected',
                conflicting_source_metrics=[m for m, vs in interpreted.items() if len(set(vs)-{'unknown'}) > 1],
                grouping_method='exact typed profiles; overlapping condition memberships; no semantic-equivalence claim',
                vex_authority=False, semantic_review_required=True)


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def signature():
    return digest([VERSION, _sha(Path(__file__)), _sha(ACTIVE) if ACTIVE.is_file() else 'not_configured'])


@lru_cache(maxsize=2)
def _published_corpus(path, modified_ns, size):
    corpus = Path(path)
    rows = [json.loads(l) for l in corpus.open(encoding='utf-8')]
    return {r['cve']: r for r in rows}, _sha(corpus)


def _question_inputs():
    path = ROOT/'data/item3_ics_cert_full_v1/cves.jsonl'
    stat = path.stat()
    return _published_corpus(str(path), stat.st_mtime_ns, stat.st_size)


def question_signature():
    # Research outputs and active model-profile pointers cannot change questions.
    _, source_hash = _question_inputs()
    return digest(['published-cvss-fixed-questions/1', source_hash, _sha(Path(__file__))])


@lru_cache(maxsize=2)
def _snapshot(pointer_hash):
    try:
        pointer = json.loads(ACTIVE.read_text(encoding='utf-8'))
        path = Path(pointer['assignments'])
        if not path.is_absolute(): path = ROOT/path
        if _sha(path) != pointer['assignments_sha256']: raise ValueError('Profile integrity mismatch')
        rows = [json.loads(l) for l in path.open(encoding='utf-8')]
        if len(rows) != pointer['population'] or len({r['cve'] for r in rows}) != len(rows):
            raise ValueError('Profile population mismatch')
        return {r['cve']: r for r in rows}, None
    except (OSError, ValueError, KeyError) as exc:
        return {}, str(exc)


def explain(cve):
    rows, error = _snapshot(_sha(ACTIVE) if ACTIVE.is_file() else 'missing')
    return deepcopy(rows.get(cve, dict(cve=cve, schema=VERSION, status='unavailable',
                                    reason=error or 'CVE not in profile snapshot', facts=[], vex_authority=False)))


def catalog():
    rows, error = _snapshot(_sha(ACTIVE) if ACTIVE.is_file() else 'missing')
    return dict(status='available' if rows else 'unavailable', reason=error, schema=VERSION,
                population=len(rows), profile_groups=len({r['cluster_id'] for r in rows.values()}),
                extracted_cves=sum(bool(r['facts']) for r in rows.values()),
                extraction_complete_cves=sum(r['extraction_complete'] for r in rows.values()),
                standard='https://www.first.org/cvss/v4.0/specification-document',
                method='Versioned CVSS profiles and overlapping source-condition types; legacy vectors are not converted.',
                shared_answers_allowed=False, vex_authority=False)


def questions(case):
    # Question selection only reads pinned publisher data. Never read model
    # conditions, interpreted metrics, or a client-supplied classification.
    corpus, _ = _question_inputs()
    p = profile(corpus.get(case['cve'], {'cve': case['cve']}))
    rows = []
    base = dict(scope='specific', answer_type='text', origin='fixed_template', can_refute=False,
                semantic_review_required=True, profile_cluster_id=p.get('cluster_id'),
                required_records=['Asset inventory, configuration, access policy, operating procedures or vendor records'])
    axes = {(m, v) for m, v in p.get('published', {}).get('metrics', {}).items()
            if p.get('published', {}).get('version') == '4.0' or m in {'AV', 'PR', 'UI'}}
    if not p.get('rejected'):
        for m, value in sorted(axes):
            purpose, text = QUESTIONS[m]
            text = VALUE_QUESTIONS.get((m, value), text)
            key = 'cvss-axis:'+m+':'+value
            rows.append(dict(base, question='On this asset, '+text[0].lower()+text[1:],
                template_id=VERSION+':'+key, template_key=key, rule_id=key, flow=key,
                kind=purpose, purpose_category=purpose, purpose='Collect operator-observable facts for the CVSS axis; a published score is not an asset finding.',
                evidence_ids=[], evidence='', source_provenance=[], necessity='unknown',
                selection_basis='versioned_published_metric', cvss_published=deepcopy(p.get('published'))))
    return p, rows
