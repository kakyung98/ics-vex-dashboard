"""Recover source-bound draft paths without inventing missing prerequisites."""
from copy import deepcopy
import re

from src.item4.decision.scoped_vex_review import digest; from src.item4.decision.scoped_vex_review import extract; from src.item4.decision.scoped_vex_review import question

VERSION = 'source-path-recovery/1'
PATTERNS = (
    ('network_access', r'\bremote (?:unauthenticated |authenticated )?(?:attackers?|users?)\b|\bremotely exploitable\b|\bnetwork access\b', True),
    ('local_access', r'\blocal (?:unauthenticated |authenticated )?(?:attackers?|users?)\b|\blocal access\b', True),
    ('physical_access', r'\bphysical access\b', True),
    ('file_processing', r'\b(?:crafted|malicious) (?:project |configuration |image )?files?\b', True),
    ('attacker_authentication', r'\b(?:remote |local )?authenticated (?:attackers?|users?)\b', False),
)


def observable(proposition):
    """Attacker wording alone must not hide an explicit access/configuration fact."""
    if re.search(r'\b(?:pointer|heap|stack|memory|buffer|control.flow)\b|\b(?:possess|obtain|valid|stolen)\b.*\b(?:credential|password|key|privilege)', proposition, re.I):
        return False
    if re.search(r'\b(?:attacker|user)s?\b',proposition,re.I) and re.search(r'\b(?:authenticated|credentials?|passwords?)\b',proposition,re.I):
        return False
    return bool(re.search(r'\b(?:network|local|physical|remote) access\b|\b(?:enabled|disabled|configured|configuration|installed|installation)\b', proposition, re.I))


def recover(record):
    """Add deterministic candidates to a derived snapshot; original bytes stay intact."""
    result = deepcopy(record)
    if record.get('original_nvd_status') == 'Rejected' or record.get('identity_ambiguous'):
        return result
    candidates = extract(record)
    for scenario in candidates:
        for condition in scenario['conditions']:
            if observable(condition['proposition']):
                condition['operator_observable'] = True
    for source in record['sources']:
        if source.get('subject_ambiguous'):
            continue
        for sentence in re.finditer(r'[^\n]+?(?:[.!?](?=\s|$)|$)', source['text']):
            text = sentence.group()
            # Preserve explicit configuration/Boolean qualifiers via the grammar,
            # rather than replacing them with a bare access descriptor.
            if re.search(r'\b(?:if|when|unless|without|requires?|must|provided|either|or|only)\b', text, re.I):
                continue
            if not re.search(r'\b(?:allows?|could|can|may|exploitable|attackers?)\b', text, re.I):
                continue
            conditions = []
            for kind, pattern, operator_observable in PATTERNS:
                match = re.search(pattern, text, re.I)
                if not match:
                    continue
                a, b = sentence.start() + match.start(), sentence.start() + match.end()
                condition = dict(id='recovered:' + digest([source['id'], a, b, kind])[:24],
                    proposition=source['text'][a:b], kind=kind, operator_observable=operator_observable,
                    source_ref=dict(source_id=source['id'], span=[a, b], quote=source['text'][a:b]),
                    context_ref=dict(source_id=source['id'], span=list(sentence.span()), quote=text))
                condition['question'] = question(condition)
                conditions.append(condition)
            if not conditions:
                continue
            leaves = [dict(condition=c['id']) for c in conditions]
            expression = leaves[0] if len(leaves) == 1 else dict(op='and', args=leaves)
            candidates.append(dict(id='recovery:' + digest([record['cve'], source['id'], expression])[:24],
                conditions=conditions, expression=expression, source_ref=conditions[0]['context_ref'],
                product_keys=source.get('product_keys', []), derivation=VERSION,
                scope_ambiguous=False, coverage_complete=False, review_status='pending_source_review'))
    existing = {s['id'] for s in result.get('scenarios', [])}
    additions = [s for s in candidates if s['id'] not in existing]
    # Updated observability also applies to an otherwise identical grammar draft.
    updates = {s['id']: s for s in candidates}
    result['scenarios'] = [updates.get(s['id'], s) for s in result.get('scenarios', [])] + additions
    result['original_record_digest'] = record['record_digest']
    result['source_recovery_version'] = VERSION
    result['record_digest'] = digest({k: v for k, v in result.items() if k != 'record_digest'})
    return result


def unresolved_evidence(record):
    """Send a complete CVE-scoped source clause even when no path was recovered."""
    sources = [s for s in record['sources'] if not s.get('subject_ambiguous') and s.get('text', '').strip()]
    if not sources:
        return []
    source = min(sources, key=lambda s: (not s['id'].startswith('nvd:'), len(s['text']), s['id']))
    return [dict(source_id=source['id'], url=source['url'], text=source['text'],
        text_sha256=source['text_sha256'], source_semantic_review='pending')]
