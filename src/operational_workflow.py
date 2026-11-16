"""Source-reviewed, per-CVE operational question compilation."""
from collections import Counter, defaultdict
from copy import deepcopy
import math
import re

from .context_vex_pipeline import approved, leaves, validate_review
from .cluster_question_pipeline import compile_plan, digest

NIST_URL = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf'
DOMAINS = [
    dict(id='O1', name='Features and configuration', references=['5.2.5', '6.2.4', 'Table 16']),
    dict(id='O2', name='Network and communication access', references=['5.2.3', '6.2.9', 'Table 19']),
    dict(id='O3', name='Authentication and privileges', references=['6.2.1', 'Tables 16 and 18']),
    dict(id='O4', name='Physical and local access', references=['5.2.2', 'Table 17']),
    dict(id='O5', name='Files and removable media', references=['6.2.7', 'Table 17']),
    dict(id='O6', name='Maintenance and remote access', references=['6.2.5', '6.2.10']),
]
PREDICATES = {
    'interface_reachable': ('O2', 'Can the assessed origin reach {target} through the specified network path?'),
    'authentication_required': ('O3', 'Does the configuration of {target} require authentication?'),
    'privilege_required': ('O3', 'Do the access rules permit the role {value} to use {target}?'),
    'file_import': ('O5', 'Are externally supplied {value} files imported into {target}?'),
    'feature_enabled': ('O1', 'Is {target} enabled in the assessed operating mode?'),
    'configuration_required': ('O1', 'Does the configuration of {target} match this requirement: {value}?'),
    'network_reachable': ('O2', 'Can the assessed origin reach {target} through the specified network path?'),
    'on_path_access': ('O2', 'Can the assessed actor access the communication path for {target}?'),
    'attacker_authenticated': ('O3', 'Does the assessed actor have an authenticated session for {target}?'),
    'attacker_has_required_privilege': ('O3', 'Does the assessed actor have the required privilege ({value}) for {target}?'),
    'physical_access': ('O4', 'Can the assessed actor physically access {target}?'),
    'local_console_access': ('O4', 'Can the assessed actor access the local console of {target}?'),
    'input_processed': ('O5', 'Is {target} processed in this operating workflow?'),
    'external_file_source': ('O5', 'Can externally supplied files enter {target}?'),
    'user_performs_action': ('O5', 'Does the operator perform this action in {target}: {value}?'),
    'maintenance_access': ('O6', 'Is maintenance access to {target} available in the assessed mode?'),
    'remote_maintenance': ('O6', 'Is the remote maintenance path to {target} available?'),
    'adversary_can_write': ('unmapped', 'Can the assessed actor write to {target}?'),
    'custom': ('unmapped', 'Does the following reviewed condition hold for {target}: {value}?'),
}


def normalize(value):
    return ' '.join(str(value).casefold().split())


def condition_key(c):
    # Do not merge service aliases or privilege levels without explicit review.
    return (c['predicate'], normalize(c['target']), normalize(c.get('value', '')))


def question(c):
    domain, template = PREDICATES.get(c['predicate'].split(':',1)[0], PREDICATES['custom'])
    return dict(domain=domain, template=template, slots={'target': c['target'], 'value': c.get('value', '')},
                text=template.format(target=c['target'], value=c.get('value', '')),
                answer_type='yes_no_unknown')


def build_workflow(reviews, records, k=0, threshold=.8, min_support=2, embedding_mode='structured', similarity_threshold=0.0):
    """Compile reviewed questions independently for each CVE."""
    records_by_cve={r['cve']:r for r in records}
    if len(records_by_cve)!=len(records) or len({r['cve'] for r in reviews})!=len(reviews) or set(records_by_cve)!={r['cve'] for r in reviews}:
        raise ValueError('One source bundle and one review per CVE are required')
    for review in reviews:
        if not approved(review.get('formula',{})):raise ValueError('Review the formula before compiling')
        for c in review['conditions']:
            if not approved(c):raise ValueError('Review every included condition')
            if c.get('explicitness') not in {'explicit','reviewed_inference'}:raise ValueError('Declare explicit or reviewed_inference for every condition')
        validate_review(review,records_by_cve[review['cve']])
    # Keep every CVE in the compiler population, even without cluster membership.
    memberships=[dict(cve=r['cve'],cluster_ids=[]) for r in reviews]
    plan=compile_plan(deepcopy(reviews),records,memberships)
    return dict(clustering=None,template_catalog=[],plan=plan,domains=DOMAINS,
        nist=dict(version='SP 800-82 Rev. 3',url=NIST_URL,classification='Research-defined question domains informed by NIST'))
