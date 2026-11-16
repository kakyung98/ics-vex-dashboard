"""Explain immutable operational assignments without granting VEX authority."""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from src import weakness_review

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT/'results/ics_operational_v2_1'

DEFINITIONS = {
    'web_interface': ('Web interfaces and APIs', 'Review web endpoints, sessions, user roles and request/data destinations.', 'Web/API or web-request context is mentioned.', 'A web term does not establish a specific endpoint, authentication requirement or complete attack path.'),
    'client_content': ('Client and embedded content', 'Review where browser, COM or ActiveX components are loaded and what calls them.', 'A client renderer or embedded component is mentioned.', 'ActiveX does not imply a browser-only attack; other applications may load it.'),
    'file_ingest': ('External files and project import', 'Review file origins, processing features and automatic or user-triggered handling.', 'Crafted files or file import/upload/processing are mentioned.', 'A file mention does not prove that a user must open it manually.'),
    'artifact_loading': ('Updates and module loading', 'Review package/module loading, search paths, write permissions and integrity checks.', 'An update, loader, DLL search path or module installation mechanism is mentioned.', 'Signature checks or restricted folders alone do not prove the vulnerable loader was fixed.'),
    'transit_trust': ('Communication interception and trust', 'Review communication segments, peer verification and replay/interception conditions.', 'Interception, replay, transport protection or peer verification is mentioned.', 'Blocking writes does not necessarily prevent passive observation; passwords may not prevent replay.'),
    'account_access': ('Account and credential use', 'Review which services use affected credentials or authentication paths and their alternatives.', 'Default/hardcoded credentials or an authentication weakness is mentioned.', 'Strong operator passwords do not refute an embedded credential or authentication bypass.'),
    'stored_resource': ('Stored files and data access', 'Review affected objects, read/write rights and backup/log/shared copies.', 'Paths, configuration/log files, traversal or stored-resource access are mentioned.', 'The exact resource name and access path can remain unknown.'),
    'local_host': ('Local execution and privileges', 'Review local users, processes, services, drivers and their privileges.', 'A local actor or local execution/driver interface is mentioned.', 'Local-user wording selects a review workflow; it does not identify the exact callable interface.'),
    'physical_maintenance': ('Physical access and maintenance', 'Review physical actors, affected hardware/mobile interfaces and operating modes.', 'Physical access, removable media or a maintenance/debug interface is mentioned.', 'This type does not imply USB or JTAG unless the CVE source actually mentions it.'),
    'network_service': ('Network services and protocol input', 'Review service roles, sending systems, network paths and message conditions.', 'A protocol, network service or crafted network input is mentioned.', 'A protocol in a product name may be incidental; traffic absence is not interface absence.'),
    'sequence_resource': ('State, concurrency and resource limits', 'Review trigger sequences, concurrent/repeated input, limits and recovery.', 'A race, repeated request, leak, exhaustion or related trigger is mentioned.', 'This module can supplement another access workflow; low normal load is not a non-impact proof.'),
    'scored_network': ('Scored network path only', 'Discover the actual affected service, client or input.', 'No source workflow matched; CVSS AV:N provides a broad scored path.', 'CVSS does not identify the interface or exhaust all attack alternatives.'),
    'scored_adjacent': ('Scored adjacent-network path only', 'Discover the affected interface and required neighboring link or zone.', 'No source workflow matched; CVSS AV:A provides a broad scored path.', 'Do not assume Internet exposure or a particular layer-2 protocol.'),
    'scored_local': ('Scored local path only', 'Discover the local operation and necessary execution rights.', 'No source workflow matched; CVSS AV:L provides a broad scored path.', 'CVSS v2 authentication is not converted into v3 privileges or user interaction.'),
    'scored_physical': ('Scored physical path only', 'Discover the relevant hardware access and maintenance operation.', 'No source workflow matched; CVSS AV:P provides a broad scored path.', 'Do not invent a hardware port or conclude physical absence.'),
    'discovery': ('Operational path unresolved', 'Obtain a CVE-specific description of the affected function and input.', 'Neither source rules nor the supported CVSS path selected a workflow.', 'Missing information is not evidence of non-impact.'),
    'rejected_review': ('Rejected CVE identity review', 'Resolve the rejection reason and any replacement identifiers.', 'The pinned CVE record is marked Rejected.', 'Rejected does not mean fixed or not affected on a real asset.'),
}

CRITERIA = {
    'principle': 'Group CVEs by the operating facts and evidence needed for review.',
    'method': 'Curated multi-label source-pattern rules with a separate CVSS fallback; not learned clustering.',
    'cwe_role': 'CWE is auxiliary and does not select these workflows.',
    'primary_policy': 'Most distinct matching source records, then total matched text length; configured order breaks ties. The primary label is for display, not causal importance.',
    'multi_label': 'Several review modules may apply. Their AND/OR or causal relation is not established by membership.',
    'boundary': 'Classification selects review questions. It does not establish complete prerequisites, real-asset exposure, or a VEX status.',
    'question_method': 'The primary review uses versioned common checks plus fixed workflow questions. CVE membership selects templates and source records explain their selection; no question model is called.',
    'question_purposes': 'Product applicability, access/trigger facts, mitigation and operational impact are separate. Dependency and recovery questions do not prove non-impact.',
}


def _sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def _read(path):
    return json.loads(path.read_text(encoding='utf-8'))


@lru_cache(maxsize=2)
def _snapshot(directory):
    """Lazy: do not load the 12k corpus at app startup. Fail closed on drift."""
    directory = Path(directory)
    try:
        manifest = _read(directory/'manifest.json')
        required = ['flow_catalog.json', 'summary.json', 'assignments.jsonl', 'sources.jsonl']
        for name in required:
            if _sha(directory/name) != manifest['files'][name]:
                raise ValueError('Classification snapshot integrity check failed: '+name)
        assignments, sources = {}, {}
        for name, target, key in [('assignments.jsonl', assignments, 'cve'), ('sources.jsonl', sources, 'id')]:
            with (directory/name).open(encoding='utf-8') as f:
                for line in f:
                    row = json.loads(line)
                    if row[key] in target:
                        raise ValueError('Duplicate classification snapshot record')
                    target[row[key]] = row
        summary = _read(directory/'summary.json')
        if len(assignments) != summary['population']:
            raise ValueError('Classification population does not match summary')
        return {'status': 'available', 'assignments': assignments, 'sources': sources,
                'catalog': _read(directory/'flow_catalog.json'), 'summary': summary,
                'manifest_sha256': _sha(directory/'manifest.json')}
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {'status': 'unavailable', 'reason': str(error)}


def _definition(profile):
    from src.fixed_operational_questions import TEXT, PURPOSE, VERSION
    name, intent, criteria, boundary = DEFINITIONS[profile['id']]
    original_questions = {q['key']: q for q in profile['questions']}
    templates = TEXT.get(profile['id'], [('discover', 'Have the actual affected interface, input and CVE-specific prerequisites been identified from a source?', 'discovery')])
    return deepcopy({'id': profile['id'], 'name': name, 'name_ko': profile['name'],
            'definition': intent, 'selection_criteria': criteria, 'does_not_establish': boundary,
            'patterns': profile['patterns'],
            'question_template_version': VERSION,
            'questions': [{'id': key, 'question': text, 'purpose_category': purpose, 'purpose': PURPOSE[purpose],
                           'required_records': original_questions.get(key, {}).get('required_records', ['CVE-specific source and scoped operational record'])}
                          for key, text, purpose in templates],
            'vex_checks': profile['decision_checks'], 'invalid_shortcut': profile['invalid_shortcut']})


def catalog():
    from src.cvss_condition_profiles import catalog as condition_catalog
    snapshot = _snapshot(str(DATASET))
    if snapshot['status'] != 'available':
        return {'status': 'unavailable', 'reason': snapshot['reason'], 'criteria': deepcopy(CRITERIA), 'vex_authority': False}
    return {'status': 'available', 'schema': snapshot['catalog']['schema'], 'dataset_version': DATASET.name,
            'snapshot_completed_at': snapshot['summary']['snapshot_completed_at'],
            'manifest_sha256': snapshot['manifest_sha256'], 'criteria': deepcopy(CRITERIA),
            'population': snapshot['summary']['population'],
            'weakness_taxonomy': weakness_review.catalog(),
            'cvss_condition_taxonomy': condition_catalog(),
            'specificity_counts': deepcopy(snapshot['summary']['specificity_counts']),
            'profiles': [_definition(p) for p in snapshot['catalog']['flows']],
            'vex_authority': False, 'semantic_accuracy_evaluated': False}


def explain(cve):
    from src.cvss_condition_profiles import explain as condition_explain
    if not isinstance(cve, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
        raise ValueError('Invalid CVE identifier')
    snapshot = _snapshot(str(DATASET))
    base = {'cve': cve, 'schema': 'ics-operational-classification-explanation/1',
            'dataset_version': DATASET.name, 'criteria': deepcopy(CRITERIA),
            'vex_authority': False, 'semantic_review_required': True,
            'weakness_review': weakness_review.explain(cve)}
    base['cvss_condition_profile'] = condition_explain(cve)
    if snapshot['status'] != 'available':
        return {**base, 'status': 'unavailable', 'reason': snapshot['reason'], 'memberships': []}
    row = snapshot['assignments'].get(cve)
    if row is None:
        return {**base, 'status': 'not_in_snapshot', 'reason': 'No assignment in this pinned classification snapshot. This is not a non-impact finding.', 'memberships': []}
    profiles = {p['id']: p for p in snapshot['catalog']['flows']}
    members = []
    for membership in row['memberships']:
        member = {**_definition(profiles[membership['flow']]), 'basis': membership['basis'],
                  'is_primary': membership['flow'] == row['primary_flow'], 'evidence': []}
        for e in membership['evidence']:
            s = snapshot['sources'].get(e['source_id'])
            if not s or s['cve'] != cve:
                return {**base, 'status': 'unavailable', 'reason': 'Missing or cross-CVE source reference', 'memberships': []}
            start, end = e['span']
            if s['text'][start:end] != e['quote']:
                return {**base, 'status': 'unavailable', 'reason': 'Source quote does not match its recorded span', 'memberships': []}
            member['evidence'].append({**deepcopy(e), 'context': s['text'][max(0,start-180):min(len(s['text']),end+220)],
                                       'context_start': max(0,start-180),
                                       'origin': deepcopy(s['origin']), 'source_text_sha256': s['text_sha256']})
        if membership['basis'] == 'cvss_coarse':
            member['scored_vector'] = row['cvss']['raw_vector']
            member['scored_source_field'] = 'pinned CVE corpus cvss.vector'
        members.append(member)
    notes = list(row.get('review_flags', []))
    if row['specificity'] == 'cvss_coarse':
        notes.append('Only a broad scored path is known. Discover the actual affected interface before using a detailed operational argument.')
    if cve == 'CVE-2010-4740':
        notes.append('Case review observation: BACnet appears in the product name while the described input is a crafted CSV file. The network-service label is a potential false positive, not a confirmed packet attack path.')
    return {**base, 'status': 'available', 'primary_flow': row['primary_flow'],
            'specificity': row['specificity'], 'memberships': members, 'review_notes': notes,
            'cwes_auxiliary': deepcopy(row['cwes_auxiliary']), 'cvss': deepcopy(row['cvss']),
            'manifest_sha256': snapshot['manifest_sha256'],
            'snapshot_completed_at': snapshot['summary']['snapshot_completed_at'],
            'classification_is_not_a_vex_decision': True}
