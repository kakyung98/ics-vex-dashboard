"""Versioned fixed workflow questions; selection is deterministic and explainable.

Shared asset/version facts are collected once by the existing common form.
These yes/no/unknown checks never make a negative VEX decision.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from src import operational_classification as CLASSIFICATION

VERSION = 'fixed-operational-templates/3-no-model-selection'

TEXT = {
 'web_interface': [
  ('endpoints', 'Is the advisory-described web endpoint or API enabled or used on this asset?', 'applicability'),
  ('sessions', 'Can a user or session reach the advisory-described operation through any management or maintenance interface?', 'access'),
  ('origins', 'Can input or content from another party reach the affected request, stored page or server-side destination?', 'input_path')],
 'client_content': [
  ('client', 'Is the affected client, COM or ActiveX component installed or loaded by any application on this host?', 'applicability'),
  ('content', 'Can externally supplied content or another process reach the advisory-described component interface?', 'input_path'),
  ('identity', 'Have the calling applications, execution accounts and isolation settings been checked and recorded?', 'scope')],
 'file_ingest': [
  ('formats', 'Does this asset process the file or project format described in the advisory?', 'applicability'),
  ('ingress', 'Can files from external, shared, removable-media or maintenance sources reach that processing feature?', 'input_path'),
  ('action', 'Can the described processing action occur through a user action or automatic handling in any assessed operating mode?', 'trigger')],
 'artifact_loading': [
  ('artifacts', 'Does this asset use the advisory-described update, package, plugin or module-loading mechanism?', 'applicability'),
  ('writers', 'Can another party modify the loaded artifact, its search path or the source from which it is obtained?', 'access'),
  ('modes', 'Have normal, boot, recovery and maintenance loading paths and verification exceptions been checked?', 'scope')],
 'transit_trust': [
  ('segments', 'Can another party observe or modify any assessed segment of the affected communication?', 'access'),
  ('trust', 'Have protocol versions, peer verification, cryptographic settings and replay protections been recorded?', 'configuration'),
  ('fallback', 'Can a fallback or maintenance path omit the protections configured on the normal communication path?', 'scope')],
 'account_access': [
  ('accounts', 'Is the advisory-described account, credential or authentication path present or used by this deployment?', 'applicability'),
  ('replacement', 'Has the vendor-documented credential change, disabling procedure or remediation been applied with a record?', 'mitigation'),
  ('alternatives', 'Have recovery accounts, service accounts and alternative authentication interfaces been checked?', 'scope')],
 'stored_resource': [
  ('resources', 'Does this deployment contain or expose the file, data object or storage feature described in the advisory?', 'applicability'),
  ('permissions', 'Can another user, process or remote party obtain the affected read, write or path-selection access?', 'access'),
  ('copies', 'Have temporary files, logs, backups, diagnostic exports and shared copies been checked for alternative access?', 'scope')],
 'local_host': [
  ('entry', 'Can any user, process, service or maintenance session obtain local execution on the affected host?', 'access'),
  ('privileges', 'Have the actual rights of the affected service, driver or local operation been recorded?', 'privileges'),
  ('operations', 'Can maintenance programs, scheduled tasks or other services call the affected local interface?', 'scope')],
 'physical_maintenance': [
  ('ports', 'Is the advisory-described physical interface, device or maintenance function present on this hardware?', 'applicability'),
  ('access', 'Can operators, maintenance staff or other parties physically handle the affected device or interface?', 'access'),
  ('debug', 'Have normal, unlocked, debug, boot and recovery states relevant to this advisory been checked?', 'scope')],
 'network_service': [
  ('service', 'Is the advisory-described protocol, server or client feature implemented and enabled on this asset?', 'applicability'),
  ('paths', 'Can any internal, external or maintenance-connected system deliver input to the affected service?', 'access'),
  ('input', 'Have the advisory-described message or command processing and any stated identity or sequence conditions been checked?', 'trigger')],
 'sequence_resource': [
  ('trigger', 'Can the affected operation and described sequence, repeated input or state transition occur in this deployment?', 'trigger'),
  ('limits', 'Are vendor-documented request, connection or resource limits enforced and supported by a configuration record?', 'mitigation'),
  ('recovery', 'Have dependent systems, restart/failover behavior and process impact been documented?', 'operational_impact')],
}

PURPOSE = {
 'applicability': 'Identify the installed affected feature; an answer alone does not prove product applicability or code absence.',
 'access': 'Record actual actors and access paths; blocked access is separate from product non-impact.',
 'input_path': 'Record input origins and handling paths; no complete attack formula is inferred.',
 'trigger': 'Review only the trigger stated by the CVE source; missing conditions remain unknown.',
 'configuration': 'Record configuration without assuming that a configured protection defeats this CVE.',
 'privileges': 'Record actual role or execution rights; privilege gain is not automatically a prerequisite.',
 'scope': 'Check alternative interfaces, actors and operating modes within the assessment scope.',
 'mitigation': 'Record a protection or remediation report; supporting fix/product evidence is evaluated separately.',
 'operational_impact': 'Plan outage, dependency and recovery actions. This answer cannot establish not_affected.',
 'discovery': 'Obtain missing CVE-specific interface or condition evidence; absence of information is not non-impact.',
}


def signature():
    from src.cvss_condition_profiles import question_signature as condition_signature
    snapshot = CLASSIFICATION.catalog()
    return hashlib.sha256(json.dumps([VERSION, snapshot.get('manifest_sha256'), snapshot.get('weakness_taxonomy', {}).get('signature'),
        condition_signature(), hashlib.sha256(Path(__file__).read_bytes()).hexdigest()], sort_keys=True).encode()).hexdigest()


def build(case):
    # Recompute from the pinned rule snapshot; caller/model labels are not inputs.
    explanation = CLASSIFICATION.explain(case['cve'])
    from src import weakness_review
    explanation['weakness_review'] = weakness_review.explain(case['cve'])
    case['operational_classification'] = explanation
    profiles = {p['id']: p for p in CLASSIFICATION.catalog().get('profiles', [])}
    members = explanation.get('memberships') or [{'id': 'discovery', 'basis': 'unresolved', 'evidence': []}]
    rows = []
    for member in members:
        flow = member['id']
        templates = TEXT.get(flow, [('discover', 'Have the actual affected interface, input and CVE-specific prerequisites been identified from a source?', 'discovery')])
        evidence = member.get('evidence', [])
        source_ids = list(dict.fromkeys(e['source_id'] for e in evidence))
        refs = list({e['origin'].get('url'): e['origin'] for e in evidence if e.get('origin')}.values())
        for key, text, purpose in templates:
            record_template = next((q for q in profiles.get(flow, {}).get('questions', []) if q['id'] == key), {})
            rows.append({'question': 'On this asset, '+text[0].lower()+text[1:],
                'scope': 'specific', 'answer_type': 'yes_no_unknown', 'origin': 'fixed_template',
                'template_id': VERSION+':'+flow+':'+key, 'template_key': flow+':'+key,
                'rule_id': flow+':'+key, 'flow': flow,
                'kind': purpose, 'purpose_category': purpose, 'purpose': PURPOSE[purpose],
                'required_records': record_template.get('required_records', ['CVE-specific source and scoped operational record']),
                'evidence_ids': source_ids, 'evidence': '\n'.join(dict.fromkeys(e.get('context', e['quote']) for e in evidence))[:4000],
                'source_provenance': refs, 'selection_basis': member.get('basis', 'unresolved'),
                'necessity': 'not_established', 'can_refute': False, 'semantic_review_required': True})
    # The 17 weakness families complement operational flows; no family is a gate.
    for member in explanation.get('weakness_review', {}).get('memberships', []):
        rows.append({'question':member['review_question'], 'scope':'specific', 'answer_type':'text',
            'origin':'fixed_template', 'template_id':VERSION+':weakness:'+member['id'],
            'template_key':'weakness:'+member['id'], 'rule_id':'weakness:'+member['id'],
            'flow':'weakness:'+member['id'], 'kind':'discovery', 'purpose_category':'discovery',
            'purpose':'Record operator-verifiable facts for this weakness family; the family is not a necessary CVE condition.',
            'required_records':member['required_operational_evidence'],
            'evidence_ids':[], 'evidence':'', 'source_provenance':[],
            'selection_basis':'weakness_family_hint', 'weakness_basis':member['basis'],
            'necessity':'not_established', 'can_refute':False, 'semantic_review_required':True})
    from src.cvss_condition_profiles import questions as condition_questions
    condition_profile, condition_rows = condition_questions(case)
    explanation['cvss_condition_profile'] = condition_profile
    rows.extend(condition_rows)
    generation = {'status': 'validated', 'method': 'fixed_operational_templates', 'llm_used': False,
                  'template_version': VERSION, 'template_signature': signature(),
                  'selection': 'shared asset/version form + all selected workflow templates',
                  'selected_flows': [m['id'] for m in members], 'attempts': [],
                  'checks': {'versioned_templates': True, 'classification_snapshot': explanation['status']},
                  'normalizations': [], 'errors': [], 'semantic_review_required': True,
                  'source_necessity': 'not_established', 'model_questions_enabled': False,
                  'condition_profile_cluster': condition_profile.get('cluster_id'),
                  'condition_extraction_complete': condition_profile.get('extraction_complete', False),
                  'model_output_used_for_selection': False,
                  'question_policy': 'pinned source rules + published CVSS + versioned fixed templates'}
    return generation, rows
