"""Per-entry evidence collection plans, never inferred CWE IDs or VEX decisions.

Routes translate directly listed official detection methods into artifact
requests. Multiple methods are alternatives, not cumulative proof obligations.
No method or requirement is inherited from a parent CWE.
"""
from collections import Counter
import hashlib,json

METHODS = {
    'Automated Static Analysis': ('implementation_review', 'Implementation/data-flow review evidence; confirm whether the cited method applies to source or compiled artifacts.'),
    'Automated Static Analysis - Source Code': ('source_review', 'Relevant source, exact revision/configuration, and a source-analysis report with locations.'),
    'Manual Static Analysis - Source Code': ('source_review', 'Relevant source and a documented manual inspection with file/line references.'),
    'Automated Static Analysis - Binary or Bytecode': ('compiled_artifact_review', 'A matching binary/bytecode analysis report, if independently available. The source parser cannot substitute for this method.'),
    'Manual Static Analysis - Binary or Bytecode': ('compiled_artifact_review', 'A scoped manual binary/bytecode review report, if independently available.'),
    'Manual Static Analysis': ('implementation_review', 'Static-review artifacts identifying what was inspected, which configuration, and the findings.'),
    'White Box': ('implementation_review', 'Internal implementation/design evidence and a documented inspection scope.'),
    'Automated Dynamic Analysis': ('runtime_observation', 'An existing, scoped runtime-analysis report tied to the exact deployed build and test conditions.'),
    'Dynamic Analysis with Manual Results Interpretation': ('runtime_observation', 'Runtime observations and a documented interpretation of the exact conditions and coverage.'),
    'Dynamic Analysis with Automated Results Interpretation': ('runtime_observation', 'Runtime-analysis results, interpretation rules, conditions and coverage.'),
    'Manual Dynamic Analysis': ('runtime_observation', 'A documented runtime observation with the tested build, inputs and limitations.'),
    'Fuzzing': ('runtime_observation', 'An existing fuzzing report with target/build, harness scope, inputs and coverage; absence of a crash is not a safety proof.'),
    'Black Box': ('runtime_observation', 'Observed external behavior with the actual interface, build and test conditions.'),
    'Simulation / Emulation': ('simulation_review', 'A scoped simulation/emulation report and its model assumptions; this backend does not execute it.'),
    'Architecture or Design Review': ('design_review', 'Architecture/design documents and a review tied to the applicable implementation/deployment.'),
    'Formal Verification': ('formal_review', 'A formal model, properties, assumptions and verification report linked to the actual system.'),
    'Manual Analysis': ('case_evidence_review', 'The CVE/vendor mechanism and a scoped manual review plan identifying the artifact to inspect.'),
    'Automated Analysis': ('case_evidence_review', 'Clarify the specified analysis technique and artifact using the CVE/vendor evidence before choosing a tool.'),
    'Other': ('case_evidence_review', 'Read the entry-specific detection description and identify the applicable artifact using CVE/vendor evidence.'),
}

LABELS = {
    'source_review': '소스 검토',
    'implementation_review': '구현 자료 검토',
    'compiled_artifact_review': '컴파일 산출물 검토',
    'runtime_observation': '실행 관찰 자료 검토',
    'simulation_review': '시뮬레이션 자료 검토',
    'design_review': '설계 자료 검토',
    'formal_review': '형식 검증 자료 검토',
    'case_evidence_review': 'CVE·벤더 근거로 검토 자료 구체화',
    'cve_mechanism_first': 'CVE·벤더 메커니즘 우선 확인',
}


def contract_hash():
    return hashlib.sha256(json.dumps({'methods':METHODS,'labels':LABELS},sort_keys=True,
                                    ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def plan(cwe, record, info):
    definition = record.get('description', '')
    methods = info.get('detection_methods', [])
    alternatives = []
    for i, method in enumerate(methods):
        name = method['method']
        route, artifacts = METHODS.get(name, ('case_evidence_review', 'Clarify this entry-specific detection method and the required artifact.'))
        alternatives.append({
            'route': route, 'route_label_ko': LABELS[route], 'method': name,
            'artifacts_to_collect': artifacts,
            'evidence': {'source_field': f'Detection_Methods[{i}]',
                         'method': name, 'description': method.get('description', ''),
                         'effectiveness': method.get('effectiveness'),
                         'definition_url': record.get('url')},
            'listed_on_this_CWE': True, 'inherited': False,
            'backend_executes_this_method': False,
        })
    routes = sorted({a['route'] for a in alternatives})
    if not routes:
        routes = ['cve_mechanism_first']
    return {
        'schema': 'ics-vex-cwe-evidence-plan/1', 'cwe': cwe,
        'contract_version':'entry-specific-method-plan-v1','contract_sha256':contract_hash(),
        'status': 'collection_plan_not_final_requirement',
        'recommended_routes': routes,
        'route_labels_ko': [LABELS[r] for r in routes],
        'route_relation': 'alternatives_require_case_selection',
        'claim_to_examine': {'text': definition, 'source_field': 'Description',
                             'span': [0, len(definition)], 'definition_url': record.get('url')},
        'basis': 'entry_specific_official_detection_methods' if methods else 'no_entry_specific_detection_method',
        'alternatives': alternatives,
        'next_action': ('Select an applicable listed method using the CVE/vendor mechanism and actual asset artifacts; methods are alternatives, not all mandatory.'
                        if methods else 'Obtain CVE/vendor/patch evidence describing the mechanism, affected feature and observable conditions; then identify the artifact needed to examine this definition. Do not inherit a method from a parent CWE.'),
        'case_selection_requirements': [
            'Exact asset product/build and the candidate CVE applicability evidence.',
            'CVE/vendor mechanism and the particular feature/interface involved.',
            'A documented link from the chosen method to the available artifact and claim; record limits and missing evidence.',
        ],
        'operator_questionnaire_alone_established_sufficient': False,
        'source_required': 'not_determined_by_detection_method',
        'operational_context_required': 'determine_from_CVE_and_asset',
        'runtime_analysis_is_not_operator_questionnaire': True,
        'independent_gold': False, 'assigns_CWE': False,
        'authorizes_VEX_status': False,
    }


def summarize(profiles):
    plans = [r['evidence_plan'] for r in profiles.values()]
    return {
        'total': len(plans),
        'contract_sha256':contract_hash(),
        'entry_specific_method_available': sum(bool(p['alternatives']) for p in plans),
        'mechanism_first': sum(not p['alternatives'] for p in plans),
        'route_memberships_overlap': True,
        'by_recommended_route': dict(Counter(route for p in plans for route in p['recommended_routes'])),
        'final_requirements_assigned': 0,
    }
