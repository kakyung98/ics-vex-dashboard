"""One review path: asset operational information and CVE-specific evidence."""
from src.common.data.weakness_review_context import ids

VERSION = 'operational-only-v1'


def policy():
    return {'version': VERSION, 'sha256': VERSION,
            'authority': 'Project operational-context review policy'}


def classify(case):
    from src.item4.assets.asset_classification_catalog import explain
    contexts = case.get('cwe_context') or {}
    cwes = sorted(set(ids(case.get('cwe')) + ids(case.get('cwes')) +
                      [e['id'] for e in contexts.get('entries', [])]))
    return {'schema': 'ics-vex-item4-route/4', 'requirement': 'operational_review',
            'route': 'operational_questions', 'workflow_branch': 'operational_only',
            'workflow_policy_version': VERSION, 'policy_version': VERSION,
            'policy_sha256': VERSION, 'operational_required': True,
            'operational_context_available': True, 'cwes': cwes,
            'reason': 'Review shared asset operational information, installed-version records and CVE-specific operator answers.',
            'initial_vex_status': 'under_investigation',
            'routing_confers_negative_verdict': False,
            'operational_classification': explain(case['cve'])}
