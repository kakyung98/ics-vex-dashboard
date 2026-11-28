"""Check that submitted blind ratings can trace absence claims to the sealed case evidence."""
import re

from src.item4.decision.inventory_evidence_policy import absence_hold_reason


BASES = {'deployment_absence', 'supplier_status', 'version_range', 'other', 'insufficient_evidence'}
OPERATOR = 'synthetic_operator_input'
COMPONENT = 'synthetic_bom_component'


def _supplier_excludes_component(card, rating):
    """An independent exclusion needs a matching verified supplier statement, not a basis label."""
    if rating['decision_basis'] not in {'supplier_status', 'version_range'}:
        return False
    citations = [e for e in card['evidence'] if e['kind'] == 'published_product_status'
                 and e['evidence_id'] in rating['evidence_ids']
                 and e['facts'].get('source_status') == 'known_not_affected']
    if not citations:
        return False
    from src.item4.analysis.product_advisory_evidence import verified_version_evidence

    identity = card['component']
    cpes = identity.get('cpes', [])
    component = dict(ref=identity['ref'], name=identity['name'],
                     value=dict(manufacturer=identity['vendor'], version=identity['version'],
                                externalRefs=[dict(referenceType='cpe23Type', referenceLocator=c) for c in cpes]))
    result = verified_version_evidence(card['cve'], component)
    return result['state'] == 'known_not_affected' and any(
        r['status'] == 'known_not_affected' and r['version_membership'] == 'true'
        and r['document_sha256'] == e['source'].get('document_sha256')
        and r['status_pointer'] == e['source'].get('status_pointer')
        and r['product_pointer'] == e['source'].get('product_pointer')
        for r in result['evidence'] for e in citations)


def inspect_absence(card, rating):
    """Reject unsupported absence without changing any reviewer's submitted judgment."""
    exhibits = {e['evidence_id']: e for e in card['evidence']}
    basis = rating['decision_basis']
    inventory_ids = rating['inventory_evidence_ids']
    if (basis not in BASES or not isinstance(inventory_ids, list)
            or any(not isinstance(i, str) for i in inventory_ids)
            or len(inventory_ids) != len(set(inventory_ids))
            or not set(inventory_ids) <= set(rating['evidence_ids'])
            or any(i not in exhibits or exhibits[i]['kind'] not in (OPERATOR, COMPONENT) for i in inventory_ids)):
        raise ValueError('Invalid decision basis or case-local inventory citation.')
    operator, = (e for e in card['evidence'] if e['kind'] == OPERATOR)
    bom, = (e for e in card['evidence'] if e['kind'] == COMPONENT)
    ctx = operator['facts']['context']
    component = card['component']
    absent = ctx.get('deployment') == 'not_deployed'
    coverage = ctx.get('inventory_coverage')
    if basis == 'insufficient_evidence' and rating['status'] != 'under_investigation':
        raise ValueError('Insufficient evidence requires investigation.')
    if absent and rating['status'] in {'affected','fixed'}:
        raise ValueError('A non-deployment observation cannot demonstrate an active affected or patched deployment.')
    if basis == 'deployment_absence' and not absent:
        raise ValueError('The case does not observe non-deployment.')
    if basis == 'deployment_absence' and rating['status'] not in {'not_affected','under_investigation'}:
        raise ValueError('A non-deployment observation cannot establish an affected or fixed state.')
    if rating['status'] == 'not_affected' and absent and not _supplier_excludes_component(card, rating):
        source = operator['source']
        bom_source = bom['source']
        if (basis != 'deployment_absence' or absence_hold_reason(ctx, component.get('ref'))
                or {operator['evidence_id'], bom['evidence_id']} != set(inventory_ids)
                or bom['facts']['component'] != component
                or not source.get('file') or source['file'] != bom_source.get('file')
                or not re.fullmatch('[0-9a-f]{64}', source.get('packet_sha256', ''))
                or source['packet_sha256'] != bom_source.get('packet_sha256')
                or not re.fullmatch('/cases/[0-9]+', source.get('pointer', ''))
                or not re.fullmatch('[0-9a-f]{64}', source.get('original_line_sha256', ''))):
            raise ValueError('An absence clearance requires an explicit complete inventory for this case, component and observation.')
    if basis == 'deployment_absence' and absence_hold_reason(ctx, component.get('ref')) and rating['status'] != 'under_investigation':
        raise ValueError('An incompletely evidenced absence in this review requires investigation.')
    return {'deployment': ctx.get('deployment'), 'scope': ctx.get('scope'), 'component_ref': component.get('ref'),
            'inventory_coverage': coverage, 'coverage_explicit_complete': coverage == 'complete',
            'operator_evidence_id': operator['evidence_id'], 'component_evidence_id': bom['evidence_id'],
            'operator_pointer': operator['source'].get('pointer')}
