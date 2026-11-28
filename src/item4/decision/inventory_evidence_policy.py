"""Current #4 inventory policy over the frozen v2 expert wire contract."""

VERSION = 'item4-scenario-moe/2+explicit-inventory/1'
MISSING_COMPLETENESS = 'inventory_completeness_not_evidenced'
UNRESOLVED_DEPLOYMENT = 'deployment_or_running_version_unresolved'


def absence_hold_reason(context, component_ref):
    """Return the missing prerequisite for an absence-based decision, if any."""
    if context.get('deployment') != 'not_deployed':
        return None
    if context.get('inventory_coverage') != 'complete':
        return MISSING_COMPLETENESS
    if context.get('scope') != 'current_single' or not isinstance(component_ref, str) or not component_ref.strip():
        return UNRESOLVED_DEPLOYMENT
    return None


def _expert_input(scenario):
    # Setting the missing value explicitly prevents the historical synthetic
    # fallback before an observation ID, prompt or cache key is constructed.
    context = scenario['context']
    if 'inventory_coverage' in context:
        return scenario
    return dict(scenario, context=dict(context, inventory_coverage='unknown'))


def _record_policy(row, scenario, product):
    from src.item4.models.scenario_review_experts import UNKNOWN; from src.item4.models.scenario_review_experts import digest

    context = scenario['context']
    row['version'] = VERSION
    observation = None
    if context.get('deployment') == 'not_deployed':
        coverage = context.get('inventory_coverage')
        observation = dict(component_ref=product.get('component_ref'), scope=context.get('scope'),
                           source_field='context.inventory_coverage', field_present='inventory_coverage' in context,
                           inventory_coverage=coverage if coverage in ('partial', 'complete') else 'unknown')
        row['inventory_observation'] = observation
        hold = absence_hold_reason(context, observation['component_ref'])
        if hold:
            row['candidate_status'] = UNKNOWN
            if UNRESOLVED_DEPLOYMENT in row['reasons']:
                row['reasons'][row['reasons'].index(UNRESOLVED_DEPLOYMENT)] = hold
            elif hold not in row['reasons']:
                row['reasons'].append(hold)
    row['input_sha256'] = digest([VERSION, row['input_sha256'], observation])
    return row


def generate_candidate(scenario, product, *, condition_rule=None, runner=None, cache=None):
    from src.item4.models import scenario_review_experts as v2

    row = v2.generate_candidate(_expert_input(scenario), product, condition_rule=condition_rule,
                                runner=runner, cache=cache)
    return _record_policy(row, scenario, product)


def generate_candidates(items, *, cache, batch_size=8, provider=None):
    from src.item4.models import expert_batch_inference as item4_moe_batch

    items = list(items)
    inputs = [(_expert_input(scenario), product, rule) for scenario, product, rule in items]
    rows = item4_moe_batch.generate_candidates(inputs, cache=cache, batch_size=batch_size, provider=provider)
    return [_record_policy(row, scenario, product) for row, (scenario, product, _) in zip(rows, items)]
