"""Auditable handoffs between identification, source context, queries and graph.

Asset classification supplies collection context, never prerequisite truth.
Advisory estimates remain suggestions until the stakeholder selects a type.
"""
from copy import deepcopy
from src.item4.decision import population_condition_rules as P
from src.item4.assets import operating_profile_catalog as M
from src.item4.decision import scoped_vex_review as A
from src.item4.assets.asset_profile_fields import COMMON; from src.item4.assets.asset_profile_fields import PROFILES

VERSION = 'component-operational-workflow/1'


def source_context(cve, product):
    record = P.get(cve)
    matched = P.choose(record, product) if record else []
    keys = {p['key'] for p in matched}
    advisories = sorted({key.split(':')[0] for key in keys if key.startswith('icsa-')})
    sources = []
    for s in record.get('sources', []) if record else []:
        sources.append({k: deepcopy(s[k]) for k in
                        ('id', 'url', 'text_sha256', 'document_sha256', 'pointer',
                         'product_keys', 'scope_binding', 'subject_ambiguous') if k in s})
    nav = A.asset_navigation() if advisories else {}
    suggestions = []
    for aid in advisories:
        detail = nav.get('assignment_details', {}).get(aid, {})
        for asset in nav.get('advisory_asset_ids', {}).get(aid, []):
            bindings = [deepcopy(e) for e in nav.get('advisory_product_evidence', {}).get(aid, [])
                        if e.get('product_key') in keys and e.get('asset_id') == asset]
            suggestions.append(dict(asset_type_id=asset, advisory_id=aid,
                source_url='https://www.cisa.gov/news-events/ics-advisories/'+aid,
                classification_status=detail.get('status', 'unreviewed'),
                product_bindings=bindings, requires_confirmation=True,
                scope='matched_product' if bindings else 'advisory_context_only'))
    return dict(cve=cve, product=product, sources=sources,
                matched_product_keys=sorted(keys), advisory_ids=advisories,
                cross_references=[dict(cve=cve, advisory_id=a,
                    relation='CVE co-reference; product applicability requires its own binding')
                    for a in advisories], asset_type_suggestions=suggestions,
                policy='Advisory clustering and source co-reference do not establish exploitability or asset operational information.')


def contract(plan, profile):
    catalog = M.catalogue()
    asset = next(p['asset'] for p in catalog['profiles'] if p['asset']['id'] == profile['asset_type_id'])
    queries = []
    for q in plan['questions']:
        fields = []
        for fid in q['nist_fields']:
            rid = fid.split('.')[0]
            fields.append(dict(field_id=fid, source_row_id=rid,
                               nist_basis=deepcopy(catalog['source_clauses'].get(rid))))
        node = 'fact:affected_version' if q['id'] == 'runtime_version' else 'fact:'+q['id']
        queries.append(dict(question_id=q['id'], graph_node_id=node,
            graph_node_present=any(n['id'] == node for n in plan['attack_graph']['nodes']),
            fields=fields, exploit_source=deepcopy(q['source']),
            comparison='operating_record_generative_llm' if q.get('record_review', {}).get('supported') else 'structured_observation',
            missing_result='unknown'))
    return dict(version=VERSION,
        stages=['sbom_identification_I1_I2_I3', 'icsa_nvd_cross_reference',
                'mitre_ics_asset_type', 'exploit_condition_graph',
                'nist_operational_queries', 'stakeholder_observations',
                'llm_vep_operating_record_review', 'exploitability_analysis', 'vex_generation'],
        source_context=source_context(plan['cve'], profile['scope']['product']),
        asset_context=dict(asset=deepcopy(asset), selected_type=profile['asset_type_id'],
            common_collection_topics=list(COMMON),
            type_specific_collection_topics=PROFILES.get(profile['asset_type_id'], []),
            affects='Collection guidance; required questions come from CVE evidence and remain mandatory across types.',
            supplies_condition_truth=False),
        query_graph_links=queries,
        record_review_output='true / false / unknown for source-bound predicates; never a VEX verdict',
        prerequisite_format=plan.get('prerequisite_format'), nli_enabled=False,
        exploitability_output='three-valued graph evaluation and canonical project VEX decision',
        exports=['OpenVEX', 'CycloneDX VEX'])
