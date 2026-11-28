"""Deterministic V1--V4 evidence chain bound to the exact assessed inputs."""
from copy import deepcopy
from src.item4.decision.attack_graph_builder import digest
from src.item4.decision.condition_logic_evaluation import logic, leaves
from src.item4.analysis.prerequisite_taxonomy import category, source_dimensions

VERSION='item4-assessment-evidence-chain/7-information-requirements'


def input_digest(job):
    return digest({k:job.get(k) for k in ('asset_classification','conditions','question_generations',
        'answers','context_answers','answer_provenance','plan_sha256','bom_sha256','components','asset_questions')})


def evidence_chain(job, case, result, row, coverage, scenarios, gaps, run_id, evaluated_at):
    artifact=result.get('prerequisite') or {};draft=artifact.get('draft',{})
    sources={s['id']:s for s in result.get('sources',[])}
    accepted={q['condition_id']:q for q in job.get('asset_questions',[]) if q['case_id']==case['id']}
    def references(refs):
        out=[]
        for ref in refs:
            source=sources.get(ref['source_id'],{});text=source.get('text','');start=text.find(ref['quote'])
            out.append(dict(ref,url=source.get('url'),text_sha256=source.get('text_sha256'),
                source_type=source.get('source_type'),cve_binding=source.get('cve_binding'),
                source_provenance=deepcopy(source.get('provenance')),
                span=[start,start+len(ref['quote'])] if start>=0 else None))
        return out
    conditions=[];facts={}
    for atom in draft.get('prerequisites',[]):
        q=accepted.get(atom['id']);qid=q['id'] if q else None
        answer=job.get('answers',{}).get(qid,'unknown')
        value={'o':'true','x':'false','holds':'true','absent':'false'}.get(answer,'unknown')
        facts[atom['id']]=value
        conditions.append(dict(condition_id=atom['id'],category=category(atom),positive_fact=atom['statement'],
            ics_context=deepcopy(atom.get('ics_context',[])),
            operational_quote=atom.get('operational_quote'),
            target=atom['target'],observation=deepcopy(atom.get('observation')),
            extraction_confidence=atom.get('extraction_confidence'),question_id=qid,
            question=q.get('label') if q else None,question_confidence=q.get('question_confidence') if q else None,
            question_artifact_sha256=q.get('question_generation_sha256') if q else None,
            information_requirement=deepcopy(q.get('information_requirement')) if q else None,
            asset_record_context=deepcopy(q.get('asset_record_context')) if q else None,
            answer=answer,value=value,source_refs=references(atom.get('source_refs',[])),
            answer_provenance=deepcopy(job.get('answer_provenance',{}).get(qid))))
    paths=[]
    for scenario in scenarios:
        blockers=[g for g in gaps if g['kind']!='context_only' and (not g['scenario_ids'] or scenario['id'] in g['scenario_ids'])]
        raw=logic(scenario['expression'],facts)
        value=logic(dict(op='and',args=[dict(condition='route'),dict(condition='gap')]),dict(route=raw)) if blockers else raw
        paths.append(dict(scenario_id=scenario['id'],expression=deepcopy(scenario['expression']),value=value,
            condition_ids=sorted(leaves(scenario['expression'])),source_refs=references(scenario['source_refs']),
            unresolved_source_gaps=deepcopy(blockers)))
    generation=job.get('question_generations',{}).get(case['id'],{})
    stages=[]
    for agent,record in [('V1',job.get('asset_classification') or {}),('V2',artifact),('V3',generation)]:
        stages.append(dict(agent=agent,run_id=record.get('run_id'),
            artifact_sha256=record.get('sha256') or digest(record),
            recorded_at=record.get('created_at'),model=deepcopy(record.get('model')),
            prompt_sha256=record.get('prompt_sha256'),input_sha256=record.get('input_sha256') or record.get('source_record_sha256'),
            generation_packet_sha256=record.get('generation_packet_sha256'),
            execution_history=deepcopy(record.get('execution_history',[])),
            prior_execution_history=deepcopy(record.get('prior_execution_history',[])),
            normalization_receipts=deepcopy(record.get('normalizations',[])),
            revalidation=deepcopy(record.get('revalidation')),
            revalidation_history=deepcopy(record.get('revalidation_history',[])),
            unknown_overflow_records=deepcopy(record.get('unknown_overflow_records',[])),
            prior_unknown_overflow_records=deepcopy(record.get('prior_unknown_overflow_records',[])),
            automation=deepcopy(record.get('automation')),
            question_contract_version=record.get('question_contract_version'),
            condition_failures=deepcopy(record.get('condition_failures')),
            validation=record.get('validation'),execution_metadata_available=bool(record.get('run_id'))))
    from src.item4.decision.asset_vex_assessment import VERSION as assessment_version
    stages.append(dict(agent='V4',run_id=run_id,recorded_at=evaluated_at,
            graph_sha256=row['attack_graph']['sha256'],rules_version=assessment_version,
        input_sha256=input_digest(job),validation='deterministic_three_valued_logic'))
    chain=dict(version=VERSION,job_id=job['id'],case_id=case['id'],cve=case['cve'],
        component_ref=row.get('component',{}).get('ref') if row.get('component') else None,
        taxonomy_version=artifact.get('taxonomy_version'),stages=stages,conditions=conditions,scenarios=paths,
        source_dimensions=source_dimensions(draft),
        scope=dict(component=deepcopy(row.get('component')),context_answers=deepcopy(job.get('context_answers',{})),
            evaluated_at=evaluated_at,answer_provenance_kind='operator_attestation'),
        version_binding=deepcopy(row.get('version_binding',{})),
        source_collection=deepcopy(result.get('source_collection')),
        source_review=deepcopy(artifact.get('coverage_review')),
        source_unknowns=deepcopy(draft.get('unknowns',[])),nonrequirements=deepcopy(draft.get('nonrequirements',[])),
        excluded_facts=deepcopy(draft.get('excluded_facts',[])),coverage=deepcopy(coverage),
        conclusion=dict(status=row['status'],reason=row['reason'],prerequisite_status=row['prerequisite_status'],
            deployment_exploitability=row['deployment_exploitability']),
        proves_exploit_success=False,independent_operating_evidence_verified=False)
    chain['sha256']=digest(chain)
    return chain
