"""Compile model proposals into source-linked review work, never expert approvals."""
import argparse
from collections import Counter,defaultdict
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.semantic_condition_contract import digest
from src.context_vex_pipeline import validate_review,select_questions,leaves
from tools.build_context_vex_pipeline import read_rows,unique
from tools.discover_ics_clusters import write_json,write_jsonl,sha


def compile_plan(record,extraction,cluster):
    cve=record['cve'];conditions=[];questions=[];by_digest={}
    for fact in extraction.get('facts',[]):
        source=next((s for s in record['sources'] if s['id']==fact['source_id']),None)
        start,end=fact['source_span']
        if source is None or not 0<=start<end<=len(source['text']) or source['text'][start:end]!=fact['source_quote']:
            raise ValueError('Invalid source span in model proposal')
        key=digest(fact);cid=cve+':condition:'+key[:16];by_digest[key]=cid
        refs=[dict(source_id=fact['source_id'],span=fact['source_span'],quote=fact['source_quote'])]
        condition=dict(id=cid,predicate=fact['condition'],kind=fact['kind'],
            target='unresolved:'+cve,target_resolution_required=True,operator_observable=None,
            necessity='not_established',proposed_necessity=fact['necessity'],validation_status='pending_review',
            source_refs=refs,evidence_demands=fact['evidence_demands'])
        conditions.append(condition)
        questions.append(dict(id=cid+':question',text='대상 자산에서 다음 조건이 성립합니까? '+fact['condition'],
            target=condition['target'],cost=1,cost_status='placeholder_until_measured',answer_type='yes_no_unknown',
            validation_status='pending_review',source_refs=refs,
            mappings=[dict(condition_id=cid,coverage='PARTIAL',proposed_coverage='FULL_after_target_and_implication_review',
                answers=dict(yes='true',no='false',unknown='unknown'),validation_status='pending_review',source_refs=refs)]))
    proposals=[]
    for packet in extraction.get('packet_path_proposals',[]):
        paths=[];refs=[]
        for path in packet.get('proposals',[]):
            literals=[]
            for literal in path['literals']:
                cid=by_digest.get(literal['fact_digest'])
                if cid is None:raise ValueError('Path proposal references a missing condition')
                node=dict(condition=cid)
                if literal['negated']:node=dict(op='not',args=[node])
                literals.append(node)
            if literals:paths.append(literals[0] if len(literals)==1 else dict(op='and',args=literals))
            refs.extend(path['source_refs'])
        if paths:
            proposals.append(dict(expression=paths[0] if len(paths)==1 else dict(op='or',args=paths),
                source_refs=refs,coverage_complete=False,validation_status='pending_review',packet_id=packet['packet_id']))
    formula=proposals[0] if len(extraction.get('packet_path_proposals',[]))==1 and len(proposals)==1 else None
    review=dict(cve=cve,cluster_id=cluster,conditions=conditions,questions=questions,formula=formula,
        packet_formula_proposals=proposals,formula_reconciliation_required=formula is None,
        identity_ambiguous=record.get('identity_ambiguous',False),source_record_status=record.get('original_nvd_status'),
        source_reading_complete=extraction.get('all_packets_read',False),
        evidence_state='no_asset_evidence',vex_status=None)
    validate_review(review,record)
    review['selection']=select_questions(conditions,questions,leaves(formula['expression']) if formula else None)
    return review


def run(output):
    output=Path(output)
    inputs=unique(read_rows(output/'full_inputs.jsonl'),'cve')
    extracted=unique(read_rows(output/'semantic_extractions.jsonl'),'cve')
    if set(inputs)!=set(extracted) or len(inputs)!=12418:raise ValueError('Full population required')
    assigned=read_rows(ROOT/'results/ics_context_cluster_tuning_v1/spherical_partial_whiten128-k128_assignments.jsonl')
    labels={r['cve']:r['cluster_id'] for r in assigned}
    plans=[compile_plan(inputs[c],extracted[c],labels[c]) for c in sorted(inputs)]
    write_jsonl(output/'review_contracts.jsonl',plans)
    groups=defaultdict(list)
    for plan in plans:
        byid={c['id']:c for c in plan['conditions']}
        for q in plan['questions']:
            condition=byid[q['mappings'][0]['condition_id']]
            key=(plan['cluster_id'],condition['kind'],' '.join(condition['predicate'].lower().split()))
            groups[key].append(dict(cve=plan['cve'],question_id=q['id'],condition_id=condition['id']))
    common=[];membership={}
    for key,members in groups.items():
        group=dict(id='question-group:'+digest(key)[:16],cluster_id=key[0],kind=key[1],predicate=key[2],members=members,
            shared_candidate=len({m['cve'] for m in members})>1,validated_answer_reuse=False,
            required_review=['same asset state and target','answer implication','operator observability','evidence scope'])
        common.append(group)
        for m in members:membership[m['question_id']]=group
    write_json(output/'common_question_candidates.json',common)
    write_jsonl(output/'draft_questionnaires.jsonl',[dict(cve=p['cve'],cluster_id=p['cluster_id'],
        common_candidates=[q for q in p['questions'] if membership[q['id']]['shared_candidate']],
        specific_candidates=[q for q in p['questions'] if not membership[q['id']]['shared_candidate']],
        validation_status='pending_review',eligible_for_vex=False) for p in plans])
    write_jsonl(output/'blind_expert_annotation.jsonl',[dict(cve=c,sources=inputs[c]['sources'],
        reviewer=None,reviewed_at=None,necessary_conditions=None,alternative_paths=None,
        path_coverage_complete=None,operator_observable_conditions=None,reference_vex_by_asset=None) for c in sorted(inputs)])
    queue=[dict(cve=p['cve'],cluster_id=p['cluster_id'],tasks=[
        'verify source interpretation and polarity','resolve exact target and observability',
        'approve or reject question implications','reconcile source-specific paths and completeness',
        'collect scoped asset evidence'],source_reading_complete=p['source_reading_complete']) for p in plans]
    write_jsonl(output/'expert_review_queue.jsonl',queue)
    summary=dict(population=12418,excluded=0,model_read_cves=sum(p['source_reading_complete'] for p in plans),
        condition_proposals=sum(len(p['conditions']) for p in plans),question_proposals=sum(len(p['questions']) for p in plans),
        shared_question_candidate_groups=sum(g['shared_candidate'] for g in common),
        cves_with_formula_proposal=sum(p['formula'] is not None for p in plans),
        reviewed_conditions=0,reviewed_formulas=0,asset_decisions=0,
        extraction_precision=None,vex_precision=None,question_time_savings=None,
        pending_external_inputs=['expert semantic annotations','actual asset scope and evidence','measured operator response costs'],
        source_hash=sha(output/'full_inputs.jsonl'),extraction_hash=sha(output/'semantic_extractions.jsonl'),
        compiler_hash=sha(__file__),contract_hash=sha(output/'review_contracts.jsonl'))
    write_json(output/'research_summary.json',summary)
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('output',nargs='?',default=str(ROOT/'results/ics_context_research_v3'))
    run(p.parse_args().output)
