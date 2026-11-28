"""Sample current test inputs and run them live, then report item-3 precision and wall time."""
import time
STARTED=time.perf_counter()
from pathlib import Path
import argparse
import json
import sys
import random
import secrets

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))


def main(argv=None):
    from tools.item3.item3_splits import test_dataset
    from tools.item3.run_item3_test import predict,score,write_json
    from src.item3.matching.identification_session import IdentificationSession
    from src.item3.matching.sbom_candidate_service import match_candidates
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,default=test_dataset(ROOT))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('agents','rules'),default='agents')
    parser.add_argument('--workers',type=int,default=16)
    parser.add_argument('--processes',type=int,default=0)
    parser.add_argument('--seed', type=int, help='Repeat a previous file selection')
    parser.add_argument('--full', action='store_true', help='Evaluate the entire test folder')
    args=parser.parse_args(argv)
    args.model_review = args.mode == 'agents'
    deadline = 180 if args.model_review else 300
    files = sorted(path.stem for path in (args.dataset/'sboms').glob('*.json'))
    if not files:
        parser.error('Empty test SBOM folder')
    seed = None if args.full else args.seed if args.seed is not None else secrets.randbits(32)
    case_ids = None if args.full else random.Random(seed).sample(files, max(1, (len(files)*30+50)//100))
    selection = dict(population_files=len(files), requested_percent=100 if args.full else 30,
                     seed=seed, unit='SBOM file', selected_files=len(case_ids or files))
    session=IdentificationSession(compact=True)
    provider=None
    process_pool=None
    if args.processes:
        if not 1<=args.processes<=16:raise ValueError('CPU processes must be between 1 and 16')
        from src.item3.matching.parallel_identification import ParallelIdentificationPool
        process_pool=ParallelIdentificationPool(args.processes, model_review=args.model_review)
    else:
        from src.item3.evidence.product_candidate_search import get_index
        from src.item3.evidence.local_vulnerability_lookup import get_source_lookup
        from src.item3.evidence.cisa_advisory_lookup import family_index
        get_index();get_source_lookup();family_index()
        if args.mode=='agents':
            from src.item3.agents.batched_provider import BatchedIdentificationProvider
            provider=BatchedIdentificationProvider()
            provider.require_identity_review=args.model_review
    def matcher(sbom,**options):
        if process_pool is not None:return process_pool(sbom,**options)
        return match_candidates(sbom,**options,component_cache=session,identification_agents=provider)
    try:
        predictions=predict(args.dataset/'sboms',args.output,mode=args.mode,matcher=matcher,workers=args.workers,audit_detail='compact',case_ids=case_ids)
    finally:
        if provider is not None:provider.close()
        if process_pool is not None:process_pool.close()
    prediction_finished=time.perf_counter()
    report=score(predictions,args.dataset,args.output,case_ids=case_ids)
    overall=report['overall']
    tp,fp=overall['TP'],overall['FP']
    precision = overall['precision_percent']
    complete=report.get('selected_cases_complete',report['full_population_complete'])
    precision_status=('incomplete' if not complete else 'undefined' if precision is None
                      else 'pass' if precision > 80 else 'fail')
    elapsed=time.perf_counter()-STARTED
    result=dict(schema='item3-live-certification/1',dataset=str(args.dataset.resolve()),
        cases=report['cases'],completed_cases=report['predicted_cases'],components=overall.get('components'),
        selection=selection,selected_cases_complete=complete,
        full_population_complete=report['full_population_complete'],execution_errors=overall['execution_errors'],mode=args.mode,
        elapsed_seconds=elapsed,prediction_seconds=prediction_finished-STARTED,
        scoring_seconds=time.perf_counter()-prediction_finished,model_review=args.model_review,time_limit_seconds=deadline,
        time_requirement_met=bool(complete and elapsed<deadline and (not args.model_review or overall.get('model_backed_cases',0)>0)),
        metric='TP/(TP+FP)',target_precision_percent=80,target_operator='>',precision_criterion_status=precision_status,
        TP=tp,FP=fp,FN=overall['FN'],unjudged=overall['unjudged'],
        outside_CPE_scope_outputs=overall.get('outside_CPE_scope_outputs',0),
        scoring_policy='expected_list_mapping_precision',
        precision_on_adjudicated_percent=precision, full_output_precision_percent=precision,
        output_adjudication_coverage_percent=overall['output_adjudication_coverage_percent'],
        recall_on_known_positives_percent=overall['recall_on_known_positives_percent'],
        model_backed_cases=overall.get('model_backed_cases'),session=session.statistics(),
        provider=provider.statistics() if provider is not None else None,
        process_pool=process_pool.statistics() if process_pool is not None else None,
        new_inference_performed=True,source_gold_modified=False,
        timing_scope='Process start through sampling, reading selected inputs, live identification, prediction serialization, gold integrity checks and scoring; excludes no model/index startup.',
        interpretation='Synthetic source-derived component/CVE mapping evaluation; each emitted component/CVE pair absent from the expected list counts as FP. Rules mode is a separately labeled baseline.')
    write_json(args.output/'certification_result.json',result)
    print(json.dumps(result,ensure_ascii=False),flush=True)
    return 0 if result['time_requirement_met'] else 2


if __name__=='__main__':raise SystemExit(main())
