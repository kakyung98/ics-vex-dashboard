"""Generate provisional scenario labels on the fixed V3 benchmark using the pinned v2 experts."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import bulk_scenario_runner as item4_bulk_run; from src.item4.evaluation import scenario_evaluation_runner as runs


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    select = parser.add_mutually_exclusive_group(required=True)
    select.add_argument('--cve', action='append', help='Select a cohort member. Repeat to select several.')
    select.add_argument('--entire-cohort', action='store_true', help='Generate candidates for every scenario in the selected cohort.')
    select.add_argument('--resume', metavar='RUN_ID', help='Resume a checkpoint using its original frozen selection.')
    parser.add_argument('--cohort', choices=['v1', 'all'], default='v1')
    parser.add_argument('--delivery', type=Path, help='Location of the original, fingerprinted V3 delivery.')
    parser.add_argument('--chunk-size', default=128, type=int, help='Scenarios per durable commit.')
    parser.add_argument('--batch-size', default=8, type=int, help='Maximum prompts per inference batch.')
    parser.add_argument('--h200-port', type=int, help='Loopback port of the pinned H200 worker.')
    args = parser.parse_args()
    if args.chunk_size < 1 or not 1 <= args.batch_size <= 256:
        parser.error('Use a positive chunk size and a batch size between 1 and 256.')
    if args.h200_port is not None and not 1 <= args.h200_port <= 65535:
        parser.error('Invalid loopback port.')
    selected, cohort = args.cve, args.cohort
    if args.resume:
        ledger_row = runs.ledger.get_run(args.resume)
        if not ledger_row.get('resumable'):
            parser.error('This run has no resumable checkpoint.')
        cfg = json.loads((runs.OUTPUT / ledger_row['run_id'] / 'setup.json').read_bytes())
        selected, cohort = cfg['selected_cves'], cfg['cohort']
        if (cfg['generation_method'] == 'scenario_moe_h200_llm') != (args.h200_port is not None):
            parser.error('Resume with the same backend as the original run.')
    provider = None
    if args.h200_port:
        from src.item4.models.remote_gpu_expert_client import H200Batch
        provider = H200Batch(args.h200_port)
    record, plan = runs.prepare_run(selected, cohort=cohort, delivery=args.delivery, bulk=True,
                                    resume_id=args.resume, backend_identity=provider.identity if provider else None)
    print(record['run_id'], flush=True)
    result = item4_bulk_run.execute(record, plan, chunk_size=args.chunk_size, batch_size=args.batch_size,
                                    resume=bool(args.resume), provider=provider)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result['status'] == 'completed' else 1)
