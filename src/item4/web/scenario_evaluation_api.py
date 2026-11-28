"""Launch a bounded evaluation of retained, synthetic V1-rejection cases."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from threading import BoundedSemaphore

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response

from src.item4.evaluation import agent_review_records as agent_reviews
from src.item4.evaluation import evidence_adjudication_records as adjudications
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.web.evaluation_runs_api import snapshot


router = APIRouter(prefix='/api/item4/evaluation-runs')
_slot = BoundedSemaphore(1)
_worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix='scenario-review')


def _run(record, plan):
    try:
        runs.execute_run(record, plan)
    finally:
        _slot.release()


@router.post('/v1-sample', status_code=202)
def start_v1_sample(selection: dict):
    return _start(selection, 'v1')


@router.post('/selection', status_code=202)
def start_selected_scenarios(selection: dict):
    return _start(selection, 'all')


def _start(selection, cohort):
    if set(selection) == {'cve'}:
        cves = [selection['cve']]
    elif set(selection) == {'cves'} and isinstance(selection['cves'], list):
        cves = selection['cves']
    else:
        raise HTTPException(422, 'Supply cve or cves from the selected frozen cohort.')
    if not 1 <= len(cves) <= 3 or any(not isinstance(c, str) or len(c) > 35 for c in cves):
        raise HTTPException(422, 'Select one to three CVEs.')
    if not _slot.acquire(blocking=False):
        raise HTTPException(429, 'Another scenario review is running.', headers={'Retry-After': '5'})
    try:
        record, plan = runs.prepare_run(cves, cohort=cohort)
        try:
            _worker.submit(_run, record, plan)
        except RuntimeError as exc:
            ledger.update_run(record['run_id'], completed=0, candidate_count=0, status='failed',
                              error='The evaluation worker could not start.')
            raise HTTPException(503, 'The evaluation worker could not start.') from exc
    except Exception as exc:
        _slot.release()
        if isinstance(exc, ValueError):
            raise HTTPException(422, str(exc)) from exc
        if isinstance(exc, OSError):
            raise HTTPException(503, 'The pinned evaluation files are unavailable.') from exc
        raise
    return {'run_id': record['run_id'], 'status': record['status']}


@router.head('/{run_id}/candidates', include_in_schema=False)
@router.get('/{run_id}/candidates')
def download_candidates(run_id: str):
    run = snapshot(run_id)
    if run['generation_method'] not in {
        'scenario_moe_local_llm', 'scenario_moe_h200_llm', 'scenario_moe_supplier_review_pilot',
        'scenario_moe_explicit_inventory_review',
    }:
        raise HTTPException(404, 'This run has no MoE candidates.')
    if run['status'] == 'running':
        raise HTTPException(409, 'The scenario review is still running.')
    path = runs.OUTPUT / run['run_id'] / 'candidates.jsonl'
    if not path.is_file():
        raise HTTPException(404, 'The run produced no candidate rows.')
    receipt = run.get('result')
    if not receipt:
        report = path.with_name('report.json')
        receipt = json.loads(report.read_bytes()) if report.is_file() else {}
    if receipt.get('candidates_sha256') != runs.file_sha(path):
        raise HTTPException(409, 'The candidate artifact does not match the completed run.')
    return FileResponse(path, filename=f'{run_id}-candidates.jsonl', media_type='application/x-ndjson')


@router.head('/{run_id}/inventory-review/{filename}', include_in_schema=False)
@router.get('/{run_id}/inventory-review/{filename}')
def inventory_review_artifact(run_id: str, filename: str):
    run = snapshot(run_id)
    if run['generation_method'] != 'scenario_moe_explicit_inventory_review' or run['status'] != 'completed':
        raise HTTPException(404, 'No completed inventory review for this run.')
    if filename == 'candidates.jsonl':
        return download_candidates(run_id)
    media_types = {'report.ko.html': 'text/html', 'report.json': 'application/json',
                   'independent_verification.json': 'application/json',
                   'prior_not_affected_review.jsonl': 'application/x-ndjson'}
    if filename not in media_types:
        raise HTTPException(404, 'Unknown inventory review artifact.')
    path = runs.OUTPUT / run['run_id'] / filename
    if not path.is_file():
        raise HTTPException(404, 'The inventory review artifact is unavailable.')
    if filename == 'prior_not_affected_review.jsonl':
        if runs.file_sha(path) != run['data_hashes'].get(filename):
            raise HTTPException(409, 'The inventory review artifact does not match the ledger.')
        return FileResponse(path, filename=filename, media_type=media_types[filename])
    content = path.read_bytes()
    if sha256(content).hexdigest() != run['data_hashes'].get(filename):
        raise HTTPException(409, 'The inventory review artifact does not match the ledger.')
    return Response(content, media_type=media_types[filename], headers={
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
    })


@router.head('/{run_id}/agent-review/{filename}', include_in_schema=False)
@router.get('/{run_id}/agent-review/{filename}')
def agent_review_artifact(run_id: str, filename: str):
    row = snapshot(run_id)
    if (row['generation_method'] != agent_reviews.METHOD or row['status'] != 'completed'
            or filename not in agent_reviews.ARTIFACTS):
        raise HTTPException(404, 'No such published agent review artifact.')
    try:
        content = (runs.OUTPUT / row['run_id'] / filename).read_bytes()
    except FileNotFoundError as exc:
        raise HTTPException(404, 'The published agent review artifact is unavailable.') from exc
    if sha256(content).hexdigest() != row['data_hashes'].get(filename):
        raise HTTPException(409, 'The agent review artifact does not match the ledger.')
    headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
               'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"}
    if 'policy_rereview' in row:
        previous = row['policy_rereview']['previous_run_id']
        headers['Link'] = f'<../../{previous}/agent-review/{filename}>; rel="predecessor-version"'
    if filename != 'report.ko.html':
        headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return Response(content, media_type=agent_reviews.ARTIFACTS[filename], headers=headers)


@router.head('/{run_id}/population-review/{filename}', include_in_schema=False)
@router.get('/{run_id}/population-review/{filename}')
def population_review_artifact(run_id: str, filename: str):
    row = snapshot(run_id)
    types = {'population-report.ko.html':'text/html','population-report.json':'application/json',
             'changes.jsonl':'application/x-ndjson'}
    if row['status'] != 'completed' or not row.get('population_comparison') or filename not in types:
        raise HTTPException(404, 'A completed population comparison is required.')
    path = runs.OUTPUT / row['run_id'] / filename
    if not path.is_file():
        raise HTTPException(404, 'The population comparison artifact is unavailable.')
    if runs.file_sha(path) != row['data_hashes'].get(filename):
        raise HTTPException(409, 'The comparison fingerprint differs from its ledger.')
    headers = {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
               'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"}
    return FileResponse(path,media_type=types[filename],
                        filename=None if filename.endswith('.html') else filename,headers=headers)


@router.head('/{run_id}/evidence-adjudication/{filename}', include_in_schema=False)
@router.get('/{run_id}/evidence-adjudication/{filename}')
def evidence_adjudication_artifact(run_id: str, filename: str):
    row = snapshot(run_id)
    if (row['generation_method'] != adjudications.METHOD or row['status'] != 'completed'
            or 'adjudication' not in row or filename not in adjudications.ARTIFACTS):
        raise HTTPException(404, 'No such published evidence adjudication artifact.')
    try:
        content = (runs.OUTPUT / row['run_id'] / filename).read_bytes()
    except FileNotFoundError as exc:
        raise HTTPException(404, 'The published evidence adjudication artifact is unavailable.') from exc
    if sha256(content).hexdigest() != row['data_hashes'].get(filename):
        raise HTTPException(409, 'The evidence adjudication artifact does not match the ledger.')
    return Response(content, media_type=adjudications.ARTIFACTS[filename], headers={
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
    })
