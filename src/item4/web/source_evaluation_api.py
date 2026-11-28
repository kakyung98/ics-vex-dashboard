"""Source question admission and Boolean contracts, never legacy CVSS gates."""
from pathlib import Path
from threading import Lock
import json
from fastapi import APIRouter
from fastapi.responses import FileResponse
from src.item4.evaluation.source_question_benchmark import run,VERSION

ROOT=Path(__file__).resolve().parents[3]
router=APIRouter(prefix='/api/item4/analyses/evaluation')
LOCK=Lock()


@router.get('/reference-labels')
def reference_labels():
    path=ROOT/'benchmark/item4_evaluation/current_reference_v1/manifest.json'
    if not path.is_file():return dict(state='not_available')
    return dict(state='available',manifest=json.loads(path.read_text(encoding='utf-8')))


@router.get('/reference-labels/labels')
def reference_label_download():
    return FileResponse(ROOT/'benchmark/item4_evaluation/current_reference_v1/labels.jsonl',
        filename='item4-assistant-reference-labels.jsonl',media_type='application/x-ndjson')


@router.get('/reference-labels/review-queue')
def reference_review_download():
    return FileResponse(ROOT/'benchmark/item4_evaluation/current_reference_v1/expert_review_queue.jsonl',
        filename='item4-expert-review-queue.jsonl',media_type='application/x-ndjson')


@router.get('/llm')
def llm_validity():
    from src.item4.analysis import exploitation_prerequisites as V2
    from src.item4.analysis import asset_operating_question_generation as V3
    path=ROOT/'results/item4_llm_validity_20261126/report.json'
    if not path.is_file():return dict(state='not_available',scope='No independent LLM accuracy claim is available.')
    report=json.loads(path.read_text(encoding='utf-8'))
    return dict(state='available',current_prompts=report.get('prompts')==dict(v2=V2.digest(V2.SYSTEM),v3=V3.digest(V3.SYSTEM)),report=report)


def cases():
    return run()['rows']


@router.get('')
def summary():
    return dict(version=VERSION,contract_cases=len(cases()),latest=None,
        scope='Source question confidence admission and Boolean-logic contracts. This is not model accuracy or confidence calibration.',
        llm_called=False)


@router.post('/run')
def execute():
    # Fixed, local synthetic cases only. No model calls, uploaded code or GPU work.
    with LOCK:return run()
