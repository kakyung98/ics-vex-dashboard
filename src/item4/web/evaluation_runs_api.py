"""Public evaluation run metadata. Uploaded operator BOMs are stored separately."""
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from src.item4.evaluation import evaluation_run_records as ledger

router = APIRouter(prefix='/api/item4/evaluation-runs')


@router.get('')
def runs():
    return JSONResponse({'runs': ledger.list_runs()}, headers={'Cache-Control': 'no-store'})


def snapshot(run_id):
    try:
        return ledger.get_run(run_id)
    except KeyError as exc:
        raise HTTPException(404, 'Evaluation run not found.') from exc


@router.get('/{run_id}')
def detail(run_id: str):
    return JSONResponse(snapshot(run_id), headers={'Cache-Control': 'no-store'})


@router.get('/{run_id}/report')
def report(run_id: str):
    row = snapshot(run_id)
    return JSONResponse(row, headers={
        'Cache-Control': 'no-store',
        'Content-Disposition': f'attachment; filename="{row["run_id"]}-run-report.json"',
    })
