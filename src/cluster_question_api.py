"""Stateless API for the reviewed cluster-question compiler and VEX judge."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from .cluster_question_pipeline import compile_plan, evaluate_plan, export_openvex
from .csaf_cluster_export import export_csaf

router=APIRouter(prefix='/api/cluster-questions',tags=['cluster-question-vex'])
DATASET=Path(__file__).resolve().parents[1]/'results/ics_cluster_question_pipeline_v3'


@router.get('/catalog')
def catalog():
    try:
        data=(DATASET/'summary.json').read_bytes()
        manifest=json.loads((DATASET/'manifest.json').read_text(encoding='utf-8'))
        if hashlib.sha256(data).hexdigest()!=manifest['artifacts']['summary.json']:
            raise ValueError('Question dataset summary integrity mismatch')
        return json.loads(data)
    except FileNotFoundError as exc:
        raise HTTPException(404,'Question dataset has not been built') from exc
    except (ValueError,KeyError) as exc:
        raise HTTPException(409,str(exc)) from exc


@router.post('/compile')
def compile_questions(payload:dict):
    try:
        return compile_plan(payload['reviews'],payload['records'],payload['memberships'])
    except (ValueError,KeyError,TypeError) as exc:
        raise HTTPException(422,str(exc)) from exc


@router.post('/evaluate')
def evaluate_questions(payload:dict):
    try:
        result=evaluate_plan(payload['plan'],payload['records'],payload['cases'],payload.get('common_answers',[]))
        timestamp=payload.get('timestamp') or datetime.now(timezone.utc).isoformat()
        if payload.get('export_openvex'):
            result['openvex']=export_openvex(result,payload['author'],timestamp)
        if payload.get('export_csaf'):
            result['csaf_vex']=export_csaf(result,payload['author'],timestamp,
                metadata=payload.get('csaf_metadata'),
                source_policy=payload.get('csaf_source_policy','evidence'),
                include_extensions=payload.get('csaf_include_analysis',payload.get('csaf_include_workbook_fields',True)))
        return result
    except (ValueError,KeyError,TypeError) as exc:
        raise HTTPException(422,str(exc)) from exc
