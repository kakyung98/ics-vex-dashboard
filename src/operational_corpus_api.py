"""Paged full-population browsing and resumable CPU build controls."""
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from fastapi import APIRouter,HTTPException
from fastapi.responses import StreamingResponse
from . import operational_corpus as corpus
from .gpu_lease import alive
from .training_io import atomic_json,read_json
import sqlite3

router=APIRouter(prefix='/api/operational-workflow/corpus',tags=['full-population-corpus'])


@router.get('/summary')
def summary():
    try:
        return dict(corpus.summary(),build=read_json(corpus.DATABASE.parent/'build_status.json'),
            extraction=read_json(corpus.SOURCE/'run_status.json'))
    except (OSError,ValueError,sqlite3.Error) as exc:raise HTTPException(503,'Full corpus index is not ready: '+str(exc)) from exc


@router.get('/cves')
def search(q:str='',state:str='',cluster:str='',offset:int=0,limit:int=50):
    try:return corpus.search(q,state,cluster,offset,limit)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    except (OSError,sqlite3.Error) as exc:raise HTTPException(503,'Full corpus index is not ready') from exc


@router.get('/clusters')
def clusters():
    try:return corpus.clusters()
    except (OSError,sqlite3.Error) as exc:raise HTTPException(503,'Full corpus index is not ready') from exc


@router.get('/cves/{cve}')
def detail(cve:str):
    try:result=corpus.detail(cve)
    except (OSError,sqlite3.Error) as exc:raise HTTPException(503,'Full corpus index is not ready') from exc
    if not result:raise HTTPException(404,'CVE outside the full corpus')
    return result


@router.get('/export')
def export():
    try:corpus.summary()
    except (OSError,ValueError,sqlite3.Error) as exc:raise HTTPException(503,'Full corpus index is not ready') from exc
    return StreamingResponse(export_rows(),media_type='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="ics-vex-full-corpus.jsonl"'})


def export_rows():
    # Starlette can resume a serialized iterator on a different pool thread.
    with corpus.connect(cross_thread=True) as db:
        for row in db.execute('SELECT cve,state,record,draft FROM corpus ORDER BY cve'):
            yield corpus.encoded(dict(cve=row['cve'],state=row['state'],record=json.loads(row['record']),draft=json.loads(row['draft'])))+'\n'


@router.post('/build',status_code=202)
def build(payload:dict):
    mode=payload.get('mode','semantic')
    if mode not in {'semantic','structured','none'}:raise HTTPException(422,'Unknown embedding mode')
    folder=corpus.DATABASE.parent;folder.mkdir(parents=True,exist_ok=True)
    process_file=folder/'build_process.json'
    if alive(read_json(process_file).get('pid')):raise HTTPException(409,'A full corpus build is already running')
    with (folder/'builder_stdout.log').open('ab') as out,(folder/'builder_stderr.log').open('ab') as err:
        child=subprocess.Popen([sys.executable,'-u',str(corpus.ROOT/'tools/build_operational_corpus.py'),'--mode',mode],
            cwd=corpus.ROOT,stdout=out,stderr=err,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    record=dict(pid=child.pid,mode=mode,started_at=datetime.now(timezone.utc).isoformat())
    atomic_json(process_file,record)
    return record
