"""Bounded external tool execution using generated facts and an isolated folder."""
from pathlib import Path
import subprocess
import uuid
from .operational_assessment import mulval_input
from .training_io import atomic_json

ROOT=Path(__file__).resolve().parents[1]
IMAGE='ics-vex-operational-tools:20261116'


def run_mulval(payload):
    facts=mulval_input(payload['binding'],payload.get('network',[]),payload.get('services',[]),
        payload.get('vulnerabilities',[]),payload['attacker_host'])
    identity=uuid.uuid4().hex
    folder=ROOT/'results/operational_tool_runs'/identity;folder.mkdir(parents=True)
    (folder/'input.P').write_text(facts,encoding='utf-8')
    command=['docker','run','--rm','--network','none','--memory','2g','--cpus','2',
        '--mount','type=bind,src='+str(folder.resolve())+',dst=/work',IMAGE,'graph_gen.sh','/work/input.P','-l']
    result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
    (folder/'stdout.log').write_text(result.stdout,encoding='utf-8')
    (folder/'stderr.log').write_text(result.stderr,encoding='utf-8')
    artifacts=[p.name for p in folder.iterdir() if p.name in ('VERTICES.CSV','ARCS.CSV','AttackGraph.xml','AttackGraph.txt')]
    completed=result.returncode==0 and 'VERTICES.CSV' in artifacts
    vertices=(folder/'VERTICES.CSV').read_text(encoding='utf-8',errors='replace') if completed else ''
    outcome=dict(id=identity,tool='MulVAL/XSB',state='complete' if completed else 'error',
        returncode=result.returncode,artifacts=artifacts,graph_has_nodes=bool(vertices.strip()),
        binding=payload['binding'],VEX_status='under_investigation',
        interpretation='Graph facts and rules bound the result. No derived path is not proof of non-impact; semantic gaps remain unknown.')
    atomic_json(folder/'result.json',outcome)
    return outcome
