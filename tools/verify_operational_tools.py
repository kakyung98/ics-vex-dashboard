"""Run actual OpenSCAP/OVAL and MulVAL/XSB in an isolated local container."""
from pathlib import Path
import json
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json
from src.operational_assessment import import_oval_results

OUT=ROOT/'results/operational_tools_v1'
IMAGE='ics-vex-operational-tools:20261116'


def run(args,folder,label):
    command=['docker','run','--rm','--network','none','--memory','2g','--cpus','2',
        '--mount','type=bind,src='+str(folder.resolve())+',dst=/work',IMAGE,*args]
    result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=180)
    (folder/(label+'.stdout.log')).write_text(result.stdout,encoding='utf-8')
    (folder/(label+'.stderr.log')).write_text(result.stderr,encoding='utf-8')
    if result.returncode:raise RuntimeError(label+' failed: '+result.stderr[-2000:])
    return result


def verify():
    OUT.mkdir(parents=True,exist_ok=True)
    oval=OUT/'oval';oval.mkdir(exist_ok=True)
    (oval/'fixture.conf').write_text('feature=enabled\n',encoding='utf-8')
    xml='''<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
<generator><oval:product_name>ICS-VEX fictional fixture</oval:product_name><oval:schema_version>5.11.2</oval:schema_version><oval:timestamp>2026-11-16T00:00:00</oval:timestamp></generator>
<definitions><definition id="oval:ics-vex:def:1" version="1" class="inventory"><metadata><title>Fictional operator feature configuration</title><description>Read an isolated fixture file, not a live ICS device.</description></metadata><criteria><criterion test_ref="oval:ics-vex:tst:1" comment="Fixture feature enabled"/></criteria></definition></definitions>
<tests><ind:textfilecontent54_test id="oval:ics-vex:tst:1" version="1" comment="Fixture setting" check="all"><ind:object object_ref="oval:ics-vex:obj:1"/><ind:state state_ref="oval:ics-vex:ste:1"/></ind:textfilecontent54_test></tests>
<objects><ind:textfilecontent54_object id="oval:ics-vex:obj:1" version="1"><ind:filepath>/work/fixture.conf</ind:filepath><ind:pattern operation="pattern match">feature=(enabled)</ind:pattern><ind:instance datatype="int" operation="equals">1</ind:instance></ind:textfilecontent54_object></objects>
<states><ind:textfilecontent54_state id="oval:ics-vex:ste:1" version="1"><ind:subexpression operation="equals">enabled</ind:subexpression></ind:textfilecontent54_state></states>
</oval_definitions>'''
    (oval/'definitions.xml').write_text(xml,encoding='utf-8')
    run(['oscap','--version'],oval,'version')
    run(['oscap','oval','validate','/work/definitions.xml'],oval,'schema_validation')
    run(['oscap','oval','eval','--results','/work/results.xml','/work/definitions.xml'],oval,'evaluation')
    observations=import_oval_results((oval/'results.xml').read_text(encoding='utf-8'),
        {'oval:ics-vex:def:1':'feature'},dict(asset_ref='fictional-container-fixture'),
        dict(report_asset_ref='fictional-container-fixture'))
    if observations[0]['value']!='true':raise AssertionError('Actual OVAL fixture not observed true')
    print('Actual OVAL validation and evaluation passed',flush=True)
    mulval=OUT/'mulval';mulval.mkdir(exist_ok=True)
    run(['sh','-c','cp /opt/mulval/testcases/3host/input.P /work/input.P && graph_gen.sh /work/input.P -l'],mulval,'graph_generation')
    artifacts=[p.name for p in mulval.iterdir() if p.name in ('AttackGraph.txt','AttackGraph.xml','VERTICES.CSV','ARCS.CSV')]
    if not {'VERTICES.CSV','ARCS.CSV'}<=set(artifacts):raise AssertionError('MulVAL graph artifacts missing')
    if not (mulval/'VERTICES.CSV').stat().st_size:raise AssertionError('Empty MulVAL graph')
    inspect=subprocess.check_output(['docker','image','inspect',IMAGE,'--format','{{.Id}}'],text=True).strip()
    atomic_json(OUT/'verification.json',dict(image=IMAGE,image_id=inspect,
        openscap_oval_schema_validation=True,openscap_oval_real_execution=True,
        mulval_xsb_real_execution=True,mulval_artifacts=artifacts,oval_observations=observations,
        fixtures_only=True,live_ICS_scanning_performed=False,
        interpretation='Actual external tools executed on fixtures; no field or CVE-semantic accuracy inferred.'))
    print('Actual MulVAL/XSB graph generation passed',flush=True)


if __name__=='__main__':verify()
