"""Validate MulVAL provenance and signed semantics on real vendor CVEs.

Operating records are explicitly synthetic counterfactuals. The expected table
comes from the quoted vendor conditions, not from the engine's own predictions.
This is not a field accuracy estimate or independent expert annotation.
"""
from pathlib import Path
from datetime import datetime, timezone
from itertools import product
from copy import deepcopy
import csv
import hashlib
import io
import json
import sys
import re
import time
from urllib.request import Request, urlopen
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bs4 import BeautifulSoup
from src.item4.decision import evidence_based_vex as E
from src.item4.decision import mulval_attack_graphs as MV
from tools.item4.auto_vex_fixture_support import profile, request

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(MV.os.environ.get('ICSVEX_MULVAL_VALIDATION_OUTPUT',ROOT/'results/mulval_integration_20261118'))


def observed_generation(program):
    for attempt in range(3):
        try:return MV.generate(program)
        except RuntimeError as exc:
            if attempt==2 or not any(word in str(exc) for word in ('WebSocket','Connection','execution deadline')):raise
            time.sleep(2**attempt)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    registry=E.registry();current={};source_checks=[]
    for sid in ['ossl_jun','ossl_jan','pan']:
        item=registry['sources'][sid]
        wire=urlopen(Request(item['url'],headers={'User-Agent':'ICS-VEX source provenance verification'}),timeout=40).read()
        (OUT/'sources').mkdir(exist_ok=True)
        (OUT/'sources'/(sid+'.raw')).write_bytes(wire)
        text=wire.decode('utf-8',errors='replace')
        if sid=='pan':text=BeautifulSoup(text,'html.parser').get_text(' ',strip=True)
        current[sid]=' '.join(text.split())
        source_checks.append(dict(source_id=sid,url=item['url'],fetched_sha256=hashlib.sha256(wire).hexdigest(),
                                  snapshot_text_sha256=item['sha256'],fetched_at=datetime.now(timezone.utc).isoformat()))
    values=['true','false','unknown'];cases=[];artifacts=[]
    specs=[('CVE-2010-5298','OpenSSL','1.0.1g',['multithreaded','release_buffers'],'and'),
           ('CVE-2014-0198','OpenSSL','1.0.1g',['release_buffers'],'single'),
           ('CVE-2024-3400','PAN-OS','10.2.4-h15',['gp_gateway','gp_portal'],'or'),
           ('CVE-2014-3569','OpenSSL','1.0.1j',['ssl3_build_support'],'source_gap')]
    for cve,name,version,qids,op in specs:
        p=profile(name,version,asset_ref='SYNTHETIC-MULVAL-'+cve)
        p['scope']['reviewer']='Automated source-rule validation; synthetic operating records'
        plan=E.plan(cve,p);graph=plan['attack_graph']
        assert graph['generator']=='MulVAL/XSB' and graph['generation_status']=='complete'
        assert graph['mulval']['all_inference_steps_checked']
        source=registry['rules'][cve]['source']
        assert ' '.join(source['quote'].split()) in current[source['source_id']],cve
        folder=OUT/cve;folder.mkdir(exist_ok=True)
        program=graph['mulval']['program'];cache=Path(MV.os.environ.get('ICSVEX_MULVAL_CACHE',ROOT/'results/mulval_prerequisite_cache'))
        receipt=json.loads((cache/(program['sha256']+'.json')).read_text(encoding='utf-8'))
        for filename,content in receipt['files'].items():(folder/filename).write_text(content,encoding='utf-8')
        (folder/'input.P').write_text(program['input_P'],encoding='utf-8')
        (folder/'rules.P').write_text(program['rules_P'],encoding='utf-8')
        assert 'execCode(' not in program['rules_P'] and 'vulProperty(' not in program['rules_P']
        for combo in product(values,repeat=len(qids)):
            selected={}
            for qid,state in zip(qids,combo):
                q=next(q for q in plan['questions'] if q['id']==qid)
                selected[qid]=q['true_values'][0] if state=='true' else q['false_values'][0] if state=='false' else 'unknown'
            req=request(cve,p,selected)
            # Replace generic fixture prose with the exact counterfactual facts.
            req['profile']['evidence']['configuration']['excerpt']='SYNTHETIC COUNTERFACTUAL: '+json.dumps(selected,sort_keys=True)
            req['plan_sha256']=E.plan(cve,req['profile'])['plan_sha256']
            result=E.evaluate(req)
            if op=='source_gap':expected='under_investigation'
            elif op=='or':expected='affected' if 'true' in combo else 'not_affected' if all(v=='false' for v in combo) else 'under_investigation'
            else:expected='not_affected' if 'false' in combo else 'affected' if all(v=='true' for v in combo) else 'under_investigation'
            assert result['decision']['status']==expected,(cve,combo,result['decision'])
            assert result['attack_graph']['sha256']==graph['sha256'],'answers changed topology'
            assert result['attack_graph_evaluation']['justification_complete']
            # Independent cross-engine check: rerun actual XSB with only known
            # signed observations, withholding unknown inputs. Compare every
            # semantic node with the three-valued annotation of the full graph.
            observed=deepcopy(program)
            lines=['% SYNTHETIC scoped observations. Unknown facts are withheld.']
            lines += [line for line in program['input_P'].splitlines() if line.startswith('attackGoal(')]
            facts=dict(result['condition_values'],affected_version='true')
            for node in graph['semantic_nodes']:
                if node['kind']!='predicate':continue
                state=facts.get(node['question_id'],'unknown')
                if state!='unknown':lines.append('icsObservation('+program['symbols'][node['id']]+','+state+').')
            observed['input_P']='\n'.join(lines)+'\n'
            observed['input_semantics']='synthetic_scoped_known_observations; unknown omitted'
            observed['sha256']=MV.digest({k:v for k,v in observed.items() if k!='sha256'})
            observed_run=observed_generation(observed)
            derived=set()
            for vertex in csv.reader(io.StringIO(observed_run['files']['VERTICES.CSV'])):
                if not vertex or vertex[2]!='OR':continue
                m=re.fullmatch(r'icsState\((n[a-f0-9]+),(true|false)\)',vertex[1])
                if m:derived.add((m[1],m[2]))
            for key,symbol in program['symbols'].items():
                positive=(symbol,'true') in derived;negative=(symbol,'false') in derived
                assert not (positive and negative),'Contradictory XSB state'
                actual='true' if positive else 'false' if negative else 'unknown'
                assert actual==result['attack_graph_evaluation']['node_states'][key],(cve,combo,key,actual)
            if op=='source_gap':assert result['condition_values']['source-ssl3-clienthello-received']=='unknown'
            case_id=cve+'-'+'-'.join(combo)
            observed_folder=folder/'observed'/case_id;observed_folder.mkdir(parents=True,exist_ok=True)
            (observed_folder/'input.P').write_text(observed['input_P'],encoding='utf-8')
            for filename,content in observed_run['files'].items():(observed_folder/filename).write_text(content,encoding='utf-8')
            (folder/(case_id+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
            cases.append(dict(id=case_id,cve=cve,input_states=dict(zip(qids,combo)),expected=expected,
                              actual=result['decision']['status'],graph_sha256=graph['sha256'],
                              inference_steps=len(result['attack_graph_evaluation']['inference_steps']),
                              justified=result['attack_graph_evaluation']['justification_complete'],
                              actual_xsb_observations_match_every_node=True,
                              observed_generation_receipt_sha256=observed_run['sha256'],
                              synthetic_operating_facts=True))
        artifacts.append(dict(cve=cve,graph_sha256=graph['sha256'],program_sha256=program['sha256'],
                              generation_receipt_sha256=receipt['sha256'],tool_sha256=receipt['tool_sha256'],
                              source_ref=source,scope='single-component source prerequisites',
                              source_gap_preserved=op=='source_gap',complete_exploit_chain_validated=False))
    report=dict(version='mulval-real-cve-provenance-validation/1',passed=True,cves=len(specs),cases=len(cases),
                actual_mulval_execution=True,source_checks=source_checks,artifacts=artifacts,cases_detail=cases,
                actual_xsb_signed_derivations_match_all_annotated_nodes=True,
                operating_facts='synthetic scoped counterfactual records; no actual ICS observations supplied',
                independent_semantic_accuracy_verified=False,source_extraction_accuracy_measured=False,
                graph_scope='source-declared prerequisites; not arbitrary code execution or cross-asset chains',
                discovered_source_gap=dict(cve='CVE-2014-3569',detail='SSL v3 ClientHello reception was omitted by the previous build-option-only rule. Kept unknown; coverage incomplete; all three build observations now remain under investigation.'),
                completeness='This source/operating-fact validation covers four CVEs. Separate full-population MulVAL generation and artifact integrity audit covers all 12,418 CVEs; neither establishes independent extraction accuracy.')
    (OUT/'validation_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(passed=True,cves=len(specs),cases=len(cases),report=str(OUT/'validation_report.json'))))


if __name__=='__main__':main()
