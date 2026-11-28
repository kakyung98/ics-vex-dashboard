"""Compare actual MulVAL trace engines without comparing unstable node numbers."""
from pathlib import Path
from copy import deepcopy
from itertools import product
import json,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from src.item4.decision import evidence_based_vex as E; from src.item4.decision import attack_graph_builder as G; from src.item4.decision import mulval_attack_graphs as M
from tools.item4.auto_vex_fixture_support import profile

def signature(graph):
    def key(n):
        return ('rule',n['inference_rule']['id']) if 'inference_rule' in n else ('fact',n['semantic_id'],n['polarity'],n['kind'])
    keys={n['id']:key(n) for n in graph['nodes']}
    return set(keys.values()),{(keys[e['source']],keys[e['target']]) for e in graph['edges']}

def main():
    results=[]
    for cve in ['CVE-2010-5298','CVE-2014-0198','CVE-2014-3569','CVE-2024-3400']:
        p=profile('PAN-OS','10.2.4-h15') if cve=='CVE-2024-3400' else profile()
        plan=E.plan(cve,p,record=dict(cve=cve));old=plan['attack_graph'];program=deepcopy(old['mulval']['program'])
        contract={k:v for k,v in old.items() if k not in {'nodes','edges','sha256'}}
        contract['nodes']=old['semantic_nodes'];contract['edges']=[]
        program.update(trace_mode='completeTrace2',execution_tool_root='/opt/mulval-population')
        program['sha256']=M.digest({k:v for k,v in program.items() if k!='sha256'})
        receipt=M.generate(program);new=M.import_graph(contract,program,receipt)
        assert signature(old)==signature(new),cve
        qids=[n['question_id'] for n in old['semantic_nodes'] if n['kind']=='predicate']
        tested=0
        for states in product(['true','false','unknown'],repeat=len(qids)):
            facts=dict(zip(qids,states))
            assert G.evaluate(old,facts)['value']==G.evaluate(new,facts)['value'],(cve,facts)
            tested+=1
        results.append(dict(cve=cve,identical_vertices_rules_and_edges=True,truth_assignments=tested,
            program_sha256=program['sha256'],receipt_sha256=receipt['sha256'],trace_bytes=len(receipt['files']['trace_output.P'])))
    # An OR with many alternatives causes combinatorial child proof enumeration
    # under completeTrace2. Every submitted rule still must appear in real CSV.
    expr=dict(op='or',args=[dict(condition='q'+str(i)) for i in range(32)])
    questions=[dict(id='q'+str(i),label='Synthetic stress '+str(i),nist_fields=['C13-02.02']) for i in range(32)]
    contract=G.source_contract('CVE-SYNTHETIC-TRACE-STRESS',expr,questions,{},'test',False,'test')
    program=M.compile_program(contract);program.update(trace_mode='completeTrace2',execution_tool_root='/opt/mulval-population')
    program['sha256']=M.digest({k:v for k,v in program.items() if k!='sha256'})
    started=time.monotonic();receipt=M.generate(program);graph=M.import_graph(contract,program,receipt)
    assert G.evaluate(graph,{})['value']=='unknown'
    results.append(dict(synthetic_alternatives=32,all_submitted_rules_imported=True,rules=len(program['rules']),
                        trace_bytes=len(receipt['files']['trace_output.P']),elapsed=time.monotonic()-started,
                        receipt_sha256=receipt['sha256']))
    out=Path('results/mulval_population_20261118/trace_mode_validation.json');out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(dict(passed=True,cases=results,independent_semantic_accuracy_verified=False),indent=2),encoding='utf-8')
    print(out.read_text())

if __name__=='__main__':main()
