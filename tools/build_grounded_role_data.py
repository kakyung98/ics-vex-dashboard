"""Build auditable pilot data; weak spans/simulated packets are explicitly labelled."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.grounded_role_tasks import CONDITION_SYSTEM,WRITER_SYSTEM,weak_conditions,check_conditions,check_writer

OUT=ROOT/'data/grounded_role_sft_v1'


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf-8')


def example(role,id,split,group,packet,gold,basis):
    system=CONDITION_SYSTEM if role=='cve-conditions' else WRITER_SYSTEM
    checks=check_conditions(packet,gold) if role=='cve-conditions' else check_writer(packet,gold)
    if not all(checks.values()):raise ValueError((id,checks))
    return {'id':id,'split':split,'group_id':group,'packet':packet,'annotation_basis':basis,
            'messages':[{'role':'system','content':system},{'role':'user','content':json.dumps(packet,ensure_ascii=False)},
                        {'role':'assistant','content':json.dumps(gold,ensure_ascii=False)}]}


def condition_rows(cache,index,test_cves):
    result=[]
    for cve,rec in sorted(cache.items()):
        desc=rec.get('description')
        if not isinstance(desc,str) or len(desc)<20:continue
        gold=weak_conditions(desc)
        if not gold['conditions'] and not gold['function_candidates']:continue
        fam=index.get(cve,{}).get('component')
        if cve in test_cves or fam in {'zlib','libexpat'} or any(t in desc.lower() for t in [' expat ',' zlib ']):
            split='test';group='reserved-zlib-expat'
        elif fam=='libcurl':split='train';group='family:libcurl'
        elif fam=='libxml2':split='validation';group='family:libxml2'
        else:
            group='family:'+fam if fam else 'subject:'+' '.join(desc.lower().split()[:4])
            bucket=int(hashlib.sha256(group.encode()).hexdigest()[:8],16)%100
            split='train' if bucket<70 else 'validation' if bucket<85 else 'test'
        packet={'vulnerability':cve,'description':desc}
        row=example('cve-conditions',cve,split,group,packet,gold,'weak_rules_on_real_nvd_description_not_expert_gold')
        row['source']={'path':'data/nvd_cache.json','description_sha256':hashlib.sha256(desc.encode()).hexdigest()}
        result.append(row)
    # Controlled text supplies negation/alternatives and explicit function
    # mentions without pretending the fictional descriptions are real CVEs.
    families=[('train',f'train-{i}') for i in range(6)]+[('validation','validation-template'),('test','test-template')]
    for split,group in families:
        for i in range(30):
            name=f'parseFrame_{group.replace("-","_")}_{i}'
            if split=='train':
                desc=f'The {name}() function has a flaw. Remote attackers can reach it only if diagnostic mode is enabled. Exploitation requires administrator privileges and crafted frames; TLS or DTLS may carry the frames.'
            elif split=='validation':
                desc=f'A malformed record reaches {name}() when the import feature is enabled. Authentication alone does not establish administrator privileges. The victim opens the record; no network access requirement is stated.'
            else:
                desc=f'Local users may call {name}() using a crafted configuration. When recovery mode is disabled, the handler is not registered. The description does not establish remote attacker access.'
            gold=weak_conditions(desc)
            result.append(example('cve-conditions',f'SYN-COND-{group}-{i:03d}',split,'synthetic:'+group,{'vulnerability':'synthetic-example','description':desc},gold,'synthetic_description_partial_span_references'))
    return result


def draft(packet):
    status=packet['decision']['status'];reason=packet['evidence'][0]['text']
    prefix='In this simulated scenario, ' if packet.get('simulation') else 'For this controlled application build, '
    impact=prefix+reason[0].lower()+reason[1:]
    if packet.get('missing_evidence'):impact+=' Missing evidence: '+', '.join(packet['missing_evidence'])+'.'
    action='Investigate the missing evidence before issuing a final applicability conclusion.' if status=='under_investigation' else None
    return {'vulnerability':packet['vulnerability'],'product':packet['product'],'status':status,
            'justification':packet['decision']['justification'],'impact_statement':impact,
            'evidence_refs':[e['id'] for e in packet['evidence']],'action_statement':action}


def writer_rows(conditions):
    fixture=ROOT/'data/source_training_sw'
    cases=read(fixture/'oracle/cases.json')
    runtime={r['id']:r for r in read(ROOT/'results/source_training_sw/runtime_audit.json')['cases']}
    rows=[]
    for split,limit,cve in [('train',400,'CVE-2023-27537'),('validation',50,'CVE-2023-39615')]:
        chosen=[r for r in cases if r['split']==split][:limit]
        for r in chosen:
            linked=runtime[r['id']]['api_symbol_linked']
            assert linked==r['dependency_linked']
            status='under_investigation' if linked else 'not_affected'
            text=f'The selected {r["id"]} target links {r["component"]} {r["version"]}; the actual CVE vulnerable-site applicability has not been established.' if linked else f'The selected {r["id"]} target does not link the selected {r["component"]} dependency, as recorded by its build recipe and link-map audit.'
            packet={'vulnerability':cve,'product':r['id'],'scope':'controlled synthetic application, MSVC static build; not deployed ICS firmware',
                    'simulation':False,'decision':{'status':status,'justification':None if linked else 'component_not_present'},
                    'evidence':[{'id':r['id']+':build','text':text},{'id':r['id']+':api','text':f'Benign-input public API witness: {runtime[r["id"]]["default_input_api_witness"]}. This is not CVE exploit verification.'}],
                    'missing_evidence':['verified CVE site mapping','CVE trigger applicability'] if linked else []}
            rows.append(example('vex-writer','WR-'+r['id'],split,f'fixture:{split}:{r["profile"]}:{r["template_group"]}',packet,draft(packet),'controlled_fixture_build_and_runtime_audit'))
    definitions=[
        ('not_affected','component_not_present','The dependency inventory and linked-image audit establish that the vulnerable component is absent from this build.'),
        ('not_affected','vulnerable_code_not_present','The validated vulnerable sites are excluded from this build by the verified configuration and compiled-image mapping.'),
        ('not_affected','vulnerable_code_not_in_execute_path','All validated vulnerable sites are unreachable from the complete configured entry-point set under the recorded analysis assumptions.'),
        ('not_affected','vulnerable_code_cannot_be_controlled_by_adversary','The complete relevant input-flow analysis establishes that the attacker cannot control the required vulnerable inputs in this configuration.'),
        ('not_affected','inline_mitigations_already_exist','The verified in-code guard blocks the vulnerability trigger on all relevant paths in this build.'),
        ('affected',None,'The recorded applicability checks and reproduced trigger establish that this build is affected within the stated scenario.'),
        ('fixed',None,'The full validated fix is present in the identified release and linked build according to the supplied fix-completeness evidence.'),
        ('under_investigation',None,'The available analysis does not resolve the vulnerable-site reachability and trigger requirements.')]
    for split,n in [('train',400),('validation',50)]:
        pool=sorted({r['packet']['vulnerability'] for r in conditions if r['split']==split and r['id'].startswith('CVE-')})
        for i in range(n):
            status,justification,text=definitions[i%len(definitions)]
            packet={'vulnerability':pool[i%len(pool)],'product':f'SIM-{split}-{i:04d}',
                    'scope':'fictional evidence packet for authoring training; no actual product verification',
                    'simulation':True,'decision':{'status':status,'justification':justification},
                    'evidence':[{'id':f'{split}:{i}:evidence','text':text}],
                    'missing_evidence':['complete dispatch model','verified trigger conditions'] if status=='under_investigation' else []}
            rows.append(example('vex-writer',f'SIM-WR-{split}-{i:04d}',split,f'simulation:{split}:{i//8}',packet,draft(packet),'simulated_decision_packet_not_real_cve_verification'))
    return rows


def main():
    if OUT.exists():raise FileExistsError(f'Refusing overwrite: {OUT}')
    from transformers import AutoTokenizer
    tok=AutoTokenizer.from_pretrained(r'C:\Users\user\Desktop\ICS-VEXForge\models\Qwen3-8B',local_files_only=True)
    cache=read(ROOT/'data/nvd_cache.json');index=read(ROOT/'data/snapshot_index.json')
    test_cves=set(read(ROOT/'evaluation/virtual_sw_100/manifest.json')['candidate_cves'])
    cond=condition_rows(cache,index,test_cves)
    roles={'cve-conditions':cond,'vex-writer':writer_rows(cond)}
    report={'schema':'ics-vex-grounded-role-sft/1','human_expert_gold':False,'live_deployment_authorized_by_training':False,
            'test100_used_for_training':False,'source_sha256':{'nvd_cache':sha(ROOT/'data/nvd_cache.json')},'roles':{}}
    for role,all_rows in roles.items():
        stats={};kept=[];excluded=[]
        for r in all_rows:
            prefix=tok.apply_chat_template(r['messages'][:-1],tokenize=False,add_generation_prompt=True,enable_thinking=False)
            size=len(tok(prefix+r['messages'][-1]['content']+tok.eos_token,add_special_tokens=False)['input_ids'])
            if size>1536:excluded.append({'id':r['id'],'reason':'over_length_not_truncated','tokens':size});continue
            r['tokens']=size;kept.append(r)
        for split in ('train','validation','test'):
            rows=[r for r in kept if r['split']==split]
            if not rows and role=='vex-writer' and split=='test':continue
            path=OUT/role/f'{split}.jsonl';path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
            stats[split]={'examples':len(rows),'sha256':sha(path),'max_tokens':max((r['tokens'] for r in rows),default=0)}
        groups={s:{r['group_id'] for r in kept if r['split']==s} for s in ('train','validation','test')}
        assert not groups['train']&groups['validation'] and not groups['train']&groups['test'] and not groups['validation']&groups['test']
        assert all(r['packet']['vulnerability'] not in test_cves for r in kept if r['split']!='test')
        assert stats['train']['examples']>0 and stats['validation']['examples']>0
        report['roles'][role]={'splits':stats,'excluded':excluded,'references':'partial rule spans and synthetic controlled text' if role=='cve-conditions' else 'controlled fixture evidence and explicitly simulated decision packets'}
    write(OUT/'manifest.json',report)
    (OUT/'README.md').write_text('''# Grounded-role SFT pilots

Two independent adapters share the local Qwen3-8B base. No test100 example is used
for training or checkpoint selection. Dataset hashes and length-filter exclusions
are recorded in manifest.json. Over-length examples are excluded, not truncated.

Condition extraction uses actual local NVD descriptions with conservative partial
rule-based span references, plus explicitly synthetic text. These are weak labels,
not exhaustive, expert-adjudicated exploit conditions. Function names are mentioned
candidates with literal evidence, not verified vulnerability sites. Missing names
are unresolved; they never prove absence. Conditions are not a formal AND formula
and cannot refute applicability. Validation agreement is not human-gold accuracy.

VEX writing preserves an assigned status and cites supplied evidence. Real-source
fixtures provide controlled build/linkage facts; linked cases stay unresolved for
CVE applicability. Additional status/justification coverage uses explicitly
simulated decision packets. Simulated evidence must never be presented as actual
CVE exploit or fix verification. The role writes drafts, not independent verdicts.

Training is not permission to deploy either model as a source of safety clearance.
Expert assessment of condition semantics and generated explanations remains open.
''',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
