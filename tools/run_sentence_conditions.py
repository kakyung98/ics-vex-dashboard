"""Sentence-first full-corpus extraction; deliberately does not launch clustering."""
import argparse,gc,json,os,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.run_context_research import Worker as PreviousWorker,contract
from src.condition_sentence_units import units,administrative
from src.semantic_condition_contract import digest
from src import gpu_lease
from src.training_io import atomic_json,read_json
from tools.discover_ics_clusters import sha,write_jsonl

RULES='''Each unit is a complete sentence, or a punctuation-delimited clause from
an oversized sentence. Read adjacent units for context, but cite the unit that
actually states each condition. Never infer prerequisites from a product/version
list, consequences, recovery steps, remediation or publication boilerplate.
Physical access needed to RESTORE a device is not physical access needed to exploit.
If a unit explicitly assigns another CVE to its vulnerability, do not attribute it
to the current CVE. Never convert absence of privilege requirements into absence
of authentication requirements. For even-if-disabled, describe enabling as not
necessary; do not claim disabling is necessary. Keep victim and attacker distinct.
State 1 requires an empty facts list. Any nonempty facts list requires state 0.
Keep optional conditions out of proposed necessary paths. No implicit AND paths.'''

def prepare(output):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    source=ROOT/'results/ics_context_research_v4/full_inputs.jsonl'
    records=[json.loads(l) for l in source.open(encoding='utf-8')]
    packets=[];admin=[];oversized=0
    policy=digest([sha(ROOT/'src/condition_sentence_units.py'),RULES,sha(ROOT/'src/compact_condition_contract.py')])
    for r in records:
        seq=0
        for s in r['sources']:
            batch=[];size=0
            def flush():
                nonlocal batch,size,seq
                if not batch:return
                aliased=[dict(id=str(i+1),**u) for i,u in enumerate(batch)]
                wire=dict(cve=r['cve'],units=[[u['id'],u['text']] for u in aliased],identity_ambiguous=r['identity_ambiguous'])
                packets.append(dict(packet_id=r['cve']+':'+str(seq),cve=r['cve'],units=aliased,wire=wire,
                    packet_sha256=digest(dict(wire=wire,policy=policy)),identity_ambiguous=r['identity_ambiguous']))
                seq+=1;batch=[];size=0
            for u in units(s['text']):
                row=dict(u,source_id=s['id'],origin=s.get('origin',{}))
                if administrative(s['text']) or administrative(u['text']):
                    admin.append(dict(cve=r['cve'],**row));continue
                oversized+=u['oversized']
                if batch and size+len(u['text'])>2400:flush()
                batch.append(row);size+=len(u['text'])
            flush()
    shutil.copyfile(source,output/'full_inputs.jsonl')
    write_jsonl(output/'model_packets.jsonl',packets);write_jsonl(output/'administrative_units.jsonl',admin)
    atomic_json(output/'input_manifest.json',dict(population=len(records),packet_count=len(packets),
        inputs_sha256=sha(source),packets_sha256=sha(output/'model_packets.jsonl'),
        contract_sha256=sha(ROOT/'src/compact_condition_contract.py'),sentence_policy_sha256=policy,
        no_population_exclusions=True,administrative_units=len(admin),oversized_units_preserved=oversized,
        arbitrary_whitespace_splitting=False,clustering_allowed=False))

class Worker(PreviousWorker):
    def verify_inputs(self):
        super().verify_inputs()
        policy=digest([sha(ROOT/'src/condition_sentence_units.py'),RULES,sha(ROOT/'src/compact_condition_contract.py')])
        if policy!=self.manifest['sentence_policy_sha256']:raise ValueError('Sentence policy changed')
        self.status.update(worker_sha256=sha(__file__),clustering_allowed=False,
            priority='Sentence-first replacement of legacy research extraction')
    def prompt(self,packet,feedback=''):
        system=contract.SYSTEM+'\n'+RULES
        if packet.get('focus')=='nonrequirements':system+='\nExtract ONLY explicitly unnecessary conditions; paths must be empty.'
        if feedback:system+='\n'+feedback
        return self.tok.apply_chat_template([dict(role='system',content=system),dict(role='user',content=json.dumps(packet['wire'],ensure_ascii=False))],tokenize=False,add_generation_prompt=True,enable_thinking=False)
    def execute_batch(self,packets,limit=1024,feedback=''):
        results=super().execute_batch(packets,limit,feedback)
        for i,(packet,result) in enumerate(zip(packets,results)):
            if result.get('error') not in ('possible_fact_cap','output_token_limit','transport_input_too_long') or len(packet['units'])<2:
                continue
            middle=len(packet['units'])//2
            children=[]
            for index,part in enumerate((packet['units'][:middle],packet['units'][middle:])):
                wire=dict(packet['wire'],units=[[u['id'],u['text']] for u in part])
                children.append(dict(packet,units=part,wire=wire,packet_id=packet['packet_id']+'@fragment:'+str(index)))
            resolved=self.execute_batch(children,limit=limit,feedback=feedback)
            complete=all(r.get('source_reading_complete') for r in resolved)
            facts=list({digest(f):f for r in resolved for f in r.get('facts',[])}.values())
            results[i]=dict(packet_id=packet['packet_id'],facts=facts,
                source_state=0 if facts else 1,source_reading_complete=complete,
                error=None if complete else 'sentence_fragment_incomplete',
                path_proposals=[],fragment_path_proposals=[r.get('path_proposals',[]) for r in resolved],
                fragment_results=resolved,fragmentation='existing sentence/clause units only; no whitespace split',
                path_reconciliation_required=True)
        return results
    def aggregate(self):
        records=super().aggregate()
        for r in records.values():
            if not r['packet_results']:
                r.update(all_packets_read=False,extraction_state='administrative_only_or_no_content_review_needed')
            r['segmentation']='sentence_first_punctuation_clause_fallback'
            r['clustering_allowed']=False
        return records
    def run(self):
        old=read_json(self.output/'run_status.json')
        if old.get('pid')!=os.getpid() and gpu_lease.alive(old.get('pid')):raise RuntimeError('Output already has live worker')
        self.verify_inputs()
        try:
            if not self.acquire():return
            self.load()
            if not self.pilot():return
            self.extract(self.packets,'reading_all_cves')
            records=self.aggregate()
            write_jsonl(self.output/'semantic_extractions.jsonl',[records[k] for k in sorted(records)])
            complete=sum(r['all_packets_read'] for r in records.values())
            self.save('stopped' if self.stopped() else 'complete' if complete==12418 else 'complete_with_pending',
                completed_cves=complete,retained_cves=len(records),clustering_allowed=False)
        except Exception as exc:
            self.save('failed',error=type(exc).__name__+': '+str(exc));raise
        finally:
            self.model=None
            if self.db:self.db.close()
            gc.collect()
            if self.owned and read_json(gpu_lease.FILE).get('pid')==os.getpid():
                atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,phase=self.status['phase'],output=str(self.output)))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',default=str(ROOT/'results/ics_sentence_conditions_qwen3_8b_v1'))
    p.add_argument('--prepare-only',action='store_true');p.add_argument('--prepare',action='store_true')
    p.add_argument('--batch-size',type=int,default=1)
    p.add_argument('--model-path',default=str(ROOT.parent/'ICS-VEXForge/models/Qwen3-8B'))
    a=p.parse_args()
    if a.prepare or a.prepare_only:prepare(a.output)
    if not a.prepare_only:Worker(a.output,a.model_path,batch_size=a.batch_size).run()
