"""Resumeable full-population model extraction; strict pilot gate precedes corpus run."""
import argparse,gc,json,os,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src import compact_condition_contract as contract
from src.semantic_condition_contract import source_units,digest
from src import gpu_lease
from src.training_io import atomic_json,read_json
from tools.discover_ics_clusters import sha,write_jsonl
import tools.run_full_semantic_conditions as base

# This isolated process supplies its own output contract to the existing local worker.
base.SYSTEM=contract.SYSTEM;base.schema=contract.schema;base.validate_output=contract.validate_output


def prepare(output):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    source=ROOT/'results/ics_condition_semantic_full_v2/full_inputs.jsonl'
    records=[json.loads(l) for l in source.read_text(encoding='utf-8').splitlines()]
    contract_hash=sha(ROOT/'src/compact_condition_contract.py')
    packets=[]
    for record in records:
        units=[u for s in record['sources'] for u in source_units(s,limit=600)]
        batches=[];current=[];size=0
        for u in units:
            if current and size+len(u['text'])>2800:
                batches.append(current);current=[];size=0
            current.append(u);size+=len(u['text'])
        if current:batches.append(current)
        for i,batch in enumerate(batches):
            aliased=[dict(id=str(j+1),**u) for j,u in enumerate(batch)]
            wire=dict(units=[[u['id'],u['text']] for u in aliased],identity_ambiguous=record['identity_ambiguous'])
            packets.append(dict(packet_id=record['cve']+':'+str(i),cve=record['cve'],units=aliased,
                wire=wire,packet_sha256=digest(dict(wire=wire,contract=contract_hash)),identity_ambiguous=record['identity_ambiguous']))
    target=output/'full_inputs.jsonl'
    if target.exists() and sha(target)!=sha(source):raise ValueError('Output contains a different source snapshot')
    shutil.copyfile(source,target)
    write_jsonl(output/'model_packets.jsonl',packets)
    atomic_json(output/'input_manifest.json',dict(population=len(records),packet_count=len(packets),
        inputs_sha256=sha(target),packets_sha256=sha(output/'model_packets.jsonl'),
        contract_sha256=sha(ROOT/'src/compact_condition_contract.py'),no_population_exclusions=True))


class Worker(base.Worker):
    def __init__(self,*args,pilot_only=False,**kwargs):
        super().__init__(*args,**kwargs);self.pilot_only=pilot_only
        self.status['worker_sha256']=sha(__file__)
        self.status['priority']='Respect live GPU owner; previous SBOM evaluation completed before this run'
    def verify_inputs(self):
        self.manifest=read_json(self.output/'input_manifest.json')
        for name,key in [('full_inputs.jsonl','inputs_sha256'),('model_packets.jsonl','packets_sha256')]:
            if sha(self.output/name)!=self.manifest[key]:raise ValueError('Input changed')
        if sha(ROOT/'src/compact_condition_contract.py')!=self.manifest['contract_sha256']:raise ValueError('Contract changed')
        self.records=[json.loads(l) for l in (self.output/'full_inputs.jsonl').read_text(encoding='utf-8').splitlines()]
        self.packets=[json.loads(l) for l in (self.output/'model_packets.jsonl').read_text(encoding='utf-8').splitlines()]
        if len(self.records)!=12418 or len({r['cve'] for r in self.records})!=12418:raise ValueError('Population mismatch')
        self.save(input_cves=len(self.records),total_packets=len(self.packets))
    def prompt(self,packet,feedback=''):
        system=contract.SYSTEM
        if packet.get('focus')=='nonrequirements':
            system+='\nFOCUS: extract ONLY explicitly unnecessary/optional conditions from this unit (even-if, regardless, not-required). Do not repeat positive attack-input requirements. paths must be empty.'
        if feedback:system+='\nRecheck separate victim actions, victim authentication, attacker roles, optional shell state and SSO configuration. Return all source-supported conditions separately.'
        return self.tok.apply_chat_template([dict(role='system',content=system),dict(role='user',content=json.dumps(packet['wire'],ensure_ascii=False))],tokenize=False,add_generation_prompt=True,enable_thinking=False)
    def load(self):
        import torch,sqlite3,importlib.metadata
        from transformers import AutoModelForCausalLM,AutoTokenizer,BitsAndBytesConfig
        self.save('loading_semantic_model')
        torch.set_num_threads(2)
        self.tok=AutoTokenizer.from_pretrained(self.model_path,local_files_only=True)
        self.tok.padding_side='left'
        if self.tok.pad_token_id is None:self.tok.pad_token=self.tok.eos_token
        config=read_json(Path(self.model_path)/'config.json')
        options={} if config.get('quantization_config') else dict(quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16))
        self.model=AutoModelForCausalLM.from_pretrained(self.model_path,local_files_only=True,
            disable_mmap=os.name=='nt',device_map={'':0},dtype=torch.bfloat16,attn_implementation='sdpa',**options).eval()
        self.save(model=str(Path(self.model_path).resolve()),model_architecture=self.model.config.model_type,
            attention='native_sdpa',model_config_sha256=sha(Path(self.model_path)/'config.json'),
            model_index_sha256=sha(Path(self.model_path)/'model.safetensors.index.json'),
            runtime_versions={p:importlib.metadata.version(p) for p in ('torch','transformers','bitsandbytes')},
            contract_sha256=self.manifest['contract_sha256'])
        self.db=sqlite3.connect(self.output/'extraction_cache.sqlite3')
        self.db.execute('CREATE TABLE IF NOT EXISTS responses (packet_id TEXT PRIMARY KEY, packet_sha256 TEXT, payload TEXT)')
        self.db.commit()
    def execute_batch(self,packets,limit=1024,feedback=''):
        results=super().execute_batch(packets,limit,feedback)
        for result in results:
            if result.get('error')=='possible_fact_cap' and len(result.get('prediction',{}).get('facts',[]))<24:
                result.update(error=None,source_reading_complete=True)
        focused=[];owners=[]
        for i,packet in enumerate(packets):
            if packet.get('focus'):continue
            for u in packet['units']:
                if any(t in u['text'].lower() for t in ('even if','regardless','not required','not necessary')):
                    wire=dict(units=[[u['id'],u['text']]],identity_ambiguous=packet['identity_ambiguous'])
                    focused.append(dict(packet,units=[u],wire=wire,focus='nonrequirements'))
                    owners.append(i)
        if focused:
            reviewed=self.execute_batch(focused,limit=limit,feedback='')
            for i,r in zip(owners,reviewed):
                if not r.get('error'):
                    results[i].setdefault('facts',[]).extend(r['facts'])
                    results[i]['nonrequirement_audit']=True
                else:
                    results[i].update(error='nonrequirement_audit_failed',source_reading_complete=False)
        return results
    def aggregate(self):
        records=super().aggregate()
        for r in records.values():r['packet_path_proposals']=[]
        for packet in self.packets:
            result=self.cached(packet) or {}
            records[packet['cve']]['packet_path_proposals'].append(dict(packet_id=packet['packet_id'],
                proposals=result.get('path_proposals',[]),source_reading_complete=result.get('source_reading_complete',False)))
        return records
    def pilot(self):
        packets=[p for p in self.packets if p['cve'] in base.PILOT_IDS]
        self.extract(packets,'semantic_pilot')
        records=self.aggregate()
        def findings(records):
            report=base.pilot_findings(records)
            # The sources for this CVE disagree. Test the read-only statement
            # locally; do not erase a different source's explicit admin claim.
            readonly=[f for f in records['CVE-2021-1220']['facts'] if 'read-only' in f['source_quote'].lower() and f['kind']=='attacker_auth_or_privilege']
            report['checks']['read_only_attacker_not_promoted_to_admin']=bool(readonly) and not any('admin' in f['condition'].lower() or 'root' in f['condition'].lower() for f in readonly)
            report['passed']=all(report['checks'].values())
            report['checks']['all_pilot_packets_valid']=all(records[c]['all_packets_read'] for c in base.PILOT_IDS)
            report['passed']=all(report['checks'].values())
            report['source_conflict_policy']='Keep distinct source claims; the read-only test applies only to its supporting source.'
            return report
        report=findings(records)
        if not report['passed']:
            # A general unit-by-unit audit, not a hardcoded answer for any CVE.
            audits=[];parents={}
            for packet in packets:
                for u in packet['units']:
                    wire=dict(units=[[u['id'],u['text']]],identity_ambiguous=packet['identity_ambiguous'])
                    audit=dict(packet,packet_id=packet['packet_id']+'@audit:'+u['id'],units=[u],wire=wire,
                               packet_sha256=digest(dict(wire=wire,contract=self.manifest['contract_sha256'])))
                    audits.append(audit);parents[audit['packet_id']]=packet
            self.extract(audits,'semantic_pilot_unit_audit',feedback='Check every clause, especially optional and explicitly unnecessary features.')
            for audit in audits:
                result=self.cached(audit)
                parent=parents[audit['packet_id']]
                original=self.cached(parent)
                if result and not result.get('error') and original:
                    original['facts'].extend(result['facts'])
                    original.setdefault('unit_audits',[]).append(audit['packet_id'])
                    self.store(parent,original)
            records=self.aggregate();report=findings(records)
        report['records']={cve:records[cve] for cve in base.PILOT_IDS}
        atomic_json(self.output/'semantic_pilot.json',report)
        if not report['passed']:
            self.save('pilot_needs_review',reason='Source-local semantic checks failed; full extraction not started')
        return report['passed']
    def run(self):
        old=read_json(self.output/'run_status.json')
        if old.get('pid')!=os.getpid() and gpu_lease.alive(old.get('pid')) and old.get('phase') not in ('complete','failed','pilot_needs_review','pilot_passed'):
            raise RuntimeError('A worker for this output is already running')
        self.verify_inputs()
        try:
            if not self.acquire():return
            self.load()
            if not self.pilot():return
            if self.pilot_only:
                self.save('pilot_passed');return
            self.extract(self.packets,'reading_all_cves')
            records=self.aggregate()
            write_jsonl(self.output/'semantic_extractions.jsonl',[records[k] for k in sorted(records)])
            complete=sum(r['all_packets_read'] for r in records.values())
            self.save('stopped' if self.stopped() else 'complete' if complete==12418 else 'complete_with_pending',
                      completed_cves=complete,retained_cves=len(records))
            if not self.stopped():
                from tools.finish_context_research import run as finish
                finish(self.output)
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
    p.add_argument('--output',default=str(ROOT/'results/ics_context_research_v3'))
    p.add_argument('--model-path',default=str(ROOT.parent/'ICS-VEXForge/models/Qwen3-8B'))
    p.add_argument('--batch-size',type=int,default=1)
    p.add_argument('--pilot-only',action='store_true')
    p.add_argument('--prepare',action='store_true')
    args=p.parse_args()
    if args.prepare:prepare(args.output)
    Worker(args.output,args.model_path,batch_size=args.batch_size,pilot_only=args.pilot_only).run()
