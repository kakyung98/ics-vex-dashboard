"""Queued, checkpointed full-population semantic reading with a local base LLM.

Wait for the existing GPU owner. Never stop another job, never use the previous
regex condition extractor, never drop a CVE because inference fails.
"""
import argparse
from datetime import datetime,timezone
import gc
import html
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.semantic_condition_contract import SYSTEM,digest,schema,validate_output
from src.training_io import atomic_json,read_json
from src import gpu_lease
from tools.discover_ics_clusters import sha,write_jsonl

PILOT_IDS=['CVE-2018-13800','CVE-2018-11457','CVE-2024-27980',
           'CVE-2018-14800','CVE-2024-53648','CVE-2020-7591','CVE-2021-1220']


def pilot_findings(records):
    """Independent small contract checks, not full-corpus accuracy estimates."""
    def facts(cve):return records.get(cve,{}).get('facts',[])
    def has(cve,kind,necessity=None):
        return any(f['kind']==kind and (necessity is None or f['necessity']==necessity) for f in facts(cve))
    checks={
      'victim_auth_is_retained':has('CVE-2018-13800','victim_auth_or_privilege','explicitly_required'),
      'victim_user_action_is_retained':has('CVE-2018-13800','user_action','explicitly_required'),
      'port_configuration_is_retained':has('CVE-2018-11457','feature_or_configuration'),
      'no_authentication_not_invented_from_no_privileges':not any(
          f['kind']=='attacker_auth_or_privilege' and f['necessity']=='not_required'
          and 'authenticat' in f['condition'].lower() for f in facts('CVE-2018-11457')),
      'shell_enabled_not_necessary':has('CVE-2024-27980','feature_or_configuration','explicitly_not_a_necessary_condition'),
      'file_input_is_retained':has('CVE-2018-14800','input_or_ingress'),
      'physical_access_is_retained':has('CVE-2024-53648','access_position'),
      'sso_configuration_is_retained':has('CVE-2020-7591','feature_or_configuration'),
      'authenticated_attacker_is_retained':has('CVE-2021-1220','attacker_auth_or_privilege'),
      'read_only_attacker_not_promoted_to_admin':not any(f['kind']=='attacker_auth_or_privilege'
          and any(word in f['condition'].lower() for word in ['admin','root']) for f in facts('CVE-2021-1220'))}
    return {'passed':all(checks.values()),'checks':checks,
            'boundary':'Prompt/contract pilot only, not independent extraction accuracy'}


class Worker:
    def __init__(self,output,model_path,batch_size=1):
        self.output=Path(output).resolve();self.output.mkdir(parents=True,exist_ok=True)
        self.model_path=str(Path(model_path).resolve());self.batch_size=batch_size
        self.status={'phase':'initializing_queue','pid':os.getpid(),'population':12418,
          'priority':'Existing CPE evaluation completes first, per user instruction',
          'worker_sha256':sha(__file__),'model_path':self.model_path,'excluded_cves':0}
        self.owned=False;self.model=None;self.tok=None;self.db=None
    def save(self,phase=None,**fields):
        if phase:self.status['phase']=phase
        self.status.update(fields,updated_at_utc=datetime.now(timezone.utc).isoformat())
        atomic_json(self.output/'run_status.json',self.status)
        labels={'waiting_for_existing_gpu_job':'기존 CPE 평가의 GPU 반환 대기',
            'initializing_queue':'전수 작업 초기화','loading_semantic_model':'의미 추출 모델 로딩',
            'semantic_pilot':'의미 구분 검사','reading_all_cves':'전체 CVE 원문 의미 추출',
            'preparing_full_population_clustering':'전수 추출 결과 군집화',
            'pilot_needs_review':'의미 구분 검사 실패: 검토 필요',
            'complete':'전수 실행 완료','complete_with_pending':'전수 실행 완료: 미해결 모델 결과 포함',
            'failed':'작업 오류: 상태 파일 확인','stopped':'중지','stopped_while_waiting':'대기 중 중지'}
        phase=self.status['phase']
        safe=html.escape
        content='<html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="20"><title>CVE 전수 분석 진행 상태</title><style>body{font:17px/1.7 system-ui;max-width:950px;margin:40px auto;padding:20px}code,p{overflow-wrap:anywhere}</style><h1>12,418개 CVE 전수 의미 추출·군집화</h1>'
        content+='<h2>'+safe(labels.get(phase,phase))+'</h2><p>모집단 12,418개 유지 · 키워드 미검출·한 축·희소 조합에 의한 제외 없음</p>'
        content+='<p>처리 모델 입력: '+str(self.status.get('completed_packets',0))+' / '+str(self.status.get('total_packets','준비 중'))+'</p>'
        if phase=='waiting_for_existing_gpu_job':
            owner=self.status.get('waiting_on',{})
            other=read_json(Path(owner.get('output',''))/'status.json') if owner.get('output') else {}
            content+='<p>사용자 지정 우선순위에 따라 기존 평가를 중단하지 않고 기다립니다.</p>'
            if other.get('total_inputs'):
                content+='<p>선행 평가: '+str(other.get('completed_inputs',0))+' / '+str(other['total_inputs'])+'</p>'
            content+='<p>새 의미 추출과 새 군집 계산은 아직 시작하지 않았습니다.</p>'
        if self.status.get('error'):content+='<p>'+safe(self.status['error'])+'</p>'
        content+='<p>업데이트: '+safe(self.status['updated_at_utc'])+'</p><p><a href="run_status.json">상세 실행 상태</a> · <a href="input_manifest.json">전체 입력 목록의 검증 정보</a></p>'
        if (self.output/'semantic_pilot.json').exists():content+='<p><a href="semantic_pilot.json">의미 구분 검사 결과</a></p>'
        if (self.output/'index.html').exists():content+='<p><a href="index.html">군집 결과 열기</a></p>'
        content+='</html>'
        try:(self.output/'progress.html').write_text(content,encoding='utf-8')
        except OSError:pass  # A viewer holding this optional page must not stop the research worker.
    def stopped(self):return (self.output/'STOP').exists()
    def verify_inputs(self):
        manifest=read_json(self.output/'input_manifest.json')
        for name,key in [('full_inputs.jsonl','inputs_sha256'),('model_packets.jsonl','packets_sha256')]:
            if sha(self.output/name)!=manifest[key]:raise ValueError('Prepared inputs changed: '+name)
        if sha(ROOT/'src/semantic_condition_contract.py')!=manifest['contract_sha256']:
            raise ValueError('Extraction contract changed after preparation')
        if manifest['population']!=12418 or not manifest['no_population_exclusions']:
            raise ValueError('Full population contract violated')
        self.manifest=manifest
        self.records=[json.loads(l) for l in (self.output/'full_inputs.jsonl').read_text(encoding='utf-8').splitlines()]
        self.packets=[json.loads(l) for l in (self.output/'model_packets.jsonl').read_text(encoding='utf-8').splitlines()]
        self.save(input_cves=len(self.records),total_packets=len(self.packets),
            inputs_sha256=manifest['inputs_sha256'],packets_sha256=manifest['packets_sha256'])
    def acquire(self):
        while not self.stopped():
            lease=read_json(gpu_lease.FILE)
            live=lease.get('active') and any(gpu_lease.alive(lease.get(k)) for k in ['pid','child_pid'])
            if live:
                self.save('waiting_for_existing_gpu_job',waiting_on=lease)
                time.sleep(20)
                continue
            atomic_json(gpu_lease.FILE,{'pid':os.getpid(),'active':True,
                'purpose':'12,418-CVE full-source semantic condition extraction',
                'output':str(self.output),'previous_job_preserved':True})
            if read_json(gpu_lease.FILE).get('pid')!=os.getpid():continue
            self.owned=True
            gpu_lease.assert_inference_available()
            return True
        self.save('stopped_while_waiting');return False
    def load(self):
        self.save('loading_semantic_model')
        # Only after owning admission: release an idle website cache, never its server.
        try:
            request=urllib.request.Request('http://127.0.0.1:8100/api/cve-match/models/unload',data=b'')
            with urllib.request.urlopen(request,timeout=120) as response:
                self.save(idle_web_model_release=json.load(response))
        except Exception as exc:self.save(idle_web_model_release={'error':str(exc)})
        import torch
        import importlib.metadata
        os.environ.setdefault('HF_ENABLE_PARALLEL_LOADING','false')
        from transformers import AutoModelForCausalLM,AutoTokenizer,BitsAndBytesConfig
        torch.set_num_threads(2)
        self.tok=AutoTokenizer.from_pretrained(self.model_path,local_files_only=True)
        self.tok.padding_side='left'
        if self.tok.pad_token_id is None:self.tok.pad_token=self.tok.eos_token
        self.model=AutoModelForCausalLM.from_pretrained(self.model_path,local_files_only=True,
            disable_mmap=os.name=='nt',device_map={'':0},dtype=torch.bfloat16,
            attn_implementation='sdpa',quantization_config=BitsAndBytesConfig(load_in_4bit=True,
                bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,bnb_4bit_compute_dtype=torch.bfloat16)).eval()
        from src.efficient_attention import install
        install(self.model)
        self.save(model='Qwen3-8B local base; no previous taxonomy adapter',
                  model_config_sha256=sha(Path(self.model_path)/'config.json'),
                  model_index_sha256=sha(Path(self.model_path)/'model.safetensors.index.json'),
                  runtime_versions={p:importlib.metadata.version(p) for p in ['torch','transformers','bitsandbytes']},
                  contract_sha256=self.manifest['contract_sha256'])
        self.db=sqlite3.connect(self.output/'extraction_cache.sqlite3')
        self.db.execute('CREATE TABLE IF NOT EXISTS responses (packet_id TEXT PRIMARY KEY, packet_sha256 TEXT, payload TEXT)')
        self.db.commit()
    def prompt(self,packet,feedback=''):
        system=SYSTEM+('\nPrevious pilot errors to avoid: '+feedback if feedback else '')
        return self.tok.apply_chat_template([{'role':'system','content':system},
            {'role':'user','content':json.dumps(packet['wire'],ensure_ascii=False,separators=(',',':'))}],
            tokenize=False,add_generation_prompt=True,enable_thinking=False)
    def cached(self,packet):
        row=self.db.execute('SELECT packet_sha256,payload FROM responses WHERE packet_id=?',(packet['packet_id'],)).fetchone()
        if row and row[0]==packet['packet_sha256']:return json.loads(row[1])
        return None
    def store(self,packet,payload):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO responses VALUES (?,?,?)',
                (packet['packet_id'],packet['packet_sha256'],json.dumps(payload,ensure_ascii=False)))
    def generate(self,packets,limit=1024,feedback=''):
        import torch
        from src.llm_output_schema import prefix_for_schema
        prompts=[self.prompt(p,feedback) for p in packets]
        lengths=[len(self.tok(p)['input_ids']) for p in prompts]
        if max(lengths)>6144:
            # Never truncate a source and report it as fully read.
            return [dict(error='transport_input_too_long',facts=[],source_state=None,
                         input_tokens=n,source_reading_complete=False) for n in lengths]
        grammars=[prefix_for_schema(self,schema(p)) for p in packets]
        def allowed(batch_id,tokens):return grammars[batch_id](0,tokens)
        encoded=self.tok(prompts,return_tensors='pt',padding=True).to('cuda')
        width=int(encoded['input_ids'].shape[1]);start=time.monotonic()
        try:
            with torch.inference_mode():
                generated=self.model.generate(**encoded,max_new_tokens=limit,do_sample=False,
                    use_cache=True,pad_token_id=self.tok.pad_token_id,logits_to_keep=1,
                    prefix_allowed_tokens_fn=allowed)
            eos=self.model.generation_config.eos_token_id
            eos=set(eos if isinstance(eos,list) else [eos])
            results=[]
            for j,packet in enumerate(packets):
                ids=generated[j,width:].tolist()
                stop=next((i+1 for i,t in enumerate(ids) if t in eos),len(ids))
                raw=self.tok.decode(ids[:stop],skip_special_tokens=True)
                try:
                    pred=json.loads(raw)
                    parsed=validate_output(packet,pred)
                    error=('output_token_limit' if stop>=limit else 'possible_fact_cap' if len(pred['facts'])>=10 else None)
                    result=dict(**parsed,raw=raw,prediction=pred,error=error,source_reading_complete=error is None)
                except Exception as exc:
                    result=dict(raw=raw,error=type(exc).__name__+': '+str(exc),facts=[],source_state=None,source_reading_complete=False)
                result.update(generated_tokens=stop,input_tokens=lengths[j],batch_size=len(packets),
                    batch_seconds=time.monotonic()-start,packet_id=packet['packet_id'])
                results.append(result)
            del generated
            return results
        finally:del encoded
    def execute_batch(self,packets,limit=1024,feedback=''):
        import torch
        try:return self.generate(packets,limit,feedback)
        except torch.cuda.OutOfMemoryError:
            gc.collect();torch.cuda.empty_cache()
            if len(packets)==1:
                return [dict(error='cuda_memory_exhausted',facts=[],source_state=None,source_reading_complete=False)]
            middle=len(packets)//2
            return self.execute_batch(packets[:middle],limit,feedback)+self.execute_batch(packets[middle:],limit,feedback)
    def extract(self,packets,phase,feedback='',force=False):
        remaining=[p for p in packets if force or self.cached(p) is None or self.cached(p).get('error')]
        # Length grouping reduces padding; every packet remains in the queue.
        remaining.sort(key=lambda p:sum(len(u['text']) for u in p['units']))
        position=0
        while position<len(remaining) and not self.stopped():
            current=[]
            while position<len(remaining) and len(current)<self.batch_size:
                p=remaining[position]
                estimate=len(self.tok(self.prompt(p,feedback))['input_ids'])
                if current and estimate*(len(current)+1)>16384:break
                current.append(p);position+=1
            self.save(phase,current_packets=[p['packet_id'] for p in current])
            results=self.execute_batch(current,feedback=feedback)
            for packet,result in zip(current,results):
                if result.get('error'):
                    result=self.execute_batch([packet],limit=1536,feedback=feedback+' Copy an EXACT supporting quote for every fact and use readable schema field names.')[0]
                self.store(packet,result)
            completed=self.db.execute('SELECT count(*) FROM responses').fetchone()[0]
            self.save(phase,completed_packets=completed,current_packets=[],
                extraction_errors=self.db.execute("SELECT count(*) FROM responses WHERE json_extract(payload,'$.error') IS NOT NULL").fetchone()[0])
    def aggregate(self):
        grouped={r['cve']:dict(cve=r['cve'],facts=[],packet_results=[],identity_ambiguous=r['identity_ambiguous'],
            excluded=False,vex_status=None) for r in self.records}
        for packet in self.packets:
            result=self.cached(packet)
            target=grouped[packet['cve']]
            if result is None:
                target['packet_results'].append(dict(packet_id=packet['packet_id'],error='not_yet_read'))
                continue
            target['facts'].extend(result.get('facts',[]))
            target['packet_results'].append({k:result.get(k) for k in ['packet_id','error','source_state','source_reading_complete','generated_tokens']})
        for row in grouped.values():
            unique={digest(f):f for f in row['facts']}
            row['facts']=list(unique.values())
            row['all_packets_read']=all(p.get('source_reading_complete') for p in row['packet_results'])
            row['source_reading_states']=sorted({p['source_state'] for p in row['packet_results'] if p.get('source_state') is not None})
            row['extraction_state']=('identity_review_needed' if row['identity_ambiguous'] else
                'model_reading_incomplete' if not row['all_packets_read'] else
                'facts_proposed' if row['facts'] else
                'withdrawn_or_rejected_text_read' if row['source_reading_states']==[2] else 'no_explicit_facts_proposed_by_model')
        return grouped
    def pilot(self):
        packets=[p for p in self.packets if p['cve'] in PILOT_IDS]
        for attempt in range(2):
            feedback='' if attempt==0 else 'Retain victim login separately from attacker authentication; preserve port configuration; even-if-disabled is not a required disabled state.'
            self.extract(packets,'semantic_pilot',feedback,force=attempt>0)
            records=self.aggregate()
            report=pilot_findings(records)
            report.update(attempt=attempt+1,records={cve:records[cve] for cve in PILOT_IDS})
            atomic_json(self.output/'semantic_pilot.json',report)
            if report['passed']:return True
        self.save('pilot_needs_review',pilot_report='semantic_pilot.json',
            reason='Model failed semantic distinctions; full corpus was not silently processed with a failed extractor')
        return False
    def run(self):
        old=read_json(self.output/'run_status.json')
        if old.get('pid')!=os.getpid() and old.get('phase') not in {'complete','complete_with_pending','failed','stopped','pilot_needs_review'} and gpu_lease.alive(old.get('pid')):
            raise RuntimeError('Another worker for this output is alive')
        self.verify_inputs()
        try:
            if not self.acquire():return
            self.load()
            if not self.pilot():return
            self.extract(self.packets,'reading_all_cves')
            if self.stopped():self.save('stopped');return
            records=self.aggregate()
            assert len(records)==12418
            write_jsonl(self.output/'semantic_extractions.jsonl',[records[k] for k in sorted(records)])
            self.save('preparing_full_population_clustering',completed_cves=len(records),
                model_read_cves=sum(r['all_packets_read'] for r in records.values()))
            self.model=None;gc.collect()
            import torch
            torch.cuda.empty_cache()
            from tools.cluster_full_semantic_conditions import run as cluster
            result=cluster(self.output)
            self.save('complete_with_pending' if result['incomplete_model_readings'] else 'complete',result=result)
        except Exception as exc:
            self.save('failed',error=type(exc).__name__+': '+str(exc))
            raise
        finally:
            self.model=None
            if self.db:self.db.close()
            gc.collect()
            if self.owned and read_json(gpu_lease.FILE).get('pid')==os.getpid():
                atomic_json(gpu_lease.FILE,dict(pid=os.getpid(),active=False,phase=self.status['phase'],output=str(self.output)))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',default=str(ROOT/'results/ics_condition_semantic_full_v2'))
    p.add_argument('--model-path',default=str(ROOT.parent/'ICS-VEXForge/models/Qwen3-8B'))
    p.add_argument('--batch-size',type=int,default=1)
    a=p.parse_args()
    Worker(a.output,a.model_path,a.batch_size).run()
