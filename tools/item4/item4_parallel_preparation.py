"""Parallelize identical source grammar preparation, preserving inference code."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from pathlib import Path
import argparse
import hashlib
import json
import sys
import threading
import time


def make_info(tokenizer,vocab_size,eos):
    import xgrammar as xgr
    return xgr.TokenizerInfo.from_huggingface(tokenizer,vocab_size=vocab_size,stop_token_ids=eos)


def compiler(info):
    import xgrammar as xgr
    return xgr.GrammarCompiler(info,max_threads=5,cache_enabled=False)


def probe(old):
    from transformers import AutoTokenizer
    from src.item4.workflow import source_analysis_jobs as Q; from src.item4.analysis import product_advisory_evidence as C; from src.item4.analysis import exploitation_prerequisites as V
    from src.common.runtime.json_output_constraints import generation_schema
    base=old.parent/'base_model';tok=AutoTokenizer.from_pretrained(old/'models/precision_roles_qwen25_14b_v1',local_files_only=True)
    config=json.loads((base/'config.json').read_text());generation=json.loads((base/'generation_config.json').read_text())
    info=make_info(tok,config['vocab_size'],generation['eos_token_id']);schemas=[]
    for i,line in enumerate((old/'benchmark/item4_evaluation/full_population_inputs.jsonl').open()):
        if i not in {0,100,1000}:
            if i>1000:break
            continue
        item=json.loads(line);components,_=Q.inventory(item['bom']);packet,_=C.packet(item['cve'],components)
        if not packet['sources']:packet=Q.description_packet(item['cve'])
        if packet.get('sources'):schemas.append(generation_schema(V.extraction_packet(packet)['schema']))
    serial=compiler(info);begin=time.monotonic()
    expected=[hashlib.sha256(serial.compile_json_schema(s,strict_mode=False).serialize_json().encode()).hexdigest() for s in schemas]
    serial_seconds=time.monotonic()-begin;local=threading.local()
    def prepare(s):
        if not hasattr(local,'compiler'):local.compiler=compiler(info)
        return hashlib.sha256(local.compiler.compile_json_schema(s,strict_mode=False).serialize_json().encode()).hexdigest()
    begin=time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as pool:actual=list(pool.map(prepare,schemas))
    result=dict(passed=expected==actual,schemas=len(schemas),serialized_compiler_sha256=expected,
        serial_seconds=serial_seconds,parallel_seconds=time.monotonic()-begin,
        no_model_generation_or_gold_used=True,source_JSON_membership_unchanged=True)
    destination=old/'results/item4_full_actual_20261120/parallel_preparation_probe.json'
    destination.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    assert result['passed'],'Parallel compiler serialization differed'


def run(old):
    import tools.item4.run_item4_full_actual as R
    probe_result=json.loads((old/'results/item4_full_actual_20261120/parallel_preparation_probe.json').read_text())
    assert probe_result['passed']
    original=R.BatchedProductionModel;original_write=R.write
    code_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    def write(path,value):
        if path.parent.name=='raw' and isinstance(value,dict) and 'generation' in value:
            value['generation']['schema_preparation']='four_thread_identical_source_grammar'
            value['generation']['preparation_wrapper_sha256']=code_sha256
        return original_write(path,value)
    R.write=write
    class ParallelPreparedModel(original):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            assert self.grammar_backend=='xgrammar' and not self.rolling
            info=make_info(self.runtime.tok,self.runtime.model.config.vocab_size,self.runtime.model.generation_config.eos_token_id)
            self.preparation_pool=ThreadPoolExecutor(max_workers=4,thread_name_prefix='source-grammar')
            local=threading.local();original_prepare=original.prepare
            def compile_entry(entry):
                if not hasattr(local,'proxy'):
                    local.proxy=copy(self);local.proxy.grammar_compiler=compiler(info)
                return original_prepare(local.proxy,*entry)
            put=self.queue.put
            def enqueue(entry,*args,**kwargs):
                if entry is not None and not hasattr(entry[0],'prepared_source_future'):
                    entry[0].prepared_source_future=self.preparation_pool.submit(compile_entry,entry)
                return put(entry,*args,**kwargs)
            self.queue.put=enqueue
        def prepare(self,future,*args):
            if hasattr(future,'prepared_source_future'):return future.prepared_source_future.result()
            return super().prepare(future,*args)
        def close(self):
            self.queue.put(None);self.preparation_pool.shutdown(wait=True,cancel_futures=True)
    R.BatchedProductionModel=ParallelPreparedModel
    sys.argv=[str(old/'tools/item4/run_item4_full_actual.py'),'--engine','hf_xgrammar_compact_cached','--batch-size','64','--threads','128']
    R.main()


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['probe','run']);p.add_argument('--old-root',type=Path,required=True)
    args=p.parse_args();sys.path.insert(0,str(args.old_root));import os;os.chdir(args.old_root)
    (probe if args.action=='probe' else run)(args.old_root)


if __name__=='__main__':main()
