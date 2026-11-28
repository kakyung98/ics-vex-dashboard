"""Gold-blind token comparison and timing before enabling GPU optimizations."""
import hashlib
import json
import time


def run(runtime, compiler, root, destination, rolling=False):
    import torch
    from xgrammar.contrib.hf import LogitsProcessor
    from src.item4.workflow import source_analysis_jobs as Q; from src.item4.analysis import product_advisory_evidence as C
    from src.item4.analysis import exploitation_prerequisites as V
    from src.item4.models.review_adapter_config import inference_context
    from src.common.runtime.json_output_constraints import generation_schema
    from src.research.nf4_dense_cache import enable
    from tools.item4.item4_compact_decode import compact_sample
    packets=[]
    with (root/'benchmark/item4_evaluation/full_population_inputs.jsonl').open(encoding='utf-8') as stream:
        for i,line in enumerate(stream):
            if i not in {0,100,1000}:
                if i>1000:break
                continue
            item=json.loads(line);components,_=Q.inventory(item['bom'])
            record,_=C.packet(item['cve'],components)
            if not record['sources']:record=Q.description_packet(item['cve'])
            if not record.get('sources'):continue
            packet=V.extraction_packet(record)
            prompt=runtime.tok.apply_chat_template([dict(role='system',content=V.SYSTEM),
                dict(role='user',content=json.dumps(packet,ensure_ascii=False))],
                tokenize=False,add_generation_prompt=True,enable_thinking=False)
            if len(runtime.tok(prompt,add_special_tokens=False)['input_ids'])>6144:continue
            packets.append((packet,prompt,compiler.compile_json_schema(generation_schema(packet['schema']),strict_mode=False)))
    if len(packets)<2:raise RuntimeError('Insufficient independent prompts for optimization preflight')
    encoded=runtime.tok([p[1] for p in packets],padding=True,return_tensors='pt',add_special_tokens=False).to('cuda')
    rows={};outputs={}
    with inference_context(runtime,'exploitation-prerequisites') as adapter,torch.inference_mode():
        for mode in ('baseline','optimized'):
            if mode=='optimized':cache=enable(runtime.model)
            options=dict(logits_processor=[LogitsProcessor([p[2] for p in packets])])
            if mode=='optimized':
                if rolling:
                    from tools.item4.item4_rolling_decode import rolling_sample
                    options['custom_generate']=rolling_sample
                else:options['custom_generate']=compact_sample
            torch.cuda.synchronize();started=time.monotonic()
            outputs[mode]=runtime.model.generate(**encoded,max_new_tokens=256,do_sample=False,
                pad_token_id=runtime.tok.pad_token_id,use_cache=True,logits_to_keep=1,**options)
            torch.cuda.synchronize();rows[mode]=dict(seconds=time.monotonic()-started,
                token_ids_sha256=hashlib.sha256(outputs[mode].cpu().numpy().tobytes()).hexdigest())
    same=outputs['baseline'].shape==outputs['optimized'].shape and torch.equal(outputs['baseline'],outputs['optimized'])
    result=dict(passed=bool(same),prompts=len(packets),timings=rows,
        measured_speed_ratio=rows['baseline']['seconds']/rows['optimized']['seconds'],
        probe_token_budget=256,full_evaluation_token_budget_unchanged=4096,
        token_equality_for_these_prompts_only=bool(same),universal_bitwise_equivalence_asserted=False,
        reusable_shape_grammar=False,source_identity_token_constraints_and_validation_unchanged=True,
        gold_consulted=False,adapter=adapter,cache=cache,
        prompt_sha256=[hashlib.sha256(p[1].encode()).hexdigest() for p in packets])
    destination.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if not same:raise RuntimeError('Optimized token comparison failed; no optimized evaluation is authorized by this probe')
    return result
