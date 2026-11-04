"""Bounded LLVM def-use witnesses, never a proof of non-controllability.

Exact-address stores/loads and direct calls are modeled. General pointer aliasing,
heap effects, concurrency and feasible-path constraints are not solved here.
"""
from collections import defaultdict,deque
import hashlib


def analyze_ir(ir,sources,targets,*,max_nodes=100000):
    from llvmlite import binding as llvm
    adjacency=defaultdict(set);labels={};blockers=set();source_nodes=[];sink_nodes=[];count=0
    def edge(a,b):
        if a and b:adjacency[a].add(b)
    with llvm.create_context() as context:
        with llvm.parse_assembly(ir,context=context) as module:
            module.verify();functions={f.name:f for f in module.functions if not f.is_declaration}
            lookup={};instructions=[]
            for name,f in functions.items():
                for i,arg in enumerate(f.arguments):
                    key=name+':arg:'+str(i);lookup[arg]=key
                    labels[key]={'function':name,'kind':'parameter','parameter_index':i,'name':arg.name}
                    if name in targets:sink_nodes.append(key)
                for bi,block in enumerate(f.blocks):
                    for ii,ins in enumerate(block.instructions):
                        count+=1
                        if count>max_nodes:
                            return {'status':'unknown','negative_proof_enabled':False,'blockers':['def_use_node_limit'],
                                    'source_to_target_paths':[],'ir_sha256':hashlib.sha256(ir.encode()).hexdigest()}
                        key=name+':block:'+str(bi)+':instruction:'+str(ii);lookup[ins]=key
                        labels[key]={'function':name,'kind':'instruction','opcode':ins.opcode,'ir':str(ins).strip()[:1000]}
                        instructions.append((name,ins,key))
            for declared in sources:
                name=declared.get('function');position=declared.get('parameter')
                key=str(name)+':arg:'+str(position)
                if not isinstance(position,int) or position<0 or key not in labels:
                    blockers.add('declared_source_parameter_not_found');continue
                source_nodes.append(key)
            for name,ins,key in instructions:
                operands=list(ins.operands);values=[o for o in operands if o.value_kind!=llvm.ValueKind.basic_block]
                # Conservative value dependency; it is not an executable witness.
                for operand in values:edge(lookup.get(operand),key)
                if ins.opcode=='store' and len(values)>=2:
                    pointer=lookup.get(values[1])
                    if pointer:edge(lookup.get(values[0]),'memory:'+pointer)
                    else:blockers.add('unresolved_store_address')
                if ins.opcode=='load' and values:
                    pointer=lookup.get(values[0])
                    if pointer:edge('memory:'+pointer,key)
                    else:blockers.add('unresolved_load_address')
                if ins.opcode=='ret' and values:edge(lookup.get(values[0]),name+':return')
                if ins.opcode in {'call','invoke','callbr'}:
                    callee=values[-1] if values else None
                    if callee is None or callee.value_kind!=llvm.ValueKind.function:
                        blockers.add('indirect_call_effects_unknown');continue
                    symbol=callee.name
                    if symbol in functions:
                        for i,operand in enumerate(values[:-1]):
                            destination=symbol+':arg:'+str(i)
                            if destination in labels:edge(lookup.get(operand),destination)
                        edge(symbol+':return',key)
                    elif not symbol.startswith('llvm.'):
                        blockers.add('external_call_effects_unknown:'+symbol)
                if ins.opcode in {'getelementptr','ptrtoint','inttoptr'}:blockers.add('general_pointer_aliasing_not_solved')
            for target in targets:
                if target not in functions:blockers.add('target_definition_not_found:'+target)
            paths=[]
            for start in source_nodes:
                queue=deque([start]);previous={start:None}
                while queue:
                    at=queue.popleft()
                    if at in sink_nodes:
                        path=[];cursor=at
                        while cursor is not None:path.append(cursor);cursor=previous[cursor]
                        path.reverse()
                        paths.append({'source':start,'target_parameter':at,'node_path':path,
                                      'steps':[{'id':n,**labels.get(n,{'kind':'memory_or_return_summary'})} for n in path]})
                    for nxt in sorted(adjacency[at]):
                        if nxt not in previous:previous[nxt]=at;queue.append(nxt)
            if not source_nodes:blockers.add('untrusted_input_sources_not_declared')
            blockers.update(['alias_and_heap_effects_incomplete','path_feasibility_not_proven',
                             'input_provenance_and_deployed_build_not_independently_verified'])
    return {'schema':'ics-vex-def-use/1','status':'possible_dependency_found' if paths else 'unknown',
            'observation':'dependency_path' if paths else 'no_dependency_path_observed_in_this_model',
            'source_declarations':sources,'targets':targets,'source_to_target_paths':paths,
            'ir_sha256':hashlib.sha256(ir.encode()).hexdigest(),'nodes':count,
            'blockers':sorted(blockers),'negative_proof_enabled':False,'standard_vex_authority':False,
            'claim_boundary':'Context-insensitive LLVM value dependencies under declared parameter sources; not attacker-control or feasibility proof.'}
