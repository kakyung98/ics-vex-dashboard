"""Clang-emitted LLVM IR CFG/call graph evidence for a selected source build.

No uploaded shell/compiler command, linker, program or JIT is executed. Only a
fixed local Clang driver and an allowlist of declarative frontend flags are used.
Unresolved calls, incomplete builds and scope assumptions block negative verdicts.
"""
from collections import defaultdict, deque
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
EXT={'.c','.cc','.cpp','.cxx','.C'}
MAX_UNITS=128
MAX_IR=32*1024*1024


def compiler():
    paths=[os.environ.get('ICSVEX_CLANG',''),str(ROOT/'.tools/llvm18/bin/clang.exe'),shutil.which('clang') or '']
    return next((str(Path(p).resolve()) for p in paths if p and Path(p).is_file()),None)


def inside(path,root):
    try:Path(path).resolve().relative_to(root);return True
    except ValueError:return False


def mapped_path(value,root,config):
    """Relocate recorded checkout paths only on unique existing suffix matches."""
    value=str(value).strip('"').replace('\\','/')
    direct=Path(value)
    if direct.is_absolute() and inside(direct,root) and direct.exists():return direct.resolve()
    if not direct.is_absolute() and not re.match(r'^[A-Za-z]:',value):
        p=(root/Path(config['database']).parent/value).resolve()
        if inside(p,root) and p.exists():return p
    # Infer the old checkout root from the selected TU's unique suffix.
    original=str(config.get('source_file','')).replace('\\','/')
    selected=config['file']
    for suffix in [selected,*['/'.join(selected.split('/')[i:]) for i in range(1,len(selected.split('/')))]]:
        if original.endswith(suffix) and len(suffix.split('/'))>=2:
            old=original[:-len(suffix)]
            new=str((root/selected).resolve())[:-len(suffix)]
            if old and value.startswith(old):
                p=Path(new+value[len(old):]).resolve()
                if inside(p,root) and p.exists():return p
    old_dir=str(config.get('directory','')).replace('\\','/').rstrip('/')
    if old_dir and value.startswith(old_dir+'/'):value=value[len(old_dir)+1:]
    value=value.lstrip('./')
    candidates=[p.resolve() for p in root.rglob('*') if p.as_posix().endswith('/'+value) and inside(p,root)]
    return candidates[0] if len(candidates)==1 else None


def frontend_flags(root,config):
    args=config.get('arguments',[]);out=[];blocked=[];i=1
    while i<len(args):
        a=args[i].strip('"');i+=1
        if a in {'-c','-S','-g','-fPIC','-fpic','-fno-common','-pthread','/c'}:continue
        if a in {'-o','-MF','-MT','-MQ'}:
            i+=1;continue
        if a in {'-MMD','-MD','-MP','-O0'}:continue
        if a.startswith('-O'):
            blocked.append('optimization_configuration_not_reproduced:'+a);continue
        if a.startswith('-W') and not a.startswith(('-Wp,','-Wa,','-Wl,')):continue
        if a in {'-D','-U'}:
            if i<len(args):out.extend([a,args[i]]);i+=1
            else:blocked.append(a)
            continue
        if a.startswith(('-D','-U')) and len(a)>2:out.append(a);continue
        if a.startswith('-std=') or a in {'-fms-extensions','-fno-exceptions','-fno-rtti','-fsigned-char','-funsigned-char'}:
            out.append(a);continue
        pathflag=None;value=None
        if a in {'-I','-isystem','-iquote','-include'}:
            pathflag=a
            if i<len(args):value=args[i];i+=1
        elif a.startswith('-I') and len(a)>2:pathflag='-I';value=a[2:]
        if pathflag:
            p=mapped_path(value,root,config) if value else None
            if p:out.extend([pathflag,str(p)])
            else:blocked.append('unmapped_include:'+str(value))
            continue
        if not a.startswith(('-','/')) or a==config.get('source_file') or a.endswith(tuple(EXT)):
            # Source/object operands are never forwarded to Clang.
            if a.endswith(('.o','.obj','.a','.lib')):blocked.append('link_input_not_analysed:'+a)
            continue
        blocked.append('unsupported_compiler_option:'+a)
    return out,blocked


def _metadata(ir):
    return {m.group(1):m.group(2) for m in re.finditer(r'^!(\d+) = (.+)$',ir,re.M)}


def decode_llvm_string(value):
    # Consume escaped backslash pairs before hex escapes: \\adler32 must not
    # accidentally decode the second slash + "ad" into a soft-hyphen character.
    return re.sub(r'\\\\|\\[0-9a-fA-F]{2}',
                  lambda m:'\\' if m.group()=='\\\\' else chr(int(m.group()[1:],16)),value)


def ir_graph(ir,unit):
    from llvmlite import binding as llvm
    meta=_metadata(ir);functions={};issues=[]
    with llvm.create_context() as context:
        with llvm.parse_assembly(ir,context=context) as module:
            module.verify()
            for f in module.functions:
                if f.is_declaration:continue
                identifier=unit+'::'+f.name
                head=next((line for line in str(f).splitlines() if line.startswith('define ')),'');di=re.search(r'!dbg !(\d+)',head)
                info=meta.get(di.group(1),'') if di else ''
                name=re.search(r'name: "([^"]+)"',info)
                line=re.search(r'\bline: (\d+)',info)
                file_ref=re.search(r'\bfile: !(\d+)',info)
                file_info=meta.get(file_ref.group(1),'') if file_ref else ''
                filename=re.search(r'filename: "([^"]+)"',file_info)
                blocks=list(f.blocks);labels={b:b.name or str(i) for i,b in enumerate(blocks)}
                nodes=[];edges=[];calls=[];problems=[]
                for b in blocks:
                    label=labels[b];instructions=list(b.instructions)
                    for ins in instructions:
                        operands=list(ins.operands)
                        if ins.opcode in {'br','switch','invoke','indirectbr','callbr','catchswitch','catchret','cleanupret'}:
                            successors=[labels[o] for o in operands if o.value_kind==llvm.ValueKind.basic_block]
                            # LLVM folds simple source constants; retain all other alternatives.
                            if ins.opcode=='br' and len(operands)==3 and operands[0].value_kind==llvm.ValueKind.constant_int:
                                successors=[labels[operands[2] if operands[0].get_constant_value() else operands[1]]]
                            edges.extend([label,s] for s in successors)
                            if ins.opcode not in {'br','switch','invoke'}:problems.append('unsupported_control_transfer:'+ins.opcode)
                        if ins.opcode in {'call','invoke','callbr'}:
                            # invoke has block operands after its callee.
                            values=[o for o in operands if o.value_kind!=llvm.ValueKind.basic_block]
                            callee=values[-1] if values else None
                            d=re.search(r'!dbg !(\d+)',str(ins));location=meta.get(d.group(1),'') if d else ''
                            at=re.search(r'line: (\d+)',location)
                            direct=callee is not None and callee.value_kind==llvm.ValueKind.function
                            symbol=callee.name if direct else None
                            if not (symbol or '').startswith('llvm.'):
                                calls.append({'block':label,'symbol':symbol,'line':int(at.group(1)) if at else None,'indirect':not direct})
                            if any(o.value_kind==llvm.ValueKind.function for o in values[:-1]):problems.append('function_address_escape')
                        elif any(o.value_kind==llvm.ValueKind.function for o in operands):problems.append('function_address_escape')
                    nodes.append({'id':label,'instruction_count':len(instructions)})
                live=set();pending=[labels[blocks[0]]] if blocks else []
                adjacency=defaultdict(list)
                for a,b in edges:adjacency[a].append(b)
                while pending:
                    b=pending.pop()
                    if b in live:continue
                    live.add(b);pending.extend(adjacency[b])
                functions[identifier]={'id':identifier,'symbol':f.name,'name':name.group(1) if name else f.name,
                    'file':filename.group(1) if filename else None,'line':int(line.group(1)) if line else None,
                    'translation_unit':unit,'internal':f.linkage in {llvm.Linkage.internal,llvm.Linkage.private},
                    'blocks':nodes,'edges':edges,'reachable_blocks':sorted(live),
                    'calls':[c for c in calls if c['block'] in live],'blockers':sorted(set(problems))}
            for g in module.global_variables:
                if re.search(r'@(?:"[^"]+"|[\w.$]+)',str(g).split('=',1)[-1]):
                    issues.append({'reason':'global_address_or_initializer','symbol':g.name})
            if re.search(r'^@.*\balias\b',ir,re.M):issues.append({'reason':'global_alias'})
    return functions,issues


def build(root,build_info,*,entries=None,scope='partial',complete=False,timeout=120):
    root=Path(root).resolve();start=time.monotonic();exe=compiler()
    graph={'engine':'clang-llvm-ir/1','scope':scope,'functions':{},'paths':{},'entries':[],
           'execution_status':'blocked',
           'call_edges':[],'blockers':[],'translation_units':[],'negative_decisions_enabled':False,
           'assumptions':{'complete_source_and_entry_set_declared':bool(complete)},
           'program_executed':False,'uploaded_commands_executed':False,'build_verified':False}
    if not exe:graph['blockers'].append({'reason':'clang_not_installed'});return graph
    try:
        graph['tool']={'path':exe,'version':subprocess.run([exe,'--version'],capture_output=True,text=True,timeout=10).stdout.splitlines()[0],
                       'resource_directory':subprocess.run([exe,'-print-resource-dir'],capture_output=True,text=True,timeout=10).stdout.strip()}
    except Exception as e:graph['blockers'].append({'reason':'compiler_unavailable','detail':str(e)[:200]});return graph
    configs=build_info.get('configurations',[])
    if not configs:
        graph['blockers'].append({'reason':'compilation_database_missing'})
        configs=[{'file':p.relative_to(root).as_posix(),'database':'compile_commands.json','arguments':[]} for p in root.rglob('*') if p.is_file() and p.suffix in EXT]
    for problem in build_info.get('unresolved_entries',[]):graph['blockers'].append({'reason':'unresolved_compilation_entry','detail':problem})
    if len(configs)>MAX_UNITS:graph['blockers'].append({'reason':'translation_unit_limit','total':len(configs)})
    graph['selected_units']=len(configs);global_defs=defaultdict(list)
    with tempfile.TemporaryDirectory(prefix='icsvex-clang-') as temp:
        for number,config in enumerate(configs[:MAX_UNITS]):
            if time.monotonic()-start>=timeout:graph['blockers'].append({'reason':'analysis_timeout'});break
            file=config['file'];source=(root/file).resolve()
            record={'file':file,'configuration':number,'status':'blocked'}
            graph['translation_units'].append(record)
            if not inside(source,root) or source.suffix not in EXT or not source.is_file():
                graph['blockers'].append({'reason':'unsupported_or_missing_translation_unit','file':file});continue
            flags,ignored=frontend_flags(root,config)
            record['accepted_flags']=flags;record['rejected_options']=ignored
            graph['blockers'].extend({'reason':p,'file':file} for p in ignored)
            output=Path(temp)/(str(number)+'.ll')
            dependency_file=Path(temp)/(str(number)+'.d')
            command=[exe,'-S','-emit-llvm','-O0','-g','-femit-all-decls','-fno-discard-value-names','-fno-modules','-fno-implicit-modules',
                     '-MD','-MF',str(dependency_file),*flags,str(source),'-o',str(output)]
            record['source_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
            record['command']=command[:-1]+['<temporary-ir>']
            try:
                result=subprocess.run(command,cwd=root,capture_output=True,timeout=min(25,max(1,timeout-(time.monotonic()-start))))
                diagnostics=result.stderr.decode('utf-8','replace');record['diagnostics']=diagnostics[:6000];record['returncode']=result.returncode
                if result.returncode or not output.exists():raise ValueError('compiler_error')
                if dependency_file.exists():
                    dep=dependency_file.read_text(encoding='utf-8').replace('\\\n','')
                    body=dep.partition(': ')[2]
                    if os.name=='nt':body=re.sub(r'\\(?![ \t])','/',body)
                    paths=shlex.split(body,posix=True)
                    record['dependencies']=[]
                    resource=(Path(graph['tool']['resource_directory'])/'include').resolve()
                    for raw in paths:
                        p=Path(raw)
                        if not p.is_absolute():p=root/p
                        p=p.resolve()
                        if inside(p,root) and p.is_file():
                            record['dependencies'].append({'file':p.relative_to(root).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
                        elif not inside(p,resource):graph['blockers'].append({'reason':'header_dependency_outside_upload','file':file})
                else:graph['blockers'].append({'reason':'missing_compiler_dependency_inventory','file':file})
                if output.stat().st_size>MAX_IR:raise ValueError('ir_size_limit')
                data=output.read_bytes();record['ir_sha256']=hashlib.sha256(data).hexdigest()
                fs,issues=ir_graph(data.decode('utf-8'),file+'#'+str(number))
                for f in fs.values():
                    filename=decode_llvm_string(f['file'] or '')
                    path=Path(filename)
                    if path.is_absolute() and inside(path,root):filename=path.resolve().relative_to(root).as_posix()
                    f['file']=Path(filename).as_posix()
                graph['functions'].update(fs);graph['blockers'].extend(issues)
                record['status']='completed';record['function_count']=len(fs)
            except subprocess.TimeoutExpired:graph['blockers'].append({'file':file,'reason':'compiler_timeout'})
            except (ValueError,RuntimeError,OSError,ImportError) as e:graph['blockers'].append({'file':file,'reason':str(e)[:300]})
    for key,f in graph['functions'].items():
        if not f['internal']:global_defs[f['symbol']].append(key)
    local={(f['translation_unit'],f['symbol']):key for key,f in graph['functions'].items()}
    requested=list(dict.fromkeys(entries or []))
    if scope=='product' and complete and not entries:graph['blockers'].append({'reason':'explicit_entry_points_required'})
    for symbol,definitions in global_defs.items():
        if len(definitions)>1:graph['blockers'].append({'reason':'multiple_external_definitions_need_link_evidence','symbol':symbol})
    if scope=='library':requested=[f['symbol'] for f in graph['functions'].values() if not f['internal']]
    if not requested:requested=['main','WinMain','wWinMain']
    roots=[k for k,f in graph['functions'].items() if f['symbol'] in requested or f['name'] in requested]
    graph['entries']=roots;graph['requested_entries']=requested
    missing=[e for e in requested if not any(f['symbol']==e or f['name']==e for f in graph['functions'].values())]
    if entries and missing:graph['blockers'].append({'reason':'entry_points_not_found','entries':missing})
    if not roots:graph['blockers'].append({'reason':'no_entry_points'})
    if scope!='product':graph['blockers'].append({'reason':'product_integration_not_supplied','scope':scope})
    if not complete:graph['blockers'].append({'reason':'source_or_entry_set_completeness_not_declared'})
    adjacency=defaultdict(list)
    for key,f in graph['functions'].items():
        for call in f['calls']:
            symbol=call['symbol'];target=local.get((f['translation_unit'],symbol))
            targets=[target] if target else global_defs.get(symbol,[])
            if len(targets)==1:
                edge={'from':key,'to':targets[0],'file':f['file'],'line':call['line'],'block':call['block']}
                graph['call_edges'].append(edge);adjacency[key].append(targets[0])
            else:f['blockers'].append('indirect_call' if call['indirect'] else 'external_or_ambiguous_call:'+str(symbol))
    pending=deque((r,[r]) for r in roots)
    while pending:
        key,path=pending.popleft()
        if key in graph['paths']:continue
        graph['paths'][key]=path
        graph['blockers'].extend({'reason':p,'function':key} for p in graph['functions'][key]['blockers'])
        pending.extend((target,path+[target]) for target in adjacency[key])
    graph['negative_decisions_enabled']=bool(roots and graph['functions'] and not graph['blockers'])
    completed=sum(t['status']=='completed' for t in graph['translation_units'])
    graph['coverage']={'selected_translation_units':graph.get('selected_units',0),'completed_translation_units':completed,
                       'uncompleted_translation_units':graph.get('selected_units',0)-completed}
    graph['execution_status']=('completed' if completed and completed==graph.get('selected_units') else 'partial' if completed
                               else 'timeout' if any('timeout' in b['reason'] for b in graph['blockers']) else 'blocked')
    graph['build_verified']=False
    graph['elapsed_seconds']=round(time.monotonic()-start,3)
    return graph


def assess(graph,names,intake_complete=True):
    present=[key for key,f in graph['functions'].items() if f['name'] in names or f['symbol'] in names]
    paths=[]
    for key in present:
        if key not in graph['paths']:continue
        ids=graph['paths'][key]
        paths.append({'function':graph['functions'][key]['name'],'path':[graph['functions'][n]['name'] for n in ids],
                      'symbol_path':ids,'locations':[{'file':graph['functions'][n]['file'],'line':graph['functions'][n]['line']} for n in ids],
                      'call_sites':[e for a,b in zip(ids,ids[1:]) for e in graph['call_edges'] if e['from']==a and e['to']==b]})
    enabled=graph['negative_decisions_enabled'] and intake_complete
    return {'engine':graph['engine'],'scope':graph['scope'],'reachable_paths':paths,'present_targets':present,
            'presence':'present' if present else 'absent_in_selected_build' if names and enabled else 'unknown',
            'reachability':'possible_path_found' if paths else 'unreachable_in_selected_scope' if present and enabled else 'unknown',
            'unreachable':bool(present and not paths and enabled),'absence_proven':bool(names and not present and enabled),
            'blockers':graph['blockers'],'target_mapping_complete':False,
            'claim_boundary':'Selected translation units and declared entry points; deployed binary and attacker control not established.'}
