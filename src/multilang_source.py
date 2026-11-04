"""Parse source text without compiling/running it. Syntax paths are not CFG proofs."""
from collections import Counter, defaultdict, deque
from pathlib import Path
import hashlib
import time
from src import source_intake as SI, clang_source

SUPPORTED = {'c','cpp','python','java','sql','javascript','go','r','ruby','typescript','csharp','rust'}
DEFINITIONS = {
    'c':{'function_definition'}, 'cpp':{'function_definition'},
    'python':{'function_definition','lambda'},
    'java':{'method_declaration','constructor_declaration'},
    'javascript':{'function_declaration','function_expression','arrow_function','method_definition','generator_function_declaration'},
    'typescript':{'function_declaration','function_expression','arrow_function','method_definition'},
    'go':{'function_declaration','method_declaration','func_literal'},
    'r':{'function_definition'}, 'ruby':{'method','singleton_method','lambda'},
    'sql':{'create_function','create_procedure'},
    'csharp':{'method_declaration','constructor_declaration','local_function_statement'},
    'rust':{'function_item','closure_expression'},
}
CALLS = {'call','call_expression','method_invocation','invocation','invocation_expression','object_creation_expression'}
CONTROL = {'if_statement','if_expression','while_statement','for_statement','for_in_statement',
           'switch_statement','try_statement','return_statement','raise_statement','throw_statement'}
MAX_FILES, MAX_BYTES, MAX_NODES = 1024, 2*1024*1024, 200000


def language(path):
    return 'cpp' if path.suffix == '.C' else SI.LANG_EXT.get(path.suffix.lower())


def source_files(root):
    return sorted(p for p in Path(root).rglob('*') if p.is_file() and language(p))


def text(node, data):
    return data[node.start_byte:node.end_byte].decode('utf-8','replace') if node else ''


def name_node(node):
    found = node.child_by_field_name('name')
    if found and found.is_named:return found
    found = node.child_by_field_name('declarator')
    while found and found.type not in {'identifier','field_identifier','qualified_identifier','operator_name'}:
        child = found.child_by_field_name('declarator')
        if not child:break
        found = child
    if found:return found
    if node.type in {'create_function','create_procedure'}:
        return next((c for c in node.named_children if c.type=='object_reference'),None)
    parent=node.parent
    if parent and parent.type in {'variable_declarator','assignment','binary_operator','assignment_expression'}:
        return parent.child_by_field_name('name') or parent.child_by_field_name('left') or parent.child_by_field_name('lhs')
    return None


def parse_file(path, root):
    from tree_sitter_language_pack import get_parser
    data=path.read_bytes();lang=language(path);rel=path.relative_to(root).as_posix()
    record={'file':rel,'language':lang,'source_sha256':hashlib.sha256(data).hexdigest(),
            'status':'blocked','parser':'tree-sitter','bytes':len(data)}
    if len(data)>MAX_BYTES:return {},record,[{'reason':'source_parse_size_limit','file':rel}]
    tree=get_parser(lang).parse(data);record['status']='partial' if tree.root_node.has_error else 'completed'
    issues=[{'reason':'syntax_errors_or_unsupported_dialect','file':rel}] if tree.root_node.has_error else []
    module=rel+'::<module>'
    functions={module:{'id':module,'name':'<module>','symbol':module,'file':rel,'line':1,'language':lang,
        'kind':'module','calls':[],'blocks':[],'edges':[],'control_constructs':[],'blockers':[]}}
    pending=[(tree.root_node,module)];visited=0
    while pending:
        node,owner=pending.pop();visited+=1
        if visited>MAX_NODES:
            issues.append({'reason':'ast_node_limit','file':rel});record['status']='partial';break
        if node.type in DEFINITIONS.get(lang,set()):
            n=name_node(node);name=text(n,data) or '<anonymous@'+str(node.start_point.row+1)+'>'
            identifier=rel+'::'+str(node.start_byte)+'::'+name
            functions[identifier]={'id':identifier,'name':name,'symbol':name,'file':rel,
                'line':node.start_point.row+1,'end_line':node.end_point.row+1,'language':lang,'kind':'function',
                'calls':[],'blocks':[],'edges':[],'control_constructs':[],'blockers':[],
                'source_span':[node.start_byte,node.end_byte], 'parent_scope':owner}
            owner=identifier
            if lang=='sql':issues.append({'reason':'sql_routine_dialect_or_quoted_body_requires_review','file':rel})
        if node.type in CALLS:
            callee=node.child_by_field_name('function') or node.child_by_field_name('method') or node.child_by_field_name('name')
            if not callee and node.type=='invocation':
                callee=next((c for c in node.named_children if c.type=='object_reference'),None)
            symbol=text(callee,data) or '<unresolved>'
            direct=bool(callee and callee.type in {'identifier','field_identifier','object_reference'} and
                        not node.child_by_field_name('object') and not node.child_by_field_name('receiver'))
            functions[owner]['calls'].append({'symbol':symbol,'line':node.start_point.row+1,
                'indirect':not direct,'block':None,'source_span':[node.start_byte,node.end_byte]})
        if node.type in CONTROL:
            functions[owner]['control_constructs'].append({'kind':node.type,'line':node.start_point.row+1})
        if node.type=='ERROR' or node.is_missing:
            if len(issues)<30:issues.append({'reason':'syntax_error','file':rel,'line':node.start_point.row+1})
        pending.extend((c,owner) for c in reversed(node.named_children))
    record['function_count']=len(functions)-1;record['ast_nodes_visited']=visited
    return functions,record,issues


def build(root, build_info=None, *, entries=None, scope='partial', complete=False, timeout=120):
    root=Path(root).resolve();started=time.monotonic();files=source_files(root)
    graph={'engine':'tree-sitter-source/1','graph_kind':'syntactic_call_graph_not_cfg',
        'tool':{'version':'Tree-sitter language pack 0.13.0'},'scope':scope,
        'functions':{},'paths':{},'entries':[],'call_edges':[],'blockers':[],
        'translation_units':[],'selected_units':len(files),'negative_decisions_enabled':False,
        'program_executed':False,'uploaded_commands_executed':False,'build_verified':False,
        'assumptions':{'complete_source_and_entry_set_declared':bool(complete)},
        'languages':dict(Counter(language(p) for p in files)),
        'limitations':['Syntax-only paths do not prove runtime reachability or unreachability.',
            'No type resolution, import linking, dynamic dispatch, taint analysis or cross-language FFI resolution.',
            'SQL dialects, quoted procedure bodies and dynamic queries may be opaque.']}
    if len(files)>MAX_FILES:graph['blockers'].append({'reason':'source_file_limit','total':len(files)})
    if not files:graph['blockers'].append({'reason':'no_supported_source_files'})
    for path in files[:MAX_FILES]:
        if time.monotonic()-started>timeout:
            graph['blockers'].append({'reason':'analysis_timeout'});break
        try:
            functions,record,issues=parse_file(path,root)
        except (ImportError,ValueError,RuntimeError,OSError,LookupError) as e:
            functions={};record={'file':path.relative_to(root).as_posix(),'language':language(path),'status':'blocked'}
            issues=[{'reason':'source_parser_unavailable_or_failed','file':record['file'],'detail':str(e)[:200]}]
        graph['functions'].update(functions);graph['translation_units'].append(record);graph['blockers'].extend(issues)
    same_file=defaultdict(list)
    for key,f in graph['functions'].items():
        if f['kind']=='function':same_file[(f['file'],f['name'])].append(key)
    adjacency=defaultdict(list)
    for key,f in graph['functions'].items():
        for call in f['calls']:
            candidates=same_file[(f['file'],call['symbol'])] if not call['indirect'] else []
            if len(candidates)==1:
                edge={'from':key,'to':candidates[0],'file':f['file'],'line':call['line'],'block':None,
                      'resolution':'unique_same_file_name_candidate_not_type_verified'}
                graph['call_edges'].append(edge);adjacency[key].append(candidates[0])
            else:f['blockers'].append('unresolved_or_ambiguous_call:'+call['symbol'])
    requested=list(dict.fromkeys(entries or []));graph['requested_entries']=requested
    roots=[key for key,f in graph['functions'].items() if f['name'] in requested or key in requested]
    if not requested:
        roots=[key for key,f in graph['functions'].items() if f['name']=='main' or f['kind']=='module']
    for name in requested:
        if not any(f['name']==name or k==name for k,f in graph['functions'].items()):
            graph['blockers'].append({'reason':'entry_points_not_found','entry':name})
    graph['entries']=roots;graph['entry_inference']='caller_supplied' if requested else 'module_and_named_main_candidates'
    pending=deque((key,[key]) for key in roots)
    while pending:
        key,path=pending.popleft()
        if key in graph['paths']:continue
        graph['paths'][key]=path;pending.extend((target,path+[target]) for target in adjacency[key])
    graph['blockers'].append({'reason':'syntax_analysis_cannot_authorize_absence_or_unreachability'})
    graph['unresolved_calls']=[{'file':f['file'],'function':f['name'],'reason':b}
                             for f in graph['functions'].values() for b in f['blockers']][:2000]
    completed=sum(r['status']=='completed' for r in graph['translation_units'])
    graph['coverage']={'selected_source_files':len(files),'parsed_source_files':completed,
                       'uncompleted_source_files':len(files)-completed}
    graph['execution_status']='completed' if files and completed==len(files) else 'partial' if completed else 'blocked'
    graph['elapsed_seconds']=round(time.monotonic()-started,3)
    return graph


def auto_build(root, build_info, **kwargs):
    files=source_files(root)
    native=files and all(language(p) in {'c','cpp'} for p in files)
    if native and build_info.get('configurations'):
        result=clang_source.build(root,build_info,**kwargs)
        result['selection_reason']='C/C++ source with a supplied compilation database.'
        if result.get('execution_status')=='blocked':
            attempt={'engine':result['engine'],'execution_status':result['execution_status'],
                     'blockers':result['blockers'],'coverage':result.get('coverage')}
            result=build(root,build_info,**kwargs)
            result['compiler_attempt']=attempt
            result['selection_reason']='Clang could not analyze the supplied build; retain source-only syntax evidence without a negative verdict.'
    else:
        result=build(root,build_info,**kwargs)
        result['selection_reason']='Parse source directly; no build database required for syntax evidence.'
    return result


def assess(graph,names,intake_complete=True):
    result=clang_source.assess(graph,names,intake_complete)
    if graph['engine']=='tree-sitter-source/1':
        result.update(graph_kind=graph['graph_kind'],absence_proven=False,unreachable=False,
            languages=graph['languages'],parser_coverage=graph['coverage'],
            unresolved_calls=graph['unresolved_calls'],
            presence='present_in_parsed_source' if result['present_targets'] else 'not_observed_not_proven_absent',
            reachability='syntactic_path_candidate' if result['reachable_paths'] else 'unknown',
            claim_boundary='Parsed source text and name-based call candidates; runtime paths, absence, attacker control and deployment identity are not established.')
    return result
