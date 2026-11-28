"""MulVAL-generated, signed prerequisite graphs with open-world observations.

Both polarities in input.P are *topology placeholders*, never asset operational information.
MulVAL generates the complete rule/derivation structure before observations.
The evaluator subsequently supplies true/false/unknown to its primitive leaves.
No absence-as-negation, generic remote-exploit shortcut, or execCode goal is used.
"""
from copy import deepcopy
from contextlib import contextmanager
import csv
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[3]
VERSION = 'source-bound-mulval/1'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def compile_program(contract):
    """Compile signed, positive Datalog; NOT uses explicit opposite evidence."""
    nodes = {n['id']: n for n in contract['nodes']}
    symbols = {key: 'n' + digest(key)[:28] for key in nodes}
    rules = {}
    refs = contract.get('source_refs', [])

    def term(key, sign, primitive=False):
        return ('icsObservation' if primitive else 'icsState') + '(' + symbols[key] + ',' + sign + ')'

    def add(head, sign, body, basis):
        # body: (semantic node id, polarity, primitive)
        body = list(dict.fromkeys(body))
        row = dict(head=[head, sign], body=[list(b) for b in body], basis=basis,
                   source_refs=deepcopy(nodes[head].get('source_refs', refs)))
        row['rule_kind'] = ('observation_binding' if basis=='explicit_observation_binding' else
                            'assessment_scope_policy' if head.startswith('exploit:') else
                            'unresolved_mapping_guard' if head=='gate:operational-mapping' else
                            'source_boolean_relation')
        row['semantic_validation'] = 'source-linked project model; independent semantic validation outstanding'
        rid = 'icsvex_' + digest(row)[:28]
        row.update(id=rid, clause=term(head, sign) + ' :- ' + ', '.join(term(*b) for b in body))
        rules[rid] = row

    for key, n in nodes.items():
        if n['kind'] == 'predicate':
            for sign in ('true', 'false'):
                add(key, sign, [(key, sign, True)], 'explicit_observation_binding')
        elif n['kind'] == 'not':
            for sign, opposite in [('true', 'false'), ('false', 'true')]:
                add(key, sign, [(n['inputs'][0], opposite, False)], 'source_negation_explicit_polarity')
        elif n['kind'] in {'and', 'or'}:
            all_sign = 'true' if n['kind'] == 'and' else 'false'
            any_sign = 'false' if n['kind'] == 'and' else 'true'
            add(key, all_sign, [(c, all_sign, False) for c in n['inputs']], 'source_' + n['kind'] + '_all_inputs')
            for child in n['inputs']:
                add(key, any_sign, [(child, any_sign, False)], 'source_' + n['kind'] + '_alternative')
        else:
            raise ValueError('Unsupported prerequisite gate')
    declarations = ['primitive(icsObservation(_node,_polarity)).',
                    'derived(icsState(_node,_polarity)).', 'meta(attackGoal(_)).',
                    ':- table icsState/2.']
    rule_text = '\n'.join(declarations + [
        "interaction_rule((" + r['clause'] + "),rule_desc('ICS VEX " + r['id'] + "',1.0))."
        for r in rules.values()]) + '\n'
    # Query both polarities of every node: keep alternatives, blockers, unknowns.
    inputs = ['% STRUCTURE ONLY: these are possible polarities, not observed facts.']
    for key, n in nodes.items():
        for sign in ('true', 'false'):
            inputs.append('attackGoal(' + term(key, sign) + ').')
            if n['kind'] == 'predicate':
                inputs.append(term(key, sign, True) + '.')
    program = dict(version=VERSION, symbols=symbols, rules=rules,
                   input_P='\n'.join(inputs) + '\n', rules_P=rule_text,
                   input_semantics='topology_placeholders_not_operating_facts',
                   goal_semantics='source_prerequisites_only_not_exploit_success')
    program['sha256'] = digest(program)
    return program


def _remote_run(program):
    """Use the existing private H200 workbench's isolated MulVAL installation."""
    from tools.common.ncp_api_transport import execute
    config = Path(os.environ.get('ICSVEX_MULVAL_KUBECONFIG', ROOT / 'hysage-kubeconfig.yaml'))
    remote_root = os.environ.get('ICSVEX_MULVAL_REMOTE_ROOT', '/home/irteam/data-vol1/ics-vex-migration-20261116')
    # Only bounded, generated Prolog and rules are sent; no operating excerpts.
    wire = {key: program[key] for key in ('sha256','input_P','rules_P')}
    wire['tool_root']=program.get('execution_tool_root',os.environ.get('ICSVEX_MULVAL_TOOL_ROOT','/opt/mulval-population'))
    wire['trace_mode']=program.get('trace_mode','completeTrace2')
    packed=base64.b64encode(zlib.compress(json.dumps(wire).encode(),6)).decode()
    if len(packed)>40000:
        remote_file=remote_root+'/mulval-programs/'+program['sha256']+'.b64'
        for offset in range(0,len(packed),40000):
            upload="from pathlib import Path\np=Path("+repr(remote_file)+")\np.parent.mkdir(parents=True,exist_ok=True)\n"
            upload+="with p.open("+repr('w' if offset==0 else 'a')+") as f:f.write("+repr(packed[offset:offset+40000])+")\nprint('uploaded')"
            execute(config,upload,timeout=45)
        loader="Path("+repr(remote_file)+").read_text()"
    else:
        loader=repr(packed)
    script = '''import json,hashlib,sys,tempfile,base64,zlib,importlib.util
from pathlib import Path
r=Path(REMOTE_ROOT)
sys.path.insert(0,str(r/'project'))
runtime_path=next((p for p in [r/'project/tools/item4/ncp_operational_runtime.py',r/'project/tools/ncp_operational_runtime.py'] if p.is_file()),None)
if runtime_path is None:raise RuntimeError('The existing isolated operational tool wrapper is unavailable')
spec=importlib.util.spec_from_file_location('icsvex_operational_runtime',runtime_path)
runtime=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
run=runtime.run
p=json.loads(zlib.decompress(base64.b64decode(PROGRAM)))
parent=r/'mulval-prerequisite-runs'
parent.mkdir(parents=True,exist_ok=True)
folder=Path(tempfile.mkdtemp(prefix=p['sha256']+'-',dir=parent))
(folder/'input.P').write_text(p['input_P'])
(folder/'rules.P').write_text(p['rules_P'])
result=run(['env','MULVALROOT='+p['tool_root'],'graph_gen.sh','-r','/work/rules.P','/work/input.P','-l','-t',p['trace_mode']],folder,'generation')
names=['VERTICES.CSV','ARCS.CSV','AttackGraph.txt','trace_output.P','xsb_log.txt']
files={n:(folder/n).read_text(errors='replace') for n in names if (folder/n).exists()}
pins={}
for n in ['utils/graph_gen.sh','bin/attack_graph','lib/libmulval.P','src/analyzer/translate.P','src/analyzer/attack_trace.P']:
 f=r/'operational_rootfs'/p['tool_root'].lstrip('/')/n
 if f.exists():pins[n]=hashlib.sha256(f.read_bytes()).hexdigest()
response=dict(returncode=result.returncode,files=files,stdout=result.stdout,stderr=result.stderr,tool_sha256=pins,backend='ncp-isolated-proot',remote_directory=str(folder),trace_mode=p['trace_mode'],runtime_wrapper_sha256=hashlib.sha256(runtime_path.read_bytes()).hexdigest())
print(json.dumps(dict(z=base64.b64encode(zlib.compress(json.dumps(response).encode(),6)).decode())))
'''.replace('REMOTE_ROOT', repr(remote_root)).replace('PROGRAM', loader)
    response=json.loads(execute(config, script, timeout=160))
    return json.loads(zlib.decompress(base64.b64decode(response['z'])))


def _local_run(program, backend):
    with tempfile.TemporaryDirectory(prefix='icsvex-mulval-') as name:
        folder = Path(name)
        (folder / 'input.P').write_text(program['input_P'], encoding='utf-8')
        (folder / 'rules.P').write_text(program['rules_P'], encoding='utf-8')
        if backend == 'docker':
            command = ['docker', 'run', '--rm', '--network', 'none', '--memory', '2g', '--cpus', '2',
                       '--mount', 'type=bind,src=' + str(folder.resolve()) + ',dst=/work',
                       os.environ.get('ICSVEX_MULVAL_IMAGE', 'ics-vex-operational-tools:20261116'),
                       'graph_gen.sh', '-r', '/work/rules.P', '/work/input.P', '-l']
        else:
            command = ['graph_gen.sh', '-r', str(folder / 'rules.P'), str(folder / 'input.P'), '-l']
        command += ['-t',program.get('trace_mode','completeTrace2')]
        result = subprocess.run(command, cwd=folder, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=140)
        files = {n: (folder / n).read_text(encoding='utf-8', errors='replace') for n in
                 ['VERTICES.CSV', 'ARCS.CSV', 'AttackGraph.txt', 'trace_output.P', 'xsb_log.txt']
                 if (folder / n).exists()}
        return dict(returncode=result.returncode, files=files, stdout=result.stdout,
                    stderr=result.stderr, backend=backend, tool_sha256={},trace_mode=program.get('trace_mode','completeTrace2'))


def execute_program(program):
    backend = os.environ.get('ICSVEX_MULVAL_BACKEND', 'auto')
    if backend == 'auto':
        config = Path(os.environ.get('ICSVEX_MULVAL_KUBECONFIG', ROOT / 'hysage-kubeconfig.yaml'))
        backend = 'native' if shutil.which('graph_gen.sh') else 'docker' if shutil.which('docker') else 'ncp' if config.is_file() else 'unavailable'
    if backend == 'ncp':
        return _remote_run(program)
    if backend in {'docker', 'native'}:
        return _local_run(program, backend)
    raise RuntimeError('MulVAL unavailable: configure native, Docker, or the existing NCP backend.')


@contextmanager
def _cache_lock(path):
    """Serialize identical requests across local service/test processes."""
    with path.open('a+b') as handle:
        # Windows permits byte-range locks beyond EOF. Do not initialize the
        # byte before locking: another request may already own that range.
        deadline=time.monotonic()+180
        while True:
            try:
                handle.seek(0)
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic()>deadline:raise RuntimeError('MulVAL generation cache is busy')
                time.sleep(.05)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name=='nt':
                msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else:
                fcntl.flock(handle.fileno(),fcntl.LOCK_UN)


def generate(program):
    cache = Path(os.environ.get('ICSVEX_MULVAL_CACHE', ROOT / 'data/runtime/mulval_prerequisite_cache'))
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / (program['sha256'] + '.json')
    with _cache_lock(cache / (program['sha256']+'.lock')):
        return _generate_locked(program,cache,path)


def _generate_locked(program,cache,path):
    if path.exists():
        record = json.loads(path.read_text(encoding='utf-8'))
        if record.get('sha256') != digest({k: v for k, v in record.items() if k != 'sha256'}):
            raise ValueError('MulVAL cache integrity failure')
        if record['program_sha256'] != program['sha256']:
            raise ValueError('MulVAL cache program mismatch')
        return record
    try:
        result = execute_program(program)
    except Exception as exc:
        details=str(exc).split("{'metadata'")[0]
        if len(details)>1000:details=details[:100]+' ... '+details[-800:]
        raise RuntimeError('MulVAL execution backend failed: ' + type(exc).__name__+': '+details) from None
    if result['returncode'] or not result['files'].get('VERTICES.CSV') or not result['files'].get('trace_output.P'):
        raise RuntimeError('MulVAL graph generation failed: ' + result.get('stderr', '')[-600:] + result['files'].get('xsb_log.txt', '')[-1000:])
    result['program_sha256'] = program['sha256']
    result['sha256'] = digest(result)
    # Atomic cache writes: concurrent readers never see a partial receipt.
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=cache, delete=False) as stream:
        stream.write(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
        temporary = Path(stream.name)
    os.replace(temporary, path)
    return result


def import_graph(contract, program, generated):
    """Import actual MulVAL vertices/arcs; check each instantiated inference."""
    semantic = {n['id']: n for n in contract['nodes']}
    symbols = {v: k for k, v in program['symbols'].items()}
    raw = {}; nodes = {}; signatures = {}; rule_nodes = {}
    for row in csv.reader(io.StringIO(generated['files']['VERTICES.CSV'])):
        if not row:
            continue
        number, label, kind = row[:3]
        if number in raw:
            raise ValueError('Duplicate MulVAL vertex')
        if kind in {'LEAF', 'OR'}:
            m = re.fullmatch(r'(icsObservation|icsState)\((n[a-f0-9]+),(true|false)\)', label)
            if not m or m[2] not in symbols or (m[1] == 'icsObservation') != (kind == 'LEAF'):
                raise ValueError('Unexpected MulVAL predicate: ' + label)
            original, sign = symbols[m[2]], m[3]
            base = semantic[original]
            key = ('observation:' + original + ':' + sign) if kind == 'LEAF' else original if sign == 'true' else 'negative:' + original
            if kind == 'LEAF' and base['kind'] != 'predicate':
                raise ValueError('MulVAL primitive is not an observable condition')
            item = dict(id=key, kind='predicate' if kind == 'LEAF' else 'or', inputs=[],
                        label=base['label'] + (' [explicit false]' if sign == 'false' else ''),
                        semantic_id=original, polarity=sign, source=base.get('source'),
                        source_refs=base.get('source_refs', contract.get('source_refs', [])),
                        nist_fields=base.get('nist_fields', []), mulval_vertex=number,
                        mulval_label=label)
            if kind == 'LEAF':
                item['question_id'] = base['question_id']
            signatures[number] = [original, sign, kind == 'LEAF']
        elif kind == 'AND':
            m = re.fullmatch(r'RULE \d+ \(ICS VEX (icsvex_[a-f0-9]+)\)', label)
            if not m or m[1] not in program['rules']:
                raise ValueError('Unattributed MulVAL inference: ' + label)
            rule = program['rules'][m[1]]
            key = 'mulval-rule:' + number
            item = dict(id=key, kind='and', inputs=[], label=rule['basis'],
                        inference_rule=deepcopy(rule), source_refs=rule['source_refs'],
                        mulval_vertex=number, mulval_label=label)
            rule_nodes[number] = rule
        else:
            raise ValueError('Unknown MulVAL node type')
        if key in nodes:
            raise ValueError('Duplicate MulVAL semantic vertex')
        nodes[key] = item; raw[number] = key
    arcs = []
    for row in csv.reader(io.StringIO(generated['files']['ARCS.CSV'])):
        if not row:
            continue
        parent, child = row[:2]
        if parent not in raw or child not in raw:
            raise ValueError('Invalid MulVAL arc')
        if (parent, child) in arcs:
            continue  # MulVAL may repeat the same dependency in its CSV trace.
        arcs.append((parent, child)); nodes[raw[parent]]['inputs'].append(raw[child])
    for vertex, rule in rule_nodes.items():
        children = [child for parent, child in arcs if parent == vertex]
        parents = [parent for parent, child in arcs if child == vertex]
        if any(c not in signatures for c in children) or sorted(signatures[c] for c in children) != sorted(rule['body']):
            raise ValueError('MulVAL inference premises differ from the source rule')
        if len(parents) != 1 or signatures.get(parents[0], []) != rule['head'] + [False]:
            raise ValueError('MulVAL inference conclusion differs from the source rule')
    if {r['id'] for r in rule_nodes.values()} != set(program['rules']):
        raise ValueError('MulVAL omitted a submitted inference rule')
    if any((p not in rule_nodes and c not in rule_nodes) or
           (p in rule_nodes and c in rule_nodes) for p,c in arcs):
        raise ValueError('MulVAL arc does not connect a fact and an inference')
    expected = {key for key in semantic} | {'negative:' + key for key in semantic}
    expected |= {'observation:'+key+':'+sign for key,n in semantic.items()
                 if n['kind']=='predicate' for sign in ('true','false')}
    if not expected <= set(nodes):
        raise ValueError('MulVAL omitted a source condition or polarity')
    for item in nodes.values():
        if item['kind'] != 'predicate' and not item['inputs']:
            raise ValueError('MulVAL derivation has no premises')
    result = {k: deepcopy(v) for k, v in contract.items() if k not in {'nodes', 'edges', 'sha256'}}
    result.update(version=VERSION, nodes=list(nodes.values()),
                  edges=[dict(source=raw[c], target=raw[p], relation='mulval_inference') for p, c in arcs],
                  semantic_nodes=list(semantic.values()),
                  semantics='MulVAL signed derivation graph; explicit evidence; three-valued annotation',
                  generator='MulVAL/XSB', generation_status='complete',
                  graph_scope='single-component CVE prerequisites; no unobserved lateral movement',
                  proves_exploit_success=False,
                  mulval=dict(program=program, receipt_sha256=generated['sha256'],
                              backend=generated['backend'], tool_sha256=generated['tool_sha256'],
                              artifact_sha256={n: hashlib.sha256(t.encode()).hexdigest() for n, t in generated['files'].items()},
                              batch_provenance={k:deepcopy(generated[k]) for k in ['batch_receipt_sha256','batch_program_sha256','namespace_owner','namespace_symbols','namespace_rules','projection'] if k in generated},all_inference_steps_checked=True))
    result['sha256'] = digest(result)
    return result


def build(contract):
    program = compile_program(contract)
    try:
        generated = generate(program)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        # No silent return to the old generator, and no positive/negative verdict.
        result = {k: deepcopy(v) for k, v in contract.items() if k not in {'nodes', 'edges', 'sha256'}}
        result.update(version=VERSION, nodes=[], edges=[], generator='MulVAL/XSB',
                      generation_status='unavailable', generation_error=str(exc)[:1500],
                      coverage_complete=False, proves_exploit_success=False,
                      mulval=dict(program_sha256=program['sha256']))
        result['sha256'] = digest(result)
        return result
    return import_graph(contract, program, generated)
