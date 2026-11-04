"""Fresh Clang-only campaign across collected snapshots; never assert product completeness."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
from datetime import datetime,timezone
import gzip,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json,read_json


def worker(cve,out,seconds):
    from src import clang_source as CL
    from src.source_evidence import inspect_build,patch_evidence
    root=ROOT/'data/source_snapshots'/cve;started=time.monotonic()
    metadata=read_json(ROOT/'data/snapshot_index.json').get(cve,{})
    mapping=read_json(ROOT/'data/vuln_targets.json').get(cve,{})
    locations=read_json(ROOT/'data/source_locations.json').get(cve,{})
    build=inspect_build(root);patch=patch_evidence(root,cve)
    names=sorted(set(mapping.get('targets',[])+patch['functions']+
                     [f['name'] for f in locations.get('functions',[]) if f.get('name')]))
    discovery=not build['configurations']
    if discovery:
        # These flags support discovery only: no fabricated compilation database,
        # generated header stubs or claim that this is the shipped build.
        preferred={f['file'] for f in locations.get('functions',[]) if isinstance(f.get('file'),str) and f['file']}
        preferred|={h['patch_file'] for p in patch['patches'] for h in p['hunks']}
        sources=[p for p in root.rglob('*') if p.is_file() and p.suffix in CL.EXT]
        def priority(p):
            rel=p.relative_to(root).as_posix()
            return (not any(rel==s or rel.endswith('/'+s) for s in preferred),
                    any(part.lower() in {'test','tests','examples','fuzz','fuzzing','doc'} for part in p.parts),rel)
        top=[p for p in root.iterdir() if p.is_dir()]
        base=top[0] if len(top)==1 else root
        includes=[p for p in [base,base/'include',base/'src',base/'lib',base/'lib/includes'] if p.is_dir()]
        build['configurations']=[{'file':p.relative_to(root).as_posix(),'source_file':p.relative_to(root).as_posix(),
            'database':'compile_commands.json','arguments':['clang',*[v for inc in includes for v in ['-I',str(inc.resolve())]]],
            'configuration_verified':False,'origin':'bounded_discovery_not_actual_build'} for p in sorted(sources,key=priority)]
    graph=CL.build(root,build,scope='library',complete=False,timeout=seconds)
    if discovery:
        graph['blockers'].append({'reason':'discovery_configuration_not_actual_build'})
        graph['blockers'].append({'reason':'compilation_database_missing'})
    graph['negative_decisions_enabled']=False
    flow=CL.assess(graph,names)
    # Compiler-emitted SDK inline functions are not collected project functions.
    project_files={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.suffix in {'.c','.h','.cc','.cpp','.cxx','.hpp','.C'}}
    project_functions=[]
    for key,f in graph['functions'].items():
        filename=(f.get('file') or '').replace('\\','/')
        matches=[p for p in project_files if p==filename or p.endswith('/'+filename)] if filename else []
        if len(matches)==1:project_functions.append(key)
    blockers=Counter(b['reason'] for b in graph['blockers'])
    result={'cve':cve,'engine':graph['engine'],'status':'under_investigation','justification':None,
        'analysis_state':graph.get('execution_status','blocked'),'cfg_execution_status':graph.get('execution_status','blocked'),
        'source':str(root.relative_to(ROOT)).replace('\\','/'),'snapshot':metadata,
        'targets':names,'mapping_source':mapping.get('source'),'target_mapping_independently_verified':False,
        'compiled_functions':len(graph['functions']),'compiled_project_functions':len(project_functions),
        'project_function_ids':project_functions,'coverage':graph.get('coverage',{}),
        'target_presence':flow['presence'],'compiled_present_targets':flow['present_targets'],
        'reachable_paths':flow['reachable_paths'],'blocker_counts':dict(blockers),'blocker_examples':graph['blockers'][:15],
        'build_database_count':len(build['compilation_databases']),'discovery_configuration_used':discovery,
        'duration_seconds':round(time.monotonic()-started,2),'scope':'library snapshot, not a complete deployed product',
        'graph_file':'graphs/'+cve+'.json.gz','patch_evidence':patch,
        'compiler':graph.get('tool'),'program_executed':False,'uploaded_build_commands_executed':False,
        'negative_verdict_disabled_reason':'Collected snapshots do not establish a complete product/build/root set or complete CVE target causality.'}
    (out/'graphs').mkdir(exist_ok=True)
    with gzip.open(out/result['graph_file'],'wt',encoding='utf-8') as f:json.dump(graph,f)
    atomic_json(out/(cve+'.json'),result)


def main():
    p=argparse.ArgumentParser();p.add_argument('--worker');p.add_argument('--output',default='results/source_clang_batch_v1')
    p.add_argument('--workers',type=int,default=2);p.add_argument('--analysis-seconds',type=int,default=90)
    a=p.parse_args();out=(ROOT/a.output).resolve();out.mkdir(parents=True,exist_ok=True)
    if a.worker:
        import re
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',a.worker):raise ValueError('Invalid CVE ID')
        worker(a.worker,out,a.analysis_seconds);return
    from src.clang_source import compiler
    exe=compiler()
    if not exe:raise RuntimeError('Clang is unavailable')
    cves=sorted(p.name for p in (ROOT/'data/source_snapshots').iterdir() if p.is_dir() and p.name.startswith('CVE-'))
    fingerprint=hashlib.sha256(b''.join((ROOT/f).read_bytes() for f in ['src/clang_source.py',
        'src/source_evidence.py','tools/batch_source_clang.py'])).hexdigest()
    manifest={'started_at':datetime.now(timezone.utc).isoformat(),'engine':'clang-llvm','compiler':exe,
              'implementation_sha256':fingerprint,'population':cves,'expected':len(cves),
              'workers':a.workers,'analysis_seconds':a.analysis_seconds,'legacy_results_reused':False}
    previous=read_json(out/'manifest.json')
    if previous and previous.get('implementation_sha256')!=fingerprint:raise RuntimeError('Implementation changed: create a new output version.')
    atomic_json(out/'manifest.json',manifest);rows=[]
    def execute(cve):
        existing=read_json(out/(cve+'.json'))
        if existing:return existing
        try:
            run=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--worker',cve,'--output',str(out),
                '--analysis-seconds',str(a.analysis_seconds)],capture_output=True,timeout=a.analysis_seconds+90)
            if run.returncode:raise RuntimeError(run.stderr.decode('utf-8','replace')[-2000:])
            row=read_json(out/(cve+'.json'))
            if not row:raise RuntimeError('Missing worker output')
            return row
        except Exception as e:
            row={'cve':cve,'status':'under_investigation','analysis_state':'timeout' if isinstance(e,subprocess.TimeoutExpired) else 'error',
                 'error':str(e)[-2000:],'engine':'clang-llvm','target_mapping_independently_verified':False}
            atomic_json(out/(cve+'.json'),row);return row
    atomic_json(out/'summary.json',{**manifest,'processed':0,'complete':False,'results':[]})
    with ThreadPoolExecutor(max_workers=max(1,min(a.workers,4))) as pool:
        futures=[pool.submit(execute,c) for c in cves]
        for future in as_completed(futures):
            rows.append(future.result());r=rows[-1]
            summary={**manifest,'updated_at':datetime.now(timezone.utc).isoformat(),'processed':len(rows),'complete':len(rows)==len(cves),
                'by_analysis_state':dict(Counter(r['analysis_state'] for r in rows)),
                'by_status':dict(Counter(r['status'] for r in rows)),
                'snapshots_with_compiled_functions':sum(bool(r.get('compiled_functions')) for r in rows),
                'snapshots_with_compiled_project_functions':sum(bool(r.get('compiled_project_functions')) for r in rows),
                'snapshots_with_compiled_targets':sum(bool(r.get('compiled_present_targets')) for r in rows),
                'completed_translation_units':sum(r.get('coverage',{}).get('completed_translation_units',0) for r in rows),
                'blocker_counts':dict(sum((Counter(r.get('blocker_counts',{})) for r in rows),Counter())),
                'results':sorted(rows,key=lambda r:r['cve'])}
            atomic_json(out/'summary.json',summary)
            print(f"{len(rows)}/{len(cves)} {r['cve']} {r['analysis_state']} functions={r.get('compiled_functions',0)}",flush=True)


if __name__=='__main__':main()
