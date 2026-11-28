"""Generate and resume a complete source-bound MulVAL population catalogue."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,wait,FIRST_COMPLETED
import argparse,json,sqlite3,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from src.item4.decision import population_condition_rules as P
from src.item4.decision import mulval_attack_graphs as M
from src.item4.decision import batch_attack_graphs as B
from src.item4.decision import attack_graph_builder as G


def run(output,batch_size,limit=None,tool_root='/opt/mulval-population',workers=3,source_db=None):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(output/'graphs.sqlite3');db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=NORMAL')
    db.execute('CREATE TABLE IF NOT EXISTS graphs(cve TEXT PRIMARY KEY,payload BLOB,sha256 TEXT,nodes INTEGER,edges INTEGER,gaps INTEGER)')
    source_path=Path(source_db) if source_db else P.HOME/'catalog.sqlite3'
    source=sqlite3.connect('file:'+str(source_path).replace(chr(92),'/')+'?mode=ro&immutable=1',uri=True);raw_rows=source.execute('SELECT cve,payload,sha256 FROM records').fetchall();source.close()
    population=sorted(r[0] for r in raw_rows);source_rows={c:(payload,seal) for c,payload,seal in raw_rows};del raw_rows
    if len(population)!=12418:raise ValueError('Population drift')
    wanted=population[:limit] if limit else population
    done={r[0] for r in db.execute('SELECT cve FROM graphs')};pending=[c for c in wanted if c not in done]
    status=dict(version=B.VERSION,state='running',population=12418,requested=len(wanted),completed=len(done),started_at=time.time(),excluded_cves=0)
    def save():
        temp=output/'status.tmp';temp.write_text(json.dumps(status,indent=2),encoding='utf-8');temp.replace(output/'status.json')
    save()
    def generate_batch(ids):
        stage=output/('batch-'+M.digest(ids)[:16]+'.json')
        def mark(name):stage.write_text(json.dumps(dict(stage=name,count=len(ids),first=ids[0],at=time.time())),encoding='utf-8')
        mark('source_loading');records=[]
        for cve in ids:
            payload,seal=source_rows[cve];record=json.loads(payload)
            if record['cve']!=cve or P.digest(record)!=seal:raise ValueError('Source record integrity failure')
            records.append(record)
        mark('contract_compilation');contracts=[B.contract(r) for r in records];programs=[M.compile_program(c) for c in contracts]
        merged,namespaces=B.combine(programs);merged['execution_tool_root']=tool_root;merged['trace_mode']='completeTrace2'
        merged['sha256']=M.digest({k:v for k,v in merged.items() if k!='sha256'})
        mark('mulval_execution')
        for attempt in range(4):
            try:
                receipt=M.generate(merged);break
            except RuntimeError as exc:
                if attempt==3:raise
                if not any(word in str(exc) for word in ('WebSocket','Connection','execution deadline','External tool exceeded')):raise
                mark('retry_'+str(attempt+1));time.sleep(2**attempt)
        mark('partition');parts=B.partition(programs,merged,namespaces,receipt)
        mark('ready');return ids,records,contracts,programs,parts,merged['sha256']
    try:
        batches=iter(pending[start:start+batch_size] for start in range(0,len(pending),batch_size))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            active=set()
            for _ in range(workers):
                ids=next(batches,None)
                if ids:active.add(pool.submit(generate_batch,ids))
            while active:
                finished,_=wait(active,return_when=FIRST_COMPLETED)
                for future in finished:
                    active.remove(future)
                    ids,records,contracts,programs,parts,batch_hash=future.result()
                    for record,contract,program,part in zip(records,contracts,programs,parts):
                        graph=M.import_graph(contract,program,part)
                        if not graph['nodes'] or graph['coverage_complete']:raise ValueError('Missing graph or fabricated complete coverage')
                        if G.evaluate(graph,{})['value']!='unknown':raise ValueError('Unobserved asset must remain unknown')
                        B.store(db,record,graph)
                    db.commit();done.update(ids)
                    status.update(completed=len(done),last_batch=len(ids),last_batch_program_sha256=batch_hash,workers=workers);save()
                    print(json.dumps(dict(completed=len(done),population=12418,elapsed=round(time.time()-status['started_at'],1))),flush=True)
                    ids=next(batches,None)
                    if ids:active.add(pool.submit(generate_batch,ids))
        actual={r[0] for r in db.execute('SELECT cve FROM graphs')}
        if actual!=set(wanted):raise ValueError('Missing or extra CVE graph')
        counts=db.execute('SELECT count(*),sum(nodes),sum(edges),sum(gaps),min(nodes) FROM graphs').fetchone()
        status.update(state='complete',finished_at=time.time(),counts=dict(zip(['cves','nodes','edges','gaps','minimum_nodes_per_cve'],counts)),all_cves_have_actual_mulval_graph=len(wanted)==12418,all_graphs_unobserved_unknown=True,semantic_accuracy_verified=False,source_extraction_backend='existing deterministic compiler; LLM candidates separately verified',population_sha256=M.digest(population))
        save();(output/'manifest.json').write_text(json.dumps(status,indent=2),encoding='utf-8')
    except Exception as exc:
        status.update(state='failed',error=str(exc),failed_at=time.time());save();raise
    finally:db.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=B.HOME);parser.add_argument('--batch-size',type=int,default=64)
    parser.add_argument('--source-db',type=Path);parser.add_argument('--limit',type=int);parser.add_argument('--tool-root',default='/opt/mulval-population');parser.add_argument('--workers',type=int,default=3)
    args=parser.parse_args()
    if not 1<=args.batch_size<=256 or not 1<=args.workers<=4:raise ValueError('Batch/worker bound exceeded')
    run(args.output,args.batch_size,args.limit,args.tool_root,args.workers,args.source_db)
