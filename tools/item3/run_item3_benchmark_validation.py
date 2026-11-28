"""Freeze every benchmark BOM occurrence, then evaluate agents and rules with resumable caches."""
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from copy import deepcopy
from pathlib import Path
import argparse,hashlib,json,os,sqlite3,sys,time,zipfile,zlib
from functools import lru_cache
from contextlib import contextmanager

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
DEFAULT=ROOT/'results/item3_benchmark_validation_20261119'


from src.common.paths import source_path

def compact(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def digest(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return zlib.compress(compact(value).encode(),6)
def decode(raw):return json.loads(zlib.decompress(raw))
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()
def save(path,obj):
    from src.common.runtime.training_progress_io import atomic_json
    atomic_json(path,obj)


def db_open(out):
    out.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(out/'validation.sqlite3')
    db.execute('pragma journal_mode=WAL')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,kind TEXT,sha256 TEXT,details TEXT);
    CREATE TABLE IF NOT EXISTS inputs(sha256 TEXT PRIMARY KEY,body BLOB,components INTEGER);
    CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,input_sha256 TEXT,family TEXT,gold_id TEXT);
    CREATE TABLE IF NOT EXISTS units(sha256 TEXT PRIMARY KEY,body BLOB,agents BLOB,rules BLOB);
    CREATE TABLE IF NOT EXISTS input_units(input_sha256 TEXT,position INTEGER,unit_sha256 TEXT,PRIMARY KEY(input_sha256,position));
    CREATE TABLE IF NOT EXISTS gold(id TEXT PRIMARY KEY,label TEXT);
    CREATE TABLE IF NOT EXISTS meta(name TEXT PRIMARY KEY,value TEXT);
    CREATE TABLE IF NOT EXISTS case_results(id TEXT PRIMARY KEY,payload TEXT);
    ''')
    return db


def is_bom(value):
    return isinstance(value,dict) and (value.get('bomFormat')=='CycloneDX' or str(value.get('spdxVersion','')).startswith('SPDX-'))


def freeze_bom(db,identity,bom,family,gold_id=None):
    canonical=compact(bom).encode();key=digest(canonical)
    field='components' if bom.get('bomFormat')=='CycloneDX' else 'packages'
    items=bom.get(field,[])
    count=len(items) if isinstance(items,list) else -1
    db.execute('insert or ignore into inputs values (?,?,?)',(key,zlib.compress(canonical,6),count))
    db.execute('insert into cases values (?,?,?,?)',(identity,key,family,gold_id))
    if not items or not isinstance(items,list):return
    for start in range(len(items)):
        chunk={k:deepcopy(bom[k]) for k in ('bomFormat','specVersion','spdxVersion','metadata','properties') if k in bom}
        chunk[field]=deepcopy(items[start:start+1])
        # Preserve fallback positional references if a large BOM needs chunking.
        if len(items)>1:
            for i,node in enumerate(chunk[field],start):
                if isinstance(node,dict):node.setdefault('bom-ref' if field=='components' else 'SPDXID',str(i))
        raw=compact(chunk).encode();unit=digest(raw)
        db.execute('insert or ignore into units(sha256,body) values (?,?)',(unit,zlib.compress(raw,6)))
        db.execute('insert or ignore into input_units values (?,?,?)',(key,start,unit))


def split_units(out):
    """Rebuild an unused execution plan component-by-component, retaining every input."""
    db=db_open(out)
    assert db.execute('select count(*) from units where agents is not null or rules is not null').fetchone()[0]==0
    db.execute('delete from input_units');db.execute('delete from units')
    inputs=db.execute('select sha256,body,components from inputs').fetchall()
    for n,(key,raw,count) in enumerate(inputs,1):
        if count<=0:continue
        bom=decode(raw);field='components' if bom.get('bomFormat')=='CycloneDX' else 'packages'
        for i,item in enumerate(bom[field]):
            chunk={k:deepcopy(bom[k]) for k in ('bomFormat','specVersion','spdxVersion','metadata','properties') if k in bom}
            node=deepcopy(item)
            if count>1 and isinstance(node,dict):node.setdefault('bom-ref' if field=='components' else 'SPDXID',str(i))
            chunk[field]=[node];encoded=compact(chunk).encode();unit=digest(encoded)
            db.execute('insert or ignore into units(sha256,body) values (?,?)',(unit,zlib.compress(encoded,6)))
            db.execute('insert into input_units values (?,?,?)',(key,i,unit))
        if n%4000==0:print('Prepared component units:',n,'/',len(inputs),flush=True)
    inventory=json.loads(db.execute("select value from meta where name='plan_complete'").fetchone()[0])
    inventory['unique_work_units']=db.execute('select count(*) from units').fetchone()[0]
    inventory['execution_unit']='One component with original metadata/properties; non-analysis fields including embedded vulnerability answers are omitted from model-processing envelopes only.'
    inventory['total_component_occurrences']=db.execute('select sum(i.components) from cases c join inputs i on i.sha256=c.input_sha256 where i.components>0').fetchone()[0]
    db.execute("update meta set value=? where name='plan_complete'",(compact(inventory),));db.commit()
    save(out/'inventory.json',inventory);db.close();print(compact(inventory),flush=True)


def parse_file(item):
    if isinstance(item,Path):
        identity=item.relative_to(ROOT).as_posix();raw=item.read_bytes();family=identity.split('/')[1]
    else:identity,raw,family=item
    try:value=json.loads(raw)
    except (ValueError,UnicodeError) as exc:return identity,raw,family,None,str(exc)
    return identity,raw,family,value,None


def plan(out):
    db=db_open(out)
    if db.execute("select value from meta where name='plan_complete'").fetchone():
        print('Existing frozen plan retained.');return
    def record_file(identity,kind,raw_sha,details=None):
        previous=db.execute('select sha256 from files where path=?',(identity,)).fetchone()
        if previous:
            if previous[0]!=raw_sha:raise ValueError('Benchmark file changed during inventory: '+identity)
            return False
        db.execute('insert into files values (?,?,?,?)',(identity,kind,raw_sha,details));return True
    ledger=ROOT/'benchmark/item3_evaluation/gold.jsonl'
    for line in ledger.open(encoding='utf-8'):
        a=json.loads(line)
        assert not set(a['expected_cves'])&set(a['unknown_cves'])
        previous=db.execute('select label from gold where id=?',(a['id'],)).fetchone()
        if previous and previous[0]!=compact(a):raise ValueError('Gold changed during inventory')
        db.execute('insert or ignore into gold values (?,?)',(a['id'],compact(a)))
    assert db.execute('select count(*) from gold').fetchone()[0]==18608
    items=sorted((ROOT/'benchmark').rglob('*.json'))
    with ThreadPoolExecutor(max_workers=8) as pool:
        for i,(identity,raw,family,value,error) in enumerate(pool.map(parse_file,items),1):
            kind='json_parse_error' if error else 'bom' if is_bom(value) else 'metadata'
            fresh=record_file(identity,kind,digest(raw),error)
            if kind=='bom' and fresh:
                gold_id=Path(identity).stem if '/item3_evaluation/sboms/' in identity else None
                freeze_bom(db,identity,value,family,gold_id)
            if i%8000==0:db.commit();print(f'Inventoried {i}/{len(items)} physical JSON files',flush=True)
    for p in sorted((ROOT/'benchmark').rglob('*.jsonl')):
        rel=p.relative_to(ROOT).as_posix();raw=p.read_bytes();nested=0;errors=[]
        for number,line in enumerate(raw.splitlines(),1):
            if not line.strip():continue
            try:value=json.loads(line)
            except ValueError as exc:errors.append({'line':number,'error':str(exc)});continue
            if isinstance(value,dict) and is_bom(value.get('sbom')):
                freeze_bom(db,rel+'::line:'+str(number),value['sbom'],rel.split('/')[1]);nested+=1
        record_file(rel,'jsonl_inputs' if nested else 'metadata_jsonl',digest(raw),compact({'bom_rows':nested,'parse_errors':errors}))
    for p in sorted((ROOT/'benchmark').rglob('*.zip')):
        rel=p.relative_to(ROOT).as_posix()
        record_file(rel,'zip',sha(p))
        with zipfile.ZipFile(p) as z:
            for name in sorted(z.namelist()):
                if not name.endswith('.json'):continue
                raw=z.read(name);identity=rel+'::'+name
                try:value=json.loads(raw);error=None
                except ValueError as exc:value=None;error=str(exc)
                kind='json_parse_error' if error else 'bom' if is_bom(value) else 'metadata'
                fresh=record_file(identity,kind,digest(raw),error)
                if kind=='bom' and fresh:freeze_bom(db,identity,value,rel.split('/')[1])
    # Join every evaluation input, annotation and gold row without excluding unknowns.
    matched=db.execute('select count(*) from cases join gold on cases.gold_id=gold.id').fetchone()[0]
    assert matched==18608
    def verify_gold(item):
        identity,label=item;a=json.loads(label);annotation=ROOT/'benchmark/item3_evaluation/annotations'/(identity+'.json')
        assert json.loads(annotation.read_bytes())==a
        assert sha(ROOT/'benchmark/item3_evaluation'/a['sbom_file'])==a['export_format']['sbom_file_sha256']
    gold_rows=db.execute('select id,label from gold').fetchall()
    with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(verify_gold,gold_rows))
    report={'physical_and_archived_bom_occurrences':db.execute('select count(*) from cases').fetchone()[0],
            'unique_input_documents':db.execute('select count(*) from inputs').fetchone()[0],
            'unique_work_units':db.execute('select count(*) from units').fetchone()[0],
            'gold_evaluation_cases':matched,
            'by_benchmark_folder':dict(db.execute('select family,count(*) from cases group by family')),
            'file_kinds':dict(db.execute('select kind,count(*) from files group by kind')),
            'empty_or_invalid_component_lists':db.execute('select count(*) from inputs where components<=0').fetchone()[0],
            'max_components':db.execute('select max(components) from inputs').fetchone()[0],
            'policy':'All physical and archive BOM occurrences retained. Byte-equivalent JSON values may share computation; every original file remains in the ledger. Metadata and gold files are inventoried, not submitted as model inputs. No score/ambiguity/source filter.'}
    db.execute("insert into meta values ('plan_complete',?)",(compact(report),));db.commit()
    save(out/'inventory.json',report);db.close();print(compact(report),flush=True)


CORE=['candidate_advisories.py','candidate_match.py','cpe23.py','identity_versions.py','version_intervals.py',
      'source_version_parser.py','identity_evidence.py','identity_retrieval.py','identity_vector_index.py',
      'identification_agent_contracts.py','identification_agent_flow.py','identification_routing.py',
      'identification_choices.py','identification_wire.py','research/identification_batch_flow.py',
      'identification_cve_matching.py','identification_output.py','project_input_contract.py',
      'source_cpe_snapshot.py','precision_role_runtime.py','model_paths.py','safetensors_loading.py',
      'unified_identification.py','operational_versions.py','cve_evidence.py','ics_agent_matcher_full/ics_agent_matcher/matcher.py']


def signature():
    marker=json.loads((ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json').read_bytes())
    value={'code':{p:sha(source_path(p, root=ROOT)) for p in CORE},'runner':sha(Path(__file__)),
           'adapter':sha(ROOT/'models/precision_roles_qwen25_14b_v1/adapter_model.safetensors'),
           'base_files':marker['base_files_sha256'],
           'data':{p:sha(ROOT/p) for p in ['data/cpe_dictionary.jsonl','data/identity_aliases_v3.json',
                   'data/item3_identification_sources_v11/cves.jsonl','data/cisa_advisories.json','data/cisa_reference_manifest.json']}}
    assert value['adapter']==marker['adapter_sha256']
    return value,digest(compact(value).encode())


def unit_error(result):
    failures=[]
    for row in result.get('components',[]):
        for role in ('i1','i2','i3'):
            a=row.get(role,{}).get('agent') or {}
            if a.get('executed') and (a.get('error') or a.get('status') in ('unavailable','rejected')):
                failures.append({'role':role,'status':a.get('status'),'error':a.get('error')})
    return failures


def status(db):
    return {'units':db.execute('select count(*) from units').fetchone()[0],
            'agents_done':db.execute('select count(*) from units where agents is not null').fetchone()[0],
            'rules_done':db.execute('select count(*) from units where rules is not null').fetchone()[0],
            'case_occurrences':db.execute('select count(*) from cases').fetchone()[0]}


@contextmanager
def gpu_admission(out):
    from src.common.gpu_lease import FILE,assert_inference_available
    assert_inference_available()
    previous=json.loads(FILE.read_text(encoding='utf-8')) if FILE.is_file() else {}
    save(FILE,{'active':True,'pid':os.getpid(),'child_pid':None,'purpose':'item3_full_benchmark_validation','output':str(out),'started':time.time()})
    try:yield
    finally:
        current=json.loads(FILE.read_text(encoding='utf-8')) if FILE.is_file() else {}
        if current.get('pid')==os.getpid():save(FILE,{**previous,'active':False,'released_pid':os.getpid(),'reason':'benchmark worker exited'})


def run(out,batch_size,window):
    with gpu_admission(out):run_units(out,batch_size,window)
    summarize(out)


def run_units(out,batch_size,window):
    from src.item3.evidence.product_candidate_search import get_index
    from src.item3.evidence.local_vulnerability_lookup import get_source_lookup
    from src.common.runtime.shared_adapter_runtime import get_precision_runtime
    from src.research.identification_batch_flow import PacketCache,resolve_window
    from src.item3.matching.identification_pipeline import run_unified
    from src.item3.evidence.cisa_advisory_lookup import enrich_result
    db=db_open(out)
    if not db.execute("select value from meta where name='plan_complete'").fetchone():raise RuntimeError('Run plan first')
    details,sig=signature();old=db.execute("select value from meta where name='signature'").fetchone()
    if old and old[0]!=sig:raise RuntimeError('Frozen source/model/reference signature changed: use a new run folder')
    db.execute("insert or ignore into meta values ('signature',?)",(sig,));db.commit()
    save(out/'run_signature.json',details)
    for name in CORE:
        destination=out/'source_snapshot/src'/name;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes((source_path(name, root=ROOT)).read_bytes())
    (out/'source_snapshot/run_item3_benchmark_validation.py').write_bytes(Path(__file__).read_bytes())
    print(compact({'stage':'loading_reference_indexes','pid':os.getpid(),'progress':status(db)}),flush=True)
    index=get_index();nvd=get_source_lookup();runtime=get_precision_runtime()
    print(compact({'stage':'loading_tuned_adapter','dictionary_identities':len(index.docs)}),flush=True)
    runtime._load()
    import importlib.metadata,platform,torch
    marker=json.loads((runtime.folder/'training_complete.json').read_bytes())
    from src.common.model_paths import pinned_base
    environment={'python':sys.version,'platform':platform.platform(),'pid':os.getpid(),
        'gpu':torch.cuda.get_device_name(0),'cuda':torch.version.cuda,'torch':torch.__version__,
        'packages':{name:importlib.metadata.version(name) for name in ('transformers','peft','bitsandbytes','numpy','scipy','langgraph','jsonschema')},
        'adapter_sha256':runtime.identification_adapter_metadata['I1']['sha256'],
        'base_snapshot_revision':pinned_base(marker).name,'dictionary_identities':len(index.docs),
        'hash_seed':os.environ.get('PYTHONHASHSEED')}
    assert environment['adapter_sha256']==details['adapter']
    save(out/'execution_environment.json',environment)
    cache=PacketCache(out/'packet_cache.sqlite3',sig)
    def core(sbom,nvd,**options):
        return enrich_result(run_unified(sbom,nvd,mapping_scope='identification',**options))
    started=time.time()
    while True:
        pending=db.execute('select sha256,body,agents,rules from units where agents is null or rules is null order by sha256 limit ?',(window,)).fetchall()
        if not pending:break
        agent_inputs=[(key,decode(body)) for key,body,agents,rules in pending if agents is None]
        resolved=resolve_window(agent_inputs,cache,runtime.identification_batch,index=index,nvd=nvd,
                                batch_size=batch_size,core=core) if agent_inputs else {}
        for key,body,agents,rules in pending:
            if agents is None:
                result,trace=resolved[key];result['validation_agent_errors']=unit_error(result)
                db.execute('update units set agents=? where sha256=?',(encode(result),key))
            if rules is None:
                try:result=core(decode(body),nvd,index=index,mode='rules')
                except Exception as exc:result={'error':type(exc).__name__+': '+str(exc)}
                db.execute('update units set rules=? where sha256=?',(encode(result),key))
        db.commit();current=status(db);current.update(elapsed_seconds_this_process=round(time.time()-started,1),packet_cache=cache.statistics())
        save(out/'progress.json',current)
        print(compact(current),flush=True)
    cache.close();db.close()
    from src.common.runtime.shared_adapter_runtime import release_precision_runtime
    release_precision_runtime()


def summarize(out):
    from tools.item3.item3_v6_metrics import case_score,aggregate
    db=db_open(out);state=status(db)
    if state['agents_done']!=state['units'] or state['rules_done']!=state['units']:
        print(compact(state));return
    universe=set()
    for raw, in db.execute('select label from gold'):
        a=json.loads(raw);universe.update(a['expected_cves']);universe.update(a['unknown_cves'])
    from src.item3.evidence.local_vulnerability_lookup import get_source_lookup
    universe.update(get_source_lookup().records)
    totals={'agents':Counter(),'rules':Counter()};gold_scores={'agents':[],'rules':[]}
    role_counts={'agents':Counter(),'rules':Counter()};mode_comparison=Counter()
    @lru_cache(maxsize=2)
    def input_results(key):
        components=db.execute('select components from inputs where sha256=?',(key,)).fetchone()[0]
        results={}
        for mode in ('agents','rules'):
            chunks=[decode(r[0]) for r in db.execute(f'select u.{mode} from input_units i join units u on u.sha256=i.unit_sha256 where i.input_sha256=? order by i.position',(key,))]
            if components<=0:result={'components':[],'error':'empty_or_invalid_component_list','source_unresolved':True}
            else:
                result={'components':[r for chunk in chunks for r in chunk.get('components',[])]}
                errors=[c.get('error') for c in chunks if c.get('error')]
                if len(result['components'])!=components:errors.append('incomplete_component_analysis')
                if errors:result['error']='; '.join(errors)
            result['validation_agent_errors']=unit_error(result)
            results[mode]=result
        return results
    output=out/'case_results.jsonl'
    with output.open('w',encoding='utf-8',newline='\n') as f:
        for identity,key,family,gold_id in db.execute('select id,input_sha256,family,gold_id from cases order by id'):
            item={'file':identity,'input_sha256':key,'benchmark_folder':family,'gold_id':gold_id,'modes':{}}
            original=decode(db.execute('select body from inputs where sha256=?',(key,)).fetchone()[0])
            declared={v.get('id') for v in original.get('vulnerabilities',[]) if isinstance(v,dict) and v.get('id')}
            for mode in ('agents','rules'):
                result=input_results(key)[mode];rows=result.get('components',[])
                confirmed={c['cve_id'] for r in rows for c in r.get('cves',[]) if c['match_status']=='match'}
                candidates={c['cve_id'] for r in rows for c in r.get('cves',[]) if c['match_status']=='unknown'}
                counts={'components':len(rows),'accepted_identities':sum(r['validation']['status']=='validated' for r in rows),
                        'confirmed_cves':sorted(confirmed),'candidate_cves':sorted(candidates),
                        'advisory_linked_components':sum(bool(r.get('advisory_evidence')) for r in rows),
                        'error':result.get('error'),'agent_errors':result['validation_agent_errors'],
                        'declared_advisory_cves':len(declared),'retrieved_declared_advisory_cves':len(declared&(confirmed|candidates))}
                item['modes'][mode]=counts
                for row in rows:
                    for role in ('i1','i2','i3'):
                        record=row.get(role,{}).get('agent') or {}
                        role_counts[mode][role+':'+str(record.get('status','rules'))]+=1
                        role_counts[mode][role+':actual_model_inference']+=bool(record.get('llm_used'))
                    role_counts[mode]['version:'+str(row.get('i2',{}).get('status'))]+=1
                totals[mode].update(inputs=1,components=len(rows),accepted_identities=counts['accepted_identities'],
                    inputs_with_candidates=bool(confirmed|candidates),input_errors=bool(result.get('error')),
                    agent_errors=bool(counts['agent_errors']),declared_advisory_links=len(declared),retrieved_declared_advisory_links=len(declared&(confirmed|candidates)))
                if gold_id:
                    a=json.loads(db.execute('select label from gold where id=?',(gold_id,)).fetchone()[0]);score=case_score(result,a,universe)
                    if counts['agent_errors']:score['error']='agent_errors'
                    gold_scores[mode].append((a['scenario'],'evaluation',score));counts['gold_score']=score
            ac=set(item['modes']['agents']['confirmed_cves']);rc=set(item['modes']['rules']['confirmed_cves'])
            mode_comparison['same_confirmed_set' if ac==rc else 'different_confirmed_set']+=1
            mode_comparison['agents_add_confirmed_ids']+=len(ac-rc);mode_comparison['agents_remove_confirmed_ids']+=len(rc-ac)
            db.execute('insert or replace into case_results values (?,?)',(identity,compact(item)))
            f.write(compact(item)+'\n')
    db.commit()
    report={'complete':True,**state,'inventory':json.loads(db.execute("select value from meta where name='plan_complete'").fetchone()[0]),
            'all_benchmark_occurrences':{m:dict(c) for m,c in totals.items()},
            'actual_role_execution':{m:dict(c) for m,c in role_counts.items()},
            'agents_vs_rules':dict(mode_comparison),
            'gold_evaluation':{m:aggregate(rows,18608) for m,rows in gold_scores.items()},
            'cisa_source_coverage':json.loads((ROOT/'data/cisa_reference_manifest.json').read_bytes()),
            'interpretation':['Gold metrics apply to all 18,608 fixed evaluation inputs with unknowns preserved.',
                'Other benchmark BOMs have source-association coverage, not independently adjudicated precision.',
                'CISA source candidates remain unknown; an affected product range is not an observed installed release.',
                'Every original BOM occurrence is recorded, including empty/source-unavailable cases and duplicate JSON values.'],
            'execution_environment':json.loads((out/'execution_environment.json').read_bytes()),
            'benchmark_input_repairs':json.loads(db.execute("select value from meta where name='plan_complete'").fetchone()[0]).get('benchmark_input_repairs',[]),
            'logical_bom_values_and_gold_unchanged':True,'gold_modified':False,'adapter_weights_modified':False}
    save(out/'report.json',report);db.close();print(compact({'complete':True,'report':str(out/'report.json'),'occurrences':state['case_occurrences']}),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['plan','split','run','status','summarize'])
    p.add_argument('--output',type=Path,default=DEFAULT);p.add_argument('--batch-size',type=int,default=2);p.add_argument('--window',type=int,default=16)
    a=p.parse_args();out=a.output.resolve()
    if a.command=='plan':plan(out)
    elif a.command=='split':split_units(out)
    elif a.command=='run':run(out,a.batch_size,a.window)
    elif a.command=='summarize':summarize(out)
    else:
        db=db_open(out);print(compact(status(db)));db.close()


if __name__=='__main__':main()
