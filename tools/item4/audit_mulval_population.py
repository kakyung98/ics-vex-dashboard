"""Audit every CVE against source snapshots and actual batch MulVAL artifacts."""
from pathlib import Path
from functools import lru_cache
from collections import Counter
import argparse,csv,hashlib,io,json,re,sqlite3,sys,zlib,zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from src.item4.decision import mulval_attack_graphs as M
from src.item4.decision import batch_attack_graphs as B
from src.item4.decision import attack_graph_builder as G


def csv_text(rows):
    out=io.StringIO();csv.writer(out,lineterminator='\n').writerows(rows);return out.getvalue()


def audit(home,source_db,cache):
    home=Path(home);cache=Path(cache)
    manifest=json.loads((home/'manifest.json').read_text())
    if manifest['state']!='complete':raise ValueError('Population generation is not complete')
    source=sqlite3.connect('file:'+str(source_db).replace(chr(92),'/')+'?mode=ro&immutable=1',uri=True)
    inputs={c:(raw,sha) for c,raw,sha in source.execute('SELECT cve,payload,sha256 FROM records')};source.close()
    counts=Counter();seen=set();batches=set();quote_count=0
    @lru_cache(maxsize=8)
    def batch(key):
        receipt=json.loads((cache/(key+'.json')).read_text(encoding='utf-8'))
        if receipt['sha256']!=M.digest({k:v for k,v in receipt.items() if k!='sha256'}):raise ValueError('Batch receipt integrity failure')
        vertices={r[0]:r for r in csv.reader(io.StringIO(receipt['files']['VERTICES.CSV'])) if r}
        arcs=[r for r in csv.reader(io.StringIO(receipt['files']['ARCS.CSV'])) if r]
        trace=receipt['files']['trace_output.P'].splitlines()
        return receipt,vertices,arcs,trace
    db=sqlite3.connect('file:'+str(home/'graphs.sqlite3').replace(chr(92),'/')+'?mode=ro&immutable=1',uri=True)
    for cve,payload,seal,nodes,edges,gaps in db.execute('SELECT cve,payload,sha256,nodes,edges,gaps FROM graphs'):
        raw=zlib.decompress(payload)
        if hashlib.sha256(raw).hexdigest()!=seal:raise ValueError('Graph storage checksum mismatch')
        graph=json.loads(raw)
        if graph['cve']!=cve or cve in seen or not graph['nodes']:raise ValueError('Missing, duplicate or wrong-CVE graph')
        seen.add(cve);record_raw,record_seal=inputs[cve];record=json.loads(record_raw)
        if M.digest(record)!=record_seal:raise ValueError('Source record checksum mismatch')
        expected=M.compile_program(B.contract(record));program=graph['mulval']['program']
        if expected!=program:raise ValueError('Graph program differs from source contract: '+cve)
        if G.evaluate(graph,{})['value']!='unknown' or graph['coverage_complete']:raise ValueError('Unobserved source graph asserted a verdict')
        if graph['source_products']!=record['products']:raise ValueError('Lost source product scope')
        provenance=graph['mulval'].get('batch_provenance',{})
        if not provenance:raise ValueError('Missing actual batch provenance: '+cve)
        key=provenance['batch_program_sha256'];receipt,vertices,arcs,trace=batch(key);batches.add(key)
        if receipt['sha256']!=provenance['batch_receipt_sha256']:raise ValueError('Wrong batch receipt')
        owner=provenance['namespace_owner'];symbols=provenance['namespace_symbols'];rules=provenance['namespace_rules']
        if symbols!={'n'+M.digest([owner,program['sha256'],v])[:28]:v for v in program['symbols'].values()}:raise ValueError('Invalid CVE namespace')
        if rules!={'icsvex_'+M.digest([owner,program['sha256'],v])[:28]:v for v in program['rules']}:raise ValueError('Invalid rule namespace')
        def restore(text):
            text=re.sub(r'\bn[a-f0-9]{28}\b',lambda m:symbols[m[0]],text)
            return re.sub(r'icsvex_[a-f0-9]{28}',lambda m:rules[m[0]],text)
        graph_by_raw={n['mulval_vertex']:n for n in graph['nodes']};raw_ids=set(graph_by_raw)
        selected=[]
        for number,row in vertices.items():
            is_owned=any(s in row[1] for s in symbols) or any(r in row[1] for r in rules)
            if is_owned:
                if number not in raw_ids:raise ValueError('MulVAL vertex omitted from CVE projection')
                item=list(row);item[1]=restore(item[1]);selected.append(item)
                if item[1]!=graph_by_raw[number]['mulval_label']:raise ValueError('Invented or changed MulVAL vertex')
        if len(selected)!=len(raw_ids):raise ValueError('Projected vertex not in actual MulVAL output')
        selected_arcs=[]
        for row in arcs:
            a,b=row[:2]
            if a in raw_ids or b in raw_ids:
                if not (a in raw_ids and b in raw_ids):raise ValueError('Cross-CVE edge in actual batch')
                selected_arcs.append(row)
        graph_ids={n['id']:n['mulval_vertex'] for n in graph['nodes']}
        if {(graph_ids[e['target']],graph_ids[e['source']]) for e in graph['edges']}!={tuple(r[:2]) for r in selected_arcs}:
            raise ValueError('Graph edges differ from actual MulVAL output')
        selected_trace=[]
        for line in trace:
            refs=re.findall(r'\bn[a-f0-9]{28}\b',line)
            if any(s in symbols for s in refs):
                if any(s not in symbols for s in refs):raise ValueError('Cross-CVE trace')
                selected_trace.append(restore(line))
        files={'VERTICES.CSV':csv_text(selected),'ARCS.CSV':csv_text(selected_arcs),
               'trace_output.P':'primitive(icsObservation,2).\nderived(icsState,2).\nmeta(attackGoal,1).\n'+'\n'.join(selected_trace)+'\n'}
        if {n:hashlib.sha256(t.encode()).hexdigest() for n,t in files.items()}!=graph['mulval']['artifact_sha256']:
            raise ValueError('Source graph projection artifact mismatch')
        projected=dict(returncode=0,files=files,backend=receipt['backend'],tool_sha256=receipt['tool_sha256'],program_sha256=program['sha256'],**provenance)
        if M.digest(projected)!=graph['mulval']['receipt_sha256']:raise ValueError('Projected receipt identity mismatch')
        sources={s['id']:s for s in record['sources']}
        refs={M.digest(ref):ref for ref in graph['source_refs']}
        for rule in program['rules'].values():
            refs.update({M.digest(ref):ref for ref in rule['source_refs']})
        for ref in refs.values():
            source=sources[ref['source_id']];a,b=ref['span']
            if source['text'][a:b]!=ref['quote'] or source['text_sha256']!=ref['source_sha256']:
                raise ValueError('Source quotation alignment failure')
            quote_count+=1
        counts.update(cves=1,nodes=nodes,edges=edges,gaps=gaps)
        counts['with_source_paths' if graph['product_path_scopes'] else 'unknown_only_no_source_path']+=1
        counts['with_operational_fields' if graph['operational_field_ids'] else 'without_operational_adapter']+=1
        counts['without_source_snapshot']+=not bool(graph['source_refs'])
        counts['identity_unresolved']+=bool(graph['source_identity_unresolved'])
    db.close()
    if seen!=set(inputs) or len(seen)!=12418:raise ValueError('Population membership mismatch')
    report=dict(passed=True,version=B.VERSION,counts=dict(counts),excluded_cves=0,
                all_12418_have_actual_mulval_nodes=True,batch_receipts=len(batches),
                source_snapshot_quotes_checked=quote_count,all_actual_vertices_edges_and_namespace_projections_checked=True,
                all_programs_recompiled_from_source_snapshots=True,all_unobserved_goals_unknown=True,
                independent_semantic_accuracy_verified=False,
                limitation='Source-snapshot/rule/derivation integrity validation, not independent CVE semantic or real-asset accuracy.',
                population_sha256=M.digest(sorted(seen)))
    (home/'integrity_audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    with zipfile.ZipFile(home/'mulval_batch_receipts.zip','w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for key in sorted(batches):archive.write(cache/(key+'.json'),arcname=key+'.json')
    print(json.dumps(report),flush=True)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--home',type=Path,required=True);p.add_argument('--source-db',type=Path,required=True);p.add_argument('--cache',type=Path,required=True)
    a=p.parse_args();audit(a.home,a.source_db,a.cache)
