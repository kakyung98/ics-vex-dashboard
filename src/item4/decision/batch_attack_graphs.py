"""Generate every CVE graph through disjoint, namespaced MulVAL batches.

Unknown-only CVEs still receive actual MulVAL nodes and inference rules. Product
and source-path guards prevent combining conditions from unrelated products.
"""
from collections import defaultdict
from copy import deepcopy
import csv
import io
import json
from pathlib import Path
import re
import sqlite3
import zlib

from src.item4.decision import attack_graph_builder as G
from src.item4.decision import population_condition_rules as P
from src.item4.decision import mulval_attack_graphs as M

VERSION='mulval-full-population/1'
HOME=Path(__file__).resolve().parents[3]/'data/runtime/mulval_population_20261118'


def contract(record):
    cve=record['cve'];compiled=record['compiled'];questions=deepcopy(compiled['questions'])
    paths=[];scopes=[];refs=[];gaps=deepcopy(compiled['gaps'])
    for path in compiled['paths']:
        qid='source-scope-'+M.digest([cve,path['id'],path['product_keys']])[:20]
        questions.append(dict(id=qid,label='Verify this exact source product/path binding',nist_fields=[],source=path['source']))
        scopes.append(dict(question_id=qid,source_path_id=path['id'],product_keys=path['product_keys'],source=path['source'],default='unknown'))
        paths.append(dict(op='and',args=[dict(condition=qid),path['expression']]))
        refs.append(path['source'])
    if not paths:
        paths=[dict(condition='unresolved-source-prerequisites')]
        gaps.append(dict(reason='No translated source path; this is an unknown graph, not a safety conclusion.'))
    if not refs:
        refs=[P.source_ref(source) for source in record['sources']]
    refs=list({M.digest(ref):ref for ref in refs}.values())
    expression=paths[0] if len(paths)==1 else dict(op='or',args=paths)
    # Catalogues are not actual operating observations; incomplete extraction
    # cannot be turned into exhaustive coverage for any CVE.
    result=G.source_contract(cve,expression,questions,
        dict(asset_ref='unbound',product='source catalogue; select an actual product before assessment',
             build='unknown',config_baseline='unknown',mode='unknown',origin='unknown'),
        'unresolved',False,record['sha256'],gaps,refs)
    result.update(population_version=VERSION,product_path_scopes=scopes,
                  source_products=record['products'],source_identity_unresolved=record.get('identity_unresolved',False),
                  source_backing=record['source_backing'],extraction_stage='source_compiler_candidates',
                  default_observation='unknown',vex_status='under_investigation',
                  assessment_binding_required=True)
    return result


def combine(programs):
    lines=[];rules=[];owners={};reverse={};rule_owner={};original_rules={}
    declarations=['primitive(icsObservation(_node,_polarity)).','derived(icsState(_node,_polarity)).',
                  'meta(attackGoal(_)).',':- table icsState/2.']
    for owner,program in enumerate(programs):
        symbols={old:'n'+M.digest([owner,program['sha256'],old])[:28] for old in program['symbols'].values()}
        rids={old:'icsvex_'+M.digest([owner,program['sha256'],old])[:28] for old in program['rules']}
        for old,new in symbols.items():owners[new]=owner;reverse[new]=old
        for old,new in rids.items():rule_owner[new]=owner;original_rules[new]=old
        def rewrite(text):
            text=re.sub(r'\bn[a-f0-9]{28}\b',lambda m:symbols[m[0]],text)
            return re.sub(r'icsvex_[a-f0-9]{28}',lambda m:rids[m[0]],text)
        lines.extend(rewrite(program['input_P']).splitlines())
        rules.extend(rewrite(program['rules_P']).splitlines()[len(declarations):])
    merged=dict(version=VERSION,input_P='\n'.join(lines)+'\n',rules_P='\n'.join(declarations+rules)+'\n',
                input_semantics='disjoint_namespaced_topology_placeholders_not_observations')
    merged['sha256']=M.digest(merged)
    return merged,dict(symbol_owners=owners,reverse_symbols=reverse,rule_owners=rule_owner,reverse_rules=original_rules)


def partition(programs,merged,namespace,receipt):
    vertices=defaultdict(list);arcs=defaultdict(list);trace=defaultdict(list);owner_by_vertex={}
    def restore(text):
        text=re.sub(r'\bn[a-f0-9]{28}\b',lambda m:namespace['reverse_symbols'][m[0]],text)
        return re.sub(r'icsvex_[a-f0-9]{28}',lambda m:namespace['reverse_rules'][m[0]],text)
    for row in csv.reader(io.StringIO(receipt['files']['VERTICES.CSV'])):
        if not row:continue
        if row[2]=='AND':
            rid=re.search(r'icsvex_[a-f0-9]{28}',row[1])[0];owner=namespace['rule_owners'][rid]
        else:
            symbol=re.search(r'\bn[a-f0-9]{28}\b',row[1])[0];owner=namespace['symbol_owners'][symbol]
        owner_by_vertex[row[0]]=owner;row[1]=restore(row[1]);vertices[owner].append(row)
    for row in csv.reader(io.StringIO(receipt['files']['ARCS.CSV'])):
        if not row:continue
        owner=owner_by_vertex[row[0]]
        if owner_by_vertex[row[1]]!=owner:raise ValueError('Cross-CVE edge in a disjoint MulVAL batch')
        arcs[owner].append(row)
    for line in receipt['files']['trace_output.P'].splitlines():
        found=re.findall(r'\bn[a-f0-9]{28}\b',line)
        if not found:continue
        groups={namespace['symbol_owners'][symbol] for symbol in found}
        if len(groups)!=1:raise ValueError('Cross-CVE trace step')
        trace[next(iter(groups))].append(restore(line))
    def csv_text(rows):
        output=io.StringIO();writer=csv.writer(output,lineterminator='\n');writer.writerows(rows);return output.getvalue()
    results=[]
    for index,program in enumerate(programs):
        if not vertices[index] or not trace[index]:raise ValueError('CVE omitted from MulVAL output')
        files={'VERTICES.CSV':csv_text(vertices[index]),'ARCS.CSV':csv_text(arcs[index]),
               'trace_output.P':'primitive(icsObservation,2).\nderived(icsState,2).\nmeta(attackGoal,1).\n'+'\n'.join(trace[index])+'\n'}
        projected=dict(returncode=0,files=files,backend=receipt['backend'],tool_sha256=receipt['tool_sha256'],
                       program_sha256=program['sha256'],batch_receipt_sha256=receipt['sha256'],
                       batch_program_sha256=merged['sha256'],namespace_owner=index,namespace_symbols={k:v for k,v in namespace['reverse_symbols'].items() if namespace['symbol_owners'][k]==index},namespace_rules={k:v for k,v in namespace['reverse_rules'].items() if namespace['rule_owners'][k]==index},projection='exact CSV/trace partition; namespace restored; no inferred edges')
        projected['sha256']=M.digest(projected);results.append(projected)
    return results


def store(connection,record,graph):
    raw=json.dumps(graph,ensure_ascii=False,separators=(',',':')).encode()
    connection.execute('INSERT OR REPLACE INTO graphs VALUES(?,?,?,?,?,?)',
        (record['cve'],zlib.compress(raw,6),__import__('hashlib').sha256(raw).hexdigest(),
         len(graph['nodes']),len(graph['edges']),len(graph['gaps'])))


def get(cve,home=HOME):
    path=Path(home)/'graphs.sqlite3'
    if not path.exists():return None
    db=sqlite3.connect('file:'+str(path).replace('\\','/')+'?mode=ro',uri=True)
    try:row=db.execute('SELECT payload,sha256 FROM graphs WHERE cve=?',(cve,)).fetchone()
    finally:db.close()
    if not row:return None
    raw=zlib.decompress(row[0])
    if __import__('hashlib').sha256(raw).hexdigest()!=row[1]:raise ValueError('Population graph integrity failure')
    graph=json.loads(raw)
    if graph['cve']!=cve or graph['sha256']!=M.digest({k:v for k,v in graph.items() if k!='sha256'}):raise ValueError('Population graph identity/integrity failure')
    return graph
