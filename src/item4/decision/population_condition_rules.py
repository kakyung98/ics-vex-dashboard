"""Deterministic source compiler and product matcher for the fixed 12,418 CVEs.

Source clauses which cannot be safely translated remain UNKNOWN operands.
CSAF recommended/first_fixed never becomes an open-ended fixed-version range.
"""
from pathlib import Path
from functools import lru_cache
import hashlib,json,re,sqlite3
from src.item4.decision.condition_logic_evaluation import leaves
ROOT=Path(__file__).resolve().parents[3];HOME=ROOT/'data/nist_population_vex_v3'
VERSION='all-cve-source-compiler/3'
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
def norm(s):return ' '.join(re.sub('[^a-z0-9]+',' ',s.casefold()).split())
from src.common.source_version_parser import number, compare, version_predicate, membership, row_membership, PARSER_VERSION

def witness(p):
    if p['op']=='=':return p['version']
    if p['op']=='any':return '1.0.0'
    if p['op']=='or':
        return next((x for a in p['args'] if (x:=witness(a)) and membership(p,x)=='true'),None)
    candidates=['0.0.1','1.0.0','2.0.0']
    bounds=p.get('args',[p])
    for b in bounds:
        v=b.get('version');n=number(v or '')
        if not n:continue
        prefix,parts=n;candidates.append(v)
        for delta in (-1,1):
            if parts[-1]+delta>=0:candidates.append(prefix+'.'.join(map(str,parts[:-1]+(parts[-1]+delta,))))
    return next((c for c in candidates if membership(p,c)=='true'),None)
def source_ref(source,ref=None):
    if ref is None:ref=dict(span=[0,len(source['text'])],quote=source['text'])
    return dict(source_id=source['id'],url=source['url'],source_sha256=source['text_sha256'],span=ref['span'],quote=ref['quote'],document_sha256=source.get('document_sha256'),json_pointer=source.get('pointer'))
def compile_condition(c,source):
    quote=c['source_ref']['quote'];text=c['proposition'].strip();qid='op-'+digest([source['id'],c['source_ref'],c['kind'],text])[:18]
    base=dict(id=qid,nist_fields=['C13-02.02'],source=source_ref(source,c['source_ref']),evidence_kinds=['configuration_record','operating_record','assessment_record','test_record'],options={'enabled':'Enabled for this exact component/function','disabled':'Disabled throughout the complete assessed scope','mixed':'Mixed or unresolved scope','unknown':'Unknown / not verified','conflicting':'Conflicting records'},true_values=['enabled'],false_values=['disabled'])
    kind=c['kind']
    if kind=='attacker_authentication':return None,None,'Attacker credential possession cannot be inferred from operator account settings.'
    if kind in ('network_access','local_access','physical_access'):
        if kind=='network_access':
            base.update(label='From the recorded origin, what is the reachability of the source-described interface on this component? '+quote,nist_fields=['C13-08.01','C16-02.03'],options={'reachable':'A permitted path to the affected interface exists','blocked':'All paths from this origin to that interface are blocked in the complete scope','mixed':'Path coverage is mixed or incomplete','unknown':'Unknown / not verified','conflicting':'Conflicting records'},true_values=['reachable'],false_values=['blocked'])
        else:base.update(label=('Is local execution/maintenance access available' if kind=='local_access' else 'Is the affected physical interface accessible')+' to the recorded origin for this component? '+quote,nist_fields=['C13-07.03'] if kind=='local_access' else ['C14-01.01'])
        return base,{'condition':qid},None
    # Only narrowly identified configuration atoms become editable questions.
    m=re.fullmatch(r'(?:the\s+)?([A-Z][A-Z0-9_]{3,}|(?:FTP|HTTP|HTTPS|SSH|Telnet|SNMP|SMB|web|debug|logging|SSLv3|TLS|DTLS)(?:\s+(?:server|service|interface|support|mode))?)(?:\s+(?:option|flag|mode))?\s+(?:(?:is|are|was|were)\s+)?(enabled|disabled|set)',text,re.I)
    if m and (re.fullmatch(r'[A-Z][A-Z0-9_]{3,}',m[1]) or re.match(r'^(?:FTP|HTTP|HTTPS|SSH|Telnet|SNMP|SMB|web|debug|logging|SSLv3|TLS|DTLS)\b',m[1],re.I)):
        base['label']='Is '+m[1]+' enabled/set on this exact assessed component instance?'
        expr={'condition':qid}
        if m[2].casefold()=='disabled':expr=dict(op='not',args=[expr])
        return base,expr,None
    return None,None,'Source condition has no validated operational enum adapter: '+text

def compile_paths(record):
    sources={s['id']:s for s in record['sources']};questions={};paths=[];gaps=[]
    for scenario in record['scenarios']:
        if scenario.get('scope_ambiguous'):gaps.append(dict(scenario=scenario['id'],reason='Ambiguous source relation'));continue
        mappings={};unknown={}
        for c in scenario['conditions']:
            s=sources.get(c['source_ref']['source_id']);r=c['source_ref']
            if not s or s.get('subject_ambiguous') or s['text'][r['span'][0]:r['span'][1]]!=r['quote']:
                q,expr,error=None,None,'Source span or subject binding is invalid'
            else:q,expr,error=compile_condition(c,s)
            if q:questions[q['id']]=q;mappings[c['id']]=expr
            else:
                missing='unresolved-'+digest([scenario['id'],c['id']])[:18];mappings[c['id']]={'condition':missing};unknown[missing]='unknown';gaps.append(dict(scenario=scenario['id'],condition=c['id'],reason=error,source_ref=r))
        def convert(node):
            if 'condition' in node:return mappings[node['condition']]
            return dict(op=node['op'],args=[convert(n) for n in node['args']])
        try:expression=convert(scenario['expression']);leaves(expression)
        except (ValueError,KeyError):gaps.append(dict(scenario=scenario['id'],reason='Invalid Boolean relation'));continue
        paths.append(dict(id=scenario['id'],expression=expression,product_keys=scenario['product_keys'],unknown_facts=unknown,source=source_ref(sources[scenario['source_ref']['source_id']],scenario['source_ref'])))
    covered={p['source']['source_id'] for p in paths}
    for source in record['sources']:
        if source['id'] in covered or source.get('subject_ambiguous'):continue
        text=source['text']
        # No mitigation text or conditional relation is converted into an implied AND.
        if re.search(r'\b(?:when|if|unless|only|enabled|disabled|mitigat\w*|workaround)\b',text,re.I):continue
        found=[];unknown={}
        for kind,pattern in [('network_access',r'\bremote (?:unauthenticated |authenticated )?attackers?\b'),('local_access',r'\blocal (?:unauthenticated |authenticated )?(?:attackers?|users?)\b'),('physical_access',r'\bphysical access\b')]:
            m=re.search(pattern,text,re.I)
            if not m:continue
            c=dict(kind=kind,proposition=m.group(),source_ref=dict(span=[m.start(),m.end()],quote=m.group()))
            q,expr,error=compile_condition(c,source)
            if q:questions[q['id']]=q;found.append(expr)
        if found:
            if re.search(r'\bauthenticated (?:remote |local )?attackers?\b|\b(?:remote|local) authenticated attackers?\b',text,re.I):
                missing='unresolved-attacker-credentials-'+digest(source['id'])[:12];unknown[missing]='unknown';found.append({'condition':missing});gaps.append(dict(scenario='descriptor:'+source['id'],reason='Attacker credentials are not an operator-observable inventory fact.'))
            expression=found[0] if len(found)==1 else dict(op='and',args=found)
            paths.append(dict(id='descriptor:'+source['id'],expression=expression,product_keys=source.get('product_keys',[]),unknown_facts=unknown,source=source_ref(source)))
    return dict(questions=list(questions.values()),paths=paths,gaps=gaps)

def connection():return sqlite3.connect('file:'+str(HOME/'catalog.sqlite3').replace('\\','/')+'?mode=ro',uri=True)
def manifest():
    p=HOME/'manifest.json';s=p.stat();return _manifest((s.st_size,s.st_mtime_ns,s.st_ctime_ns))
@lru_cache(maxsize=2)
def _manifest(signature):return json.loads((HOME/'manifest.json').read_text(encoding='utf-8'))
@lru_cache(maxsize=256)
def _get(cve,stamp):
    db=connection()
    try:r=db.execute('SELECT payload,sha256 FROM records WHERE cve=?',(cve,)).fetchone()
    finally:db.close()
    if not r:return None
    data=json.loads(r[0])
    if digest(data)!=r[1]:raise ValueError('Full-population compiled source integrity failure')
    return data
def get(cve):
    path=HOME/'catalog.sqlite3'
    if not path.exists():return None
    stat=path.stat();return _get(cve,(stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns))
def choose(record,product):
    return [p for p in record['products'] if norm(product) in {norm(v) for v in p['aliases']}]
def make_rule(cve,product):
    r=get(cve)
    if r is None:return None
    from src.item4.analysis import exploitation_prerequisites as VEP
    from copy import deepcopy
    r=deepcopy(r)
    r['compiled'],artifact,extraction_error=VEP.compiled(r)
    matched=choose(r,product);keys={p['key'] for p in matched};expressions=[];questions={};implicit={};sources=[];gaps=list(r['compiled']['gaps']);path_scopes=[]
    for path in r['compiled']['paths']:
        if not matched:continue
        if path['product_keys'] and keys and not keys.intersection(path['product_keys']):continue
        expression=path['expression']
        if artifact is not None:
            guard='scope-vep:'+digest(path['id'])[:20]
            expression=dict(op='and',args=[expression,{'condition':guard}]);implicit[guard]='unknown'
            path_scopes.append(dict(condition_id=guard,product_keys=path['product_keys'],scope_evidence=path['scope_evidence']))
        expressions.append(expression);implicit.update(path['unknown_facts']);sources.append(path['source'])
        wanted=leaves(path['expression'])
        for q in r['compiled']['questions']:
            if q['id'] in wanted:questions[q['id']]=q
    # Missing or partial extraction never constitutes a global negative proof.
    if not expressions:
        name='unresolved-vep-source-scope'
        expressions=[{'condition':name}];implicit[name]='unknown'
        gaps.append(dict(reason='No source-bound LLM VEP scenario is available for this product.'))
    expression=expressions[0] if len(expressions)==1 else dict(op='or',args=expressions)
    if gaps:
        implicit['unresolved-source-gaps']='unknown';expression=dict(op='and',args=[expression,{'condition':'unresolved-source-gaps'}])
    source=(sources or [source_ref(r['sources'][0])])[0]
    return dict(cve=cve,product=product,product_aliases=[product],version_scheme='csaf_source_set',source_product_rows=matched,questions=list(questions.values()),expression=expression,coverage_complete=False,source=source,fix_sources=[source],implicit_values=implicit,population_source_sha256=r['sha256'],compiled_gaps=gaps,decision_mode='full_population',known_source_products=len(r['products']),source_backing=r['source_backing'],source_path_scopes=path_scopes,extraction_provider='generative_llm_vep',prerequisite=artifact,extraction_format=VEP.VERSION,extraction_error=extraction_error)
def status(rule,version):
    states=set();unresolved=False
    for p in rule['source_product_rows']:
        match=row_membership(p,version)
        if match=='unknown':unresolved=True
        if match=='true':states.add(p['status'])
    if len(states)>1:return 'conflicting'
    # An untranslated row may overlap a recognized release and contradict it.
    # Preserve that uncertainty for safety claims and affected claims alike.
    if unresolved:return 'unknown'
    if states:return {'known_affected':'vulnerable','fixed':'fixed','known_not_affected':'unaffected','under_investigation':'unknown'}[next(iter(states))]
    return 'unknown' # Outside known-affected does not mean fixed/not affected.


def get_many(cves):
    """Read a bounded batch through one connection; preserve every row check."""
    if len(cves)>500 or len(cves)!=len(set(cves)):
        raise ValueError('Invalid source batch')
    if not cves:return []
    db=connection()
    try:
        rows=db.execute('SELECT cve,payload,sha256 FROM records WHERE cve IN ('+','.join('?' for _ in cves)+')',list(cves)).fetchall()
    finally:db.close()
    found={}
    for cve,payload,seal in rows:
        record=json.loads(payload)
        if record['cve']!=cve or digest(record)!=seal:
            raise ValueError('Full-population source batch integrity failure')
        found[cve]=record
    if set(found)!=set(cves):raise ValueError('Missing full-population source records')
    return [found[cve] for cve in cves]


def path_bindings(rule,version):
    """Bind each VEP route to its own source product/version rows server-side."""
    values={};trace=[]
    for scope in rule.get('source_path_scopes',[]):
        rows=[p for p in rule['source_product_rows'] if p['key'] in scope['product_keys']]
        memberships=[dict(product_key=p['key'],source_status=p['status'],version_text=p['version_text'],
                          value=row_membership(p,version) if version else 'unknown',
                          document_sha256=p['document_sha256'],product_pointer=p['product_pointer'],status_pointer=p['status_pointer']) for p in rows]
        states=[m['value'] for m in memberships]
        value='unknown' if not states or 'unknown' in states else 'true' if 'true' in states else 'false'
        values[scope['condition_id']]=value
        trace.append(dict(condition_id=scope['condition_id'],value=value,actual_version=version,
                          source_scope_evidence=scope['scope_evidence'],memberships=memberships))
    return values,trace
