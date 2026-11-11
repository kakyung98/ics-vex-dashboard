"""Indexed full-population source and prerequisite drafts; never automatic approval."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'results/ics_sentence_conditions_v1'
DATABASE=ROOT/'results/operational_corpus_v1/corpus.sqlite3'
EXPECTED_POPULATION=12418
KIND_DOMAINS={'access_position':'O2','attacker_auth_or_privilege':'O3','victim_auth_or_privilege':'O3',
    'user_action':'O5','input_or_ingress':'O5','feature_or_configuration':'O1','operating_state':'O1'}


def encoded(value):return json.dumps(value,ensure_ascii=False,separators=(',',':'))


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def rows(path):
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            if line.strip():yield json.loads(line)


def connect(path=None,write=False,*,cross_thread=False):
    path=Path(path or DATABASE)
    if not write and not path.is_file():raise FileNotFoundError('Full corpus database is not built')
    if write:path.parent.mkdir(parents=True,exist_ok=True)
    if write and cross_thread:raise ValueError('Cross-thread connections are read-only')
    db=sqlite3.connect(str(path) if write else path.resolve().as_uri()+'?mode=ro',uri=not write,timeout=60,check_same_thread=not cross_thread)
    db.row_factory=sqlite3.Row
    return db


def make_draft(record,extraction):
    sources={s['id']:s for s in record['sources']}
    facts=[];invalid=[]
    for index,fact in enumerate(extraction.get('facts',[])):
        try:
            source=sources[fact['source_id']];start,end=fact['source_span']
            if not 0<=start<end<=len(source['text']) or source['text'][start:end]!=fact['source_quote']:
                raise ValueError('Source span mismatch')
            key=hashlib.sha256(encoded(fact).encode()).hexdigest()[:24]
            necessity=fact.get('necessity','described_not_proven_required')
            kind=fact.get('kind','unknown');domain=KIND_DOMAINS.get(kind,'unmapped')
            # These are collection prompts, not assertions that an operator knows an attacker's secrets.
            observable=kind in {'access_position','user_action','input_or_ingress','feature_or_configuration','operating_state','victim_auth_or_privilege'}
            facts.append(dict(id='corpus:'+key,predicate='custom',target='',value=fact['condition'],kind=kind,
                proposed_necessity=necessity,role='nonrequirement' if necessity in {'not_required','explicitly_not_a_necessary_condition'} else 'candidate_condition',
                domain=domain,operator_observable=observable,explicitness='reviewed_inference',
                source_refs=[dict(source_id=source['id'],span=[start,end],quote=fact['source_quote'])],
                evidence_requirements=fact.get('evidence_demands',[]),validation_status='pending_review',
                question=('Which available records establish this operating fact: '+fact['condition']+'?') if observable else None,
                missing=['specific target binding','source necessity review','CVE-specific Boolean relationship'],
                eligible_for_vex=False))
        except (KeyError,TypeError,ValueError) as exc:
            invalid.append(dict(index=index,error=str(exc),retained_original=fact))
    read=extraction.get('all_packets_read') is True
    state=('source_evidence_error' if invalid else 'identity_review_needed' if record.get('identity_ambiguous') else
           'source_reading_pending' if not read else 'conditions_pending_review' if facts else 'no_explicit_conditions')
    return dict(cve=record['cve'],state=state,source_reading_complete=read,conditions=facts,invalid_candidates=invalid,
        formula=None,formula_review_required=True,source_path_proposals=extraction.get('packet_path_proposals',[]),
        nonrequirements=[f for f in facts if f['role']=='nonrequirement'],
        unknowns=['Actual asset facts and unmentioned prerequisites are unknown'],
        automatic_approvals=0,eligible_for_vex=False,extraction_state=extraction.get('extraction_state','not_started'))


def build(source=None,database=None,expected_population=EXPECTED_POPULATION):
    source=Path(source or SOURCE);database=Path(database or DATABASE)
    manifest=json.loads((source/'input_manifest.json').read_text(encoding='utf-8'))
    if sha(source/'full_inputs.jsonl')!=manifest['inputs_sha256']:raise ValueError('Full corpus source digest mismatch')
    extracted={r['cve']:r for r in rows(source/'semantic_extractions.jsonl')}
    records=list(rows(source/'full_inputs.jsonl'))
    ids={r['cve'] for r in records}
    if len(ids)!=len(records) or len(records)!=expected_population:raise ValueError('Full population is required, with no duplicates')
    if not set(extracted)<=ids:raise ValueError('Extraction contains a CVE outside the source population')
    stamp=datetime.now(timezone.utc).isoformat();counts=Counter();condition_count=0;invalid_count=0
    with connect(database,write=True) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''CREATE TABLE IF NOT EXISTS corpus(cve TEXT PRIMARY KEY,state TEXT,source_read INTEGER,conditions INTEGER,record TEXT,draft TEXT);
        CREATE INDEX IF NOT EXISTS corpus_state ON corpus(state,cve);
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,payload TEXT);
        CREATE TABLE IF NOT EXISTS assignments(condition_id TEXT PRIMARY KEY,cve TEXT,cluster_id TEXT,similarity REAL);
        CREATE INDEX IF NOT EXISTS assignments_cluster ON assignments(cluster_id,cve);
        CREATE INDEX IF NOT EXISTS assignments_cve ON assignments(cve,cluster_id);
        CREATE TABLE IF NOT EXISTS clusters(cluster_id TEXT PRIMARY KEY,payload TEXT);''')
        # One transaction exposes either the old population or the entire new snapshot.
        db.execute('DELETE FROM corpus');db.execute('DELETE FROM assignments');db.execute('DELETE FROM clusters')
        for record in records:
            if len({s['id'] for s in record['sources']})!=len(record['sources']):raise ValueError('Duplicate source ID')
            for s in record['sources']:
                if hashlib.sha256(s['text'].encode()).hexdigest()!=s['text_sha256']:raise ValueError('Source passage digest mismatch')
            draft=make_draft(record,extracted.get(record['cve'],{}))
            n=len(draft['conditions']);condition_count+=n;invalid_count+=len(draft['invalid_candidates']);counts[draft['state']]+=1
            db.execute('INSERT INTO corpus VALUES(?,?,?,?,?,?)',(record['cve'],draft['state'],int(draft['source_reading_complete']),n,encoded(record),encoded(draft)))
        summary=dict(population=len(records),excluded=0,indexed_cves=len(records),states=dict(counts),
            source_read_cves=sum(1 for r in records if extracted.get(r['cve'],{}).get('all_packets_read') is True),
            condition_candidates=condition_count,invalid_candidates=invalid_count,automatic_approvals=0,
            source_digest=manifest['inputs_sha256'],extraction_digest=sha(source/'semantic_extractions.jsonl'),
            updated_at=stamp,clustering=dict(status='not_built',unit='source-linked condition candidate',eligible_for_vex=False))
        db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('summary',encoded(summary)))
    return summary


def summary(database=None):
    with connect(database) as db:
        row=db.execute("SELECT payload FROM metadata WHERE key='summary'").fetchone()
    if not row:raise ValueError('Full corpus index has not been built')
    return json.loads(row['payload'])


def search(query='',state='',cluster='',offset=0,limit=50,database=None):
    if offset<0 or not 1<=limit<=200:raise ValueError('Use nonnegative offset and 1–200 rows per page')
    where=['1=1'];args=[]
    if query:where.append('c.cve LIKE ?');args.append('%'+query.strip().upper()+'%')
    if state:where.append('c.state=?');args.append(state)
    if cluster:where.append('EXISTS(SELECT 1 FROM assignments a WHERE a.cve=c.cve AND a.cluster_id=?)');args.append(cluster)
    with connect(database) as db:
        count=db.execute('SELECT count(*) FROM corpus c WHERE '+' AND '.join(where),args).fetchone()[0]
        data=db.execute('SELECT c.cve,c.state,c.source_read,c.conditions FROM corpus c WHERE '+' AND '.join(where)+' ORDER BY c.cve LIMIT ? OFFSET ?',[*args,limit,offset]).fetchall()
        result=[]
        for row in data:
            clusters=[r[0] for r in db.execute('SELECT DISTINCT cluster_id FROM assignments WHERE cve=? ORDER BY cluster_id',(row['cve'],))]
            result.append(dict(row,cluster_ids=clusters))
    return dict(total=count,offset=offset,limit=limit,rows=result)


def detail(cve,database=None):
    with connect(database) as db:
        row=db.execute('SELECT record,draft FROM corpus WHERE cve=?',(cve.upper(),)).fetchone()
        if not row:return None
        assigned=[dict(r) for r in db.execute('SELECT condition_id,cluster_id,similarity FROM assignments WHERE cve=?',(cve.upper(),))]
    return dict(record=json.loads(row['record']),draft=json.loads(row['draft']),assignments=assigned)


def clusters(database=None):
    with connect(database) as db:
        return [json.loads(r['payload']) for r in db.execute('SELECT payload FROM clusters ORDER BY cluster_id')]
