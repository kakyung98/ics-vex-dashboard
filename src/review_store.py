"""Local durable job/plan/review objects. Never exported to public Pages."""
from pathlib import Path
import json,sqlite3,time
DB=Path(__file__).resolve().parents[1]/'results/runtime_sessions.sqlite3'

def connection():
    DB.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(str(DB),timeout=30)
    c.execute('CREATE TABLE IF NOT EXISTS objects (kind TEXT, id TEXT, expires REAL, payload TEXT, PRIMARY KEY(kind,id))')
    return c

def put(kind,key,value,ttl=86400):
    payload=json.dumps(value,ensure_ascii=False)
    if len(payload.encode())>64*1024*1024:raise ValueError('Session snapshot exceeds 64 MiB.')
    with connection() as c:c.execute('INSERT OR REPLACE INTO objects VALUES (?,?,?,?)',(kind,key,time.time()+ttl,payload))

def get(kind,key):
    with connection() as c:row=c.execute('SELECT expires,payload FROM objects WHERE kind=? AND id=?',(kind,key)).fetchone()
    return json.loads(row[1]) if row and row[0]>time.time() else None
