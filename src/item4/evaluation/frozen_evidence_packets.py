"""Sequentially stage pinned v3 packets on local storage for full-population review."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import zlib


PREFIX = 'benchmark/item4_evaluation/extracted_ox_v3/cves/'


def stage(delivery, manifest, archive_sha, population, *, cache_dir=None):
    wanted = set(population)
    if len(wanted) != len(population):
        raise ValueError('Duplicate frozen CVE IDs')
    cache = Path(cache_dir or (Path(tempfile.gettempdir())/'ICS-VEX'/'moe-inputs'))
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / (archive_sha + '.sqlite3')
    if target.exists():
        return target
    archive = delivery / 'delivery.tar.gz'
    h = hashlib.sha256()
    with archive.open('rb') as src:
        for chunk in iter(lambda: src.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    if h.hexdigest() != archive_sha:
        raise ValueError('The frozen scenario delivery failed its archive hash check')
    with tempfile.TemporaryDirectory(dir=cache) as directory:
        build = Path(directory)/'inputs.sqlite3'
        with closing(sqlite3.connect(build)) as db, tarfile.open(archive, 'r|gz') as stream:
            db.execute('PRAGMA journal_mode=OFF')
            db.executescript('''
                CREATE TABLE packets(cve TEXT PRIMARY KEY, packet BLOB NOT NULL);
                CREATE TABLE cases(id TEXT PRIMARY KEY, cve TEXT NOT NULL);
                CREATE INDEX by_cve ON cases(cve);
            ''')
            for member in stream:
                if not member.isfile() or not member.name.startswith(PREFIX):
                    continue
                name = member.name[len(PREFIX):]
                if not name.endswith('.json') or name[:-5] not in wanted:
                    raise ValueError('Unexpected packet in frozen archive: ' + name)
                cve = name[:-5]
                raw = stream.extractfile(member).read()
                if hashlib.sha256(raw).hexdigest() != manifest[member.name]:
                    raise ValueError('Frozen archive packet hash mismatch: ' + cve)
                packet = json.loads(raw)
                if packet['cve'] != cve or not packet['cases'] or any(c['cve'] != cve for c in packet['cases']):
                    raise ValueError('Invalid frozen CVE packet or scope: ' + cve)
                db.execute('INSERT INTO packets VALUES (?,?)', (cve, zlib.compress(raw, level=1)))
                db.executemany('INSERT INTO cases VALUES (?,?)', ((c['id'], cve) for c in packet['cases']))
            if {r[0] for r in db.execute('SELECT cve FROM packets')} != wanted:
                raise ValueError('The archive does not contain the exact frozen CVE population')
            db.commit()
        try:
            os.link(build, target)
        except FileExistsError:
            pass  # Another builder published the same sealed input first.
    return target


def read(path, cve):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        row = db.execute('SELECT packet FROM packets WHERE cve=?', (cve,)).fetchone()
        if row is None:
            raise ValueError('Staged packet missing for ' + cve)
        return zlib.decompress(row[0])
