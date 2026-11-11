"""Replay the unchanged identification core, resolving exact pending packets in GPU batches."""
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
import sqlite3
import zlib


class PendingInference(BaseException):
    # Intentionally not Exception: the core must suspend, rather than treat a
    # scheduling event as an unavailable model and manufacture downstream packets.
    def __init__(self, key, task, packet, owner):
        self.key, self.task, self.packet, self.owner = key, task, packet, owner


def packet_text(task, packet):
    from src.identification_agent_contracts import SYSTEMS
    # Preserve insertion order and JSON spacing: this is the exact user prompt.
    return task + '\n' + SYSTEMS[task] + '\n' + json.dumps(packet, ensure_ascii=False)


class PacketCache:
    def __init__(self, path, signature):
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS meta(signature TEXT NOT NULL)')
        self.db.execute('''CREATE TABLE IF NOT EXISTS packets(
            key TEXT PRIMARY KEY,task TEXT,packet TEXT NOT NULL,response BLOB NOT NULL,owner TEXT NOT NULL)''')
        row = self.db.execute('SELECT signature FROM meta').fetchone()
        if row and row[0] != signature: raise ValueError('Packet cache model/code signature changed')
        if not row: self.db.execute('INSERT INTO meta VALUES (?)', (signature,));self.db.commit()
        self._stats = self._scan_statistics()

    def provider(self, owner):
        trace = {}
        def infer(task, packet):
            text = packet_text(task, packet);key = hashlib.sha256(text.encode()).hexdigest()
            row = self.db.execute('SELECT packet,response,owner FROM packets WHERE key=?', (key,)).fetchone()
            if row is None: raise PendingInference(key, task, deepcopy(packet), owner)
            if row[0] != text: raise AssertionError('Packet hash collision')
            response = json.loads(zlib.decompress(row[1]))
            trace[task.lower()] = {'packet_key': key, 'origin_input_id': row[2],
                'execution': 'exact_packet_reuse' if owner != row[2] else 'deferred_batch_inference'}
            return response
        return infer, trace

    def put(self, request, response):
        encoded = json.dumps(response, ensure_ascii=False).encode()
        with self.db:
            self.db.execute('INSERT INTO packets VALUES (?,?,?,?,?)',
                (request.key, request.task, packet_text(request.task, request.packet), zlib.compress(encoded, 6), request.owner))
        self._stats['cached_packets'] += 1
        self._stats['actual_llm_requests'] += int(bool(response.get('llm_used')))
        self._stats['generated_tokens'] += (response.get('generation') or {}).get('generated_tokens', 0)

    def _scan_statistics(self):
        stats = {'actual_llm_requests': 0, 'generated_tokens': 0, 'cached_packets': 0}
        for blob, in self.db.execute('SELECT response FROM packets'):
            response = json.loads(zlib.decompress(blob));stats['cached_packets'] += 1
            stats['actual_llm_requests'] += int(bool(response.get('llm_used')))
            stats['generated_tokens'] += (response.get('generation') or {}).get('generated_tokens', 0)
        return stats

    def statistics(self): return dict(self._stats)

    def close(self): self.db.close()


def resolve_window(inputs, cache, batch_infer, *, index, nvd, batch_size=4, progress=None, core=None):
    from src.unified_identification import run_unified
    remaining = dict(inputs); completed = {}
    while remaining:
        pending = {}
        for owner, sbom in list(remaining.items()):
            infer, trace = cache.provider(owner)
            try:
                result = (core or run_unified)(sbom, nvd, index=index, mode='agents', agents=infer)
            except PendingInference as request:
                pending.setdefault(request.key, request)
            except Exception as exc:
                completed[owner] = ({'error': type(exc).__name__ + ': ' + str(exc)}, trace)
                del remaining[owner]
            else:
                completed[owner] = (result, trace)
                del remaining[owner]
        if not remaining: break
        if not pending: raise RuntimeError('Unresolvable batch dependency')
        groups = defaultdict(list)
        for request in pending.values(): groups[request.task].append(request)
        for task, requests in groups.items():
            requests.sort(key=lambda r: len(packet_text(task, r.packet)))
            for start in range(0, len(requests), batch_size):
                chunk = requests[start:start+batch_size]
                if progress: progress(task, len(chunk))
                responses = batch_infer(task, [r.packet for r in chunk], batch_size=batch_size)
                if len(responses) != len(chunk): raise ValueError('Batch response count mismatch')
                for request, response in zip(chunk, responses): cache.put(request, response)
    return completed
