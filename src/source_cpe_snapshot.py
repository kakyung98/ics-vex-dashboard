"""Pinned CVE product/version/edition lookup, without benchmark labels."""
from collections import defaultdict
from functools import lru_cache
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FOLDER=ROOT/'data/item3_identification_sources_v11'


class SourceCPELookup:
    def __init__(self,folder=FOLDER):
        from ics_agent_matcher_full.ics_agent_matcher.matcher import cpe_parts
        folder=Path(folder);manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
        path=folder/'cves.jsonl'
        if hashlib.sha256(path.read_bytes()).hexdigest()!=manifest['sha256']:
            raise ValueError('Pinned identification source integrity failure')
        self.records={};self.by_identity=defaultdict(set)
        for line in path.open(encoding='utf-8'):
            record=json.loads(line);cid=record['id'];self.records[cid]=record
            for match in record['configurations'][0]['cpeMatch']:
                p=cpe_parts(match.get('criteria'))
                if p:self.by_identity[tuple(p[2:5])].add(cid)

    def get_all(self,path,params,field):
        from ics_agent_matcher_full.ics_agent_matcher.matcher import cpe_parts,CVE_API
        if path!=CVE_API:raise ValueError('Only pinned CVE source lookup is supported')
        p=cpe_parts(params.get('virtualMatchString') or params.get('cpeName'))
        ids=self.by_identity.get(tuple(p[2:5]),()) if p else ()
        return {'vulnerabilities':[{'cve':self.records[cid]} for cid in sorted(ids)]}


@lru_cache(maxsize=1)
def get_source_lookup():return SourceCPELookup()
