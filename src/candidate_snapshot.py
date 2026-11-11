"""Read-only local NVD snapshot lookup. Flattened caches cannot prove full applicability."""
import json
from pathlib import Path
from functools import lru_cache

from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD,CPE_API,CVE_API,norm,cpe_parts

ROOT=Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def dictionary():
    products={}
    with (ROOT/'data/cpe_dictionary.jsonl').open(encoding='utf-8') as handle:
        for line in handle:
            row=json.loads(line)
            if row.get('cpe'):
                products.setdefault(norm(row['product']),{})[row['cpe']]={'cpe':{'cpeName':row['cpe']}}
    return products


@lru_cache(maxsize=1)
def cve_index():
    return json.loads((ROOT/'data/cpe_index.json').read_text(encoding='utf-8'))['by_product']


class SnapshotNVD(NVD):
    def __init__(self,index_path=None):
        super().__init__(offline=True)
        self._frozen_index=json.loads(Path(index_path).read_text(encoding='utf-8'))['by_product'] if index_path else None

    def get_all(self,path,params,field):
        if path==CPE_API:
            rows=list(dictionary().get(norm(params.get('keywordSearch','')),{}).values())
        elif path==CVE_API:
            parts=cpe_parts(params.get('cpeName') or params.get('virtualMatchString',''))
            index=self._frozen_index if self._frozen_index is not None else cve_index()
            entries=index.get(parts[4],[]) if parts else []
            ids=sorted({r['cve'] for r in entries if r['vendor']==parts[3]})
            # This cache flattened original AND/OR/platform configurations. Never
            # rebuild those as OR-only rules and falsely label them a proven match.
            rows=[]
            for cve in ids:
                conditions=[]
                for entry in entries:
                    if entry['vendor']!=parts[3] or entry['cve']!=cve:continue
                    condition={'criteria':':'.join(parts[:5]+[entry.get('version') or '*']+['*']*7),'vulnerable':True}
                    for old,new in [('startIncl','versionStartIncluding'),('startExcl','versionStartExcluding'),
                                    ('endIncl','versionEndIncluding'),('endExcl','versionEndExcluding')]:
                        if entry.get(old) is not None:condition[new]=entry[old]
                    # A row with no release/range information does not establish all versions.
                    if condition['criteria'].split(':')[5] in {'*','-'} and len(condition)==2:continue
                    conditions.append(condition)
                rows.append({'cve':{'id':cve,'configurations':[],
                    'sbom_version_conditions':conditions,'applicability_scope':'product_version_only',
                    'platform_configuration_preserved':False}})
        else:raise ValueError('Unsupported snapshot query')
        return {field:rows,'totalResults':len(rows)}
