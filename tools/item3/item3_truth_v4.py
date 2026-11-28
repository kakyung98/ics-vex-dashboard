"""Source-only v4 truth: versioned product branches, with explicit uncertainty.

No model outputs, dictionary retrieval or production identification imports.
"""
from collections import defaultdict
import re
from tools.item3.item3_full_population import family,version_state


def product_line(name):
    m=re.fullmatch(r'(.+?)\s+[vV](\d+(?:\.\d+)*)',name.strip())
    return (m[1],m[2]) if m else (name,None)


def canonical_family(vendor,name):
    return family(vendor,product_line(name)[0])


def line_state(version,line):
    if line is None:return True
    if version is None:return None
    value=re.sub(r'^[vV]','',version)
    if not re.fullmatch(r'\d+(?:\.\d+)*',value):return None
    actual=tuple(map(int,value.split('.')));required=tuple(map(int,line.split('.')))
    return actual[:len(required)]==required


class TruthV4:
    def __init__(self,origins,rejected=()):
        self.groups=defaultdict(list);self.rejected=set(rejected);self.cache={}
        for o in origins:self.groups[canonical_family(o['vendor'],o['product'])].append(o)

    def labels(self,vendor,product,version):
        f=canonical_family(vendor,product);input_line=product_line(product)[1];key=(f,version,input_line)
        input_conflict=line_state(version,input_line) is False
        if key in self.cache:return self.cache[key]
        states=defaultdict(list);refs=defaultdict(list)
        for o in self.groups[f]:
            state=None;cid=o['cve'];_,line=product_line(o['product'])
            if (not input_conflict and o['relation_kind']=='csaf_known_affected' and not o['relationship_context_required']
                and not o['identification_helper'].get('model_numbers') and cid not in self.rejected
                and f[0] not in ('noassertion','unknown','other')):
                branch=line_state(version,line)
                release=version_state(version,o['release'])
                state=False if branch is False or release is False else None if branch is None or release is None else True
            states[cid].append(state)
            if state is True:refs[cid].append(o['id'])
        value={'expected_cves':sorted(c for c,s in states.items() if True in s),
            'unknown_cves':sorted(c for c,s in states.items() if True not in s and None in s),
            'positive_origin_refs':{c:sorted(set(ids)) for c,ids in refs.items()}}
        value['complete_within_scored_universe']=not value['unknown_cves']
        self.cache[key]=value;return value
