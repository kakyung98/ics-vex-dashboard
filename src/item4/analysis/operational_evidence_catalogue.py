"""Enumerate literal source spans, not prerequisites or necessity claims.

The model selects an ID instead of copying/paraphrasing/concatenating quotes.
Original paragraphs remain the authority for qualifiers and Boolean relations.
"""
from copy import deepcopy
import re

VERSION='item4-operational-evidence-catalogue/2'


def catalogue(evidence):
    rows=[];seen=set()
    for parent in evidence:
        text=parent['quote'];candidates=[text]
        candidates.extend(re.split(r'(?<=[.!?;])\s+|\n+',text))
        for part in list(candidates):
            # Literal prefixes are quotation choices only. Their necessity and
            # all actor/OR/NOT qualifiers must still be interpreted by the model.
            prefix=re.split(r'\b(?:to cause|that can (?:initiate|cause)|is able to|allowing|are prone to|is vulnerable to)\b',part,maxsplit=1,flags=re.I)[0]
            if prefix!=part:candidates.append(prefix)
        candidates.extend(m.group() for m in re.finditer(
            r'\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+[\w/.-]+(?:\s+or\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+[\w/.-]+)?(?:\s+requests?)?',text))
        for quote in candidates:
            quote=quote.strip()
            key=(parent['evidence_id'],quote)
            if len(quote)<4 or text.count(quote)!=1 or key in seen:continue
            seen.add(key);start=text.index(quote)
            rows.append(dict(id='op'+str(len(rows)+1),evidence_id=parent['evidence_id'],
                source_id=parent['source_id'],span=[start,start+len(quote)],quote=quote))
    return rows


def bind(packet):
    wire=deepcopy(packet);rows=catalogue(packet['evidence'])
    if not rows:raise ValueError('No exact operational evidence choices')
    wire['operational_evidence']=rows
    item=wire['schema']['properties']['prerequisites']['items']
    item['required']=[k for k in item['required'] if k!='operational_quote']+['operational_evidence_id']
    # Optional narrowing of a selected paragraph supports arbitrary new source
    # phrasing; the finite hint catalogue is not an extraction allowlist.
    item['properties']['operational_quote']={'type':'string','minLength':1}
    item['properties']['operational_evidence_id']={'enum':[r['id'] for r in rows]}
    return wire


def resolve(atom,packet):
    if 'operational_evidence_id' not in atom:return  # Legacy artifacts/test fixtures.
    key=atom.pop('operational_evidence_id')
    row=next((r for r in packet.get('operational_evidence',[]) if r['id']==key),None)
    if row is None:raise ValueError('Unknown operational evidence ID')
    if not any(ref.get('evidence_id')==row['evidence_id'] or
            (ref.get('source_id')==row['source_id'] and row['quote'] in ref.get('quote',''))
            for ref in atom.get('source_refs',[])):
        raise ValueError('Operational evidence binding must cite its parent paragraph')
    # Never add a supporting reference silently; a mismatched selection fails
    # ordinary quote/scope validation and is repaired as an evidence error.
    quote=atom.get('operational_quote',row['quote'])
    if not isinstance(quote,str) or not quote or row['quote'].count(quote)!=1:
        raise ValueError('Operational evidence binding clause is not an exact unique substring of the selected source span')
    atom['operational_quote']=quote
