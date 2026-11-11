"""Lossless source offsets; no arbitrary whitespace splitting."""
import re


def sentence_spans(text):
    starts=[0]
    # A period inside a version, identifier or abbreviation is not a boundary.
    for m in re.finditer(r'(?:[.!?][\"\')\]]*\s+|\n\s*\n)',text):
        left=text[:m.start()+1]
        if m.group()[0]=='.' and re.search(r'\b(?:e\.g|i\.e|Mr|Dr|vs|etc)\.$',left,re.I):
            continue
        starts.append(m.end())
    starts.append(len(text))
    return [(a,b) for a,b in zip(starts,starts[1:]) if a<b]


def units(text,max_chars=1600):
    result=[]
    for sentence_id,(a,b) in enumerate(sentence_spans(text)):
        cuts=[a]
        if b-a>max_chars:
            cuts += [a+m.end() for m in re.finditer(r'[;,]\s+|\n+',text[a:b])]
        cuts.append(b)
        for start,end in zip(cuts,cuts[1:]):
            if start==end:continue
            result.append(dict(start=start,end=end,text=text[start:end],sentence_id=sentence_id,
                boundary='sentence' if len(cuts)==2 else 'clause',
                oversized=end-start>max_chars))
    if ''.join(r['text'] for r in result)!=text:raise ValueError('Lost source characters')
    return result


def administrative(text):
    return bool(re.match(r'\s*(?:Rejected reason:|\*\*\s*REJECT\s*\*\*|DO NOT USE (?:THIS|THE))',text,re.I))
