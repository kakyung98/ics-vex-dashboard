"""Conservative source ranges: numeric bounds, VERS intervals and opaque equality.

VERS '|' separates interval boundaries, not arbitrary Boolean OR.
References: https://www.packageurl.org/docs/vers/specification.html and
https://raw.githubusercontent.com/package-url/www.packageurl.org/main/website/docs/vers/vers-types.md
Undefined vendor/generic ordering, installation wildcards and qualified prose
remain unknown. A stored compiler predicate never overrides its raw source.
"""
from functools import lru_cache
import re

PARSER_VERSION='source-version-parser/2'


def number(s):
    m=re.fullmatch(r'([vVrR]?)(\d+(?:\.\d+){0,7})',s.strip())
    return (m[1].casefold(),tuple(map(int,m[2].split('.')))) if m else None


def intdot(s):
    # The declared intdot type ignores leading zeros and stops at non digit/dot.
    m=re.match(r'\d+(?:\.\d+)*',s)
    return ('',tuple(map(int,m[0].split('.')))) if m else None


def compare(a,b,scheme='numeric'):
    parse=intdot if scheme=='intdot' else number
    a,b=parse(a),parse(b)
    if a is None or b is None or a[0].lstrip('v')!=b[0].lstrip('v'):return None
    size=max(len(a[1]),len(b[1]));x=a[1]+(0,)*(size-len(a[1]));y=b[1]+(0,)*(size-len(b[1]))
    return (x>y)-(x<y)


def unknown(raw):return dict(op='unknown',raw=raw)


def _atom(token,scheme='numeric'):
    m=re.fullmatch(r'(<=|>=|!=|<|>|=)?\s*([^<>!=|\s]+)',token.strip())
    if not m:return unknown(token)
    op,version=m.groups();return dict(op=op or '=',version=version,scheme=scheme)


def _sequence(tokens,scheme='numeric',strict=False):
    atoms=[_atom(t,scheme) for t in tokens]
    if any(a['op']=='unknown' for a in atoms):return unknown('|'.join(tokens))
    if strict:
        if any(t.startswith('=') for t in tokens):return unknown('|'.join(tokens))
        if any(intdot(a['version']) is None for a in atoms):return unknown('|'.join(tokens))
        if any(compare(a['version'],b['version'],'intdot')>=0 for a,b in zip(atoms,atoms[1:])):
            return unknown('|'.join(tokens))
    exclusions=[a for a in atoms if a['op']=='!='];atoms=[a for a in atoms if a['op']!='!=']
    paths=[];i=0
    while i<len(atoms):
        a=atoms[i];op=a['op']
        if op in ('>','>='):
            if i+1<len(atoms) and atoms[i+1]['op'] in ('<','<='):
                b=atoms[i+1];order=compare(a['version'],b['version'],scheme)
                if order is not None and order>=0:return unknown('|'.join(tokens))
                paths.append(dict(op='and',args=[a,b]));i+=2;continue
            if i+1<len(atoms) and strict:return unknown('|'.join(tokens))
            paths.append(a)
        elif op in ('<','<='):
            if i!=0 and strict:return unknown('|'.join(tokens))
            paths.append(a)
        else:paths.append(a)
        i+=1
    result=(paths[0] if len(paths)==1 else dict(op='or',args=paths)) if paths else dict(op='any')
    return dict(op='and',args=[result,*exclusions]) if exclusions else result


@lru_cache(maxsize=32768)
def version_predicate(text):
    raw=text.strip()
    if raw.startswith('vers:'):
        m=re.fullmatch(r'vers:([a-z][a-z0-9.-]*)/([^\s]+)',raw)
        if not m:return unknown(raw)
        scheme,body=m.groups()
        if scheme=='all':return dict(op='any') if body=='*' else unknown(raw)
        if scheme=='none':return dict(op='none') if body=='*' else unknown(raw)
        if '*' in body:return dict(op='any',scheme='intdot') if body=='*' and scheme=='intdot' else unknown(raw)
        if scheme=='intdot':return _sequence(body.split('|'),'intdot',strict=True)
        # generic has no specified ordering. Reflexive comparisons of a single
        # exact opaque version are sound, but no natural/lexical order is guessed.
        if scheme=='generic' and '|' not in body and '%' not in body:
            result=_atom(body,'opaque')
            if result['op']=='=' and body.startswith('='):return unknown(raw)
            return result
        return unknown(raw)
    s=re.sub(r'\b(?:all\s+)?versions?\s*','',raw,flags=re.I).strip()
    if s.casefold() in ('all','all affected','*','all releases') or raw.casefold() in ('all versions','all version'):
        return dict(op='any')
    # Prose qualifiers can bind a different product, feature, release channel or
    # exception. Never discard them to make a numeric-only range.
    if re.search(r'\b(?:except|excluding|and later|and newer|with|using|only)\b|[()]',s,re.I):return unknown(raw)
    s=re.sub(r'\b(?:prior to|before|earlier than)\s*','<',s,flags=re.I)
    if re.search(r'\b(?:and earlier|and prior)\s*$',s,re.I):
        s='<='+re.sub(r'\b(?:and earlier|and prior)\s*$','',s,flags=re.I).strip()
    if '|' in s:
        tokens=[t.strip() for t in s.split('|')]
        if not all(tokens):return unknown(raw)
        if any(re.match(r'[<>!=]',t) for t in tokens):return _sequence(tokens)
        return dict(op='or',args=[_atom(t) for t in tokens])
    s=re.sub(r'_(?:and_)?(?=[<>])',' ',s,flags=re.I)
    bounds=list(re.finditer(r'(<=|>=|!=|<|>|=)\s*([^<>!=\s,;]+)',s))
    if bounds:
        remainder=re.sub(r'(<=|>=|!=|<|>|=)\s*[^<>!=\s,;]+','',s)
        if re.sub(r'\b(?:and|to)\b|[ ,;]','',remainder,flags=re.I):return unknown(raw)
        return dict(op='and',args=[dict(op=m[1],version=m[2],scheme='numeric') for m in bounds])
    m=re.fullmatch(r'([vVrR]?\d+(?:\.\d+){0,7})\s+(?:through|to|-)\s+([vVrR]?\d+(?:\.\d+){0,7})',s,re.I)
    if m:return dict(op='and',args=[dict(op='>=',version=m[1]),dict(op='<=',version=m[2])])
    if s and not re.search(r'\b(?:all|unknown|unspecified|prior|before|through|sp\d|update|hotfix|hf\d)\b|[<>*]',s,re.I):
        return dict(op='=',version=s)
    return unknown(raw)


def concrete(actual):
    return isinstance(actual,str) and bool(re.search(r'\d',actual)) and not re.search(
        r'unknown|unverified|unspecified|noassertion|[<>!=|*]|\d[xX]+$|(?:^|[.\s_-])[xX](?:$|[.\s_-])',actual)


def membership(predicate,actual):
    op=predicate['op']
    if not concrete(actual):return 'unknown'
    if predicate.get('scheme')=='intdot' and intdot(actual) is None:return 'unknown'
    if op=='any':return 'true'
    if op=='none':return 'false'
    if op=='unknown':return 'unknown'
    if op in ('and','or'):
        states=[membership(p,actual) for p in predicate['args']]
        decisive='false' if op=='and' else 'true'
        if decisive in states:return decisive
        return ('true' if op=='and' else 'false') if states and 'unknown' not in states else 'unknown'
    bound=predicate['version'];scheme=predicate.get('scheme','numeric')
    if scheme=='opaque':
        if actual!=bound:return 'unknown'
        order=0
    elif op=='=':
        if scheme!='intdot':return 'true' if actual.strip().casefold()==bound.strip().casefold() else 'false'
        order=compare(actual,bound,scheme)
    else:
        order=0 if actual==bound else compare(actual,bound,scheme)
    if order is None:return 'unknown'
    return 'true' if {'=':order==0,'!=':order!=0,'<':order<0,'<=':order<=0,'>':order>0,'>=':order>=0}[op] else 'false'


def row_membership(row,actual):
    # The immutable catalog contains older parsed predicates. Interpret its
    # original source text at runtime without editing or re-sealing source rows.
    predicate=version_predicate(row['version_text']) if 'version_text' in row else row['version_predicate']
    return membership(predicate,actual)
