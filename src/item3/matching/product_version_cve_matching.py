"""Product/version/edition identification; operational prerequisites stay separate."""
import re
from functools import lru_cache
from src.item3.matching.sbom_matching_engine import cpe_parts
from src.item3.evidence.version_evidence import compare_versions; from src.item3.evidence.version_evidence import clean

@lru_cache(maxsize=16384)
def _pattern(pattern):
    tokens=[];i=0
    while i<len(pattern):
        c=pattern[i]
        if c=='\\' and i+1<len(pattern):i+=1;tokens.append(re.escape(pattern[i]))
        elif c=='*':tokens.append('.*')
        elif c=='?':tokens.append('.')
        else:tokens.append(re.escape(c))
        i+=1
    return re.compile(''.join(tokens),re.I)


def atom(pattern,value):
    if pattern=='*':return True
    if value is None:return None
    if pattern=='-':return value=='-'
    if value=='-':return False
    if not any(c in pattern for c in '\\*?') and '\\' not in str(value):
        return pattern.casefold()==str(value).casefold()
    value=re.sub(r'\\(.)',r'\1',str(value))
    return _pattern(pattern).fullmatch(value) is not None

def facts(component,validation,versions):
    result=[validation[k] for k in ('part','vendor','product')]+[None]*8
    result[3]=versions.get('comparison_version') or versions.get('normalized')
    if not versions.get('conflicts') and str(versions.get('raw','')).strip()=='-':result[3]='-'
    observed=[]
    for text in component.get('cpes',[]):
        p=cpe_parts(text)
        if p and p[2:5]==result[:3]:observed.append(p[2:])
    for index in range(4,11):
        values={p[index] for p in observed if p[index]!='*'}
        if len(values)==1:result[index]=next(iter(values))
    if result[3] is not None and not versions.get('conflicts'):
        values={p[3] for p in observed if p[3] not in ('*','-') and clean(p[3])==clean(result[3])}
        if len(values)==1:result[3]=next(iter(values))
    return result

def identify(configurations,actual,scheme='unknown',declared_range=None):
    compiled=[]
    def visit(value):
        if isinstance(value,list):
            for v in value:visit(v)
        elif isinstance(value,dict):
            for match in value.get('cpeMatch',[]):
                p=cpe_parts(match.get('criteria'))
                if not p or match.get('vulnerable') is not True:continue
                compiled.append((tuple(p[2:]),match))
            for key in ('nodes','children'):visit(value.get(key,[]))
    visit(configurations)
    return identify_compiled(compiled,actual,scheme,declared_range)


def identify_compiled(compiled,actual,scheme='unknown',declared_range=None):
    """The same predicate over source-bound, pre-parsed CPE conditions."""
    states=[]
    for p,match in compiled:
        if any(atom(s,a) is False for s,a in zip(p[:3],actual[:3])):continue
        tests=[atom(s,a) for s,a in zip(p,actual)]
        # Apply the same display-prefix policy to the version field only.
        # Other CPE attributes and unknown values retain their original meaning.
        tests[3]=atom(clean(p[3]) or p[3],clean(actual[3]) if actual[3] is not None else None)
        if actual[3] is None and declared_range:
            from src.item3.evidence.version_evidence import interval_condition
            state=interval_condition(declared_range,match,['cpe','2.3',*p],scheme)
            tests[3]={'true':True,'false':False,'unknown':None}[state]
        for field,side,inclusive in [('versionStartIncluding','lower',True),('versionStartExcluding','lower',False),
            ('versionEndIncluding','upper',True),('versionEndExcluding','upper',False)]:
            if field not in match:continue
            if actual[3] is None and declared_range:continue
            bound=clean(str(match[field]));version=clean(actual[3]) if actual[3] is not None else None
            if bound in (None,'-','*',''):tests.append(None);continue
            if version=='-':tests.append(False);continue
            supported = (scheme!='unknown' or version==bound or
                (isinstance(version,str) and re.fullmatch(r'\d+(?:\.\d+)*',version)
                 and re.fullmatch(r'\d+(?:\.\d+)*',bound)))
            d=compare_versions(version,bound,scheme) if version is not None and supported else None
            tests.append(None if d is None else (d>=0 if inclusive else d>0) if side=='lower' else (d<=0 if inclusive else d<0))
        states.append(False if False in tests else None if None in tests else True)
    return 'true' if True in states else 'unknown' if None in states else 'false'
