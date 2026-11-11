"""Product/version/edition identification; operational prerequisites stay separate."""
import re
from ics_agent_matcher_full.ics_agent_matcher.matcher import cpe_parts
from src.identity_versions import compare_versions,clean

def atom(pattern,value):
    if pattern=='*':return True
    if value is None:return None
    if pattern=='-':return value=='-'
    if value=='-':return False
    tokens=[];i=0
    while i<len(pattern):
        c=pattern[i]
        if c=='\\' and i+1<len(pattern):i+=1;tokens.append(re.escape(pattern[i]))
        elif c=='*':tokens.append('.*')
        elif c=='?':tokens.append('.')
        else:tokens.append(re.escape(c))
        i+=1
    value=re.sub(r'\\(.)',r'\1',str(value))
    return re.fullmatch(''.join(tokens),value,re.I) is not None

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

def identify(configurations,actual,scheme='unknown'):
    states=[]
    def visit(value):
        if isinstance(value,list):
            for v in value:visit(v)
        elif isinstance(value,dict):
            for match in value.get('cpeMatch',[]):
                p=cpe_parts(match.get('criteria'))
                if not p or match.get('vulnerable') is not True:continue
                p=p[2:]
                if any(atom(s,a) is False for s,a in zip(p[:3],actual[:3])):continue
                tests=[atom(s,a) for s,a in zip(p,actual)]
                for field,side,inclusive in [('versionStartIncluding','lower',True),('versionStartExcluding','lower',False),
                    ('versionEndIncluding','upper',True),('versionEndExcluding','upper',False)]:
                    if field not in match:continue
                    bound=str(match[field]);version=actual[3]
                    if bound in ('-','*',''):tests.append(None);continue
                    if version=='-':tests.append(False);continue
                    d=compare_versions(version,bound,scheme) if version is not None else None
                    tests.append(None if d is None else (d>=0 if inclusive else d>0) if side=='lower' else (d<=0 if inclusive else d<0))
                states.append(False if False in tests else None if None in tests else True)
            for key in ('nodes','children'):visit(value.get(key,[]))
    visit(configurations)
    return 'true' if True in states else 'unknown' if None in states else 'false'
