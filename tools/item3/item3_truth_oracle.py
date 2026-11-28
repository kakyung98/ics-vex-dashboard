"""Independent #3 product/version/edition oracle. Does not import the identifier or LLM."""
from collections import defaultdict
from functools import lru_cache
import hashlib,json,re

ATTRS=['part','vendor','product','version','update','edition','language','sw_edition','target_sw','target_hw','other']
BOUNDS=[('versionStartIncluding',True,True),('versionStartExcluding',True,False),
        ('versionEndIncluding',False,True),('versionEndExcluding',False,False)]


def parts(text):
    if not isinstance(text,str) or not text.startswith('cpe:2.3:'):return None
    out=[];buf=[];escaped=False
    for char in text:
        if char==':' and not escaped:out.append(''.join(buf));buf=[]
        else:buf.append(char)
        escaped=char=='\\' and not escaped
    out.append(''.join(buf))
    return tuple(out[2:]) if len(out)==13 else None


def literal(value):return re.sub(r'\\(.)',r'\1',value) if value is not None else None
def bind(value):return re.sub(r'([^A-Za-z0-9_.-])',r'\\\1',value)
def compact(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def key(value):return hashlib.sha256(compact(value).encode()).hexdigest()


@lru_cache(maxsize=250000)
def attribute(pattern,actual):
    if pattern=='*':return True
    if actual is None or actual=='*':return None
    if pattern=='-':return actual=='-'
    if actual=='-':return False
    regex=[];i=0
    while i<len(pattern):
        char=pattern[i]
        if char=='\\' and i+1<len(pattern):i+=1;regex.append(re.escape(pattern[i]))
        elif char=='*':regex.append('.*')
        elif char=='?':regex.append('.')
        else:regex.append(re.escape(char))
        i+=1
    return re.fullmatch(''.join(regex),literal(actual),re.I) is not None


@lru_cache(maxsize=250000)
def version_compare(a,b):
    if a is None:return None
    if a==b:return 0
    if not re.fullmatch(r'\d+(?:\.\d+)*',a) or not re.fullmatch(r'\d+(?:\.\d+)*',b):return None
    x=tuple(map(int,a.split('.')));y=tuple(map(int,b.split('.')));width=max(len(x),len(y))
    x+=(0,)*(width-len(x));y+=(0,)*(width-len(y))
    return (x>y)-(x<y)


def condition(fields,match):
    source=parts(match.get('criteria'))
    if source is None:return None
    states=[attribute(s,a) for s,a in zip(source,fields)]
    if False in states:return False
    version=literal(fields[3])
    for name,lower,inclusive in BOUNDS:
        if match.get(name) is None:continue
        if fields[3]=='-':return False
        compared=version_compare(version,str(match[name]))
        if compared is None:states.append(None)
        elif not ((compared>=0 if inclusive else compared>0) if lower else (compared<=0 if inclusive else compared<0)):return False
    return None if None in states else True


def walk(value,path='/configurations'):
    if isinstance(value,list):
        for i,item in enumerate(value):yield from walk(item,path+'/'+str(i))
    elif isinstance(value,dict):
        for k,item in value.items():
            if k=='cpeMatch':
                for i,match in enumerate(item):yield path+'/'+k+'/'+str(i),match
            elif isinstance(item,(dict,list)):yield from walk(item,path+'/'+k)


def identity(fields):return tuple(literal(v).lower() for v in fields[:3])


def has_wildcard(value):
    escaped=False
    for char in value:
        if char in '*?' and not escaped:return True
        escaped=char=='\\' and not escaped
    return False


def concrete_atom(value):
    if value=='*':return '-'
    if value=='-':return '-'
    chars=[];i=0
    while i<len(value):
        if value[i]=='\\' and i+1<len(value):i+=1;chars.append(value[i])
        elif value[i] in '*?':chars.append('0')
        else:chars.append(value[i])
        i+=1
    return bind(''.join(chars))


class Oracle:
    def __init__(self,source):
        self.rows=[];self.by_identity=defaultdict(list);self.by_cve=defaultdict(list);self.info={};self.unscorable=[];self.cache={}
        for cid,text in source.execute('SELECT cve,payload FROM cves ORDER BY cve'):
            record=json.loads(text);found=list(walk(record.get('configurations',[])))
            self.info[cid]={'status':record.get('vulnStatus'),'source_status':record.get('_acquisition_status'),'cpe_occurrences':len(found)}
            if not found:self.unscorable.append(cid)
            for path,match in found:
                fields=parts(match.get('criteria'))
                if fields is None:raise ValueError('Unparseable source criterion: '+cid+path)
                item={'cve':cid,'path':path,'match':match,'fields':fields,'source_id':'SRC-'+key([cid,path])[:24]}
                self.rows.append(item);self.by_cve[cid].append(item)
                if match.get('vulnerable') is True:self.by_identity[identity(fields)].append(item)
        self.universe=sorted(self.by_cve)
        # Exact release buckets avoid comparing every IOS release with every
        # other release. Ranges and wildcard releases remain in the broad bucket.
        self.exact_versions=defaultdict(lambda:defaultdict(list));self.broad_versions=defaultdict(list)
        for ident,rows in self.by_identity.items():
            for row in rows:
                version=row['fields'][3]
                if has_wildcard(version):self.broad_versions[ident].append(row)
                else:self.exact_versions[ident][literal(version).lower()].append(row)
        self.products=defaultdict(list)
        for ident in self.by_identity:self.products[ident[:2]].append(ident[2])
        for k in self.products:self.products[k]=sorted(set(self.products[k]))

    def witness(self,row,catalog):
        fields=list(map(concrete_atom,row['fields']));source=row['fields'];match=row['match']
        proposed=[]
        if source[3] not in ('*','-'):proposed.append((concrete_atom(source[3]),'source_exact_or_pattern'))
        if source[3]=='-':proposed.append(('-','source_version_not_applicable'))
        for name in ('versionStartIncluding','versionEndIncluding'):
            if match.get(name) is not None:proposed.append((bind(str(match[name])),'inclusive_boundary'))
        for name in ('versionStartExcluding','versionEndExcluding'):
            value=match.get(name)
            if value is not None and re.fullmatch(r'\d+(?:\.\d+)*',str(value)):
                if name.startswith('versionStart'):proposed.append((str(value)+'.0.1','synthetic_numeric_inside_boundary'))
                else:
                    nums=list(map(int,str(value).split('.')))
                    for i in range(len(nums)-1,-1,-1):
                        if nums[i]>0:
                            changed=nums[:i]+[nums[i]-1]+[0]*(len(nums)-i-1)
                            proposed.append(('.'.join(map(str,changed)),'synthetic_numeric_inside_boundary'));break
        for ver in catalog.get(identity(source),[]):proposed.append((ver,'official_dictionary_release'))
        proposed.extend([('0','synthetic_numeric_witness'),('1.0','synthetic_numeric_witness')])
        for version,basis in proposed:
            fields[3]=version
            if condition(fields,match) is True:return tuple(fields),basis
        fields[3]=None
        return tuple(fields),'no_supported_version_witness'

    def labels(self,fields):
        profile=key(fields)
        if profile in self.cache:return self.cache[profile]
        states=defaultdict(list);support=defaultdict(list)
        ident=identity(fields);version=fields[3]
        candidates=(self.by_identity.get(ident,[]) if version is None or version=='*' else
                    self.exact_versions.get(ident,{}).get(literal(version).lower(),[])+self.broad_versions.get(ident,[]))
        for row in candidates:
            cid=row['cve']
            if self.info[cid]['status']=='Rejected':continue
            state=condition(fields,row['match']);states[cid].append(state)
            if state is True:support[cid].append(row['source_id'])
        positive=sorted(cid for cid,vals in states.items() if True in vals)
        unknown=sorted(cid for cid,vals in states.items() if True not in vals and None in vals)
        result={'profile_id':profile,'canonical_fields':dict(zip(ATTRS,fields)),'expected_cves':positive,'unknown_cves':unknown,
                'positive_source_refs':{cid:sorted(refs) for cid,refs in support.items()},'complete_within_cpe_universe':not unknown}
        self.cache[profile]=result
        return result
