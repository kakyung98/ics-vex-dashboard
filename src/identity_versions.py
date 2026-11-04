"""Version observations preserve source, spans, revisions and uncertainty."""
import re
from urllib.parse import unquote,parse_qsl
from packaging.version import Version,InvalidVersion

UNKNOWN={'','unknown','latest','unspecified','noassertion','none','n/a'}

def purl_parts(value):
    if not isinstance(value,str) or not value.startswith('pkg:'):return None
    from packageurl import PackageURL
    try:p=PackageURL.from_string(value)
    except (ValueError,TypeError):return None
    return {'type':p.type,'namespace':p.namespace,'name':p.name,'version':p.version,
            'qualifiers':p.qualifiers or {},'subpath':p.subpath,'raw':value}

def clean(value):
    value=str(value or '').strip()
    if value.lower() in UNKNOWN:return None
    return re.sub(r'^[vV](?=\d)','',value)

def version_info(component,*,synthetic=False,llm_spans=None):
    observations=[];missing=[];invalid=[];purl=purl_parts(component.get('purl'))
    def add(value,source,text,start=0,end=None,kind='exact',operator=None):
        normalized=clean(value)
        if normalized is None:return
        raw=str(value);end=start+len(raw) if end is None else end
        if 0<=start<end<=len(text):raw=text[start:end]
        observations.append({'value':normalized,'raw':raw,'source':source,'evidence':text[start:end],
            'span':[start,end],'kind':kind,'operator':operator,'deployment_verified':False})
    raw=str(component.get('version') or '')
    if clean(raw) is not None:
        m=re.fullmatch(r'\s*(<=|>=|<|>|~|\^)?\s*([vV]?\d[^\s]*)\s*',raw)
        if m:add(m.group(2),'version',raw,m.start(2),m.end(2),'range' if m.group(1) else 'exact',m.group(1))
        else:add(raw,'version',raw,kind='exact' if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+:~_-]*',raw.strip()) and not re.search(r'(?i)^(all|any|affected)$',raw.strip()) else 'opaque')
    if purl and purl['version']:add(purl['version'],'purl.version',purl['version'])
    for i,cpe in enumerate(component.get('cpes',[])):
        from ics_agent_matcher_full.ics_agent_matcher.matcher import cpe_parts
        fields=cpe_parts(cpe)
        if fields and fields[5] not in {'*','-',''}:add(fields[5],f'cpe:{i}.version',fields[5])
    name=component.get('name') or ''
    pattern=r'(?i)(?<![\w.])(?P<op><=|>=|<|>|~|\^)?\s*(?:(?:version|release|ver\.?)\s*|(?P<v>v)(?=\d))(?P<value>\d[\w.+:~-]*(?:\.[\w.+:~-]+)*)(?![\w.])'
    for m in re.finditer(pattern,name):
        add(('v' if m.group('v') else '')+m.group('value'),'name',name,
            m.start('value')-bool(m.group('v')),m.end('value'),'range' if m.group('op') else 'exact',m.group('op'))
    # Unmarked dotted versions are provisional observations too. Avoid model/order codes.
    for m in re.finditer(r'(?<![\w.])(?P<op><=|>=|<|>|~|\^)?(?P<value>\d+\.\d+(?:\.[0-9A-Za-z_+~-]+)*)(?![\w.])',name):
        if any(o['source']=='name' and o['span'][0]<=m.start('value')<o['span'][1] for o in observations):continue
        add(m.group('value'),'name',name,m.start('value'),m.end('value'),'range' if m.group('op') else 'exact',m.group('op'))
    for span in llm_spans or []:
        if not isinstance(span,dict) or span.get('source') not in {'name','version'}:invalid.append('invalid_llm_span');continue
        text=str(component.get(span['source']) or '');a=span.get('start');b=span.get('end');value=span.get('value')
        if not isinstance(a,int) or not isinstance(b,int) or not isinstance(value,str) or not 0<=a<b<=len(text) or text[a:b]!=value or not re.search(r'\d',value):
            invalid.append('unsupported_llm_span');continue
        if any(o['source']==span['source'] and o['span']==[a,b] for o in observations):continue
        add(value,span['source'],text,a,b,'range' if re.match(r'\s*[<>~^]',text[max(0,a-2):a]) else 'exact')
    observations=list({(o['source'],o['span'][0],o['span'][1],o['value']):o for o in observations}.values())
    explicit=[o for o in observations if o['source']!='name' and o['kind']=='exact']
    named=[o for o in observations if o['source']=='name' and o['kind']=='exact']
    values={o['value'] for o in explicit};all_values={o['value'] for o in explicit+named}
    conflicts=[]
    if len(all_values)>1:conflicts.append('version_sources_disagree')
    if any(o['kind']=='range' for o in observations):missing.append('range_is_not_an_installed_version')
    normalized=next(iter(values)) if len(values)==1 and not conflicts and not synthetic else None
    comparison_version=next((o['raw'].strip() for o in explicit if o['source']=='version'),explicit[0]['raw'].strip() if explicit else None) if normalized else None
    status='conflict' if conflicts else 'reported' if normalized else 'provisional' if observations else 'unknown'
    if not normalized:missing.append('installed_version_unconfirmed')
    if synthetic:missing.append('synthetic_inventory_is_not_deployment_evidence')
    scheme={'pypi':'pep440','npm':'semver','cargo':'semver','golang':'semver','deb':'debian','rpm':'rpm'}.get(purl['type']) if purl else None
    return {'raw':raw,'normalized':normalized,'status':status,'observations':observations,'conflicts':conflicts,
            'comparison_version':comparison_version,
            'provisional_values':sorted({o['value'] for o in named}),'purl':purl,'scheme':scheme or 'unknown',
            'missing_evidence':missing,'rejected_spans':invalid,'deployment_verified':False,
            'comparison_policy':'No universal ordering is assumed; unsupported schemes remain unknown.'}

def compare_versions(a,b,scheme):
    """Never apply PEP440 or lexical ordering to an unidentified version scheme."""
    if a==b:return 0
    if scheme=='pep440':
        try:x,y=Version(a),Version(b);return (x>y)-(x<y)
        except InvalidVersion:return None
    if scheme=='semver':
        def parse(v):
            m=re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?',v)
            if not m:return None
            pre=m[4].split('.') if m[4] else None
            if pre and any(not x or (x.isdigit() and len(x)>1 and x[0]=='0') for x in pre):return None
            return tuple(map(int,m.group(1,2,3))),pre
        x,y=parse(a),parse(b)
        if x is None or y is None:return None
        if x[0]!=y[0]:return (x[0]>y[0])-(x[0]<y[0])
        if x[1] is None or y[1] is None:return (y[1] is not None)-(x[1] is not None)
        for left,right in zip(x[1],y[1]):
            if left==right:continue
            if left.isdigit() and right.isdigit():return (int(left)>int(right))-(int(left)<int(right))
            if left.isdigit()!=right.isdigit():return -1 if left.isdigit() else 1
            return (left>right)-(left<right)
        return (len(x[1])>len(y[1]))-(len(x[1])<len(y[1]))
    if scheme=='debian':
        try:
            from debian.debian_support import Version as DebianVersion
            x,y=DebianVersion(a),DebianVersion(b);return (x>y)-(x<y)
        except (ImportError,ValueError):return None
    if scheme=='rpm':return rpm_compare(a,b)
    # Vendor/custom ordering is unresolved until an explicit comparator is supplied.
    return None

def rpm_compare(a,b):
    """ASCII EVR comparison, including tilde/caret; invalid EVRs stay unknown.
    Specification: https://rpm.org/docs/6.0.x/man/rpm-version.7
    """
    def parse(v):
        m=re.fullmatch(r'(?:(\d+):)?([A-Za-z0-9._+~^]+)(?:-([A-Za-z0-9._+~^]+))?',v)
        return (int(m[1] or 0),m[2],m[3] or '') if m else None
    def cmp_component(x,y):
        i=j=0
        while i<len(x) or j<len(y):
            while i<len(x) and not x[i].isalnum() and x[i] not in '~^':i+=1
            while j<len(y) and not y[j].isalnum() and y[j] not in '~^':j+=1
            l=x[i] if i<len(x) else '';r=y[j] if j<len(y) else ''
            if l=='~' or r=='~':
                if l!='~':return 1
                if r!='~':return -1
                i+=1;j+=1;continue
            if l=='^' or r=='^':
                if not l:return -1
                if not r:return 1
                if l!='^':return 1
                if r!='^':return -1
                i+=1;j+=1;continue
            if not l or not r:return (bool(l)>bool(r))-(bool(l)<bool(r))
            number=l.isdigit()
            if number!=r.isdigit():return 1 if number else -1
            a1=i;b1=j
            while i<len(x) and (x[i].isdigit() if number else x[i].isalpha()):i+=1
            while j<len(y) and (y[j].isdigit() if number else y[j].isalpha()):j+=1
            left=x[a1:i];right=y[b1:j]
            if number:
                left=left.lstrip('0');right=right.lstrip('0')
                if len(left)!=len(right):return (len(left)>len(right))-(len(left)<len(right))
            if left!=right:return (left>right)-(left<right)
        return 0
    left,right=parse(a),parse(b)
    if left is None or right is None:return None
    if left[0]!=right[0]:return (left[0]>right[0])-(left[0]<right[0])
    return cmp_component(left[1],right[1]) or cmp_component(left[2],right[2])

def evaluate_configurations(nodes,vendor,product,version,scheme,part=None):
    from ics_agent_matcher_full.ics_agent_matcher.matcher import cpe_parts
    def combine(vs,operator):
        if not vs:return 'unknown'
        if operator=='AND':return 'false' if 'false' in vs else 'unknown' if 'unknown' in vs else 'true'
        return 'true' if 'true' in vs else 'unknown' if 'unknown' in vs else 'false'
    def rec(node):
        values=[]
        for item in node.get('cpeMatch',[]):
            parts=cpe_parts(item.get('criteria',''))
            if not parts or (parts[3],parts[4])!=(vendor,product) or (part and parts[2]!=part):values.append('unknown');continue
            # Non-vulnerable product predicates may be platform requirements, not refutations.
            if not item.get('vulnerable'):values.append('unknown');continue
            if not version:values.append('unknown');continue
            if parts[5] not in {'*','-'}:
                d=compare_versions(version,parts[5],scheme)
                values.append('unknown' if d is None else 'true' if d==0 else 'false');continue
            tests=[]
            for field,operator in [('versionStartIncluding','ge'),('versionStartExcluding','gt'),('versionEndIncluding','le'),('versionEndExcluding','lt')]:
                if field in item:
                    d=compare_versions(version,str(item[field]),scheme)
                    tests.append('unknown' if d is None else 'true' if {'ge':lambda:d>=0,'gt':lambda:d>0,'le':lambda:d<=0,'lt':lambda:d<0}[operator]() else 'false')
            values.append(combine(tests,'AND') if tests else 'true')
        values.extend(rec(child) for child in node.get('children',[])+node.get('nodes',[]))
        result=combine(values,node.get('operator','OR'))
        return {'true':'false','false':'true','unknown':'unknown'}[result] if node.get('negate') else result
    return combine([rec(n) for n in nodes],'OR')
