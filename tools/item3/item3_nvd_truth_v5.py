"""Independent dictionary binding and NVD configuration-tree truth.

Never imports the production identifier, retrieval, LLM or saved predictions.
Missing identity/environment facts remain unknown, not negative labels.
"""
from collections import defaultdict
import json,re
from tools.item3.item3_truth_oracle import parts,identity,literal,condition,version_compare,has_wildcard
from tools.item3.item3_advisory_scope import vendor_key,product_key,normalized
from tools.item3.item3_truth_v4 import product_line,line_state

def either(values):
    return True if True in values else None if None in values else False

def both(values):
    return False if False in values else None if None in values else True

def evaluate_tree(configurations,fields):
    """Return applicability of THIS component, preserving other environment facts.

    Each subtree tracks environment truth and positive vulnerable-target support.
    Negation is a constraint; it cannot manufacture vulnerable-target support.
    """
    ident=identity(fields)
    def rec(node):
        if isinstance(node,list):
            values=[rec(n) for n in node]
            return either([v[0] for v in values]),either([v[1] for v in values])
        if not isinstance(node,dict):return None,False
        values=[]
        for match in node.get('cpeMatch',[]):
            parsed=parts(match.get('criteria'))
            if parsed is None:values.append((None,None));continue
            if identity(parsed)!=ident:
                values.append((None,False));continue
            state=condition(fields,match)
            values.append((state,state if match.get('vulnerable') is True else False))
        for name in ('nodes','children'):
            values.extend(rec(child) for child in node.get(name,[]))
        if not values:return None,False
        operator=node.get('operator','OR').upper()
        env=(both if operator=='AND' else either)([v[0] for v in values])
        support=either([v[1] for v in values])
        target=both([env,support]) if operator=='AND' else support
        if node.get('negate'):
            return None if env is None else not env,False
        return env,target
    return rec(configurations)[1] if configurations else None


class DictionaryBinding:
    """Exact source spellings and exact official titles; no ranking/fuzzy aliases."""
    def __init__(self,path):
        self.names=defaultdict(set);self.titles=defaultdict(set);self.versions=defaultdict(set)
        self.examples={};self.ids=set();self.rows=0;self.cache={}
        with open(path,encoding='utf-8') as f:
            for text in f:
                r=json.loads(text);p=parts(r.get('cpe'))
                if not p or r.get('deprecated') or has_wildcard(p[1]) or has_wildcard(p[2]):continue
                ident=identity(p);self.ids.add(ident);self.rows+=1
                self.names[(vendor_key(ident[1]),product_key(ident[2],ident[1]))].add(ident)
                # Firmware spelling is a possible identity, not an assertion that
                # a device and its firmware are the same component.
                if ident[2].endswith('_firmware'):
                    self.names[(vendor_key(ident[1]),product_key(ident[2][:-9],ident[1]))].add(ident)
                self.examples.setdefault(ident,{'cpe':r['cpe'],'cpe_name_id':r.get('cpe_name_id'),'title':r.get('title')})
                if p[3] not in ('*','-'):self.versions[ident].add(literal(p[3]))
                title=str(r.get('title') or '')
                for suffix in (literal(p[4]),literal(p[3])):
                    if suffix and suffix not in ('*','-'):
                        title=re.sub(r'(?:\s|\(|\[|:)+[vV]?'+re.escape(suffix)+r'[\s)\]]*$', '',title,flags=re.I)
                self.titles[normalized(title)].add(ident)

    def bind(self,vendor,name,component_type='unknown',source_cpes=()):
        key=(vendor,name,component_type,tuple(sorted(source_cpes)))
        if key in self.cache:return self.cache[key]
        allowed={'application':{'a'},'library':{'a'},'device':{'h'},'firmware':{'a','o'},'operating-system':{'o'}}.get(component_type,{'a','o','h'})
        explicit={identity(p) for text in source_cpes if (p:=parts(text)) is not None and identity(p) in self.ids and p[0] in allowed}
        base,_=product_line(name)
        matches={i for i in self.names.get((vendor_key(vendor),product_key(base,vendor)),set()) if i[0] in allowed}
        title_matches={i for i in self.titles.get(normalized(vendor+' '+base),set()) if i[0] in allowed}
        if vendor_key(vendor) in ('','noassertion','unknown','other'):matches=set();title_matches=set()
        chosen=explicit or (matches|title_matches)
        method='explicit_CISA_CPE' if explicit else 'exact_official_dictionary_name_or_title'
        result={'status':'resolved' if len(chosen)==1 else 'ambiguous' if chosen else 'unresolved',
            'candidate_identities':[list(i) for i in sorted(chosen)],'method':method if chosen else None,
            'independent_of_model':True,'dictionary_examples':[self.examples[i] for i in sorted(chosen)]}
        self.cache[key]=result;return result

    def version(self,ident,raw):
        if raw in (None,'','NOASSERTION','*','-'):return None,'installed_version_not_supplied'
        value=re.sub(r'^[vV](?=\d)','',str(raw).strip())
        if re.fullmatch(r'\d+(?:\.\d+)*',value):return value,'explicit_numeric_installed_version'
        if value in self.versions[ident]:return value,'explicit_literal_matches_official_dictionary_version'
        return None,'vendor_version_representation_unverified'


class NVDTruth:
    def __init__(self,connection):
        self.records={};self.by_identity=defaultdict(set);self.rows=[]
        from tools.item3.item3_truth_oracle import walk
        for cve,text in connection.execute('SELECT cve,payload FROM cves ORDER BY cve'):
            r=json.loads(text);rows=list(walk(r.get('configurations',[])))
            if not rows:continue
            self.records[cve]=r
            for path,match in rows:
                p=parts(match.get('criteria'))
                if p is None:raise ValueError('Invalid original CPE: '+cve+path)
                self.rows.append((cve,path,match))
                if match.get('vulnerable') is True:self.by_identity[identity(p)].add(cve)
        self.universe=set(self.records);self.cache={}

    def state(self,ident,version):
        cachekey=(ident,version)
        if cachekey in self.cache:return self.cache[cachekey]
        fields=tuple(ident)+(version,)+(None,)*7
        states={}
        for cid in sorted(self.by_identity.get(ident,set())):
            if self.records[cid].get('vulnStatus')=='Rejected':states[cid]=None
            else:states[cid]=evaluate_tree(self.records[cid].get('configurations',[]),fields)
        self.cache[cachekey]=states;return states

    def state_fields(self,fields):
        """Evaluate independently fixed complete component facts, not model output."""
        fields=tuple(fields);key=('full_fields',fields)
        if key in self.cache:return self.cache[key]
        ident=identity(fields);states={}
        for cid in sorted(self.by_identity.get(ident,set())):
            states[cid]=None if self.records[cid].get('vulnStatus')=='Rejected' else evaluate_tree(self.records[cid].get('configurations',[]),fields)
        result={'expected_cves':sorted(c for c,s in states.items() if s is True),
            'unknown_cves':sorted(c for c,s in states.items() if s is None),
            'canonical_fields':fields,'unknown_scope':'listed_cves','truth_source':'full_NVD_configuration_trees'}
        self.cache[key]=result;return result

    def labels(self,binding,installed,binder,input_product):
        candidates=[tuple(i) for i in binding['candidate_identities']]
        if not candidates or line_state(installed,product_line(input_product)[1]) is False:
            return {'expected_cves':[],'unknown_cves':[],'unknown_scope':'all_scored_cves',
                'truth_status':'identity_unresolved' if not candidates else 'input_product_version_conflict',
                'positive_configuration_refs':{},'installed_version_evidence':[]}
        possibilities=[];version_evidence=[]
        for ident in candidates:
            value,basis=binder.version(ident,installed);possibilities.append(self.state(ident,value))
            version_evidence.append({'identity':list(ident),'version':value,'basis':basis})
        positive=[];unknown=[];refs={}
        for cve in sorted(set().union(*(set(s) for s in possibilities))):
            states=[s.get(cve,False) for s in possibilities]
            if all(v is True for v in states):
                positive.append(cve)
                # Store full configuration trees in the frozen source DB, not
                # flattened rows that would lose AND/OR/platform constraints.
                refs[cve]={'source':'NVD configurations','cve':cve}
            elif not all(v is False for v in states):unknown.append(cve)
        return {'expected_cves':positive,'unknown_cves':unknown,'unknown_scope':'listed_cves',
            'truth_status':'resolved_identity' if len(candidates)==1 else 'consensus_across_ambiguous_identities',
            'positive_configuration_refs':refs,'installed_version_evidence':version_evidence}
