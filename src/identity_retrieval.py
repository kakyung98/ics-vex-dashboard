"""Vendor-scoped product candidates: BM25 + character trigrams + RRF.

Retrieval scores are ranking signals, never probabilities or acceptance evidence.
All returned identities originate from the supplied dictionary snapshot.
"""
from collections import Counter,defaultdict
from functools import lru_cache
from pathlib import Path
import hashlib,json,math,re
from ics_agent_matcher_full.ics_agent_matcher.matcher import norm,cpe_parts

ROOT=Path(__file__).resolve().parents[1]
STOP={'the','and','of','for','vendor','application','version','versions','series'}

def tokens(text):return [w for w in re.findall(r'[a-z0-9]+',str(text).lower()) if w not in STOP]
def grams(text):
    s='^'+norm(text).replace('_','')+'$'
    return {s[i:i+3] for i in range(max(0,len(s)-2))}
def vendor_key(text):
    value=re.sub(r'^(organization|person):\s*','',str(text or ''),flags=re.I)
    parts=norm(value).split('_')
    while parts and parts[-1] in {'inc','incorporated','ltd','limited','llc','corp','corporation','ag','gmbh','co'}:parts.pop()
    return '_'.join(parts)

class ProductIndex:
    def __init__(self,rows,*,snapshot_hash=None,aliases=None):
        grouped={};self.by_cpe={};self.by_product=defaultdict(set);self.by_vendor=defaultdict(set);self.by_identity={}
        self.snapshot_hash=snapshot_hash
        self.aliases=[]
        for a in aliases or []:
            if isinstance(a,dict) and a.get('review_status')=='reviewed' and a.get('reviewer') and isinstance(a.get('source'),str) and a['source'].startswith('https://') and a.get('kind') in {'vendor_alias','product_alias'} and a.get('alias') and a.get('vendor'):
                if a['kind']=='vendor_alias' or a.get('product'):self.aliases.append(a)
        self.aliases_hash=hashlib.sha256(json.dumps(self.aliases,sort_keys=True).encode()).hexdigest()
        for r in rows:
            cpe=r.get('cpe','');p=cpe_parts(cpe)
            if not p or p[2] not in {'a','o','h'} or p[3] in {'*','-',''} or p[4] in {'*','-',''} or r.get('deprecated'):continue
            key=(p[2],p[3],p[4]);rid='identity-'+hashlib.sha256('|'.join(key).encode()).hexdigest()[:20]
            doc=grouped.setdefault(rid,{'candidate_id':rid,'part':p[2],'vendor':p[3],'product':p[4],
                'cpe':cpe,'origin':'nvd_dictionary','titles':set(),'release_count':0})
            title=r.get('title','')
            if isinstance(title,str) and len(doc['titles'])<3:doc['titles'].add(title)
            doc['release_count']+=1;self.by_cpe[cpe]=rid
        self.docs={rid:{**r,'titles':sorted(r['titles'])} for rid,r in grouped.items()}
        self.words=defaultdict(dict);self.trigrams=defaultdict(set);self.lengths={}
        for rid,r in self.docs.items():
            self.by_identity[(r['part'],r['vendor'],r['product'])]=rid
            self.by_product[norm(r['product'])].add(rid);self.by_vendor[vendor_key(r['vendor'])].add(rid)
            counts=Counter(tokens(' '.join([r['vendor'],r['product'],*r['titles']])))
            self.lengths[rid]=sum(counts.values())
            for w,n in counts.items():self.words[w][rid]=n
            for g in grams(r['product']):self.trigrams[g].add(rid)
        self.avglen=sum(self.lengths.values())/max(1,len(self.docs))

    def check_cpes(self,component):
        checks=[]
        allowed={'device':{'h'},'library':{'a'},'application':{'a'},'operating-system':{'o'},'firmware':{'a','o'}}.get(component.get('component_type'))
        for value in component.get('cpes',[]):
            p=cpe_parts(value)
            status='unsupported_escaped_cpe' if isinstance(value,str) and '\\' in value else 'invalid_format'
            rid=None;corrections=[];dictionary_status=status
            if p and p[2] in {'a','o','h'} and all(p[3:]) and not any(re.search(r'\s',x) for x in p[3:]):
                rid=self.by_identity.get(tuple(p[2:5]))
                if value in self.by_cpe:status='exact_dictionary_entry'
                elif rid and all(x=='*' for x in p[5:]):status='dictionary_product_identity'
                elif rid:status='product_found_release_or_attributes_unverified'
                else:
                    status='not_in_dictionary'
                    corrections=[self.docs[i]['cpe'] for i in sorted(self.by_product.get(norm(p[4]),set())) if self.docs[i]['vendor']==p[3] and self.docs[i]['product']==p[4] and self.docs[i]['part']!=p[2]][:3]
                dictionary_status=status
                if allowed and p[2] not in allowed:status='component_type_conflict'
            checks.append({'input':value,'status':status,'candidate_id':rid,
                           'dictionary_status':dictionary_status,
                           'identity_in_dictionary':rid is not None,
                           'usable_identity':rid is not None and status in {'exact_dictionary_entry','dictionary_product_identity'},
                           'suggested_dictionary_entries':corrections,'automatically_corrected':False})
        return checks

    def search(self,component,versions,k=20,query_expansions=None):
        name=component.get('name') or '';forms={norm(name)};cleaned=name
        expansions={norm(x) for x in query_expansions or [] if isinstance(x,str) and 0<len(x)<=160}
        expansions.discard('')
        for o in sorted([o for o in versions['observations'] if o['source']=='name'],key=lambda o:-o['span'][0]):
            a,b=o['span'];cleaned=cleaned[:a]+cleaned[b:]
        cleaned=re.sub(r'(?i)\b(?:version|release|ver)\b',' ',cleaned)
        cleaned=re.sub(r'(?i)\s+Vendor\s+Firmware/Application\s*$','',cleaned)
        cleaned=re.sub(r'(?i)\s+vers:[^\s/]+/[^\s]+\s*$','',cleaned)
        forms.add(norm(cleaned))
        for source in ['manufacturer','supplier']:
            value=component.get(source) or ''
            if value:
                stripped=re.sub(re.escape(value),' ',cleaned,flags=re.I)
                forms.add(norm(stripped))
        forms.discard('')
        vendor_aliases={vendor_key(a['alias']):vendor_key(a['vendor']) for a in self.aliases if a['kind']=='vendor_alias'}
        manufacturer=vendor_aliases.get(vendor_key(component.get('manufacturer')),vendor_key(component.get('manufacturer')))
        # Separator-only spelling equivalence is allowed only if unique in this
        # dictionary. No brand/parent-company or upstream relationship is inferred.
        equivalent=[v for v in self.by_vendor if v.replace('_','')==manufacturer.replace('_','')] if manufacturer else []
        if len(equivalent)==1:manufacturer=equivalent[0]
        alias_evidence={}
        alias_candidates=set()
        for a in self.aliases:
            if a['kind']!='product_alias' or norm(a['alias']) not in forms:continue
            for rid in self.by_product.get(norm(a['product']),set()):
                r=self.docs[rid]
                if r['vendor']!=a['vendor'] or (a.get('part') and r['part']!=a['part']):continue
                alias_candidates.add(rid)
                if manufacturer==vendor_key(r['vendor']):alias_evidence[rid]=a
        query=' '.join([name,component.get('supplier') or '',component.get('manufacturer') or '',
                        (versions.get('purl') or {}).get('name',''),' '.join(sorted(expansions))])
        n=len(self.docs);bm=Counter();char=Counter()
        for word in set(tokens(query)):
            posting=self.words.get(word,{})
            idf=math.log(1+(n-len(posting)+.5)/(len(posting)+.5))
            for rid,tf in posting.items():
                bm[rid]+=idf*tf*2.2/(tf+1.2*(.25+.75*self.lengths[rid]/max(1,self.avglen)))
        query_grams=set().union(*(grams(f) for f in forms|expansions)) if forms|expansions else set()
        informative=sorted((g for g in query_grams if g in self.trigrams),key=lambda g:(len(self.trigrams[g]),g))[:16]
        for g in informative:
            posting=self.trigrams[g];weight=math.log(1+n/(1+len(posting)))
            for rid in posting:char[rid]+=weight
        lexical=bm.most_common(100);characters=char.most_common(100);rrf=Counter()
        for ranked in [lexical,characters]:
            for rank,(rid,_) in enumerate(ranked,1):rrf[rid]+=1/(60+rank)
        exact=set().union(*(self.by_product.get(f,set()) for f in forms)) if forms else set()
        cpe_checks=self.check_cpes(component)
        cpe_ids={c['candidate_id'] for c in cpe_checks if c['usable_identity']}
        # Also recognize canonical "vendor product" names without a supplier field.
        for rid,_ in lexical[:100]:
            r=self.docs[rid]
            if norm(cleaned)==norm(r['vendor']+' '+r['product']):exact.add(rid)
        proposal_pool=set().union(*(self.by_product.get(f,set()) for f in expansions)) if expansions else set()
        pool=set(rrf)|exact|cpe_ids|alias_candidates|proposal_pool;ranked=[]
        supplier=vendor_key(component.get('supplier'))
        for rid in pool:
            r=self.docs[rid];v=vendor_key(r['vendor']);conflicts=[];notes=[]
            name_vendor=norm(cleaned)==norm(r['vendor']+' '+r['product'])
            if manufacturer and manufacturer!=v:conflicts.append('explicit_manufacturer_differs')
            if supplier and supplier!=v:notes.append('supplier_is_not_assumed_to_be_product_vendor')
            if cpe_ids and rid not in cpe_ids:notes.append('different_from_reported_cpe')
            if cpe_ids and exact and not cpe_ids&exact:conflicts.append('name_and_reported_cpe_disagree')
            if len(cpe_ids)>1:conflicts.append('multiple_reported_cpe_identities')
            purl=versions.get('purl')
            if purl and exact and norm(purl['name']) in self.by_product and not self.by_product[norm(purl['name'])]&exact:
                conflicts.append('purl_name_and_component_name_disagree')
            features={'exact_product':rid in exact,'dictionary_verified_input_cpe':rid in cpe_ids,
                'llm_query_proposal':rid in proposal_pool,
                'reviewed_vendor_scoped_alias':rid in alias_evidence,
                'purl_name_matches_product':bool((versions.get('purl') or {}).get('name') and norm(versions['purl']['name'])==norm(r['product'])),
                'manufacturer_match':bool(manufacturer and manufacturer==v),'supplier_match':bool(supplier and supplier==v),
                'vendor_named_in_component':name_vendor,'bm25':round(bm[rid],6),'character_overlap':round(char[rid],6),
                'rrf':round(rrf[rid],6)}
            score=rrf[rid]+.08*(rid in exact)+.08*(rid in alias_evidence)+.10*(rid in cpe_ids)+.03*features['manufacturer_match']+.01*features['supplier_match']+.03*name_vendor
            ranked.append({**r,'features':features,'ranking_score':round(score,6),'conflicts':conflicts,'notes':notes,
                'evidence_refs':['input:name']+(['input:manufacturer'] if manufacturer else [])+(['input:supplier'] if supplier else [])+
                    (['input:cpe'] if rid in cpe_ids else [])+['dictionary:'+rid]+
                    (['reviewed_alias:'+alias_evidence[rid]['source']] if rid in alias_evidence else []),
                'alias_evidence':alias_evidence.get(rid)})
        ranked.sort(key=lambda r:(-r['ranking_score'],r['candidate_id']))
        # Preserve all exact competitors for ambiguity checks even if display is top-k.
        mandatory=exact|cpe_ids|alias_candidates|proposal_pool
        kept=ranked[:k]+[r for r in ranked[k:] if r['candidate_id'] in mandatory]
        return {'candidates':kept,'query_forms':sorted(forms),'algorithm':'BM25 + character-trigram retrieval + reciprocal-rank fusion',
                'query_expansions':sorted(expansions),'model_proposals_are_identity_evidence':False,
                'input_cpe_checks':cpe_checks,
                'top_k':k,'snapshot_sha256':self.snapshot_hash,'dictionary_identities':n,
                'reviewed_aliases_sha256':self.aliases_hash,'reviewed_alias_records':len(self.aliases),
                'ranking_scores_are_probabilities':False,'fuzzy_acceptance_calibrated':False}

@lru_cache(maxsize=1)
def get_index():
    file=ROOT/'data/cpe_dictionary.jsonl'
    digest=hashlib.sha256(file.read_bytes()).hexdigest()
    def rows():
        with file.open(encoding='utf-8') as f:
            for line in f:yield json.loads(line)
    alias_file=ROOT/'data/identity_aliases_v3.json'
    aliases=json.loads(alias_file.read_text(encoding='utf-8')).get('records',[]) if alias_file.is_file() else []
    return ProductIndex(rows(),snapshot_hash=digest,aliases=aliases)
