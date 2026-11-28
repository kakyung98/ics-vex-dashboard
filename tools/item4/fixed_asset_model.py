"""Fixed MITRE asset meanings, literal phrase evidence, and anchored text assignment."""
from pathlib import Path
from collections import defaultdict
import json,re,hashlib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer,ENGLISH_STOP_WORDS
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import normalize
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.metrics import silhouette_samples

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'results/icsa_fixed18_reclassification'
ROOT_PATTERNS=[
 r'\b(?:engineering |operator )?workstations?\b',
 r'\bhuman[ -]machine interfaces?\b|\bHMIs?\b',
 r'\bprogrammable logic controllers?\b|\bPLCs?\b',
 r'\bremote terminal units?\b|\bRTUs?\b',
 r'\bintelligent electronic devices?\b|\bIEDs?\b|\bprotection relays?\b',
 r'\b(?:data )?historians?\b',r'\bcontrol servers?\b',r'\bapplication servers?\b',
 r'\b(?:data |serial to ethernet |industrial )?gateways?\b',
 r'\bsafety controllers?\b',r'\bVPN\b|\bvirtual private network\b',
 r'\bjump hosts?\b|\bbastion hosts?\b',r'\b(?:remote|field|distributed) I/?O\b',
 r'\brouters?\b',r'\b(?:ethernet|network|managed|industrial|layer [23]) switches?\b',
 r'\bfirewalls?\b',r'\bdistributed control systems?\b|\bDCS\b',
 r'\bprogrammable automation controllers?\b|\bPACs?\b']


def load(variant='source'):
    source_path=OUT/('source_advisories_fulltext_v3.json' if variant=='source_v3' else 'source_advisories.json')
    source=json.loads(source_path.read_text(encoding='utf-8'))
    seed=json.loads((OUT/'seed_navigation.json').read_text(encoding='utf-8'))
    stix=json.loads((ROOT/'data/standards/ics-attack-20.1.json').read_text(encoding='utf-8'))
    objects={e['external_id']:o for o in stix['objects'] if o.get('type')=='x-mitre-asset'
             and not o.get('revoked') for e in o.get('external_references',[]) if e.get('source_name')=='mitre-attack'}
    assets=seed['categories'];templates=[]
    # Related assets are overlapping relationships, not an exclusive taxonomy.
    canonical={re.sub(r'\s*\([^)]*\)','',a['name']).casefold():a['id'] for a in assets}
    for i,a in enumerate(assets):
        obj=objects[a['id']]
        templates.append(dict(key=a['id'],parent_id=a['id'],name=a['name'],description=obj['description'],
            pattern=ROOT_PATTERNS[i],kind='top_level',url='https://attack.mitre.org/assets/'+a['id']+'/'))
        for j,related in enumerate(obj.get('x_mitre_related_assets',[])):
            base=re.sub(r'\s*\([^)]*\)','',related['name']).strip()
            words=re.findall(r'[A-Za-z0-9]+',base)
            pattern=r'\b'+r'[\s/–—-]+'.join(re.escape(w) for w in words)+r's?\b'
            target=canonical.get(base.casefold(),a['id'])
            templates.append(dict(key=f"{a['id']}:related:{j}",parent_id=target,
                relation_owner=a['id'],name=related['name'],description=related['description'],
                pattern=pattern,kind='related_asset',url='https://attack.mitre.org/assets/'+a['id']+'/'))
    if variant=='source_v3':
        aliases={
            'A0001':r'\bengineering stations?\b',
            'A0002':r'\bhuman[\s\u2010-\u2015-]+machine[\s\u2010-\u2015-]+interfaces?\b',
            'A0015':r'\b(?:ethernet|network|managed|industrial|layer[ -]?[23])\s+switch(?:es)?\b',
            'Field Device / Controller':r'\bfield (?:devices?|controllers?)\b',
            'Operator Workstation (OWS)':r'\boperator stations?\b',
            'License Server':r'\blicen[cs]e management servers?\b',
            'Database Server':r'\b(?:SQL|MS SQL|Oracle database) servers?\b',
            'Update / Patch Management Server':r'\b(?:patch management|update management|patch|update) servers?\b',
            'Asset Management Server':r'\bFactoryTalk AssetCent(?:er|re)\b|\basset management servers?\b',
            'Telemetry Server':r'\bremote data servers?\b|\bPI Feeders?\b',
            'Supervisory Control And Data Acquisition (SCADA) Server':r'\bSCADA servers?\b',
            'Building Management / Automation System (BMS / BAS)':r'\bbuilding (?:management|automation) systems?\b',
            'Distribution/Energy Management System (DMS/EMS)':r'\b(?:distribution|energy) management systems?\b',
            'Safety Instrumented System (SIS) controller':r'\bSIS controllers?\b',
            'Emergency Shutdown Systems (ESD) controller':r'\bESD controllers?\b',
            'Variable Frequency Drive (VFD)':r'\bvariable[\s\u2010-\u2015-]+frequency[\s\u2010-\u2015-]+drives?\b',
        }
        for t in templates:
            if t['kind']=='related_asset':
                base=re.sub(r'\s*\([^)]*\)','',t['name']).strip()
                words=re.findall(r'[A-Za-z0-9]+',base);pieces=[]
                for word in words:
                    if word.lower().endswith('s') and not word.lower().endswith('ss') and len(word)>3:pieces.append(re.escape(word[:-1])+'s?')
                    elif word.lower().endswith(('ch','sh','x','z')):pieces.append(re.escape(word)+'(?:es)?')
                    else:pieces.append(re.escape(word))
                if words and not words[-1].lower().endswith(('s','ch','sh','x','z')):pieces[-1]+='s?'
                t['pattern']=r'\b'+r'[\s/\u2010-\u2015-]+'.join(pieces)+r'\b'
            extra=aliases.get(t['key']) or aliases.get(t['name'])
            if extra:t['pattern']='(?:'+t['pattern']+')|(?:'+extra+')'
    return source,seed,assets,templates


def phrase_evidence(rows,templates):
    fingerprint=hashlib.sha256(json.dumps([[r['id'],r['feature_text'],r.get('feature_fragments'),r.get('validated_original_evidence')] for r in rows],ensure_ascii=False).encode()+json.dumps(templates,sort_keys=True).encode()).hexdigest()
    cache=OUT/('phrase_evidence_cache.'+fingerprint[:12]+'.json')
    if cache.exists():
        previous=json.loads(cache.read_text(encoding='utf-8'))
        if previous.get('input_sha256')==fingerprint:return previous['evidence']
    compiled=[(t,re.compile(t['pattern'],re.I)) for t in templates]
    output=[]
    for row in rows:
        text=row['feature_text'];matches=[]
        fragments=row.get('feature_fragments')
        approved={(e['template_key'],*e['span']) for e in row.get('validated_original_evidence',[])}
        for t,pattern in compiled:
            for m in pattern.finditer(text):
                if fragments:
                    if t['name']=='Field Device / Controller' and not any(f['source_field']=='original_icsa_overview' and f['assembled_span'][0]<=m.start() and m.end()<=f['assembled_span'][1] for f in fragments):continue
                    q=m.group().upper()
                    if q=='PACS' and re.search(r'picture.{0,12}archiv',text,re.I) and not re.search(r'programmable automation controller',text,re.I):continue
                    if q=='PLC' and re.search(r'power[ -]line communication',text,re.I) and not re.search(r'programmable logic controller',text,re.I):continue
                    if q=='DCS' and re.search(r'device configuration software',text,re.I) and not re.search(r'distributed control system',text,re.I):continue
                    fragment=next((f for f in fragments if f['assembled_span'][0]<=m.start() and m.end()<=f['assembled_span'][1]),None)
                    if fragment is None:continue
                    if fragment['source_field']=='original_icsa_overview' and (t['key'],m.start(),m.end()) not in approved:continue
                matches.append(dict(template_key=t['key'],asset_id=t['parent_id'],template_name=t['name'],
                    template_kind=t['kind'],template_description=t['description'],definition_url=t['url'],
                    quote=m.group(),span=[m.start(),m.end()],source_url=row['url'],source_field='source_feature_text',
                    source_excerpt=text[max(0,m.start()-100):min(len(text),m.end()+150)]))
        # Prefer a specific phrase such as Operator Workstation to generic Workstation.
        if matches:
            if fragments:
                strong=[m for m in matches if not any(o['span'][0]<=m['span'][0] and m['span'][1]<=o['span'][1]
                        and len(o['quote'])>len(m['quote']) for o in matches)]
            else:
                longest=max(len(m['quote']) for m in matches)
                strong=[m for m in matches if len(m['quote'])>=max(3,longest*.6)]
            related_spans={(m['span'][0],m['span'][1]) for m in strong if m['template_kind']=='related_asset'}
            strong=[m for m in strong if not(m['template_kind']=='top_level'
                and tuple(m['span']) in related_spans and m['quote'].casefold()!=m['template_name'].casefold())]
        else:strong=[]
        output.append(dict(all=matches,strong=strong))
    temporary=cache.with_name(cache.name+'.'+str(__import__('os').getpid())+'.tmp')
    temporary.write_text(json.dumps(dict(input_sha256=fingerprint,evidence=output),ensure_ascii=False),encoding='utf-8');temporary.replace(cache)
    return output


def prepare(variant='source'):
    source,seed,assets,templates=load(variant);rows=source['advisories'];classes=[a['id'] for a in assets]
    if variant=='source_v3':assert source.get('feature_enrichment_version')=='v3'
    texts=[re.sub(r'\b(?:CVE-\d{4}-\d+|ICSA-\S+|CWE-\d+)\b',' ',r['feature_text'],flags=re.I) for r in rows]
    stop=set(ENGLISH_STOP_WORDS)
    if variant=='without_vendor':
        index=json.loads((ROOT/'site/advisories_list.json').read_text(encoding='utf-8'))['advisories']
        stop.update(w.lower() for a in index for w in re.findall('[A-Za-z]{3,}',a.get('vendor','')))
        stop.update(['vulnerability','vulnerabilities','update','updates','overflow','buffer','versions','version','firmware'])
    if variant=='source_v3':
        inner=TfidfVectorizer(ngram_range=(1,2),stop_words=sorted(stop)).build_analyzer()
        def fragments_analyzer(text):return [term for line in text.splitlines() for term in inner(line)]
        vectorizer=TfidfVectorizer(analyzer=fragments_analyzer,min_df=1,max_features=30000,sublinear_tf=True,dtype=np.float32)
    else:
        vectorizer=TfidfVectorizer(ngram_range=(1,2),min_df=1,max_features=30000,
            sublinear_tf=True,stop_words=sorted(stop),dtype=np.float32)
    x=vectorizer.fit_transform(texts)
    template_x=vectorizer.transform([t['name']+' '+t['description'] for t in templates])
    evidence=phrase_evidence(rows,templates)
    legacy=[np.array([classes.index(c) for c in seed['advisory_asset_ids'][r['id']]],dtype=int) for r in rows]
    allowed=[np.array(sorted({classes.index(m['asset_id']) for m in e['strong']}),dtype=int) for e in evidence]
    known=np.array([i for i,a in enumerate(legacy) if len(a)])
    raw_sim=cosine_similarity(x,x[known]);nearest=raw_sim.argmax(axis=1);max_raw=raw_sim[np.arange(len(rows)),nearest]
    return dict(source=source,seed=seed,rows=rows,classes=classes,assets=assets,templates=templates,
        vectorizer=vectorizer,x=x,template_x=template_x,evidence=evidence,legacy=legacy,
        allowed=allowed,known=known,raw_sim=raw_sim,nearest=nearest,max_raw=max_raw)


def fit(p,dim,definition_weight,anchor_weight,iterations=10,threshold=.05):
    x=p['x'];legacy=p['legacy'];known=p['known'];classes=p['classes']
    svd=TruncatedSVD(n_components=dim,random_state=42)
    z=normalize(svd.fit_transform(x));zt=normalize(svd.transform(p['template_x']))
    definitions=normalize(np.array([zt[[j for j,t in enumerate(p['templates']) if t['parent_id']==c]].mean(axis=0) for c in classes]))
    seed_centers=[]
    for j in range(18):
        indices=[i for i in known if j in legacy[i]]
        seed_centers.append(z[indices].mean(axis=0) if indices else definitions[j])
    initial=normalize(np.array(seed_centers)+definition_weight*definitions);centers=initial.copy()
    for _ in range(iterations+1):
        decision_centers=centers.copy()
        scores=z@centers.T
        # Do not invent a seedless Jump Host category from generic server words.
        jump=classes.index('A0012')
        for i in range(len(z)):
            if jump not in p['allowed'][i]:scores[i,jump]=-1e6
        labels=scores.argmax(axis=1)
        for i,allowed in enumerate(p['allowed']):
            if len(allowed):labels[i]=allowed[np.argmax(scores[i,allowed])]
        proposed=normalize(np.array([z[labels==j].mean(axis=0) if (labels==j).any() else initial[j] for j in range(18)]))
        centers=normalize(anchor_weight*initial+proposed)
    reject=((p['max_raw']<threshold)|(x.getnnz(axis=1)==0))
    for i in range(len(z)):
        if len(p['allowed'][i]) or len(legacy[i]):reject[i]=False
    y=labels.copy();y[reject]=-1
    # Final source-constrained labels use the final center scores, not injected label features.
    native=silhouette_samples(z,y,metric='cosine')
    metrics=dict(full_population=len(z),unassigned=int(reject.sum()),assigned=int((~reject).sum()),
        full_svd_cosine_silhouette=float(native.mean()),svd_explained_variance=float(svd.explained_variance_ratio_.sum()),
        nonempty_asset_types=len(set(y)-{-1}),unassigned_scored_as_separate_group=True,
        negative_silhouette_records=int((native<0).sum()),
        literal_phrase_advisories=sum(bool(e['strong']) for e in p['evidence']),
        target_silhouette_met=float(native.mean())>.5,target_unassigned_met=int(reject.sum())<=500)
    return dict(labels=y,model_labels=labels,svd=svd,z=z,centers=decision_centers,scores=scores,
                native=native,metrics=metrics,initial_centers=initial)


def reference_labels(p,consistent=True):
    labels=np.full(len(p['rows']),-1)
    for i,row in enumerate(p['rows']):
        allowed=p['allowed'][i];legacy=p['legacy'][i]
        if len(allowed)==1:labels[i]=allowed[0];continue
        if len(legacy)!=1 or (consistent and len(allowed) and legacy[0] not in allowed):continue
        text=row['feature_text']
        if p['source'].get('feature_enrichment_version')=='v3':
            asset=p['classes'][legacy[0]]
            if asset=='A0018' and re.search(r'picture.{0,12}archiv',text,re.I) and not re.search(r'programmable automation controller',text,re.I):continue
            if asset=='A0003' and re.search(r'power[ -]line communication',text,re.I) and not re.search(r'programmable logic controller',text,re.I):continue
            if asset=='A0017' and re.search(r'device configuration software',text,re.I) and not re.search(r'distributed control system',text,re.I):continue
        labels[i]=legacy[0]
    return labels
