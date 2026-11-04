"""Expand real operational inputs without inventing gold or changing frozen splits."""
from pathlib import Path
from collections import defaultdict,Counter
import hashlib,json,re,sys,zipfile
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.vex_routing import classify


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def build():
    out=ROOT/'data/operational_expansion_v1'
    if (out/'manifest.json').exists():raise FileExistsError('Frozen expansion exists; use a new version.')
    nvd=json.loads((ROOT/'data/nvd_cache.json').read_text(encoding='utf-8'))
    advisories=json.loads((ROOT/'data/cisa_advisories.json').read_text(encoding='utf-8'))
    parent={c:c for c in nvd};origins=defaultdict(list);summaries=defaultdict(list)
    def find(c):
        while parent[c]!=c:parent[c]=parent[parent[c]];c=parent[c]
        return c
    def union(a,b):parent[find(a)]=find(b)
    for aid,rec in advisories.items():
        ids=[c for c in rec.get('cves',[]) if c in nvd]
        for c in ids:origins[c].append(aid)
        for c in ids[1:]:union(ids[0],c)
    archive=ROOT/'data/upstream_csaf_latest.zip'
    with zipfile.ZipFile(archive) as z:
        names={n:n for n in z.namelist()}
        for aid,rec in advisories.items():
            path=rec.get('csaf_path')
            if not path:continue
            found=[n for n in names if n.endswith('/'+path)]
            if len(found)!=1 or z.getinfo(found[0]).file_size>4*1024**2:continue
            d=json.loads(z.read(found[0]));sha=hashlib.sha256(json.dumps(d,sort_keys=True).encode()).hexdigest()
            if sha!=rec.get('csaf_sha256'):continue
            for v in d.get('vulnerabilities',[]):
                if v.get('cve') not in nvd:continue
                for note in v.get('notes',[]):
                    text=note.get('text','')
                    if note.get('category')=='summary' and text:
                        summaries[v['cve']].append({'id':aid+':'+digest(text)[:12],'text':text,'source_kind':'summary',
                            'source':{'source':'CISA CSAF','advisory_id':aid,'url':rec.get('url'),'document_sha256':sha}})
    frozen={};oldgroups=defaultdict(list)
    for split in ['train','validation','test']:
        for line in (ROOT/'data/item4_v3'/(split+'.cases.jsonl')).read_text(encoding='utf-8').splitlines():
            row=json.loads(line);frozen[row['cve']]=split;oldgroups[row['group_id']].append(row['cve'])
    for members in oldgroups.values():
        for c in members[1:]:union(members[0],c)
    normalized={}
    for c,r in nvd.items():
        text=' '.join(r.get('description','').lower().split())
        if text in normalized:union(c,normalized[text])
        elif text:normalized[text]=c
    candidates=[];route_counts=Counter()
    for c,rec in sorted(nvd.items()):
        case={'cve':c,'description':rec.get('description',''),'cwe':rec.get('cwes',[]),'routing_sources':summaries[c]}
        route=classify(case);route_counts[route['requirement']]+=1
        if route['requirement']=='operational_review':
            candidates.append({**case,'analysis_route_prediction':route,'advisory_ids':sorted(origins[c])})
    # Bound lexical duplicate grouping to the eligible cohort; no all-pairs dense
    # matrix over the full 12k corpus. This is not proof of semantic independence.
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    vectors=TfidfVectorizer(analyzer='char_wb',ngram_range=(3,5),min_df=2).fit_transform(r['description'].lower() for r in candidates)
    matrix=cosine_similarity(vectors);near=0
    for i,a in enumerate(candidates):
        for j in range(i+1,len(candidates)):
            if matrix[i,j]>=.85:union(a['cve'],candidates[j]['cve']);near+=1
    groups=defaultdict(list)
    for c in nvd:groups[find(c)].append(c)
    assignments={};conflicts=[]
    for group,members in groups.items():
        locked={frozen[c] for c in members if c in frozen}
        if len(locked)>1:split='quarantine';conflicts.append({'group_id':digest(sorted(members))[:20],'frozen_splits':sorted(locked),'members':members})
        elif locked:split=next(iter(locked))
        else:
            bucket=int(digest(sorted(members))[:8],16)%100
            split='train' if bucket<80 else 'validation' if bucket<90 else 'test'
        for c in members:assignments[c]=split
    out.mkdir(parents=True)
    result=defaultdict(list)
    for row in candidates:
        c=row['cve'];split=assignments[c]
        result[split].append({**row,'id':'expanded:'+c,'split':split,'group_id':'global-'+digest(sorted(groups[find(c)]))[:20],
            'routing_gold':None,'reference_questions':None,'reference_assessment':None,'review_status':'pending_LLM_proposal_and_independent_review',
            'human_gold':False,'train_ready':False,'frozen_original_split':frozen.get(c),
            'operator_scenarios':[],'condition_function_proposals':None})
    for split in ['train','validation','test','quarantine']:
        (out/(split+'.inputs.jsonl')).write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in result[split]),encoding='utf-8')
    manifest={'schema':'ics-vex-operational-expansion/1','source_population':len(nvd),'operational_candidates':len(candidates),
        'routes_over_full_corpus':dict(route_counts),'counts':{s:len(result[s]) for s in ['train','validation','test','quarantine']},
        'near_duplicate_pairs_grouped':near,'split_unit':'global advisory + original frozen group + exact description + eligible-cohort char TFIDF >=0.85',
        'frozen_split_bridges_quarantined':conflicts,'frozen_files_modified':False,
        'human_gold_count':0,'train_ready_count':0,'LLM_proposals_are_gold':False,'training_started':False,
        'source_hashes':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'data/nvd_cache.json',ROOT/'data/cisa_advisories.json',archive]},
        'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.jsonl')},
        'limitations':['Input expansion is not new labelled training data.','Do not count multiple simulated scenarios as independent CVEs.',
                       'Unknown routing is not relaxed to increase cohort size.','Semantic and unseen-product independence remain unverified.']}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({k:manifest[k] for k in ['source_population','operational_candidates','counts','near_duplicate_pairs_grouped']},indent=2))


if __name__=='__main__':build()
