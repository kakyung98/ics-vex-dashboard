"""Read-only leakage/provenance audit; frozen rows and pending labels stay intact."""
import hashlib,json,sys
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json

def main():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    directory=ROOT/'data/operational_review_benchmark_v2'
    manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'));rows=[];files={}
    for split in ['train','validation','test']:
        file=directory/(split+'.annotation.jsonl')
        files[file.name]={'hash_matches_manifest':hashlib.sha256(file.read_bytes()).hexdigest()==manifest['files'][file.name]}
        rows.extend(json.loads(l) for l in file.read_text(encoding='utf-8').splitlines())
    x=TfidfVectorizer(analyzer='char_wb',ngram_range=(3,5),min_df=2).fit_transform(r['description'].lower() for r in rows)
    similarities=cosine_similarity(x);pairs=[]
    for i,a in enumerate(rows):
        for j in range(i+1,len(rows)):
            b=rows[j]
            if a['split']!=b['split'] and similarities[i,j]>=.85:
                pairs.append({'a':a['cve'],'a_split':a['split'],'b':b['cve'],'b_split':b['split'],'similarity':round(float(similarities[i,j]),5)})
    cves=[r['cve'] for r in rows];descs=[r['description_group_sha256'] for r in rows]
    cache=json.loads((ROOT/'data/nvd_cache.json').read_text(encoding='utf-8'))
    cvss=json.loads((ROOT/'data/nvd_cvss.json').read_text(encoding='utf-8'))
    enriched=[]
    for r in rows:
        rec=cache.get(r['cve'],{});metric=rec.get('metric') or {}
        enriched.append({'id':r['id'],'split':r['split'],'cve':r['cve'],
            'vector':cvss.get(r['cve'],{}).get('vector') or metric.get('vector'),
            'cwes':rec.get('cwes',[]),'provenance':'local_nvd_cache_and_cvss_snapshot',
            'source_description_matches':hashlib.sha256(r['description'].encode()).hexdigest()==r['source']['description_sha256']})
    result={'files':files,'counts':dict(Counter(r['split'] for r in rows)),
        'unique_cve_count':len(set(cves)),'unique_identical_description_count':len(set(descs)),
        'near_duplicate_cross_split_threshold':.85,'near_duplicate_cross_split_pairs':sorted(pairs,key=lambda r:-r['similarity']),
        'annotation_cvss_missing':sum(not r.get('cvss_vector') for r in rows),
        'annotation_cwe_missing':sum(not r.get('cwe') for r in rows),
        'enriched_cvss_available':sum(bool(r['vector']) for r in enriched),
        'enriched_cwe_available':sum(bool(r['cwes']) for r in enriched),
        'human_adjudicated':sum(r['review_status']=='adjudicated' for r in rows),
        'training_ready':False,'reason':'Annotations pending; resolve near-duplicate/product group leakage before real-CVE training.',
        'frozen_inputs_modified':False,'similarity_is_candidate_not_proven_semantic_duplicate':True}
    atomic_json(ROOT/'results/operational_benchmark_audit.json',result)
    atomic_json(ROOT/'results/operational_benchmark_enriched_context.json',{'cases':enriched})
    print(json.dumps({k:v for k,v in result.items() if k!='near_duplicate_cross_split_pairs'}))
    print('Near-duplicate cross-split candidates:',len(pairs))

if __name__=='__main__':main()
