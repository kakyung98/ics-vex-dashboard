"""Reproduce fixed-category assignments with traceable phrase/term explanations."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import csv,hashlib,json,re
from collections import Counter,defaultdict
from pathlib import Path
import numpy as np
from sklearn.metrics import silhouette_samples
from tools.item4.fixed_asset_model import ROOT,OUT,prepare,fit


from tools.common.paths import tool_path

def atomic(path,text):
    temp=path.with_name(path.name+'.codex-tmp');temp.write_text(text,encoding='utf-8');temp.replace(path)


def term_explanation(p,model,i,label):
    scores=model['scores'][i].copy();allowed=p['allowed'][i]
    candidates=allowed.tolist() if len(allowed)>1 else list(range(18))
    candidates=[j for j in candidates if j!=label and scores[j]>-1e5]
    if not candidates:return []
    rival=max(candidates,key=lambda j:scores[j])
    cache=p.setdefault('_coefficient_cache',{})
    if (label,rival) not in cache:
        cache[label,rival]=model['svd'].components_.T@(model['centers'][label]-model['centers'][rival])
    coefficients=cache[label,rival]
    row=p['x'].getrow(i);denominator=float(np.linalg.norm(row@model['svd'].components_.T)) or 1
    values=row.data*coefficients[row.indices]/denominator
    if '_terms' not in p:p['_terms']=p['vectorizer'].get_feature_names_out()
    terms=p['_terms'];source=p['rows'][i]['feature_text'];output=[]
    fragments=p['rows'][i].get('feature_fragments',[])
    for k in np.argsort(values)[::-1]:
        if values[k]<=1e-9:break
        term=terms[row.indices[k]]
        if not any(c.isalpha() for c in term):continue
        pattern=r'\b'+r'\W+'.join(re.escape(t) for t in term.split())+r'\b'
        matches=list(re.finditer(pattern,source,re.I))
        if fragments:
            matches=[m for m in matches if any(f['assembled_span'][0]<=m.start() and m.end()<=f['assembled_span'][1] for f in fragments)]
            matches.sort(key=lambda m:not any(f['source_field']=='original_icsa_overview' and f['assembled_span'][0]<=m.start() and m.end()<=f['assembled_span'][1] for f in fragments))
        match=matches[0] if matches else None
        if match:
            output.append(dict(term=term,contribution=round(float(values[k]),8),
                span=[match.start(),match.end()],rival_asset_id=p['classes'][rival]))
        if len(output)==3:break
    return output


def attach_source_quote(row,evidence):
    start,end=evidence['span'];text=row['feature_text']
    fragment=next((f for f in row.get('feature_fragments',[]) if f['assembled_span'][0]<=start and end<=f['assembled_span'][1]),None)
    lower=fragment['assembled_span'][0] if fragment else 0;upper=fragment['assembled_span'][1] if fragment else len(text)
    left=max(lower,start-90);right=min(upper,end+120)
    evidence.update(quote=text[start:end],source_excerpt=text[left:right],excerpt_span=[start-left,end-left],
        source_field=(fragment.get('origin_kind') or fragment['source_field']) if fragment else 'source_feature_text',
        source_url=fragment.get('source_url',row['url']) if fragment else row['url'])
    if fragment and fragment.get('source_artifact'):
        evidence['source_artifact']=fragment['source_artifact'];evidence['source_json_path']=fragment['source_json_path']
        evidence['original_span']=[fragment['original_span'][0]+start-lower,fragment['original_span'][0]+end-lower]
    return evidence


def main():
    import sys
    if '--legacy' not in sys.argv:
        from tools.item4.discriminant_asset_model import load_model
        p,model,selected=load_model('fulltext_best' if '--fulltext-v3' in sys.argv else None)
    else:
        candidates=[]
        for filename in ['hierarchical_search.json','refine_search.json']:
            path=OUT/filename
            if path.exists():candidates.extend(json.loads(path.read_text(encoding='utf-8')))
        eligible=[c for c in candidates if c['unassigned']<=500]
        selected=max(eligible or candidates,key=lambda c:c['full_svd_cosine_silhouette'])
        p=prepare(selected['variant'])
        model=fit(p,selected['dimensions'],selected['definition_weight'],selected['anchor_weight'],
                  selected['iterations'],selected['min_lexical_similarity'])
    y=model['labels'];details={};reject_reasons=Counter()
    known_by_class={label:[j for j,k in enumerate(p['known']) if label in p['legacy'][k]] for label in range(18)}
    for i,r in enumerate(p['rows']):
        label=int(y[i]);strong=p['evidence'][i]['strong'];legacy=p['legacy'][i]
        literal=[dict(template_key=e['template_key'],span=e['span']) for e in strong
                 if label>=0 and e['asset_id']==p['classes'][label]]
        if label<0:
            if not r['feature_text'].strip():reason='source_text_unavailable'
            elif p['x'][i].nnz==0:reason='no_retained_text_features'
            elif p['max_raw'][i]<=0:reason='no_shared_terms_with_labeled_advisories'
            else:reason='lexical_support_below_threshold'
            status='unassigned';reject_reasons[reason]+=1
        elif literal:
            reason='literal_related_or_asset_phrase';status='source_phrase' if len(p['allowed'][i])==1 else 'ambiguous_phrase_estimate'
        else:reason='anchored_tfidf_svd_estimate';status='model_estimate'
        terms=term_explanation(p,model,i,label) if label>=0 and (not literal or len(p['allowed'][i])>1) else []
        # Do not claim an unexplained estimate as an assignment.
        if label>=0 and not literal and not terms:
            y[i]=-1;label=-1;status='unassigned';reason='no_positive_explainable_term';reject_reasons[reason]+=1
        references=[]
        if label>=0:
            relevant=[j for j in known_by_class[label] if p['known'][j]!=i]
            for j in sorted(relevant,key=lambda j:float(p['raw_sim'][i,j]),reverse=True)[:3]:
                similarity=float(p['raw_sim'][i,j])
                if similarity>0:references.append(dict(id=p['rows'][p['known'][j]]['id'],similarity=round(similarity,6)))
        for e in literal+terms:attach_source_quote(r,e)
        details[r['id']]=dict(asset_id=p['classes'][label] if label>=0 else None,status=status,reason=reason,
            legacy_asset_ids=[p['classes'][j] for j in legacy],
            literal_evidence=literal,term_contributions=terms,reference_advisories=references,
            source_candidate_asset_ids=sorted({e['asset_id'] for e in strong}),
            nearest_labeled_text_similarity=round(float(p['max_raw'][i]),6),
            source_feature_sha256=hashlib.sha256(r['feature_text'].encode()).hexdigest())
    native=silhouette_samples(model['z'],y,metric='cosine')
    original=silhouette_samples(p['x'],y,metric='cosine')
    assigned=y>=0
    metrics=dict(model['metrics'],unassigned=int((~assigned).sum()),assigned=int(assigned.sum()),
        full_svd_cosine_silhouette=float(native.mean()),full_embedding_cosine_silhouette=float(native.mean()),full_original_tfidf_cosine_silhouette=float(original.mean()),
        assigned_only_svd_cosine_silhouette=float(silhouette_samples(model['z'][assigned],y[assigned],metric='cosine').mean()),
        assigned_only_population=int(assigned.sum()),negative_silhouette_records=int((native<0).sum()),target_silhouette_met=float(native.mean())>.5,
        target_unassigned_met=int((~assigned).sum())<=500,
        reference_taxonomy_asset_types=18,related_asset_relations=43,unique_related_asset_names=39,
        independent_accuracy_validated=False)
    categories=[]
    for j,a in enumerate(p['assets']):
        members=[p['rows'][i] for i in np.flatnonzero(y==j)]
        categories.append(dict(id=a['id'],name=a['name'],advisory_ids=[r['id'] for r in members],
            advisory_count=len(members),cves=sorted({c for r in members for c in r['cves']}),
            cve_count=len({c for r in members for c in r['cves']}),
            estimated_advisories=sum(details[r['id']]['status']!='source_phrase' for r in members)))
    rejected=[p['rows'][i] for i in np.flatnonzero(y<0)]
    unassigned=dict(id='unassigned',name='Asset type unassigned',advisory_ids=[r['id'] for r in rejected],
        advisory_count=len(rejected),cves=sorted({c for r in rejected for c in r['cves']}),
        cve_count=len({c for r in rejected for c in r['cves']}))
    counts=Counter(d['status'] for d in details.values())
    summary=dict(phrase_supported_advisories=counts['source_phrase']+counts['ambiguous_phrase_estimate'],ambiguous_phrase_advisories=counts['ambiguous_phrase_estimate'],model_only_advisories=counts['model_estimate'],asset_types=18,advisories=3881,cves=12418,assigned_advisories=int(assigned.sum()),
        unassigned_advisories=len(rejected),source_phrase_advisories=counts['source_phrase'],
        estimated_advisories=counts['model_estimate']+counts['ambiguous_phrase_estimate'])
    taxonomy={t['key']:{k:v for k,v in t.items() if k!='pattern'} for t in p['templates']}
    result=dict(version='icsa-fixed-assets/2',categories=categories,unassigned=unassigned,
        advisory_asset_ids={aid:([d['asset_id']] if d['asset_id'] else []) for aid,d in details.items()},
        advisory_product_evidence=p['seed']['advisory_product_evidence'],assignment_details=details,
        taxonomy_templates=taxonomy,summary=summary,metrics=metrics,unassigned_reasons=dict(reject_reasons),
        settings=selected,policy='One primary fixed asset type per advisory. Literal evidence and model estimates are distinct. CVE associations do not assert affected asset roles or VEX status.')
    if selected['variant']=='source_v3':
        candidate=ROOT/'results/icsa_fixed18_improvement_v2/fulltext_candidate_metrics.json'
        candidate.write_text(json.dumps(dict(summary=summary,metrics=metrics),indent=2),encoding='utf-8')
        assert metrics['target_silhouette_met'] and metrics['target_unassigned_met'],'Source-enriched candidate did not meet both active targets; current publication retained'
    assert set(details)=={r['id'] for r in p['rows']}
    assert {c for g in categories+[unassigned] for c in g['cves']}==set(p['source']['cve_memberships'])
    encoded=json.dumps(result,ensure_ascii=False,separators=(',',':'))+'\n'
    atomic(OUT/'assignments.json',encoded)
    atomic(ROOT/'site/asset_vulntology/icsa_asset_navigation.json',encoded)
    atomic(ROOT/'results/icsa_role_clusters_k18/asset_navigation.json',encoded)
    np.savez_compressed(OUT/'projection.npz',reduced=model['z'],labels=y,components=model['svd'].components_,
        centers=model['centers'],svd_silhouette=native,original_silhouette=original)
    with (OUT/'icsa_assignments.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.writer(f);writer.writerow(['advisory_id','asset_id','status','reason'])
        writer.writerows([aid,d['asset_id'],d['status'],d['reason']] for aid,d in details.items())
    with (OUT/'cve_asset_memberships.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.writer(f);writer.writerow(['cve','advisory_id','asset_id','status'])
        for row in p['rows']:
            d=details[row['id']]
            writer.writerows([c,row['id'],d['asset_id'],d['status']] for c in row['cves'])
    manifest=dict(summary=summary,metrics=metrics,settings=selected,unassigned_reasons=dict(reject_reasons),
        input_sha256={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in {
            'seed_navigation.json':OUT/'seed_navigation.json','source_advisories.json':OUT/'source_advisories.json',
            'mitre_snapshot':ROOT/'data/standards/ics-attack-20.1.json'}.items()},
        code_sha256={name:hashlib.sha256((tool_path(name, root=ROOT)).read_bytes()).hexdigest()
                     for name in ['fixed_asset_model.py','reclassify_fixed_assets.py']},
        assignments_sha256=hashlib.sha256((OUT/'assignments.json').read_bytes()).hexdigest())
    if selected.get('model_family')=='source_reference_discriminant':
        manifest['code_sha256']['discriminant_asset_model.py']=hashlib.sha256((ROOT/'tools/item4/discriminant_asset_model.py').read_bytes()).hexdigest()
    if selected['variant']=='source_v3':
        for name in ['source_advisories_fulltext_v3.json','source_enrichment_manifest.json']:
            manifest['input_sha256'][name]=hashlib.sha256((OUT/name).read_bytes()).hexdigest()
        manifest['code_sha256']['enrich_original_asset_phrases.py']=hashlib.sha256((ROOT/'tools/item4/enrich_original_asset_phrases.py').read_bytes()).hexdigest()
    atomic(OUT/'manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    # An inert data element survives the app's script stripping; no server restart.
    html_path=ROOT/'src/item4/web/scoped_vex_review.html';html=html_path.read_text(encoding='utf-8')
    inline=dict(result,advisory_product_evidence={})
    payload=json.dumps(inline,ensure_ascii=False,separators=(',',':')).replace('<','\\u003c')
    from html import escape
    block='<div id="av-asset-navigation-data" hidden>'+escape(payload,quote=False)+'</div>'
    html=re.sub(r'<div id="av-asset-navigation-data" hidden>.*?</div>',lambda _:block,html,flags=re.S)
    atomic(html_path,html)
    print(json.dumps(dict(summary=summary,metrics=metrics,reasons=dict(reject_reasons)),ensure_ascii=True),flush=True)


if __name__=='__main__':main()
