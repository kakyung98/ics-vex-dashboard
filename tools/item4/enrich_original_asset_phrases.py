"""Find target-scoped role phrases in original ICSA text, excluding generic advice."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import hashlib,json,re,shutil
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from tools.item4.fixed_asset_model import ROOT,OUT,load


def build():
    old,seed,assets,_=load()
    target=OUT/'source_advisories_fulltext_v3.json'
    if not target.exists():shutil.copy2(OUT/'source_advisories.json',target)
    _,_,_,templates=load('source_v3')
    compiled=[(t,re.compile(t['pattern'],re.I)) for t in templates]
    details={};hashes={}
    for path in sorted((ROOT/'site').glob('advisory_details_*.json')):
        details.update(json.loads(path.read_text(encoding='utf-8')))
        hashes[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
    index={a['id']:a for a in json.loads((ROOT/'site/advisories_list.json').read_text(encoding='utf-8'))['advisories']}
    excluded=Counter();totals=Counter()
    generic={'vulnerability','vulnerabilities','update','updates','security','multiple','products','product','series','device','devices','software','system','systems','versions','version','and','the','for','in','of','remote','code','execution'}
    advice=re.compile(r'\b(?:locate control system|behind firewalls|recognize.{0,20}VPN|when remote access|use (?:more )?secure|defensive measures|recommended practices|CISA recommends|ICS-CERT recommends|should|ensure|disable|restrict|never)\b',re.I)
    context_pattern=re.compile(r'\b(?:SCADA|engineering software|engineering tools?|historical (?:process )?data|licen[cs]e management|telemetry|process visualization)\b',re.I)
    def structured(row):
        aid=row['id'];path=ROOT/'icsa/csaf'/f'{aid}.json';records=[]
        if path.exists():
            wire=path.read_bytes();obj=json.loads(wire);document=obj.get('document',{})
            url=next((r['url'] for r in document.get('references',[]) if r.get('category')=='self' and r.get('url','').endswith('.json')),row['url'])
            artifact=path.relative_to(ROOT).as_posix()
            for j,note in enumerate(document.get('notes',[])):
                if re.search(r'legal|disclaimer|recommend|practice|mitigat',note.get('title',''),re.I):continue
                if note.get('text'):records.append((note['text'],'CSAF document note',artifact,['document','notes',j,'text'],url))
            for j,vulnerability in enumerate(obj.get('vulnerabilities',[])):
                for k,note in enumerate(vulnerability.get('notes',[])):
                    if note.get('text'):records.append((note['text'],'CSAF vulnerability note',artifact,['vulnerabilities',j,'notes',k,'text'],url))
            def products(node,keys):
                for j,branch in enumerate(node.get('branches',[])):
                    key=keys+['branches',j]
                    if branch.get('category') in {'product_name','product_family'}:records.append((branch['name'],'CSAF affected product name',artifact,key+['name'],url))
                    products(branch,key)
            products(obj.get('product_tree',{}),['product_tree'])
            return aid,records,artifact,hashlib.sha256(wire).hexdigest()
        raw=details.get(aid,{}).get('overview','')
        if raw:records.append((raw,'archived CISA web overview',None,None,row['url']))
        return aid,records,None,None
    with ThreadPoolExecutor(max_workers=12) as pool:raw_sources={aid:(records,artifact,digest) for aid,records,artifact,digest in pool.map(structured,old['advisories'])}
    for row in old['advisories']:
        aid=row['id'];records,artifact,digest=raw_sources[aid]
        if artifact:hashes[artifact]=digest
        vendor=set(re.findall(r'[a-z0-9]{3,}',index.get(aid,{}).get('vendor','').casefold()))
        tokens=set(re.findall(r'[a-z][a-z0-9]{2,}',row['title'].casefold()))-generic-vendor
        target_terms=re.compile(r'\b(?:'+'|'.join(re.escape(t) for t in tokens)+r')\b',re.I) if tokens else None
        base=row['feature_text'];parts=[base];fragments=[dict(assembled_span=[0,len(base)],source_field='legacy_title_csaf_and_function_features',source_url=row['url'])];approved=[];length=len(base);contexts=0
        seen=set()
        for raw,field,artifact,json_path,url in records:
            if raw in seen:continue
            seen.add(raw);found=[]
            for t,pattern in compiled:
                found.extend((m.start(),m.end(),t) for m in pattern.finditer(raw))
            found.extend((m.start(),m.end(),None) for m in context_pattern.finditer(raw))
            accepted=[]
            for start,end,t in found:
                left=max(0,start-180);right=min(len(raw),end+220);context=raw[left:right]
                boundaries=list(re.finditer(r'[.!?]\s+|\n',raw[:start]));begin=boundaries[-1].end() if boundaries else 0
                after=re.search(r'[.!?](?=\s|$)|\n',raw[end:]);finish=end+after.end() if after else len(raw)
                sentence=raw[begin:finish]
                if advice.search(sentence):excluded['generic_advice']+=1;continue
                before=raw[max(0,start-70):start]
                if re.search(r'\b(?:connect(?:s|ed)? to|communicat\w* with|behind|via|through|network of)\s+(?:a |the |an )?$',before,re.I):excluded['neighbor_or_access_path']+=1;continue
                if t and t['name']=='Field Device / Controller' and field!='CSAF affected product name':
                    if re.search(r'\b(?:to|from|with|of)\s+(?:the |a |an )?$',before,re.I):excluded['generic_field_device_neighbor']+=1;continue
                    subject=re.search(r'\bfield (?:devices?|controllers?)\s+(?:is|are|has|have|contains?|can|could|suffers?)\b|\b(?:is|are) (?:a |an )?field (?:device|controller)\b|vulnerabilit(?:y|ies) in.{0,60}field (?:devices?|controllers?)',sentence,re.I)
                    if not subject:excluded['generic_field_device_scope_unresolved']+=1;continue
                scoped=field in {'CSAF affected product name','CSAF vulnerability note'}
                if not scoped and not(target_terms and target_terms.search(context)) and not re.search(r'\b(?:affected|vulnerable|equipment|product|component|vulnerabilit(?:y|ies) in)\b',context,re.I):excluded['no_target_scope']+=1;continue
                accepted.append((start,end,t,left,right))
            intervals=[]
            for _,_,_,left,right in sorted(accepted,key=lambda e:e[3]):
                if intervals and left<=intervals[-1][1]:intervals[-1][1]=max(intervals[-1][1],right)
                else:intervals.append([left,right])
            for left,right in intervals:
                snippet=raw[left:right];assembled=length+1;parts.append(snippet);length=assembled+len(snippet)
                fragments.append(dict(assembled_span=[assembled,length],source_field='original_icsa_overview',origin_kind=field,original_span=[left,right],source_url=url,source_artifact=artifact,source_json_path=json_path,original_text_sha256=hashlib.sha256(raw.encode()).hexdigest()))
                for start,end,t,_,_ in accepted:
                    if left<=start and end<=right:
                        if t:approved.append(dict(template_key=t['key'],asset_id=t['parent_id'],span=[assembled+start-left,assembled+end-left],original_span=[start,end]))
                        else:contexts+=1
        row['feature_text']='\n'.join(parts);row['feature_fragments']=fragments;row['validated_original_evidence']=approved;row['original_function_context_count']=contexts
        if approved:totals['advisories_with_original_type_phrases']+=1
        if contexts:totals['advisories_with_function_context']+=1
        totals['original_phrase_occurrences']+=len(approved)
    old['feature_enrichment_version']='v3';old['original_source_sha256']=hashes
    old['enrichment_summary']=dict(totals,excluded=dict(excluded))
    temp=target.with_name(target.name+'.tmp');temp.write_text(json.dumps(old,ensure_ascii=False,separators=(',',':'))+'\n',encoding='utf-8');temp.replace(target)
    (OUT/'source_enrichment_manifest.json').write_text(json.dumps(dict(summary=old['enrichment_summary'],source_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),source_inputs=hashes),indent=2)+'\n',encoding='utf-8')
    print(json.dumps(old['enrichment_summary']),flush=True)


if __name__=='__main__':build()
