"""Controlled candidate-ranking curriculum; dictionary/rule references, not expert gold."""
import sys,json,hashlib,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.identity_retrieval import get_index,ProductIndex
from src.identity_evidence import parse_components,grounded_versions,validate_identity
from src.l2_candidates import rank,SYSTEM,CONTRACT


def family_key(group):
    vendor,product=group
    # Group obvious hardware/firmware naming variants together. Unrecorded
    # manufacturer aliases still require an independent dataset audit.
    family=re.sub(r'(?:_(?:firmware|software|application|driver|operating_system))+$','',product)
    return vendor,family


def main():
    index=get_index();groups={}
    for c in index.docs.values():groups.setdefault((c['vendor'],c['product']),c)
    ordered=sorted(groups,key=lambda g:hashlib.sha256('|'.join(g).encode()).hexdigest())
    pools={'train':[],'validation':[],'test':[]}
    for g in ordered:
        bucket=int(hashlib.sha256(('split|'+ '|'.join(family_key(g))).encode()).hexdigest()[:8],16)%10
        pools['train' if bucket<8 else 'validation' if bucket==8 else 'test'].append(g)
    counts={'train':4096,'validation':1024,'test':1024};base=ROOT/'data/l2_candidate_ranking_v1';folder=base/'l2-candidates'
    folder.mkdir(parents=True,exist_ok=True);manifest={'contract':CONTRACT,'expert_gold':False,'experimental':True,
        'source_dictionary_sha256':index.snapshot_hash,'split_rule':'vendor-product families with obvious firmware/software suffixes removed; positive and negative candidates stay in one split; split hash fixed before row generation',
        'size_rationale':'Fixed pilot comparison budget matching the previous 4096/1024/1024 role experiment; not an empirically optimal sample size.',
        'limitations':['Procedural dictionary/rule references, not independently reviewed real SBOMs.','Candidate pools are controlled; this dataset does not measure full-dictionary retrieval recall.'],
        'roles':{'l2-candidates':{'references':'dictionary identities plus original-evidence conflict rules','splits':{}}}}
    for split,n in counts.items():
        rows=[];assert len(pools[split])>=n
        for i,g in enumerate(pools[split][:n]):
            keys=pools[split]
            target=groups[g];others=[groups[keys[(i*7+j*991)%len(keys)]] for j in range(1,4)]
            choices=[target]+[c for c in others if (c['vendor'],c['product'])!=g]
            local=ProductIndex([{'cpe':c['cpe'],'title':c['titles'][0] if c['titles'] else ''} for c in choices],snapshot_hash=index.snapshot_hash)
            product=target['product'].replace('_',' ');case='exact'
            if i%4==0:product='Unidentified component';case='unsupported_name'
            elif i%4==1:product+=' Vendor Firmware/Application';case='description_suffix'
            kind={'h':'device','a':'application','o':'operating-system'}[target['part']]
            component=parse_components({'bomFormat':'CycloneDX','components':[{'name':product,'manufacturer':{'name':target['vendor']},'type':kind,'version':'NOASSERTION'}]})[0]
            versions=grounded_versions(component,local);retrieval=local.search(component,versions)
            state=rank(component,versions,retrieval,lambda _: {'prediction':{'ranked_candidate_ids':[],'evidence_refs':[],'status':'unresolved'}})
            validation=validate_identity(component,state['candidates']);packet=state['packet'];chosen=validation.get('selected_candidate_id')
            gold={'ranked_candidate_ids':[chosen] if chosen else [],'evidence_refs':['input:name','dictionary:'+chosen] if chosen else [],'status':'ranked' if chosen else 'unresolved'}
            rows.append({'id':f'{split}-l2-id-{i}','split':split,'group_id':'|'.join(family_key(g)),'annotation_basis':'procedural_'+case,
                         'packet':packet,'target':gold,'messages':[{'role':'system','content':SYSTEM},{'role':'user','content':json.dumps(packet,ensure_ascii=False)},{'role':'assistant','content':json.dumps(gold)}]})
        path=folder/(split+'.jsonl');path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf-8')
        manifest['roles']['l2-candidates']['splits'][split]={'examples':len(rows),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    (base/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
