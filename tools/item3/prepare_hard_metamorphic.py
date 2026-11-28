"""Predeclare stronger relational tests; no expected CVE labels are read."""
from pathlib import Path
from copy import deepcopy
import json,hashlib,random,re,sys
from urllib.parse import quote
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item3.evidence.product_identity_evidence import parse_components
from src.common.data.sbom_input_normalization import to_analysis_input
from src.item3.evidence.product_candidate_search import vendor_key
from src.item3.matching.sbom_matching_engine import norm,cpe_parts


def prepare(out):
    blocked=set();files=set();old=ROOT/'results/scoped_llm_evaluations_20261127'
    for name in ('item3_metamorphic','item3_metamorphic_confirmatory','item3_metamorphic_version_stress'):
        for r in json.loads((old/name/'inputs.json').read_text(encoding='utf-8')):
            if r['variant']!='original':continue
            files.add(Path(r['source']).stem)
            for comp in parse_components(to_analysis_input(r['sbom'])):
                for value in comp.get('cpes',[]):
                    p=cpe_parts(value)
                    if p:blocked.add(tuple(p[2:5]))
            pred=json.loads((old/name/'predictions'/(r['id']+'.json')).read_text(encoding='utf-8'))
            for s in pred.get('signature',[]):
                if s['identity'][0]=='validated':blocked.add(tuple(s['identity'][1:]))
    training=json.loads((old/'audit/verified_training_metadata.json').read_text(encoding='utf-8'))
    for row in training['identification_training_rows']:
        for value in (row.get('component') or {}).get('cpes',[]):
            p=cpe_parts(value)
            if p:blocked.add(tuple(p[2:5]))
    paths=sorted((ROOT/'benchmark/item3_evaluation/sboms').glob('*.json'));random.Random(217903).shuffle(paths);bases=[]
    numeric=r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)'
    for path in paths:
        if path.stem in files:continue
        raw=json.loads(path.read_text(encoding='utf-8'));cs=parse_components(to_analysis_input(raw))
        if len(cs)!=1:continue
        c=cs[0];v=str(c.get('version',''))
        if not re.fullmatch(numeric,v) or c.get('purl'):continue
        ps=[cpe_parts(x) for x in c.get('cpes',[])];ps=[p for p in ps if p and p[5]==v]
        if len({tuple(p[2:5]) for p in ps})!=1:continue
        p=ps[0];key=tuple(p[2:5])
        if key in blocked or norm(c['name'])!=norm(p[4]) or vendor_key(c['manufacturer'])!=vendor_key(p[3]):continue
        blocked.add(key)
        comp=dict(**{'bom-ref':'target'},type={'a':'application','o':'operating-system','h':'device'}[p[2]],name=c['name'],manufacturer={'name':c['manufacturer']},version=v,cpe=':'.join(p))
        identity=hashlib.sha256((str(path)+json.dumps(comp,sort_keys=True)).encode()).hexdigest()[:16]
        bases.append(dict(id='hard-'+identity,component=comp,identity=list(key),version=v,source=str(path.relative_to(ROOT)),source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        if len(bases)==24:break
    if len(bases)!=24:raise ValueError('Only '+str(len(bases))+' fresh eligible source products; do not silently change selection')
    rows=[];refs=[]
    def wildcard(c):
        c.pop('version',None);c.pop('purl',None);p=c['cpe'].split(':');p[5]='*';c['cpe']=':'.join(p)
    for i,b in enumerate(bases):
        base=dict(bomFormat='CycloneDX',specVersion='1.6',version=1,components=[deepcopy(b['component'])]);v=b['version'];part,vendor,product=b['identity'];purl='pkg:generic/'+quote(vendor,safe='')+'/'+quote(product,safe='')+'@'+quote(v,safe='')
        mutations={'original':base}
        x=deepcopy(base);x['components'][0]['purl']=purl;mutations['redundant_purl']=x
        x=deepcopy(base);wildcard(x['components'][0]);x['components'][0]['purl']=purl;mutations['release_relocated_to_purl']=x
        x=deepcopy(base);wildcard(x['components'][0]);x['components'][0]['version']='>='+v+',<='+v;mutations['singleton_interval']=x
        x=deepcopy(base);decoy=deepcopy(bases[(i+1)%len(bases)]['component']);decoy['bom-ref']='decoy';x['components'].insert(0,decoy);mutations['cross_component_isolation']=x
        x=deepcopy(base);v2=str(int(v.split('.')[0])+100)+'.0.0';x['components'][0]['purl']=purl.rsplit('@',1)[0]+'@'+v2;mutations['conflicting_release_evidence']=x
        x=deepcopy(base);wildcard(x['components'][0]);mutations['release_information_removed']=x
        x=deepcopy(base);different=next(z for z in bases if z['identity'][1]!=vendor);x['components'][0]['manufacturer']={'name':different['identity'][1]};mutations['conflicting_manufacturer']=x
        for relation,sbom in mutations.items():rows.append(dict(id=b['id']+'__'+relation,base_id=b['id'],relation=relation,sbom=sbom,target_id='target'))
        refs.append({k:b[k] for k in ('id','identity','version','source','source_sha256')})
    out.mkdir(parents=True,exist_ok=True)
    for name,value in [('inputs.json',rows),('relations.json',refs)]: (out/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(source_groups=len(bases),inputs=len(rows),relations=7,absolute_cve_gold_loaded=False,source_selection='24 fresh, exact, consistent source CPE/product/three-part numeric release; fixed seed217903; prior evaluated/training CPE identities excluded.')))


if __name__=='__main__':prepare(Path(sys.argv[1]))
