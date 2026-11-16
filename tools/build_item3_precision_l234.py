"""Build balanced synthetic #3 stress inputs and independent complete-set gold."""
from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime,timezone
import argparse,hashlib,json,re,sqlite3,sys,uuid
from urllib.parse import quote

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.item3_truth_oracle import Oracle,ATTRS,BOUNDS,parts,literal,bind,identity,condition,compact,key
from tools.preprocess_item3_ics_cert import sha
from src.training_io import atomic_json

NS=uuid.UUID('3ff5d601-5970-46a2-b25e-d53af12f241e')
KINDS={'a':'application','o':'operating-system','h':'device'}


def split_cves(oracle):
    ids=oracle.universe;size=len(ids)//3;caps={'L2':size+(len(ids)%3>0),'L3':size+(len(ids)%3>1),'L4':size}
    eligible=[cid for cid in ids if any(r['match'].get('vulnerable') is True and
        (r['fields'][3] not in ('*','-') or any(r['match'].get(b[0]) is not None for b in BOUNDS)) for r in oracle.by_cve[cid])]
    eligible.sort(key=lambda x:key(['l3-stratum-v1',x]))
    if len(eligible)<caps['L3']:raise ValueError('Not enough version-bearing CVEs to form the P3 third')
    assigned={c:'L3' for c in eligible[:caps['L3']]};loads=Counter()
    for cid in assigned:loads['L3']+=len(oracle.by_cve[cid])
    counts=Counter(assigned.values())
    for cid in sorted(set(ids)-assigned.keys(),key=lambda x:(-len(oracle.by_cve[x]),key(['partition-v1',x]))):
        group=min((g for g in ('L2','L4') if counts[g]<caps[g]),key=lambda g:(loads[g],counts[g],g))
        assigned[cid]=group;loads[group]+=len(oracle.by_cve[cid]);counts[group]+=1
    assert dict(counts)==caps
    return assigned,dict(counts),dict(loads)


def display(value):return re.sub(r'[_-]+',' ',value).strip()


def component(fields,axis,oracle,variant='challenge'):
    part,vendor,product=identity(fields);version=literal(fields[3]);shown=product;maker=vendor;subtype='canonical_control'
    prefix=None
    if variant=='challenge' and axis=='L2':
        neighbors=oracle.products.get((part,vendor),[])
        head=product[:max(4,len(product)//2)]
        near=next((p for p in neighbors if p!=product and p.startswith(head)),None)
        if near:
            prefix=next((product[:n] for n in range(min(len(product),len(near)),3,-1) if product[:n]==near[:n]),None)
        shown=display(vendor)+' '+display(prefix or product)
        subtype='similar_name_resolved_by_inventory_model' if prefix else 'display_name_variation'
    elif variant=='challenge' and axis=='L4':
        maker=display(vendor).upper();shown=display(product).title();subtype='manufacturer_name_purl_spelling_difference'
    shown_version=version if version is not None else 'NOASSERTION'
    if variant=='challenge' and axis=='L3':
        if version not in (None,'-'):
            shown_version=('v'+version if re.fullmatch(r'\d+(?:\.\d+)*',version) and int(key(fields)[0],16)%2==0 else 'Version '+version)
            subtype='version_notation'
        else:subtype='version_not_applicable_or_unconfirmed'
    facts=['Inventory model identifier: '+product+'.']
    for attribute,raw in zip(ATTRS[4:],fields[4:]):
        facts.append(attribute+': '+('not applicable' if raw=='-' else literal(raw) if raw is not None else 'unconfirmed')+'.')
    if version=='-':facts.append('Installed version: not applicable.')
    obj={'type':KINDS[part],'bom-ref':'component-'+key([fields,axis,variant])[:24],
        'name':shown,'version':shown_version,'description':' '.join(facts),'scope':'required','manufacturer':{'name':maker}}
    if variant=='challenge' and axis=='L4':
        purl='pkg:generic/'+quote(vendor,safe='')+'/'+quote(product,safe='')
        if version not in (None,'-'):purl+='@'+quote(version,safe='')
        obj['purl']=purl
    return obj,subtype


def envelope(case_id,components,stamp):
    asset='asset-'+case_id
    return {'bom_type':'SBOM','bomFormat':'CycloneDX','specVersion':'1.7',
        'serialNumber':'urn:uuid:'+str(uuid.uuid5(NS,case_id)),'version':1,
        'properties':{'BOM_CREATION_DATE':stamp,'BOM_MODIFY_DATE':stamp},
        'metadata':{'timestamp':stamp,'lifecycles_phase':'operations','manufacturer':{'name':'ICS-VEX synthetic inventory'},
            'tools':{'components':[{'type':'application','bom-ref':'tool:ics-vex-item3-builder','name':'ICS-VEX precision dataset builder',
                'version':'1.0','publisher':'ICS-VEX','description':'Generates controlled synthetic inventory fixtures.'}]},
            'distributionConstraints':{'tlp':'CLEAR'},
            'component':{'type':'device','bom-ref':asset,'name':'ICS synthetic inventory container','version':'1',
                'description':'Synthetic benchmark asset; not an observed deployed system.','scope':'required'}},
        'components':components,'dependencies':[{'ref':asset,'dependsOn':[c['bom-ref'] for c in components]}]+
            [{'ref':c['bom-ref'],'dependsOn':[]} for c in components]}


def build(output,contract):
    output=output.resolve()
    if not output.is_relative_to(ROOT/'data'):raise ValueError('Keep dataset in workspace data')
    if output.exists():raise FileExistsError('Use a fresh version; completed/failing datasets are preserved')
    output.mkdir();(output/'inputs').mkdir();(output/'gold').mkdir()
    for axis in ('L2','L3','L4'):(output/'inputs'/axis).mkdir();(output/'gold'/axis).mkdir()
    contract=json.loads(contract.read_text(encoding='utf-8'))
    atomic_json(output/'input_contract.json',contract)
    from jsonschema import Draft202012Validator,FormatChecker
    validator=Draft202012Validator(contract['json_schema'],format_checker=FormatChecker())
    source_path=ROOT/'data/item3_all_assigned_cpes_v1/corpus.sqlite3'
    source_manifest=ROOT/'data/item3_all_assigned_cpes_v1/manifest.json'
    source=sqlite3.connect(f'file:{source_path.as_posix()}?mode=ro',uri=True);oracle=Oracle(source)
    assignment,group_counts,loads=split_cves(oracle)
    atomic_json(output/'partitions.json',{'assignment_unit':'seed CVE','role':'synthetic stress groups, not train/test splits',
        'counts':group_counts,'source_cpe_counts':loads,'cves':{g:sorted(c for c,a in assignment.items() if a==g) for g in group_counts}})
    atomic_json(output/'universe.json',{'id':'ics-cert-cpe-mapping-snapshot-v1','scored_cves':oracle.universe,
        'outside_scored_scope_cves':oracle.unscorable,'unknown_policy':'Do not treat out-of-scope/unsupported pairs as FP or TP.'})
    catalog=defaultdict(set)
    with (ROOT/'data/cpe_dictionary.jsonl').open(encoding='utf-8') as handle:
        for line in handle:
            row=json.loads(line);f=parts(row.get('cpe'))
            if f and identity(f) in oracle.by_identity and f[3] not in ('*','-') and not row.get('deprecated'):
                catalog[identity(f)].add(f[3])
    catalog={k:sorted(v) for k,v in catalog.items()}
    stamp=json.loads(source_manifest.read_text(encoding='utf-8'))['created_at_utc']
    db=sqlite3.connect(output/'dataset.sqlite3')
    db.executescript('''CREATE TABLE cases(id TEXT PRIMARY KEY,axis TEXT,seed_cve TEXT,input_path TEXT,gold_path TEXT,input_sha256 TEXT);
        CREATE TABLE components(case_id TEXT,component_ref TEXT,profile_id TEXT,variant TEXT,PRIMARY KEY(case_id,component_ref));
        CREATE TABLE profiles(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
        CREATE TABLE source_cpes(id TEXT PRIMARY KEY,cve TEXT,path TEXT,raw_match TEXT);
        CREATE TABLE coverage(source_id TEXT PRIMARY KEY,axis TEXT,case_id TEXT,component_ref TEXT,profile_id TEXT);
        CREATE INDEX components_profile ON components(profile_id);''')
    for row in oracle.rows:db.execute('INSERT INTO source_cpes VALUES (?,?,?,?)',(row['source_id'],row['cve'],row['path'],compact(row['match'])))
    stats=Counter();axis_stats=defaultdict(Counter);recipes=Counter();saved_profiles=set();witness_cache={};examples={}
    records=(output/'cases.jsonl').open('w',encoding='utf-8')
    def save_profile(fields):
        truth=oracle.labels(fields);pid=truth['profile_id']
        if pid not in saved_profiles:db.execute('INSERT INTO profiles VALUES (?,?)',(pid,compact(truth)));saved_profiles.add(pid)
        return truth
    for position,cid in enumerate(sorted(assignment),1):
        axis=assignment[cid];grouped={}
        for row in oracle.by_cve[cid]:
            fingerprint=key(row['match'])
            if fingerprint not in witness_cache:witness_cache[fingerprint]=oracle.witness(row,catalog)
            fields,basis=witness_cache[fingerprint];pid=key(fields)
            slot=grouped.setdefault(pid,{'fields':fields,'basis':basis,'sources':[]});slot['sources'].append(row)
        groups=list(grouped.values())
        for chunk_start in range(0,len(groups),80):
            chunk=groups[chunk_start:chunk_start+80];case_id='SBOM-'+key([axis,cid,chunk_start,'precision-v1'])[:24]
            components=[];gold=[];provenance=[]
            for slot in chunk:
                fields=slot['fields'];obj,subtype=component(fields,axis,oracle);truth=save_profile(fields);ref=obj['bom-ref']
                components.append(obj);recipes[subtype]+=1
                gold.append({'component_ref':ref,'profile_ref':truth['profile_id'],'expected_cves':truth['expected_cves'],
                    'unknown_cves':truth['unknown_cves'],'complete_within_scored_universe':truth['complete_within_cpe_universe']})
                provenance.append({'component_ref':ref,'variant':'challenge','problem_subtype':subtype,'version_witness_basis':slot['basis'],
                    'source_cpe_refs':[r['source_id'] for r in slot['sources']]})
                for r in slot['sources']:db.execute('INSERT INTO coverage VALUES (?,?,?,?,?)',(r['source_id'],axis,case_id,ref,truth['profile_id']))
                db.execute('INSERT INTO components VALUES (?,?,?,?)',(case_id,ref,truth['profile_id'],'challenge'))
            first=chunk[0]['fields']
            # A matched clean control and a closed-universe wrong-manufacturer control.
            negative=list(first);negative[1]=bind('inventoryvendor'+key([case_id,'vendor'])[:12]);negative=tuple(negative)
            controls=[(first,'canonical_control'),(negative,'different_manufacturer_control')]
            if axis=='L3':
                # Keep the real identity, move beyond the seed's numeric bounds.
                # This may still match other CVEs, so never hardcode a negative.
                values=[literal(r['fields'][3]) for r in oracle.by_cve[cid]]
                values += [str(r['match'][bound]) for r in oracle.by_cve[cid] for bound,_,_ in BOUNDS if bound in r['match']]
                majors=[int(v.split('.')[0]) for v in values if v and re.fullmatch(r'\d+(?:\.\d+)*',v)]
                changed=list(first);changed[3]=str(max(majors,default=0)+1)+'.0'
                controls.append((tuple(changed),'version_outside_seed_numeric_bounds_control'))
            for fields,variant in controls:
                obj,subtype=component(fields,axis,oracle,variant);truth=save_profile(fields);components.append(obj)
                gold.append({'component_ref':obj['bom-ref'],'profile_ref':truth['profile_id'],'expected_cves':truth['expected_cves'],
                    'unknown_cves':truth['unknown_cves'],'complete_within_scored_universe':truth['complete_within_cpe_universe']})
                provenance.append({'component_ref':obj['bom-ref'],'variant':variant})
                db.execute('INSERT INTO components VALUES (?,?,?,?)',(case_id,obj['bom-ref'],truth['profile_id'],variant))
                if variant=='different_manufacturer_control':assert not truth['expected_cves'] and not truth['unknown_cves']
            document=envelope(case_id,components,stamp)
            errors=list(validator.iter_errors(document))
            if errors:raise ValueError(str(errors[0]))
            refs=[c['bom-ref'] for c in components];assert len(set(refs))==len(refs)
            assert not re.search(r'CVE-\d{4}-\d{4,}',compact(document)),'CVE label leaked into input'
            input_rel=f'inputs/{axis}/{case_id}.json';gold_rel=f'gold/{axis}/{case_id}.json'
            (output/input_rel).write_text(json.dumps(document,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            adjudicated=sum(not c['unknown_cves'] for c in gold)
            target={'case_id':case_id,'seed_cve':cid,'axis':axis,'scoring_unit':'SBOM/component-ref/CVE',
                'universe_ref':'universe.json','negative_definition':'scored universe minus expected_cves minus unknown_cves',
                'components':gold,'synthesis_provenance':provenance}
            atomic_json(output/gold_rel,target)
            digest=sha(output/input_rel);db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?)',(case_id,axis,cid,input_rel,gold_rel,digest))
            row={'id':case_id,'axis':axis,'seed_cve':cid,'input':input_rel,'gold':gold_rel,'input_sha256':digest,'components':len(components)}
            records.write(compact(row)+'\n');examples.setdefault(axis,row)
            stats.update(sboms=1,components=len(components),fully_adjudicated_components=adjudicated,
                unknown_components=len(gold)-adjudicated,expected_edges=sum(len(c['expected_cves']) for c in gold),
                unknown_edges=sum(len(c['unknown_cves']) for c in gold),schema_valid_sboms=1)
            axis_stats[axis].update(sboms=1,components=len(components),source_cpes=sum(len(s['sources']) for s in chunk))
        if position%200==0:
            db.commit();atomic_json(output/'status.json',{'phase':'building','cves_completed':position,'total_cves':len(assignment),'counts':dict(stats)})
            print(position,'/',len(assignment),'CVEs;',stats['sboms'],'SBOMs',flush=True)
    records.close();db.commit()
    assert db.execute('SELECT COUNT(*) FROM coverage').fetchone()[0]==len(oracle.rows)
    db.close();source.close()
    atomic_json(output/'examples.json',examples)
    inputs_hasher=hashlib.sha256();golds_hasher=hashlib.sha256()
    for row in map(json.loads,(output/'cases.jsonl').read_text(encoding='utf-8').splitlines()):
        inputs_hasher.update(bytes.fromhex(row['input_sha256']));golds_hasher.update(bytes.fromhex(sha(output/row['gold'])))
    manifest={'schema':'ics-vex-item3-precision-l234/1','created_at_utc':datetime.now(timezone.utc).isoformat(),
        'source_population_cves':len(oracle.info),'cpe_linked_cves':len(assignment),'source_cpe_occurrences':len(oracle.rows),
        'partition_counts':group_counts,'axis_counts':{k:dict(v) for k,v in axis_stats.items()},'counts':dict(stats),
        'problem_recipes':dict(recipes),'unique_gold_profiles':len(saved_profiles),'excluded_source_cpes':0,
        'input_schema_workbook':contract['source_workbook'],'input_schema_workbook_sha256':contract['source_sha256'],
        'sources':{'full_nvd_snapshot_manifest_sha256':sha(source_manifest),'workbook_sha256':contract['source_sha256'],
            'dictionary_sha256':sha(ROOT/'data/cpe_dictionary.jsonl')},
        'artifacts':{name:sha(output/name) for name in ('input_contract.json','partitions.json','universe.json','cases.jsonl','dataset.sqlite3','examples.json')},
        'input_inventory_sha256':inputs_hasher.hexdigest(),'gold_inventory_sha256':golds_hasher.hexdigest(),
        'oracle_code_sha256':sha(Path(__file__).with_name('item3_truth_oracle.py')),'builder_code_sha256':sha(Path(__file__)),
        'inference_run':False,'gold_uses_identification_logic':False,'gold_search_scope':'all CPE-linked CVEs across all three groups',
        'limitations':['Controlled synthetic inventory, not independent real-ICS generalization.',
            'Non-numeric unequal vendor version ranges remain unknown; unknown output pairs are not counted as FP or TP.',
            'Negative mappings are complete only within the frozen CPE-linked CVE universe.',
            'vulnerable=false platform references are preserved as inputs, not automatically made positive component mappings.',
            'Operational affected/fixed status and full platform AND/OR applicability are outside test item #3.',
            'Generic PURLs and formatting variants are synthetic fixtures, not newly asserted vendor registry aliases.',
            'Workbook Input layout is used literally; it is not an unmodified official CycloneDX JSON schema.']}
    atomic_json(output/'manifest.json',manifest);atomic_json(output/'status.json',{'phase':'complete','counts':dict(stats)})
    print(json.dumps(manifest,ensure_ascii=False),flush=True)
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'data/item3_precision_l234_v1')
    parser.add_argument('--contract',type=Path,default=ROOT/'results/item3_input_contract.json')
    args=parser.parse_args();build(args.output,args.contract)
