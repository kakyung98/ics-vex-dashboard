"""Generate a source-complete, paired single-fault SBOM benchmark in compact stores."""
from pathlib import Path
from collections import defaultdict,Counter
from copy import deepcopy
import hashlib,json,re,sqlite3,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json,read_json
from tools.item3_truth_oracle import literal,key,version_compare
from tools.item3_nvd_truth_v5 import NVDTruth
from tools.build_item3_precision_l234 import envelope,KINDS

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()

def as_cpe(fields):return 'cpe:2.3:'+':'.join(v if v is not None else '*' for v in fields)

def make_input(pid,fields,variant,stamp,alternative=None):
    ref='component-'+pid[:24];case='SBOM-'+key([pid,variant])[:24]
    attrs=('update','edition','language','sw_edition','target_sw','target_hw','other')
    component={'type':KINDS[fields[0]],'bom-ref':ref,'name':literal(fields[2]).replace('_',' '),
        'version':literal(fields[3]) if fields[3] is not None else 'NOASSERTION',
        'description':'Controlled inventory. '+ ' '.join(a+': '+literal(v)+'.' for a,v in zip(attrs,fields[4:]) if v is not None),
        'scope':'required','manufacturer':{'name':literal(fields[1]).replace('_',' ')}}
    if variant=='component_mask':component['name']='NOASSERTION'
    if variant=='component_wrong':component['name']=literal(alternative[2]).replace('_',' ')
    if variant=='version_mask':component['version']='NOASSERTION'
    if variant=='version_wrong':component['version']=literal(alternative[3])
    document=envelope(case,[component],stamp)
    document['metadata']['component']=deepcopy(component)
    if variant!='CPE_mask':document['metadata']['component']['cpe']=as_cpe(alternative if variant=='CPE_wrong' else fields)
    return case,document

def main():
    plan=ROOT/'results/item3_cpe_fault_design_v6';out=ROOT/'data/item3_cpe_faults_v6'
    if out.exists():raise FileExistsError(out)
    out.mkdir();atomic_json(out/'build_status.json',{'phase':'source_validation'})
    profiles={r['id']:r for r in (json.loads(t) for t in (plan/'base_profiles.jsonl').read_text(encoding='utf-8').splitlines())}
    assigned={r['profile']:r['fault'] for r in (json.loads(t) for t in (plan/'paired_fault_assignments.jsonl').read_text().splitlines())}
    assert len(profiles)==len(assigned)==44567
    contract=read_json(ROOT/'results/item3_input_contract.json')
    assert sha(ROOT/contract['source_workbook'])==contract['source_sha256']
    from jsonschema import Draft202012Validator,FormatChecker
    validator=Draft202012Validator(contract['json_schema'],format_checker=FormatChecker())
    atomic_json(out/'input_contract.json',contract);atomic_json(out/'design_counts.json',read_json(plan/'design_counts.json'))
    raw_path=ROOT/'data/item3_all_assigned_cpes_v1/corpus.sqlite3'
    raw=sqlite3.connect(f'file:{raw_path.as_posix()}?mode=ro',uri=True);truth=NVDTruth(raw);raw.close()
    assert len(truth.universe)==10847 and len(truth.rows)==145204
    atomic_json(out/'universe.json',{'scored_cves':sorted(truth.universe),'source_population_CVEs':12418,
        'excluded_no_CPE_or_no_NVD_record':1571,'product_name_filter_exclusions':0})
    db=sqlite3.connect(out/'dataset.sqlite3');db.execute('PRAGMA journal_mode=WAL')
    db.executescript('CREATE TABLE profiles(id TEXT PRIMARY KEY,payload TEXT);'
        'CREATE TABLE cases(id TEXT PRIMARY KEY,profile_id TEXT,scenario TEXT,input_sha256 TEXT,sbom TEXT,expected_behavior TEXT,score_CVE_mapping INTEGER,fold TEXT);'
        'CREATE TABLE source_coverage(cve TEXT,path TEXT,profile TEXT,vulnerable INTEGER,PRIMARY KEY(cve,path));')
    coverage=sqlite3.connect(plan/'coverage.sqlite3')
    db.executemany('INSERT INTO source_coverage VALUES (?,?,?,?)',coverage.execute('SELECT * FROM source_coverage'));coverage.close()
    by_vendor=defaultdict(list);by_identity=defaultdict(list)
    for pid,p in sorted(profiles.items()):
        f=p['canonical_fields'];by_vendor[tuple(f[:2])].append(pid);by_identity[tuple(f[:3])].append(pid)
    all_ids=sorted(profiles);counts=Counter();fold_counts=Counter();gold_counts=Counter();examples={};inventory=[]
    stamp=read_json(ROOT/'data/item3_all_assigned_cpes_v1/manifest.json')['created_at_utc']
    with (out/'inputs.jsonl').open('w',encoding='utf-8') as inputs,(out/'gold_profiles.jsonl').open('w',encoding='utf-8') as gold:
        for n,(pid,p) in enumerate(sorted(profiles.items()),1):
            fields=p['canonical_fields'];labels=truth.state_fields(fields)
            labels.update(profile_id=pid,version_witness_basis=p['version_basis'],
                identity_source='Original NVD CPE, fixed before input corruption; no inferred identity is used as gold')
            db.execute('INSERT INTO profiles VALUES (?,?)',(pid,json.dumps(labels,ensure_ascii=False)))
            gold.write(json.dumps(labels,ensure_ascii=False)+'\n')
            gold_counts.update(positive_edges=len(labels['expected_cves']),unknown_edges=len(labels['unknown_cves']))
            scenario=assigned[pid];alternative=None
            if scenario in ('component_wrong','CPE_wrong'):
                alternatives=[i for i in by_vendor[tuple(fields[:2])] if profiles[i]['canonical_fields'][2]!=fields[2]]
                if not alternatives:alternatives=[i for i in all_ids if profiles[i]['canonical_fields'][:3]!=fields[:3]]
                if not alternatives:raise ValueError('No distinct CPE identity available')
                alternative=profiles[alternatives[int(pid[:8],16)%len(alternatives)]]['canonical_fields']
            elif scenario=='version_wrong':
                alternatives=[profiles[i]['canonical_fields'] for i in by_identity[tuple(fields[:3])]
                    if profiles[i]['canonical_fields'][3] not in (None,'-')
                    and re.fullmatch(r'\d+(?:\.\d+)*',literal(profiles[i]['canonical_fields'][3]))
                    and version_compare(literal(fields[3]),literal(profiles[i]['canonical_fields'][3])) not in (None,0)]
                if not alternatives:raise ValueError('No different source-grounded numeric version')
                alternative=alternatives[int(pid[:8],16)%len(alternatives)]
            fold='development' if int(key(fields[:3])[:8],16)%5==0 else 'evaluation'
            for variant in ('control',scenario):
                cid,document=make_input(pid,fields,variant,stamp,alternative)
                validator.validate(document)
                text=json.dumps(document,ensure_ascii=False,separators=(',',':'));digest=hashlib.sha256(text.encode()).hexdigest()
                wrong=variant.endswith('_wrong');behavior='detect_conflict_and_avoid_unjustified_mapping' if wrong else 'identify_from_remaining_consistent_evidence'
                db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?)',(cid,pid,variant,digest,text,behavior,not wrong,fold))
                inputs.write(json.dumps({'case_id':cid,'input':document},ensure_ascii=False)+'\n')
                counts[variant]+=1;fold_counts[fold]+=1;inventory.append((cid,pid,variant,digest))
                if variant not in examples:
                    examples[variant]={'case_id':cid,'input':document,'expected_behavior':behavior,'latent_asset_gold':labels}
            if n%1000==0:
                db.commit();atomic_json(out/'build_status.json',{'phase':'building','base_profiles_completed':n,'base_profiles_total':len(profiles),'BOMs_created':2*n})
                print(n,'/',len(profiles),'profiles;',2*n,'BOMs',flush=True)
    assert db.execute('SELECT count(*) FROM cases').fetchone()[0]==89134
    assert db.execute('SELECT count(DISTINCT cve) FROM source_coverage').fetchone()[0]==10847
    assert db.execute('SELECT count(*) FROM source_coverage').fetchone()[0]==145204
    assert not db.execute('SELECT profile_id FROM cases GROUP BY profile_id HAVING count(*)!=2').fetchall()
    db.commit();db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.execute('PRAGMA journal_mode=DELETE');db.close()
    atomic_json(out/'examples.json',examples)
    report={'passed':True,'BOMs':89134,'base_components':44567,'scenarios':dict(counts),'folds':dict(fold_counts),
        'CVE_population':10847,'original_CPE_occurrences_covered':145204,'CVE_or_CPE_exclusions':0,
        'schema_valid_BOMs':89134,'gold_source':'Original NVD CPE anchors and complete NVD configuration trees',
        'gold_component_edge_counts':dict(gold_counts),'gold_used_model_predictions':False,
        'CVE_mapping_precision_population':'Control and masking cases; wrong-value conflicts have separate detection/unsafe-acceptance metrics.',
        'all_cases_retained':True,'wrong_cases_keep_latent_asset_gold':True,
        'latent_asset_CVE_recovery_from_conflicting_inputs_is_not_assumed':True,
        'CPE_input_location':'metadata.component.cpe, explicitly linked to the sole component by shared bom-ref',
        'storage':'89,134 independent schema-valid BOM JSON records in inputs.jsonl and SQLite; examples.json contains readable examples.'}
    atomic_json(out/'validation_audit.json',report)
    manifest={'schema':'ics-vex-paired-CPE-faults/6','report':report,'sources':{
        'data/item3_all_assigned_cpes_v1/corpus.sqlite3':sha(raw_path),
        'results/item3_cpe_fault_design_v6/base_profiles.jsonl':sha(plan/'base_profiles.jsonl'),
        'results/item3_cpe_fault_design_v6/paired_fault_assignments.jsonl':sha(plan/'paired_fault_assignments.jsonl')},
        'code':{p:sha(ROOT/p) for p in ('tools/build_item3_cpe_faults_v6.py','tools/item3_nvd_truth_v5.py',
            'tools/item3_truth_oracle.py','tools/plan_item3_cpe_faults_v6.py')},
        'artifacts':{p.name:sha(p) for p in out.iterdir() if p.is_file() and p.name not in ('manifest.json','build_status.json')},
        'case_inventory_sha256':hashlib.sha256(json.dumps(sorted(inventory)).encode()).hexdigest()}
    atomic_json(out/'manifest.json',manifest);atomic_json(out/'build_status.json',{'phase':'complete',**report})
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
