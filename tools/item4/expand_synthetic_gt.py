"""Build a larger controlled synthetic corpus, not independent expert GT.

Old sealed tests are development regression cases only. New cases are grouped
by domain before splitting. Four variants of a source scenario change the
logical contract, not just entity names. Shared renderer families are disclosed.
No model inference, model selection, or production scorer edits occur here.
"""
from pathlib import Path
from collections import Counter
import hashlib,json,random,sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from src.item4.evaluation import metamorphic_synthetic as E
from tools.item4.prepare_sealed_source_gt import fact

VERSION='expanded-controlled-source-gt/1'
SEED=27112026
# Each row supplies four distinct source scenarios, with real logical differences
# supplied below. Fictional products and operating conditions, never real CVEs.
# Domain | network origin | permission object | account role | endpoint |
# four independent features | four victim objects | four operational modes.
DOMAINS=[
('water-treatment','clarifier operator subnet','chlorination job queue','water process operator account','reservoir diagnostics endpoint','trend replay;dose scheduler;alarm bridge;sample importer','pump recipe;filter schedule;dose worksheet;reservoir diagram','backwash;calibration;sampling;commissioning'),
('substation','protection engineering workstation','relay settings directory','relay configuration account','bay maintenance endpoint','event forwarder;setting synchronizer;disturbance exporter;relay script engine','relay project;bay configuration;fault record;interlock plan','test;maintenance;simulation;setting review'),
('wind-turbine','nacelle service segment','pitch calibration queue','turbine service account','converter diagnostic endpoint','pitch logger;yaw scheduler;vibration uploader;power curve importer','pitch profile;yaw plan;vibration archive;converter project','blade calibration;yaw alignment;converter service;parked maintenance'),
('building-automation','building management VLAN','air handler task queue','building commissioning account','floor controller endpoint','schedule adapter;occupancy bridge;trend exporter;zone script plug-in','air handler project;lighting schedule;zone recipe;fire damper diagram','commissioning;occupied test;air balancing;controller service'),
('rail-signalling','depot service workstation','route test directory','signalling maintenance account','interlocking diagnostic endpoint','route simulator;event recorder;track importer;signal preview engine','route diagram;track plan;signal project;depot schedule','depot test;route simulation;signal maintenance;offline review'),
('maritime-control','engine room service segment','ballast task queue','vessel engineering account','propulsion service endpoint','ballast scheduler;engine trend bridge;navigation importer;cargo preview engine','ballast recipe;engine archive;navigation project;cargo plan','harbor service;engine calibration;navigation simulation;cargo test'),
('pharmaceutical','cleanroom engineering VLAN','batch release staging directory','batch engineering account','tablet line diagnostics endpoint','batch script engine;weighing scheduler;label archive importer;sterility trend exporter','batch recipe;weighing project;label layout;sterility report','validation;weighing calibration;label test;sterilizer maintenance'),
('semiconductor','fab maintenance workstation','wafer handling job queue','process tool service account','lithography maintenance endpoint','wafer scheduler;chamber trend bridge;mask importer;recipe preview engine','wafer recipe;chamber project;mask archive;etch worksheet','tool service;chamber calibration;mask review;etch simulation'),
('oil-gas','compressor service VLAN','pipeline inspection directory','pipeline maintenance account','metering diagnostics endpoint','compressor logger;pigging scheduler;meter archive importer;valve script engine','compressor profile;pipeline plan;meter archive;valve project','compressor service;inspection;meter calibration;valve commissioning'),
('food-processing','packaging engineering subnet','pasteurizer task queue','line commissioning account','filler diagnostic endpoint','thermal replay engine;wash scheduler;label importer;filler preview engine','thermal recipe;wash plan;label archive;filler project','thermal validation;wash service;label review;filler calibration'),
('hydropower','dam service workstation','spillway task directory','hydro maintenance account','generator inspection endpoint','spillway scheduler;vibration bridge;governor importer;generator replay engine','spillway plan;vibration project;governor recipe;generator archive','spillway test;vibration calibration;governor service;generator simulation'),
('district-heating','heat network management VLAN','heat exchanger job queue','heat network operator account','boiler maintenance endpoint','heat trend bridge;pump scheduler;boiler archive importer;exchanger script engine','heat profile;pump recipe;boiler project;exchanger worksheet','heat balancing;pump calibration;boiler service;exchanger test'),
('mining','conveyor service segment','ventilation task directory','mine engineering account','hoist diagnostic endpoint','belt replay engine;ventilation scheduler;hoist importer;crusher preview engine','belt plan;ventilation recipe;hoist project;crusher archive','belt inspection;ventilation test;hoist service;crusher calibration'),
('airport-baggage','baggage maintenance VLAN','sorter task queue','baggage service account','carousel diagnostics endpoint','sorter logger;diverter scheduler;carousel importer;scanner preview engine','sorter project;diverter plan;carousel archive;scanner layout','sorter service;diverter test;carousel calibration;scanner review'),
('cold-storage','warehouse engineering subnet','defrost job queue','refrigeration service account','evaporator maintenance endpoint','defrost scheduler;temperature bridge;compressor importer;evaporator replay engine','defrost recipe;temperature archive;compressor project;evaporator profile','defrost service;temperature calibration;compressor inspection;evaporator test'),
('waste-recycling','sorting service workstation','shredder task directory','recycling maintenance account','separator diagnostics endpoint','sorting logger;shredder scheduler;separator importer;compactor preview engine','sorting recipe;shredder project;separator archive;compactor plan','sorting calibration;shredder service;separator test;compactor commissioning'),
('textile-machinery','loom engineering segment','dye cycle queue','textile commissioning account','spindle service endpoint','loom replay engine;dye scheduler;spindle importer;weave preview engine','loom recipe;dye project;spindle archive;weave plan','loom service;dye calibration;spindle test;weave simulation'),
('glass-manufacturing','furnace service VLAN','annealing job directory','glass process service account','forming diagnostic endpoint','furnace logger;annealing scheduler;forming importer;inspection script engine','furnace profile;annealing recipe;forming project;inspection archive','furnace inspection;annealing calibration;forming test;quality service'),
('solar-generation','inverter engineering workstation','tracker task queue','solar maintenance account','combiner service endpoint','inverter replay engine;tracker scheduler;combiner importer;storage preview engine','inverter project;tracker plan;combiner archive;storage profile','inverter service;tracker calibration;combiner test;storage simulation'),
('paper-mill','mill maintenance subnet','dryer task directory','paper process engineering account','winder diagnostics endpoint','pulp trend bridge;dryer scheduler;winder importer;coating preview engine','pulp recipe;dryer project;winder archive;coating worksheet','pulp calibration;dryer inspection;winder service;coating test'),
]
PATTERNS=['and','or','and_negative_guard','common_gate_alternatives','two_conjunctive_paths','relation_unknown','no_prerequisite_stated','mitigation_only','product_scope_alternatives','version_scope']

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def build_case(domain,scenario,variant):
    name,origin,permission,account,endpoint,features,objects,modes=domain
    feature=features.split(';')[scenario];obj=objects.split(';')[scenario];mode=modes.split(';')[scenario]+' mode'
    kind=['C3','C5','C4','C2'][scenario]
    a=[f'connectivity from the {origin}',f'the submitting account has write permission on the {permission}',f'authentication using the {account}',f'an available {endpoint}'][scenario]
    alias=[origin,permission,account,endpoint][scenario]
    A=fact('a',kind,alias,a,actor='attacker' if scenario in (0,1,2) else None)
    B=fact('b','C1',feature,f'the {feature} enabled')
    C=fact('c','C6',obj,f'an operator opens the {obj}',actor='victim')
    D=fact('d','C7',mode,f'the {mode} active')
    group=f'{name}/scenario-{scenario}';pattern=PATTERNS[(DOMAINS.index(domain)*4+scenario+variant*3)%10]
    intro=[f'The fictional {name} controller bulletin concerns one reported processing defect.',f'A lab note for the fictional {name} system separates entry conditions from subsequent effects.',f'The fictional {name} supplier describes the affected workflow below.',f'A fictional {name} maintenance ticket records the following prerequisite findings.'][variant]
    facts=[];branches=[];scopes={};uncertainty=['none','scope'];scope=f'fictional/{name}/workflow-{scenario}'
    def branch(ids,span,source='S0'):branches.append(dict(facts=ids,source=source,evidence=[span]))
    if pattern=='and':
        core=f'The reported path requires both {a} and {B["evidence"][0]}. Neither condition alone reaches the affected handler.';facts=[A,B];branch(['a','b'],core.split('. Neither')[0])
    elif pattern=='or':
        core=f'Two alternative entry routes are documented: {a}, or {D["evidence"][0]}. Either route meets the entry requirement; simultaneous presence is unnecessary.';facts=[A,D];branch(['a'],core.split('. Either')[0]);branch(['d'],core.split('. Either')[0])
    elif pattern=='and_negative_guard':
        B=fact('b','C1',feature,f'the {feature} disabled',negative=True)
        core=f'The path is reachable only with {a} and {B["evidence"][0]}. Keeping that feature enabled blocks this particular path.';facts=[A,B];branch(['a','b'],core.split('. Keeping')[0])
    elif pattern=='common_gate_alternatives':
        core=f'In every documented route, {B["evidence"][0]} is necessary. With that shared requirement satisfied, either {a} or {D["evidence"][0]} supplies the remaining entry condition.';facts=[A,B,D];branch(['b','a'],core);branch(['b','d'],core)
    elif pattern=='two_conjunctive_paths':
        left=f'The first documented route requires {a} and {B["evidence"][0]}'
        right=f'The second documented route requires {C["evidence"][0]} with {D["evidence"][0]}'
        core=left+'. '+right+'. These are alternatives; do not combine the two routes into four mandatory conditions.';facts=[A,B,C,D];branch(['a','b'],left);branch(['c','d'],right)
    elif pattern=='relation_unknown':
        core=f'One record lists {a} as required. Another lists {B["evidence"][0]} as required. The available records do not establish whether these belong to the same route or to alternative routes.';facts=[A,B];uncertainty=['relation','scope']
    elif pattern=='no_prerequisite_stated':
        core=f'The report describes a crash during processing of a {obj}. It gives no entry requirement, required account, reachable interface, feature state, or triggering operator action. The resulting outage is an effect, not an entry condition.';uncertainty=['unspecified','scope']
    elif pattern=='mitigation_only':
        B=fact('b','C1',feature,f'disable the {feature}',negative=True,necessity='contextual')
        core=f'Pending a fix, administrators are advised to disable the {feature}. This is mitigation advice. The report does not establish that the feature is a prerequisite or give any other entry requirement.';facts=[B];uncertainty=['unspecified','scope']
    elif pattern=='product_scope_alternatives':
        p0=f'For the {name} gateway edition only, the reported path requires {a}.'
        p1=f'For the {name} workstation edition only, the reported path requires {C["evidence"][0]}. This is a separate product path, not a second gateway requirement.'
        C['source']='S1';facts=[A,C];branch(['a'],p0);branch(['c'],p1.split('. This')[0],'S1');scopes={'S0':scope+'/gateway','S1':scope+'/workstation'}
        core=[intro+' '+p0,p1]
    elif pattern=='version_scope':
        core=f'These findings apply only to release branch 2 of the {name} system. Within that branch, the path requires {B["evidence"][0]} and {C["evidence"][0]}. Release branch 3 has not been assessed.';facts=[B,C];scope+='/branch-2';branch(['b','c'],core.split('. Release')[0])
    else:raise ValueError(pattern)
    if isinstance(core,str):passages={'S0':intro+' '+core}
    else:passages={'S0':core[0],'S1':core[1]}
    # Explicit nonrequirements are labeled, never silently converted to gates.
    if variant==1 and pattern not in ('no_prerequisite_stated','mitigation_only'):
        nr='Administrator privileges are not required.'
        passages['S0']+=' '+nr
        facts.append(fact('nr','C5',['administrator privileges','administrator privilege'],nr,negative=True,necessity='nonrequirement',actor='attacker'))
    # A named consequence is a distractor, not a source-supported prerequisite.
    passages['S0']+=' A successful attack may interrupt telemetry; that interruption is a consequence. Applying the corrected release is remediation.'
    scopes=scopes or {s:scope for s in passages}
    byid={f['id']:f for f in facts};terms=[]
    for b in branches:
        leaves=[E.leaf(i) if byid[i]['polarity'] else E.node('not',E.leaf(i)) for i in b['facts']]
        terms.append(leaves[0] if len(leaves)==1 else E.node('and',*leaves))
    expr=terms[0] if len(terms)==1 else E.node('or',*terms) if terms else None
    ident=digest(passages)
    return dict(id='expanded-'+ident[:20],cve='CVE-2096-'+str(1000000000+int(ident[:8],16)),passages=passages,cvss_version='4.0',scopes=scopes,
        challenge=pattern,group_id=group,domain=name,variant=variant,synthetic=True,
        gold=dict(facts=facts,branches=branches,expression=expr,allowed_uncertainty=uncertainty),
        provenance=dict(method='controlled semantic composition',independent_expert_review=False,inference_seen=False,scenario_family=group))

def validate(rows):
    errors=[];seen=set();source_spans=0
    for c in rows:
        if c['id'] in seen:errors.append(c['id']+': duplicate ID')
        seen.add(c['id']);g=c['gold'];fs={f['id']:f for f in g['facts']}
        if len(fs)!=len(g['facts']):errors.append(c['id']+': duplicate fact ID')
        for f in fs.values():
            for span in f['evidence']:
                source_spans+=1
                if span not in c['passages'][f['source']]:errors.append(c['id']+': missing fact evidence '+f['id'])
                if len(span.split())>25:errors.append(c['id']+': fact evidence exceeds quote budget')
        for b in g['branches']:
            for i in b['facts']:
                if i not in fs or fs[i]['necessity']!='required':errors.append(c['id']+': invalid branch ref')
            for span in b['evidence']:
                if span not in c['passages'][b['source']]:errors.append(c['id']+': missing relation evidence')
        if set(c['scopes'])!=set(c['passages']):errors.append(c['id']+': scope coverage')
    return dict(passed=not errors,errors=errors,documents=len(rows),annotated_fact_spans=source_spans)

def main(out):
    if out.exists():raise FileExistsError('Use a new dataset version; never overwrite an evaluated corpus')
    rows=[build_case(d,s,v) for d in DOMAINS for s in range(4) for v in range(4)]
    check=validate(rows)
    if not check['passed']:raise ValueError(check)
    names=[d[0] for d in DOMAINS];random.Random(SEED).shuffle(names)
    split_domains={'dev':names[:12],'validation':names[12:16],'test_candidate':names[16:]}
    membership={n:s for s,ns in split_domains.items() for n in ns}
    for c in rows:c['split']=membership[c['domain']]
    old=ROOT/'results/sealed_recheck_20261127/item4'
    oi=json.loads((old/'inputs.json').read_text(encoding='utf-8'));og=json.loads((old/'gold.json').read_text(encoding='utf-8'));oldgold={g['id']:g for g in og}
    oldtexts={p for c in oi for p in c['passages'].values()};newtexts={p for c in rows for p in c['passages'].values()}
    assert not oldtexts&newtexts
    out.mkdir(parents=True)
    def write(p,x):
        p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf-8')
    input_keys=('id','cve','passages','cvss_version','scopes')
    for split in split_domains:
        chosen=[c for c in rows if c['split']==split]
        write(out/split/'inputs.json',[{k:c[k] for k in input_keys} for c in chosen])
        write(out/split/'gold.json',[{k:c[k] for k in ('id','challenge','gold','group_id','domain','variant','provenance')} for c in chosen])
    write(out/'dev_regression/inputs.json',oi)
    write(out/'dev_regression/gold.json',[dict(oldgold[c['id']],prior_test_exposed=True,permitted_use='development regression only') for c in oi])
    write(out/'catalog.json',[{k:c[k] for k in ('id','challenge','group_id','domain','variant','split','provenance')} for c in rows])
    files={p.relative_to(out).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in out.rglob('*.json')}
    manifest=dict(version=VERSION,seed=SEED,new_documents=len(rows),prior_exposed_dev_regression=len(oi),total_documents=len(rows)+len(oi),
        new_required_facts=sum(f['necessity']=='required' for c in rows for f in c['gold']['facts']),new_fact_annotations=sum(len(c['gold']['facts']) for c in rows),
        source_scenario_groups=len({c['group_id'] for c in rows}),domain_split_groups=len(DOMAINS),variants_per_scenario=4,
        splits={s:dict(documents=sum(c['split']==s for c in rows),domains=ns,source_groups=len({c['group_id'] for c in rows if c['split']==s})) for s,ns in split_domains.items()},
        challenges=dict(Counter(c['challenge'] for c in rows)),fact_kinds=dict(Counter(f['kind'] for c in rows for f in c['gold']['facts'])),
        quality_checks=dict(check,exact_prior_passage_overlap=0,cross_split_domain_overlap=0,cross_split_scenario_overlap=0),sha256=files,
        generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        evaluation_status='not run; new test_candidate is not a final independent validation claim',
        scorer_policy='Dataset annotation uses the existing schema. Existing frozen final scores/oracles remain untouched. A revised scorer must be validated and frozen before new performance evaluation.',
        limitations=['80 source scenario groups, not 320 independent source worlds','Ten shared construction families occur across splits; domain/source-group separation does not prove template independence','Controlled generated English, not real clinical or Korean notes and not real CVE evidence','No independent expert annotation or adversarially independent generator','Prior 32 exposed test documents are development regression only','Do not train on validation/test_candidate or upload their gold to inference','Source conditions are fictional and do not establish actual exploitation feasibility'])
    write(out/'manifest.json',manifest)
    print(json.dumps({k:manifest[k] for k in ('new_documents','total_documents','new_required_facts','new_fact_annotations','challenges','quality_checks')}))

if __name__=='__main__':main(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'data/item4_synthetic_gt_expanded_v1')
