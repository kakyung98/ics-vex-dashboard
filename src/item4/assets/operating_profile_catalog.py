"""54 source rows / 167 observations, with versioned CVE-review compatibility."""
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import hashlib, importlib.util, json
from datetime import datetime,timezone
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
LEGACY_HOME = ROOT/'local-service/sbom-vex/operating_profiles_r4_rederived'
VERSION = 'ics-operating-profile/nist-tables-12-17-choice/2'
spec = importlib.util.spec_from_file_location('nist_legacy_validation', LEGACY_HOME/'operating_profiles.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
digest = legacy.digest
applicability = legacy.applicability


@lru_cache(maxsize=1)
def catalogue():
    data = json.loads((ROOT/'site/nist-operating-information.json').read_text(encoding='utf-8'))
    document = ROOT/'docs/ICS_OT_profiles_v0_1.md'
    if hashlib.sha256(document.read_bytes()).hexdigest() != data['mapping_document_sha256']:
        raise ValueError('Source mapping integrity changed; rebuild the catalogue')
    assert len(data['rows']) == 54 and sum(len(r['collection_elements']) for r in data['rows']) == 167
    old = legacy.catalogue()
    answers=json.loads((ROOT/'docs/nist_selectable_answers.v1.json').read_text(encoding='utf-8'))
    claimed=answers['sha256'];unsigned={k:v for k,v in answers.items() if k!='sha256'}
    if hashlib.sha256(json.dumps(unsigned,sort_keys=True,ensure_ascii=False).encode()).hexdigest()!=claimed:
        raise ValueError('Answer specification integrity failure')
    result = dict(version=VERSION, scope_fields=old['scope_fields'], rows=data['rows'],
                  source_clauses={}, profiles=[], applicability_probes={},
                  answer_specs=answers['fields'],answer_spec_sha256=claimed,
                  policy='167 project-derived observations, not mandatory questions or automatic CVE prerequisites.')
    fields = []
    for row in data['rows']:
        rid = row['source_id']
        result['source_clauses'][rid] = dict(section='Table '+str(row['table']), title=row['title'],
            pdf_page=row['pdf_page'], printed_page=row['printed_page'], url=row['url'], quote=row['description'])
        result['applicability_probes'][rid] = dict(label=row['label'], source_ids=[rid])
        for item in row['collection_elements']:
            fields.append(dict(id=item['id'], row_id=rid, label=item['id']+' · '+item['label'],
                response_spec=answers['fields'][item['id']],
                category='conditional', applies_if=dict(gate=rid), source_ids=[rid],
                nist_basis=[dict(primary=result['source_clauses'][rid], source_clause_id=rid)]))
    for old_p in old['profiles']:
        schema = deepcopy(old_p['definition']['schema'])
        props = schema['properties']
        props['version'] = dict(const=VERSION)
        basis = dict(document_id='NIST SP 800-82 Rev.4 IPD, Tables 12–17', status='Initial Public Draft',
                     pdf_sha256=data['pdf_sha256'], derivation_sha256=data['mapping_document_sha256'])
        props['standard_basis'] = dict(const=basis)
        gate_schema = deepcopy(next(iter(props['gates']['properties'].values())))
        props['gates'] = dict(type='object', properties={r['source_id']:deepcopy(gate_schema) for r in data['rows']},
                             required=[r['source_id'] for r in data['rows']], additionalProperties=False)
        value_schema = deepcopy(next(iter(props['inventory']['properties']['values']['properties'].values())))
        value_schema['properties']['state']['enum']=['unknown','recorded','not_applicable','conflicting']
        value_schema['properties']['unknown_reason']={'enum':['','not_surveyed','evidence_missing','outside_inventory','value_not_represented','scope_mismatch']}
        value_schema['required'].append('unknown_reason')
        value_schemas={}
        for f in fields:
            v=deepcopy(value_schema)
            v['properties']['data']={'oneOf':[{'type':'null'},{'type':'object','additionalProperties':False,
                'required':['choice','coverage','value_refs'], 'properties':{
                    'choice':{'enum':[o['code'] for o in f['response_spec']['options']]},
                    'coverage':{'enum':['complete','partial']},
                    'value_refs':{'type':'array','uniqueItems':True,'maxItems':100,'items':{'type':'string','minLength':1,'maxLength':200}}}}]}
            v['properties']['coverage_scope']={'enum':['','assessed_asset','assessed_component','system_context']}
            value_schemas[f['id']]=v
        props['inventory']['properties']['values'] = dict(type='object', properties=value_schemas,
            required=[f['id'] for f in fields], additionalProperties=False)
        for g in props['gates']['properties'].values():g['properties']['coverage_scope']={'enum':['','assessed_asset','assessed_component','system_context']}
        props['reference_values']={'type':'object','maxProperties':2000,'additionalProperties':{
            'type':'object','additionalProperties':False,'required':['kind','label','asset_ref','evidence_ids'],
            'properties':{'kind':{'enum':sorted({f['response_spec']['reference_kind'] for f in fields if f['response_spec']['reference_kind']})},
                          'label':{'type':'string','minLength':1,'maxLength':2000},'asset_ref':{'type':'string','minLength':1,'maxLength':2000},
                          'evidence_ids':{'type':'array','minItems':1,'uniqueItems':True,'items':{'type':'string','maxLength':200}}}}}
        schema['required'].append('reference_values')
        props['evidence']['additionalProperties']['properties']['reviewed']={'type':'boolean'}
        props['evidence']['additionalProperties']['required'].append('reviewed')
        for name in ['asset_ref','build','config_baseline','observed_at','valid_until']:
            props['evidence']['additionalProperties']['properties'][name]={'type':'string','minLength':1,'maxLength':2000}
            props['evidence']['additionalProperties']['required'].append(name)
        definition = dict(fields=deepcopy(fields), schema=schema, category_counts=dict(conditional=167),
                          answer_spec_sha256=claimed,
                          source_derivation_sha256=data['mapping_document_sha256'])
        definition['definition_sha256'] = digest(definition)
        blank = deepcopy(old_p['blank'])
        blank.update(version=VERSION, standard_basis=basis, template_sha256=definition['definition_sha256'],
                     reference_values={},
                     gates={r['source_id']:dict(state='unknown', evidence_ids=[], coverage_scope='') for r in data['rows']},
                     inventory=dict(asset_type_ids=[old_p['asset']['id']], values={f['id']:dict(state='unknown', data=None,
                         evidence_ids=[], coverage_scope='',unknown_reason='not_surveyed') for f in fields}))
        result['profiles'].append(dict(asset=old_p['asset'], definition=definition, blank=blank, role_confirmation_gates=[]))
    return result


def validate(payload, templates=None):
    templates = templates or catalogue()
    if not isinstance(payload, dict) or payload.get('version') != VERSION:
        raise ValueError('Incompatible profile version. Preserve earlier free-text drafts and review them against the current selectable-answer template. Automatic migration is not supported.')
    p = next((p for p in templates['profiles'] if p['asset']['id'] == payload.get('asset_type_id')), None)
    if not p:
        raise ValueError('Unknown asset type')
    # Auto-CVE forms keep the optional 167-field catalogue at its exact server
    # blank. Validate its immutable part by equality and schema-check only the
    # dynamic scope/evidence registry, instead of re-walking 167 unions per CVE.
    dynamic={'scope','evidence','reference_values'}
    exact_blank=set(payload)==set(p['blank']) and all(payload[k]==v for k,v in p['blank'].items() if k not in dynamic)
    if exact_blank:
        schema=dict(type='object',properties={k:p['definition']['schema']['properties'][k] for k in dynamic},required=sorted(dynamic),additionalProperties=False)
        errors=list(Draft202012Validator(schema).iter_errors({k:payload[k] for k in dynamic}))
    else:errors = list(Draft202012Validator(p['definition']['schema']).iter_errors(payload))
    if errors:
        raise ValueError(str(list(errors[0].absolute_path))+': '+errors[0].message)
    definition=p['definition']
    if digest({k:v for k,v in definition.items() if k!='definition_sha256'})!=definition['definition_sha256']:
        raise ValueError('Template integrity failure')
    if payload['template_sha256']!=definition['definition_sha256']:raise ValueError('Stale selectable-answer template')
    evidence=payload['evidence'];refs=payload['reference_values'];gates=payload['gates']
    for key,e in evidence.items():
        if not key.strip() or not e['source'].strip() or not e['excerpt'].strip():raise ValueError('Evidence requires its original source and excerpt; it is never interpreted by an LLM')
    def check_refs(ids,context):
        if not ids or any(i not in evidence for i in ids):raise ValueError(context+': select registered evidence')
        if any(evidence[i]['reviewed'] is not True for i in ids):raise ValueError(context+': explicitly review selected evidence records')
        for i in ids:
            e=evidence[i]
            for key in ['asset_ref','build','config_baseline']:
                if not payload['scope'][key].strip() or e[key]!=payload['scope'][key]:raise ValueError(context+': evidence does not bind the current '+key)
            try:
                observed=datetime.fromisoformat(e['observed_at'].replace('Z','+00:00'))
                expiry=datetime.fromisoformat(e['valid_until'].replace('Z','+00:00'))
                assessment=datetime.fromisoformat(payload['scope']['observed_at'].replace('Z','+00:00'))
                if any(d.utcoffset() is None for d in [observed,expiry,assessment]):raise ValueError()
                if not observed<=assessment<=expiry or not observed<=datetime.now(timezone.utc)<=expiry:raise ValueError()
            except (ValueError,TypeError) as exc:raise ValueError(context+': evidence is expired, future-dated, or does not cover the assessment observation time') from exc
    for key,r in refs.items():
        if not key.strip() or any(i not in evidence for i in r['evidence_ids']):raise ValueError('Registered value has missing evidence references')
    for key,g in gates.items():
        if g['state']=='unknown':
            if g['evidence_ids'] or g['coverage_scope']:raise ValueError('Unknown applicability cannot assert a surveyed finding')
        else:
            check_refs(g['evidence_ids'],key)
            if not g['coverage_scope']:raise ValueError(key+': select assessed scope')
    counts={'recorded':0,'unknown':0,'not_applicable':0,'conflicting':0};pending=0
    for f in definition['fields']:
        fid=f['id'];v=payload['inventory']['values'][fid];state=v['state'];ap=applicability(f['applies_if'],gates)
        counts[state]+=1;pending+=ap=='unknown'
        if state=='unknown':
            if v['data'] is not None or v['evidence_ids'] or v['coverage_scope']:raise ValueError(fid+': unknown answers cannot assert values or surveyed evidence')
            if not v['unknown_reason']:raise ValueError(fid+': select the reason this remains unknown')
            continue
        if v['unknown_reason']:raise ValueError(fid+': unknown reason is reserved for unknown answers')
        check_refs(v['evidence_ids'],fid)
        if any(evidence[e]['kind'] not in f['response_spec']['allowed_evidence_kinds'] for e in v['evidence_ids']):
            raise ValueError(fid+': evidence type does not support this observation domain')
        if not v['coverage_scope']:raise ValueError(fid+': select assessed scope')
        if state=='not_applicable':
            if ap!='false' or v['data'] is not None:raise ValueError(fid+': non-applicability requires evidenced absent applicability and no asserted answer')
            continue
        if state=='conflicting':
            if v['data'] is not None or len(v['evidence_ids'])<2:raise ValueError(fid+': conflict requires at least two reviewed evidence records and no selected truth')
            continue
        if ap=='false':raise ValueError(fid+': recorded answer conflicts with declared non-applicability')
        if not isinstance(v['data'],dict):raise ValueError(fid+': select a structured answer')
        d=v['data'];o=next(x for x in f['response_spec']['options'] if x['code']==d['choice'])
        if o['requires_complete_scope'] and d['coverage']!='complete':raise ValueError(fid+': this negative/exhaustive answer requires complete surveyed coverage')
        if o['requires_value_reference'] and not d['value_refs']:raise ValueError(fid+': select actual values from the registered inventory')
        if not o['requires_value_reference'] and d['value_refs']:raise ValueError(fid+': this answer does not assert registered object values')
        for key in d['value_refs']:
            if key not in refs:raise ValueError(fid+': unknown registered value')
            r=refs[key]
            if r['kind']!=f['response_spec']['reference_kind']:raise ValueError(fid+': wrong registered value type')
            if not payload['scope']['asset_ref'].strip() or r['asset_ref']!=payload['scope']['asset_ref']:raise ValueError(fid+': registered value belongs to a different or unbound asset')
            check_refs(r['evidence_ids'],fid)
            if not set(r['evidence_ids'])<=set(v['evidence_ids']):raise ValueError(fid+': selected values require their evidence to be linked to this answer')
    dates={}
    for key in ['observed_at','valid_until']:
        if payload['scope'][key].strip():
            try:
                dates[key]=datetime.fromisoformat(payload['scope'][key].replace('Z','+00:00'))
                if dates[key].utcoffset() is None:raise ValueError()
            except ValueError as exc:raise ValueError('Use timezone-qualified ISO 8601 for '+key) from exc
    if len(dates)==2 and dates['valid_until']<=dates['observed_at']:raise ValueError('Expiry must follow observation')
    now=datetime.now(timezone.utc);expired=bool(dates.get('valid_until') and dates['valid_until']<=now)
    return dict(valid=True,state='expired' if expired else 'draft',recorded_fields=counts['recorded'],unknown_fields=counts['unknown'],
        conflicting_fields=counts['conflicting'],not_applicable_fields=counts['not_applicable'],pending_applicability=pending,
        unknown_gates=sum(g['state']=='unknown' for g in gates.values()),type_role_conflicts=[],
        missing_scope=[k for k,v in payload['scope'].items() if not v.strip()],evidence_expired=expired,
        observation_in_future=bool(dates.get('observed_at') and dates['observed_at']>now),
        source_rows=54,collection_elements=167,answer_spec_sha256=templates['answer_spec_sha256'],
        evidence_semantics_independently_verified=False,automatic_cve_mapping=False,proves_non_exploitability=False,vex_status=None,llm_used=False)
