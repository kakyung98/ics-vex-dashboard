"""Source/product/role/question contracts for the v5 conditional Gold.

Checks here are explicit, reproducible source constraints, not human semantic
approval. Unresolved scope, role, predicates, or grammar never become facts.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from src.item4.decision.scoped_vex_review import digest; from src.item4.decision.scoped_vex_review import extract
from src.item4.analysis.advisory_source_bundles import _products; from src.item4.analysis.advisory_source_bundles import resolve_pointer

VERSION = 'product-source-question-grounding/2'
# The existing 18 asset categories are unchanged. A source-described component
# role may be known while its mapping to those categories remains unknown.
ROLE_PATTERNS = (
    ('A0001', 'workstation', r'\bworkstations?\b'),
    ('A0002', 'human_machine_interface', r'\bhmi\b|\bhuman[- ]machine interfaces?\b'),
    ('A0003', 'programmable_logic_controller', r'\bplc\b|\bprogrammable logic controllers?\b'),
    ('A0004', 'remote_terminal_unit', r'\brtu\b|\bremote terminal units?\b'),
    ('A0005', 'intelligent_electronic_device', r'\bintelligent electronic devices?\b'),
    ('A0006', 'data_historian', r'\b(?:data |process )?historians?\b'),
    ('A0007', 'control_server', r'\bcontrol servers?\b'),
    ('A0008', 'application_server', r'\bapplication servers?\b'),
    ('A0009', 'data_gateway', r'\bdata gateways?\b'),
    ('A0010', 'safety_controller', r'\bsafety controllers?\b'),
    ('A0011', 'vpn_server', r'\bVPN servers?\b'),
    ('A0012', 'jump_host', r'\bjump hosts?\b'),
    ('A0013', 'field_io', r'\b(?:field|remote) I/O\b'),
    ('A0014', 'router', r'\brouters?\b'),
    ('A0015', 'switch', r'\b(?:ethernet|network|industrial|managed) switch(?:es)?\b'),
    ('A0016', 'firewall', r'\bfirewalls?\b'),
    ('A0017', 'dcs_controller', r'\bDCS controllers?\b|\bdistributed control system controllers?\b'),
    ('A0018', 'programmable_automation_controller', r'\bprogrammable automation controllers?\b'),
)


def normalized_name(name):
    name = re.sub(r'\([^)]*\)', '', name)
    return re.sub(r'[^a-z0-9]+', '', name.casefold())


def title_products(title, products):
    """Product-specific titles must match a complete named product family."""
    if not re.match(r'^\s*For\s+', title, re.I):
        return None
    body=re.sub(r'^\s*For\s+', '', title, flags=re.I)
    if '(' in body or ')' in body:
        compact=lambda value:re.sub(r'[^a-z0-9]+','',value.casefold())
        return {key for key,product in products.items() if compact(product['name'])==compact(body)}
    target = normalized_name(body)
    return {key for key, product in products.items() if normalized_name(product['name']) == target}


def typed_question(statement, product_name):
    """Only bounded operator-observable predicates receive answer mappings."""
    s = statement.strip()
    if re.search(r'\b(?:attacker|users?)\b|\b(?:heap|stack|memory|pointer|buffer|credential|password|privilege)\b', s, re.I):
        return None
    port = re.fullmatch(r'network access \(port (\d+)/(TCP|UDP)\) is available', s, re.I)
    if port:
        kind='network_port_access';parameters={'port':int(port[1]),'protocol':port[2].upper()}
        text=f'평가 출발점에서 {product_name}의 원문 해당 인터페이스 {port[2].upper()} {port[1]}번 포트까지 접근할 수 있습니까?'
        evidence=['network_diagram','effective_access_rules','connection_records']
    elif re.fullmatch(r'access to the (PROFIBUS|PROFINET|Industrial Ethernet) network', s, re.I):
        network=re.fullmatch(r'access to the (.+) network',s,re.I)[1]
        kind='network_segment_access';parameters={'network':network}
        text=f'평가 출발점에서 {product_name}이 연결된 {network} 네트워크에 접근할 수 있습니까?'
        evidence=['network_diagram','access_rules','bus_connection_records']
    elif re.fullmatch(r"the CPs' configuration was stored on their corresponding CPUs",s):
        kind='cp_configuration_on_cpu';parameters={'storage':'corresponding_CPU'}
        text=f'{product_name}의 설정 데이터가 해당 CPU에 저장되어 있습니까?'
        evidence=['engineering_project','configuration_records','vendor_configuration_manual']
    elif re.fullmatch(r'(?:physical|local|network|remote) access(?: to [\w /.-]+)?',s,re.I):
        kind='access';parameters={'source_predicate':s}
        text=f'평가 출발점과 자산 범위에서 다음 접근 조건을 확인할 수 있습니까: {s}?'
        evidence=['access_rules','asset_inventory','operating_records']
    elif re.fullmatch(r"[\w /().'-]{1,160}\s+(?:is|are|was|were)\s+(?:enabled|disabled|configured|installed|active|inactive)",s,re.I):
        kind='configuration_state';parameters={'source_predicate':s}
        text=f'{product_name}의 평가 시점 구성에서 다음 상태가 성립합니까: {s}?'
        evidence=['configuration_records','engineering_project','vendor_manual']
    else:
        return None
    return dict(kind=kind,parameters=parameters,question=text,
        answers={'yes':'true','no':'false','unknown':'unknown'},
        accepted_evidence=evidence,operator_answer_collected=False,
        preserves_source_polarity=True,validation_method='bounded_predicate_to_question_contract')


class GroundingIndex:
    def __init__(self, root):
        self.root=Path(root);self.documents={}
        self.vendor_path=self.root/'data/item4_grounding_v1/siemens_ssa_763427.json'
        self.vendor=json.loads(self.vendor_path.read_text(encoding='utf-8')) if self.vendor_path.exists() else None

    def document(self, advisory):
        if advisory not in self.documents:
            path=self.root/'icsa/csaf'/f'{advisory}.json'
            raw=path.read_bytes();payload=json.loads(raw.decode('utf-8-sig'))
            self.documents[advisory]=(payload,hashlib.sha256(raw).hexdigest(),_products(payload,advisory))
        return self.documents[advisory]

    def asset_type(self, product, raw_product):
        name=product['name'];matches=[]
        if re.search(r'\b(?:simulator|emulator|engineering|programming|SDK|library|driver)\b',name,re.I):
            return dict(status='unknown',reason='Tool/component name does not establish the operated asset role')
        if re.search(r'\bfirmware\b',name,re.I):
            return dict(status='unknown',reason='Component/host relation requires separate asset-role evidence')
        # Exact product-tree names can identify a role. Model estimates and
        # advisory-wide asset keywords are deliberately not imported.
        contextual_role=False
        qualifier=re.search(r'\s+(?:for|used by|compatible with)\s+',name,re.I)
        for taxonomy_id,role,pattern in ROLE_PATTERNS:
            for m in re.finditer(pattern,name,re.I):
                in_parentheses=name[:m.start()].count('(')>name[:m.start()].count(')')
                protocol_abbreviation=(role=='remote_terminal_unit' and re.search(r'modbus\s*$',name[max(0,m.start()-15):m.start()],re.I))
                if in_parentheses or (qualifier and m.start()>qualifier.start()) or protocol_abbreviation:
                    contextual_role=True;continue
                if re.search(r'\bmodules?\b',name,re.I):
                    contextual_role=True;continue
                matches.append((taxonomy_id,role,m.span()));break
        if len(matches)==1:
            taxonomy_id,role,span=matches[0]
            return dict(status='source_supported',role=role,taxonomy_id=taxonomy_id,
                taxonomy_status='explicit_product_name',evidence=dict(
                    source_json_pointer=raw_product['source_json_pointer']+'/name',
                    text=name,span=list(span),quote=name[slice(*span)]))
        if len(matches)>1:
            return dict(status='unknown',reason='Multiple asset roles in the product name',candidates=[x[1] for x in matches])
        if self.vendor and re.match(r'^(?:SIMATIC (?:NET )?|SIPLUS NET )CP(?=\s|\d|-|$)',name,re.I):
            v=self.vendor;quote=v['communication_processor_description']
            if not quote or quote not in v['text']:raise ValueError('Vendor role quotation mismatch')
            a=v['text'].index(quote)
            return dict(status='source_supported',role='communication_processor_interface_module',
                taxonomy_id=None,taxonomy_status='component_role_not_forced_into_fixed18',
                evidence=dict(url=v['url'],document_sha256=v['document_sha256'],
                    text_sha256=hashlib.sha256(v['text'].encode()).hexdigest(),
                    span=[a,a+len(quote)],quote=quote,source_artifact='data/item4_grounding_v1/siemens_ssa_763427.json'),
                family_binding='SIMATIC CP / SIPLUS NET CP named in the same vendor advisory')
        if contextual_role:
            return dict(status='unknown',reason='Component/host or protocol context is not the product asset type')
        return dict(status='unknown',reason='No unambiguous product-scoped asset-role evidence')

    def prepare(self, original):
        record=deepcopy(original);products={p['key']:p for p in record['products']}
        source_by_id={s['id']:s for s in record['sources']};scope_reasons=[]
        for product in products.values():
            product['asset_type']=dict(status='unknown',reason='No raw CSAF product binding')
            try:
                payload,sha,raw_products=self.document(product['advisory_id'])
                raw=raw_products[product['source_product_id']]
                if raw['name']!=product['name']:raise ValueError('Product name drift')
                matches=[i for i,v in enumerate(payload.get('vulnerabilities',[])) if v.get('cve')==record['cve'] and raw['native_id'] in v.get('product_status',{}).get('known_affected',[])]
                if len(matches)!=1:raise ValueError('CVE/product known-affected binding is unresolved')
                product['source_product_ref']=dict(advisory_id=product['advisory_id'],document_sha256=sha,
                    source_json_pointer=raw['source_json_pointer'],native_product_id=raw['native_id'],name=raw['name'],
                    known_affected_pointer=f'/vulnerabilities/{matches[0]}/product_status/known_affected')
                product['version_scope']=[]
                branch=raw['source_json_pointer'].rsplit('/product',1)[0]
                while '/branches/' in branch:
                    value=resolve_pointer(payload,branch)
                    if value.get('category') in ('product_version','product_version_range'):
                        product['version_scope'].append(dict(category=value['category'],name=value['name'],source_json_pointer=branch+'/name'))
                    branch=branch.rsplit('/branches/',1)[0]
                product['asset_type']=self.asset_type(product,raw)
                product['asset_ids']=[product['asset_type']['taxonomy_id']] if product['asset_type'].get('taxonomy_id') else []
            except (OSError,KeyError,ValueError,TypeError) as exc:
                product['grounding_error']=str(exc)
        # Compute exceptions from raw note TITLES, which the old flattened
        # source records discarded. Unknown exception titles block the general
        # source for the affected product set, rather than widening its scope.
        scopes={}
        for source in record['sources']:
            source['original_product_keys']=source.get('product_keys',[])[:]
            source['product_keys']=[]
            try:
                if source['id'].startswith('nvd:'):raise ValueError('NVD prose has no product-specific CSAF binding')
                advisory=source['id'].split(':v',1)[0]
                payload,sha,raw_products=self.document(advisory)
                if sha!=source['document_sha256']:raise ValueError('Original document hash mismatch')
                pointer=source['pointer'];text=resolve_pointer(payload,pointer)
                if text!=source['text']:raise ValueError('Original source text mismatch')
                parent=pointer.rsplit('/notes/',1)[0];vuln=resolve_pointer(payload,parent)
                if vuln.get('cve')!=record['cve']:raise ValueError('Source belongs to another CVE')
                affected=set(vuln.get('product_status',{}).get('known_affected',[]))
                eligible={k:p for k,p in products.items() if p.get('advisory_id')==advisory and p.get('source_product_id') in affected and p.get('source_product_ref')}
                if parent not in scopes or scopes[parent][0]!=advisory:
                    exceptions=set();unresolved=False
                    for note in vuln.get('notes',[]):
                        matched=title_products(note.get('title',''),eligible)
                        if matched is not None:
                            if not matched:unresolved=True
                            exceptions.update(matched)
                    scopes[parent]=(advisory,exceptions,unresolved)
                _,exceptions,unresolved=scopes[parent]
                note=resolve_pointer(payload,pointer.rsplit('/',1)[0])
                if note.get('category') not in ('summary','description','details'):raise ValueError('Not vulnerability description evidence')
                matched=title_products(note.get('title',''),eligible)
                if matched is None:
                    if unresolved:raise ValueError('Unresolved product-specific exception title')
                    allowed=set(eligible)-exceptions;basis='general_description_excluding_product_specific_exceptions'
                else:
                    if not matched:raise ValueError('Product-specific title did not resolve')
                    allowed=matched;basis='exact_product_family_note_title'
                source['product_keys']=sorted(allowed)
                source['product_scope_validation']=dict(status='source_supported',basis=basis,
                    title=note.get('title',''),source_json_pointer=pointer.rsplit('/',1)[0],
                    product_keys=sorted(allowed),source_document_sha256=sha,
                    excluded_specific_products=sorted(exceptions) if matched is None else [])
            except (OSError,KeyError,ValueError,TypeError,IndexError) as exc:
                source['product_scope_validation']=dict(status='unknown',reason=str(exc))
                scope_reasons.append(str(exc))
        # A CVE-specific description can explicitly name the affected role.
        # Only the bounded "affected/vulnerable <role>" construction is used;
        # neighboring PLCs, generic recommendations, and navigation estimates
        # cannot supply the assessed product's type.
        for key,product in products.items():
            supported=[]
            for source in record['sources']:
                if key not in source.get('product_keys',[]) or source.get('subject_ambiguous'):continue
                for taxonomy_id,role,pattern in ROLE_PATTERNS:
                    m=re.search(r'\b(?:affected|vulnerable)\s+(?:industrial\s+)?(?:'+pattern+r')',source['text'],re.I)
                    if m:supported.append(dict(status='source_supported',role=role,taxonomy_id=taxonomy_id,
                        taxonomy_status='explicit_affected_role_in_product_scoped_CVE_text',evidence=dict(
                            source_id=source['id'],url=source['url'],source_json_pointer=source['pointer'],
                            span=list(m.span()),quote=m.group(),text_sha256=source['text_sha256'])))
            roles={s['role'] for s in supported}
            current=product['asset_type']
            if current.get('reason','').startswith(('Component/host','Tool/component')):continue
            if current.get('status')=='source_supported':roles.add(current['role'])
            if len(roles)>1:
                product['asset_type']=dict(status='unknown',reason='Conflicting product-scoped role evidence',candidates=sorted(roles))
                product['asset_ids']=[]
            elif current.get('status')!='source_supported' and len(roles)==1:
                product['asset_type']=supported[0];product['asset_ids']=[supported[0]['taxonomy_id']]
        # Reparse the complete source under corrected product scopes. Do not
        # import the broad remote-attacker descriptor fallback as a prerequisite.
        record['scenarios']=extract(record)
        for scenario in record['scenarios']:
            source=source_by_id[scenario['source_ref']['source_id']]
            scenario['product_keys']=source['product_keys'][:]
            errors=[]
            if source.get('subject_ambiguous'):errors.append('Source subject is ambiguous')
            if source.get('product_scope_validation',{}).get('status')!='source_supported':errors.append('Product scope is unresolved')
            if scenario.get('scope_ambiguous'):errors.append('Boolean connective attachment is ambiguous')
            def operators(expr):
                return set() if 'condition' in expr else {expr['op']}|set().union(*(operators(a) for a in expr['args']))
            if {'and','or'}<=operators(scenario['expression']) and not re.search(r'\([^)]*\b(?:and|or)\b[^)]*\)|\beither\b',scenario['source_ref']['quote'],re.I):
                errors.append('Mixed Boolean operators need explicit logical grouping')
            if scenario.get('derivation') not in ('explicit_necessity','conditional_context','unless_guard'):
                errors.append('Access descriptor alone is not an explicit source condition')
            for condition in scenario['conditions']:
                contract=typed_question(condition['proposition'],'{product}')
                condition['operator_observable']=contract is not None
                condition['question_contract']=contract
                if not contract:errors.append('Unsupported or unobservable source predicate: '+condition['proposition'])
            scenario['grounding_validation']=dict(status='source_supported' if not errors else 'unknown',
                errors=sorted(set(errors)),method=VERSION,independent_human_semantic_review=False)
        record['grounding_version']=VERSION
        record['legacy_asset_ids']=original.get('asset_ids',[])
        record['asset_ids']=sorted({p['asset_type']['taxonomy_id'] for p in products.values() if p['asset_type'].get('status')=='source_supported' and p['asset_type'].get('taxonomy_id')})
        record['asset_type_policy']='Per-product source evidence only; legacy/model navigation categories are not Gold labels'
        record['original_record_digest']=original['record_digest']
        record['grounding_unknown_reasons']=sorted(set(scope_reasons))
        record['record_digest']=digest({k:v for k,v in record.items() if k!='record_digest'})
        return record


def validate_scenario(record, scenario):
    if scenario.get('grounding_validation',{}).get('status')!='source_supported':
        raise ValueError('Source condition/question/formula validation unresolved')
    source=next(s for s in record['sources'] if s['id']==scenario['source_ref']['source_id'])
    scope=source.get('product_scope_validation',{})
    if scope.get('status')!='source_supported':raise ValueError('Product scope validation unresolved')
    products={p['key']:p for p in record['products']}
    candidates=sorted(k for k in scenario['product_keys'] if k in scope['product_keys'] and products[k].get('asset_type',{}).get('status')=='source_supported' and products[k].get('version_scope'))
    if not candidates:raise ValueError('No product with source-supported asset role and version scope')
    # A specific note is preferred for its named product; general notes cannot
    # select products whose exception has been excluded above.
    product=products[candidates[0]]
    for condition in scenario['conditions']:
        contract=typed_question(condition['proposition'],'{product}')
        if contract is None or contract!=condition.get('question_contract'):
            raise ValueError('Question/predicate contract mismatch')
    return product
