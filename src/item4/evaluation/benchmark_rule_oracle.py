"""Independent #4 benchmark oracle. Never imports a model or model predictions.

This policy evaluates declared evidence in a bounded synthetic assessment world;
it does not establish real-world exploit success or semantic truth of arbitrary prose.
"""
from copy import deepcopy
import hashlib
import json
from jsonschema import Draft202012Validator

VERSION = 'item4-rule-evaluation/1'
STATES = ['fixed', 'not_affected', 'under_investigation', 'affected']
VALUES = ['o', 'x', 'unknown', 'not_applicable', 'mixed']


def obj(properties):
    return dict(type='object', properties=properties, required=list(properties), additionalProperties=False)


def arr(item):
    return dict(type='array', items=item)


TEXT = dict(type='string', minLength=1)
EXPRESSION = {'oneOf': [obj({'condition': TEXT}), obj({
    'op': {'enum': ['and', 'or']}, 'args': {'type': 'array', 'minItems': 2,
                                         'items': {'$ref': '#/$defs/expression'}}}), obj({
    'op': {'const': 'not'}, 'args': {'type': 'array', 'minItems': 1, 'maxItems': 1,
                                  'items': {'$ref': '#/$defs/expression'}}})]}
CONDITION = obj(dict(id=TEXT, key=TEXT, target=TEXT, polarity={'const': 'positive'}, quote=TEXT))
EXTRACTION = obj(dict(conditions=arr(CONDITION), expression={'anyOf': [
    {'$ref': '#/$defs/expression'}, {'type': 'null'}]}))
EXTRACTION['$defs'] = {'expression': EXPRESSION}
REVIEW = obj(dict(support={'enum': ['supported', 'unsupported', 'unknown']},
                  issues=arr(TEXT), evidence_quotes=arr(TEXT)))
MAPPING = obj(dict(values=arr(obj(dict(condition_id=TEXT, key=TEXT,
    value={'enum': ['true', 'false', 'unknown']}, reason=TEXT)))))
ROUTING = obj(dict(status={'enum': STATES}, rule_id={'enum': ['R0','R1','R2','R3','R4','R5','R6','R7']},
                  evidence_refs=arr(TEXT), reason=TEXT))
FACTS = obj(dict(scope_confirmed={'type':'boolean'}, product_bound={'type':'boolean'},
    conflicting={'type':'boolean'},deployment={'enum':['running','absent','unknown']},
    inventory_complete={'type':'boolean'},runtime_exact={'type':'boolean'},
    supplier_status={'enum':['fixed','known_not_affected','known_affected','under_investigation','unknown']},
    condition_binding_valid={'type':'boolean'},route_sufficient={'type':'boolean'},paths_exhaustive={'type':'boolean'}))
ASSET_VALUE = obj(dict(asset_type_id=TEXT,key=TEXT,target=TEXT,scope_id=TEXT,
    value={'enum':VALUES},current={'type':'boolean'},evidence_ref=TEXT))
CASE = obj(dict(contract_version={'const':VERSION},synthetic={'const':True},scope_id=TEXT,asset_type_id=TEXT,
    allowed_keys=arr(TEXT),evidence_ids=arr(TEXT),source_id=TEXT,source_text=TEXT,reference=deepcopy(EXTRACTION),
    facts=FACTS,asset_values=arr(ASSET_VALUE),template_id=TEXT,split={'enum':['train','dev','test']},mutation=TEXT))
CASE['$defs']={'expression':EXPRESSION}
SCHEMAS = dict(extract=EXTRACTION, review=REVIEW, mapping=MAPPING, routing=ROUTING, case=CASE)

POLICY = [
    ('R0', 'Unknown assessment scope, unbound product, or conflicting evidence -> under_investigation.'),
    ('R1', 'Confirmed absence with complete scoped inventory -> not_affected.'),
    ('R2', 'Otherwise require confirmed running deployment and exact runtime build; missing facts -> under_investigation.'),
    ('R3', 'Matching supplier fixed declaration for the actual running build -> fixed.'),
    ('R4', 'Matching supplier known_not_affected declaration -> not_affected.'),
    ('R5', 'Supplier known_affected AND valid condition binding AND sufficient modeled route satisfied -> affected.'),
    ('R6', 'Supplier known_affected AND valid condition binding AND exhaustive modeled routes false -> not_affected.'),
    ('R7', 'All other cases -> under_investigation; necessary conditions alone do not establish affected.'),
]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def validate(task, value):
    Draft202012Validator(SCHEMAS[task]).validate(value)
    return value


def leaves(expression):
    if set(expression) == {'condition'}:
        return {expression['condition']}
    if expression.get('op') not in {'and', 'or', 'not'}:
        raise ValueError('Invalid connective')
    args = expression.get('args', [])
    if (expression['op'] == 'not' and len(args) != 1) or (expression['op'] != 'not' and len(args) < 2):
        raise ValueError('Invalid arity')
    return set().union(*(leaves(a) for a in args))


def truth(expression, values):
    if 'condition' in expression:
        return values.get(expression['condition'])
    children = [truth(a, values) for a in expression['args']]
    if expression['op'] == 'not':
        return None if children[0] is None else not children[0]
    if expression['op'] == 'and':
        return False if any(x is False for x in children) else True if all(x is True for x in children) else None
    if expression['op'] == 'or':
        return True if any(x is True for x in children) else False if all(x is False for x in children) else None
    raise ValueError('Invalid connective')


def condition_values(case, extraction):
    validate('extract', extraction)
    conditions = extraction['conditions']
    ids = [c['id'] for c in conditions]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate condition IDs')
    expression = extraction['expression']
    if (expression is None and conditions) or (expression is not None and leaves(expression) != set(ids)):
        raise ValueError('Expression/condition mismatch')
    values, audit = {}, []
    for c in conditions:
        rows = [r for r in case['asset_values'] if r['key'] == c['key'] and r['target'] == c['target']
                and r['scope_id'] == case['scope_id'] and r['asset_type_id'] == case['asset_type_id']
                and r['current'] is True and r['evidence_ref'] in case['evidence_ids']
                and r['key'] in case['allowed_keys']]
        raw = {r['value'] for r in rows}
        value = {'o': True, 'x': False}.get(next(iter(raw))) if len(raw) == 1 else None
        values[c['id']] = value
        audit.append(dict(condition_id=c['id'], key=c['key'], value={True:'true',False:'false',None:'unknown'}[value],
                          evidence_refs=[r['evidence_ref'] for r in rows]))
    return values, audit


def oracle(case):
    """Priority ordered, fail-closed rules over independently specified facts."""
    validate('case',{k:v for k,v in case.items() if k not in ('id','expected')})
    extraction = case['reference']
    values, mapping = condition_values(case, extraction)
    formula = truth(extraction['expression'], values) if extraction['expression'] else None
    facts = case['facts']
    status, rule = route_facts(facts, formula)
    return dict(status=status, rule_id=rule, condition_values=mapping,
                formula_value={True:'true',False:'false',None:'unknown'}[formula],
                basis='bounded_synthetic_policy_oracle', policy_version=VERSION,
                evidence_refs=deepcopy(case['evidence_ids']),
                evaluated_rules=[r[0] for r in POLICY[:int(rule[1:])+1]],
                facts_sha256=digest(facts))


def route_facts(facts, formula):
    """Apply the benchmark routing policy to scoped facts and a three-valued result."""
    status, rule = 'under_investigation', 'R7'
    if not facts['scope_confirmed'] or not facts['product_bound'] or facts['conflicting']:
        rule = 'R0'
    elif facts['deployment'] == 'absent' and facts['inventory_complete']:
        status, rule = 'not_affected', 'R1'
    elif facts['deployment'] != 'running' or not facts['runtime_exact']:
        rule = 'R2'
    elif facts['supplier_status'] == 'fixed':
        status, rule = 'fixed', 'R3'
    elif facts['supplier_status'] == 'known_not_affected':
        status, rule = 'not_affected', 'R4'
    elif facts['supplier_status'] == 'known_affected' and facts['condition_binding_valid']:
        if formula is True and facts['route_sufficient']:
            status, rule = 'affected', 'R5'
        elif formula is False and facts['paths_exhaustive']:
            status, rule = 'not_affected', 'R6'
    return status, rule


def public_case(case):
    result = deepcopy(case)
    for name in ('reference', 'expected', 'split', 'mutation', 'template_id'):
        result.pop(name, None)
    return result


def semantic_equal(left, right):
    """Bounded exhaustive ternary equivalence, invariant to IDs and operand order."""
    import itertools
    validate('extract', left); validate('extract', right)
    def index(value):
        result = {c['id']: (c['key'], c['target'], c['polarity']) for c in value['conditions']}
        if len(result) != len(value['conditions']) or len(set(result.values())) != len(result):
            raise ValueError('Duplicate semantic atoms')
        if value['expression'] is not None and leaves(value['expression']) != set(result):
            raise ValueError('Unbound expression')
        if value['expression'] is None and result:
            raise ValueError('Missing expression')
        return result
    a, b = index(left), index(right)
    if set(a.values()) != set(b.values()):
        return False
    if (left['expression'] is None) != (right['expression'] is None):
        return False
    if left['expression'] is None:
        return True
    atoms = sorted(set(a.values()))
    if len(atoms) > 7:
        raise ValueError('Controlled equivalence budget exceeded')
    for vector in itertools.product((True, False, None), repeat=len(atoms)):
        assigned = dict(zip(atoms, vector))
        if truth(left['expression'], {k:assigned[v] for k,v in a.items()}) != truth(right['expression'], {k:assigned[v] for k,v in b.items()}):
            return False
    return True
