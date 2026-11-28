"""Build a source-bound prerequisite DAG before collecting asset operational information.

Edges are prerequisites, not invented lateral-movement or network links. AND
gates are hyperedges: ordinary graph reachability would incorrectly accept one
of several necessary prerequisites. Missing observations always stay unknown.
"""
from copy import deepcopy
import hashlib
import json

VERSION = 'nist-operational-attack-graph/1'
STATES = {'true', 'false', 'unknown'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def source_contract(cve, expression, questions, scope, asset_type_id, coverage_complete,
          source_digest, gaps=(), source_refs=()):
    """Compile structure only. No submitted answer changes the graph topology."""
    nodes = {}; edges = []; by_question = {q['id']: q for q in questions}

    def predicate(qid):
        key = 'fact:' + qid
        if key not in nodes:
            q = by_question.get('runtime_version' if qid == 'affected_version' else qid, {})
            nodes[key] = dict(id=key, kind='predicate', question_id=qid,
                              label=q.get('label', qid), nist_fields=q.get('nist_fields', []),
                              operating_field_ids=q.get('operating_field_ids', []),
                              source=q.get('source'), nli=q.get('nli'), inputs=[])
            nodes[key]['source_refs'] = [q['source']] if q.get('source') else list(source_refs)
        return key

    def visit(expr):
        if not isinstance(expr, dict):
            return predicate('unresolved-source-rule')
        if set(expr) == {'condition'}:
            return predicate(expr['condition'])
        op = expr.get('op'); args = expr.get('args')
        if op not in {'and', 'or', 'not'} or not isinstance(args, list) or not args or (op == 'not' and len(args) != 1):
            raise ValueError('Invalid attack graph prerequisite expression')
        children = [visit(a) for a in args]
        key = 'gate:' + digest([op, children])[:24]
        if key not in nodes:
            nodes[key] = dict(id=key, kind=op, inputs=children, label=op.upper())
            edges.extend(dict(source=c, target=key, relation='prerequisite') for c in children)
        return key

    root = visit(expression)
    operational = sorted({f for q in questions if q['id'] not in {'deployment', 'runtime_version', 'product_family'}
                          for f in (q.get('operating_field_ids') or q.get('nist_fields', []))})
    # Identity/version records alone cannot stand in for operational path data.
    if not operational:
        missing = predicate('unmapped-operating-information')
        key = 'gate:operational-mapping'
        nodes[key] = dict(id=key, kind='and', inputs=[root, missing], label='AND')
        edges.extend(dict(source=c, target=key, relation='prerequisite') for c in [root, missing])
        root = key
    deployment = predicate('deployment'); version = predicate('affected_version')
    goal = 'exploit:' + cve
    nodes[goal] = dict(id=goal, kind='and', inputs=[deployment, version, root], label=cve)
    edges.extend(dict(source=c, target=goal, relation='prerequisite') for c in [deployment, version, root])
    graph = dict(version=VERSION, cve=cve, scope=deepcopy(scope), asset_type_id=asset_type_id,
                 source_digest=source_digest, nodes=list(nodes.values()), edges=edges,
                 source_refs=deepcopy(list(source_refs)),
                 goal=goal, operating_root=root, operational_field_ids=operational,
                 coverage_complete=bool(coverage_complete and operational and not gaps), gaps=deepcopy(list(gaps)),
                 semantics='three-valued prerequisite DAG; AND/OR/NOT gates',
                 topology='single component and recorded origin; no inferred network or cross-asset edges')
    return graph


def build(cve, expression, questions, scope, asset_type_id, coverage_complete,
          source_digest, gaps=(), source_refs=()):
    from src.item4.decision.mulval_attack_graphs import build as mulval_build
    return mulval_build(source_contract(cve,expression,questions,scope,asset_type_id,
                                       coverage_complete,source_digest,gaps,source_refs))


def evaluate(graph, facts):
    """Evaluate every dependency and retain a witness/blocker subgraph."""
    if digest({k: v for k, v in graph.items() if k != 'sha256'}) != graph['sha256']:
        raise ValueError('Attack graph integrity failure')
    if any(v not in STATES for v in facts.values()):
        raise ValueError('Invalid attack graph observation')
    if graph.get('generation_status') == 'unavailable':
        return dict(value='unknown', path_found=False, no_path_proven=False,
                    node_states={graph['operating_root']:'unknown'}, witness_nodes=[],
                    unresolved_questions=sorted(facts), graph_sha256=graph['sha256'],
                    generation_status='unavailable', generation_error=graph['generation_error'],
                    inference_steps=[])
    nodes = {n['id']: n for n in graph['nodes']}
    if len(nodes) != len(graph['nodes']):
        raise ValueError('Duplicate attack graph node')
    if any(n['kind']=='predicate' and n['inputs'] for n in nodes.values()):
        raise ValueError('Primitive observation cannot have dependencies')
    states = {}; visiting = set()

    def visit(key):
        if key in states:
            return states[key]
        if key in visiting or key not in nodes:
            raise ValueError('Cyclic or dangling attack graph dependency')
        visiting.add(key); n = nodes[key]
        if n['kind'] == 'predicate':
            value = facts.get(n['question_id'], 'unknown')
            if n.get('polarity') == 'false':
                value = {'true':'false', 'false':'true', 'unknown':'unknown'}[value]
        else:
            values = [visit(k) for k in n['inputs']]
            if n['kind'] == 'not' and len(values) == 1:
                value = {'true': 'false', 'false': 'true', 'unknown': 'unknown'}[values[0]]
            elif n['kind'] == 'and' and values:
                value = 'false' if 'false' in values else 'true' if all(v == 'true' for v in values) else 'unknown'
            elif n['kind'] == 'or' and values:
                value = 'true' if 'true' in values else 'false' if all(v == 'false' for v in values) else 'unknown'
            else:
                raise ValueError('Invalid attack graph gate')
        states[key] = value; visiting.remove(key)
        return value

    value = visit(graph['goal'])
    for key in nodes:
        visit(key)
    witness = set()

    def explain(key):
        if key in witness:
            return
        witness.add(key); n = nodes[key]
        if n['kind'] == 'or' and states[key] == 'true':
            selected = [k for k in n['inputs'] if states[k] == 'true'][:1]
        elif n['kind'] == 'and' and states[key] == 'false':
            selected = [k for k in n['inputs'] if states[k] == 'false'][:1]
        else:
            selected = n['inputs']
        for child in selected:
            explain(child)

    explain(graph['goal'])
    steps = [dict(node_id=n['id'], value=states[n['id']], rule=n['inference_rule'],
                  premise_node_ids=n['inputs'], source_refs=n['source_refs'],
                  in_goal_witness=n['id'] in witness)
             for n in nodes.values() if 'inference_rule' in n]
    return dict(value=value, path_found=value == 'true',
                no_path_proven=value == 'false' and graph['coverage_complete'],
                node_states=states, witness_nodes=sorted(witness),
                unresolved_questions=sorted({n['question_id'] for n in nodes.values()
                                            if n['kind'] == 'predicate' and states[n['id']] == 'unknown'}),
                inference_steps=steps, generation_status='complete',
                proves_exploit_success=False,
                graph_sha256=graph['sha256'])


def mitigation_questions(questions):
    """Re-observe actual path predicates after a control, with efficacy evidence.

    No generic 'firewall installed' or 'mitigation done' checkbox establishes a
    fix. The graph must be blocked by the measured post-control facts.
    """
    result = []
    for q in questions:
        if q['id'] in {'deployment', 'runtime_version', 'product_family'}:
            continue
        item = deepcopy(q)
        item.update(id='mitigation:' + q['id'], target_question_id=q['id'],
                    label='After applying a mitigation, verify this path condition: ' + q['label'],
                    stage='mitigation', requires_effectiveness_record=True)
        result.append(item)
    return result
