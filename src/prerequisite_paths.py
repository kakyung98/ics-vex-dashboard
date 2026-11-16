"""Bounded Boolean path expansion; signed literals remain outside embeddings."""
from itertools import product
from .context_vex_pipeline import logic


def attack_paths(expression, limit=256):
    logic(expression, {})

    def expand(node, negated=False):
        if 'condition' in node:
            return [frozenset([(node['condition'], not negated)])]
        op = node['op']
        if op == 'not':
            return expand(node['args'][0], not negated)
        if negated:
            op = 'or' if op == 'and' else 'and'
        rows = [expand(child, negated) for child in node['args']]
        result = [frozenset()] if op == 'and' else []
        for row in rows:
            if op == 'or':
                result += row
            else:
                if len(result) * len(row) > limit:
                    raise ValueError('Formula expands beyond 256 attack paths; split the review into smaller source-supported formulas')
                result = [a | b for a, b in product(result, row)]
            result = list(set(p for p in result if not any((cid, not sign) in p for cid, sign in p)))
            if len(result) > limit:
                raise ValueError('Too many attack paths')
        return result

    paths = expand(expression)
    # Absorption: A OR (A AND B) requires only A for the second path too.
    paths = [p for p in paths if not any(q < p for q in paths)]
    if not paths:
        raise ValueError('The reviewed formula has no satisfiable attack path')
    return [sorted(p) for p in sorted(paths, key=lambda p: sorted(p))]
