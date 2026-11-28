"""Translate supported VERS predicates to intervals without inventing a release."""
from src.common.source_version_parser import version_predicate,compare


def _interval(lower=None,upper=None,lower_inclusive=False,upper_inclusive=False):
    return dict(lower=lower,upper=upper,lower_inclusive=lower_inclusive,upper_inclusive=upper_inclusive)


def compile_vers(raw):
    if not isinstance(raw,str) or not raw.startswith('vers:'):return None
    predicate=version_predicate(raw)
    kind=raw.split(':',1)[1].split('/',1)[0]
    scheme='intdot' if kind=='intdot' else 'opaque' if kind=='generic' else 'unknown'

    def order(a,b):
        if a==b:return 0
        return compare(a,b,'intdot') if scheme=='intdot' else None

    def intersection(left,right):
        out=_interval()
        for side in ('lower','upper'):
            a,b=left[side],right[side]
            if a is None:out[side]=b;out[side+'_inclusive']=right[side+'_inclusive'];continue
            if b is None:out[side]=a;out[side+'_inclusive']=left[side+'_inclusive'];continue
            c=order(a,b)
            if c is None:raise ValueError('Unknown VERS ordering')
            chosen=left if (c>0 if side=='lower' else c<0) else right
            out[side]=chosen[side]
            out[side+'_inclusive']=(left[side+'_inclusive'] and right[side+'_inclusive']) if c==0 else chosen[side+'_inclusive']
        if out['lower'] is not None and out['upper'] is not None:
            c=order(out['lower'],out['upper'])
            if c is None:raise ValueError('Unknown VERS ordering')
            if c>0 or (c==0 and not (out['lower_inclusive'] and out['upper_inclusive'])):return None
        return out

    def convert(node):
        op=node['op']
        if op=='unknown':raise ValueError('Unsupported VERS')
        if op=='any':return [_interval()]
        if op=='none':return []
        if op=='or':return [part for child in node['args'] for part in convert(child)]
        if op=='and':
            current=[_interval()]
            for child in node['args']:
                current=[part for left in current for right in convert(child) if (part:=intersection(left,right)) is not None]
                if len(current)>128:raise ValueError('Excessive VERS complexity')
            return current
        v=node['version']
        if op=='=':return [_interval(v,v,True,True)]
        if op=='!=':return [_interval(upper=v),_interval(lower=v)]
        if op in ('>','>='):return [_interval(lower=v,lower_inclusive=op=='>=')]
        if op in ('<','<='):return [_interval(upper=v,upper_inclusive=op=='<=')]
        raise ValueError('Unsupported VERS operator')

    try:intervals=convert(predicate)
    except (ValueError,KeyError):return None
    # An empty or contradictory declaration is missing evidence, not a negative.
    if not intervals or len(intervals)>128:return None
    result={'raw':raw,'scheme':scheme,'intervals':intervals}
    if len(intervals)==1:result.update(intervals[0])
    return result
