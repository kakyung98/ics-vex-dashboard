"""Lossless identity normalization; never infer semantic similarity or new facts."""
from copy import deepcopy
import json

VERSION='exact-duplicate-source-atoms/1'


def normalize(value):
    out=deepcopy(value)
    if not isinstance(out,dict) or not isinstance(out.get('prerequisites'),list):return out,[]
    ids=[a.get('id') for a in out['prerequisites'] if isinstance(a,dict)]
    if len(ids)!=len(out['prerequisites']) or any(not isinstance(i,str) for i in ids) or len(set(ids))!=len(ids):return out,[]
    if any('condition_id' in a and a['condition_id']!=a.get('id') for a in out['prerequisites']):return out,[]
    seen={};aliases={};kept=[]
    for atom in out['prerequisites']:
        if not isinstance(atom,dict) or not isinstance(atom.get('id'),str):return out,[]
        signature=json.dumps({k:v for k,v in atom.items() if k not in ('id','condition_id')},sort_keys=True,ensure_ascii=False)
        if signature in seen:aliases[atom['id']]=seen[signature]
        else:seen[signature]=atom['id'];kept.append(atom)
    if not aliases:return out,[]
    def rewrite(expr):
        if not isinstance(expr,dict):return expr
        if 'condition' in expr:
            if not isinstance(expr['condition'],str):return expr
            return dict(expr,condition=aliases.get(expr['condition'],expr['condition']))
        if isinstance(expr.get('args'),list):return dict(expr,args=[rewrite(a) for a in expr['args']])
        return expr
    out['prerequisites']=kept
    for scenario in out.get('scenarios',[]):
        if isinstance(scenario,dict) and 'expression' in scenario:scenario['expression']=rewrite(scenario['expression'])
    return out,[dict(version=VERSION,aliases=aliases,policy='All fields except identity must be byte-equivalent after JSON key ordering; formula operators and unknowns unchanged.')]
