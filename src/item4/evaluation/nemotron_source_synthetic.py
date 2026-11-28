"""Frozen synthetic oracle for the native Nemotron source-condition contract.

No C1-C7 type labels are invented for its AV/AC/AT/PR/UI/OTHER schema.
Negative state atoms are evaluated against the same positive-world variables.
This is controlled source reading, not real-world exploitability accuracy.
"""
import re
from src.item4.evaluation import metamorphic_synthetic as E

VERSION = 'nemotron-native-source-oracle/2'


def state_polarity(text,kind):
    """Conservative, explicit assertion grammar; unparsed wording is not a pass.

    Negation is resolved before positive words. Mere mention of a permission
    does not assert that anyone holds it. This is not a universal NLI oracle.
    """
    s=E.textnorm(text)
    if re.search(r'\b(unknown|unspecified|unclear|uncertain|maybe|possibly)\b',s):return None
    if re.search(r'\b(not required|not necessary|not needed|unnecessary|optional|no authentication|without authentication|unauthenticated|no credentials|no user interaction|no user action)\b',s):return False if kind=='C4' else None
    if re.search(r'\b(has|have|holds|possesses) (no|zero)\b|\b(does not have|do not have|lacks|not authorized|not permitted|not allowed|unauthorized|denied|without permissions?|no permissions?|no privileges?)\b',s):return False
    if re.search(r'\b(not disabled|not inactive|not unavailable|not unreachable|not off)\b',s):return True
    if re.search(r'\b(disable|disabled|inactive|unavailable|unreachable|inaccessible|blocked|absent|stopped|closed|uninstalled|off|not enabled|not active|not available|not reachable|not accessible|not present|does not open|do not open|not opened|not running|not installed)\b',s):return False
    if re.search(r'\b(no|not|never|without)\b',s):return None
    patterns={
        'C1':r'\b(enable|enabled|switched on|turned on|running|installed|on)\b',
        'C7':r'\b(active|activated|enabled|maintenance|recovery)\b',
        'C2':r'\b(available|accessible|present|enabled|listening|running)\b',
        'C3':r'\b(reachable|accessible|access|connect|connected|connectivity|route)\b',
        'C4':r'\b(required|necessary|authenticated|needed)\b',
        'C5':r'\b(has|have|holds|possesses|authorized|permitted|granted|allowed|required)\b',
        'C6':r'\b(open|opens|opened|opening|import|imports|imported|upload|uploads|load|loads|loaded|click|clicks|clicked|export|exports|exported|select|selects|selected|insert|inserts|inserted)\b'}
    return True if re.search(patterns[kind],s) else None


def relation_quote_valid(quote,passage,targets):
    if not quote or quote not in passage:return False
    text=E.textnorm(quote)
    if not all(E.textnorm(t) in text for t in targets):return False
    return bool(re.search(r'\b(requires?|required|necessary|only|must|both|either|and|or|unless|provided|when|if|until|cannot|needs?|without)\b',text))


def judge(case, prediction, valid=True):
    prediction=prediction or {};gold=case['gold'];found=set();mapping={};fp=0;citations=True
    passages={'S'+str(i):s['text'] for i,s in enumerate(case['record']['sources'])}
    ids=[a.get('id') for a in prediction.get('conditions',[])]
    duplicate=len(ids)!=len(set(ids))
    nr=[]
    for atom in prediction.get('conditions',[]):
        necessity=atom.get('necessity')
        if necessity=='nonrequirement':nr.append(atom);continue
        if necessity!='required':continue
        wording=E.textnorm(atom.get('target','')+' '+atom.get('state',''))
        state=E.textnorm(atom.get('state',''))
        matches=[k for k,g in gold['atoms'].items() if E.textnorm(g['target']) in wording]
        key=matches[0] if len(matches)==1 else None
        polarity=state_polarity(state,gold['atoms'][key]['category']) if key else None
        negative=polarity is False
        meaning_ok=False
        if key:
            g=gold['atoms'][key];cat=g['category']
            if cat=='C1':meaning_ok=bool(re.search(r'\b(enabled|disabled)\b',state))
            elif cat=='C7':meaning_ok=bool(re.search(r'\b(active|inactive|activated|enabled|disabled)\b',state))
            elif cat=='C2':meaning_ok=bool(re.search(r'\b(available|unavailable|accessible|present|enabled)\b',state))
            elif cat=='C4':meaning_ok='authenticat' in wording and bool(re.search(r'\b(required|necessary|authenticated)\b',state))
            elif cat=='C5':meaning_ok=bool(re.search(r'\bassessed (principal|actor)\b',wording)) and bool(re.search(r'\b(has|holds|possesses|authorized|permitted|lacks)\b',state))
            elif cat=='C6':meaning_ok=atom.get('actor')=='victim' and bool(re.search(r'\b(open|opens|opened|opening)\b',state))
            elif cat=='C3':meaning_ok=bool(re.search(r'\bassessed (origin|source|starting point)\b',wording)) and bool(re.search(r'\b(reachable|unreachable|accessible)\b',state))
        # Only the explicitly negated feature family has a negative gold state.
        if key is None or key in found or not meaning_ok or polarity is None or (negative and case['family']!=4):
            fp+=1;mapping[atom.get('id')]=E.leaf('extra:'+str(fp));continue
        found.add(key);mapping[atom['id']]=E.node('not',E.leaf(key)) if negative else E.leaf(key)
        quote=atom.get('quote','');source=atom.get('source')
        expected_span=gold['atoms'][key]['negative' if negative else 'positive']
        citations &= bool(quote) and source in passages and quote in passages[source] and len(quote.split())<=25 and E.textnorm(expected_span) in E.textnorm(quote)
    branches=[];relation_valid=True
    for scenario in prediction.get('scenarios',[]):
        keys=scenario.get('conditions',[]);quote=scenario.get('quote','');source=scenario.get('source')
        referenced={x['condition'] if 'condition' in x else x['args'][0]['condition'] for i in keys for x in [mapping.get(i,{})] if x}
        required_targets=[gold['atoms'][k]['target'] for k in referenced if k in gold['atoms']]
        relation_valid &= bool(keys) and source in passages and relation_quote_valid(quote,passages.get(source,''),required_targets)
        if not keys or any(k not in mapping for k in keys):relation_valid=False;continue
        parts=[mapping[k] for k in keys]
        branches.append(parts[0] if len(parts)==1 else E.node('and',*parts))
    expression=branches[0] if len(branches)==1 else E.node('or',*branches) if branches else None
    logic=valid and not duplicate and not fp and found==set(gold['atoms']) and relation_valid and E.equivalent(expression,gold['expression'],sorted(found))
    nr_ok=bool(nr)==bool(gold['nonrequirements']) and all('authenticat' in E.textnorm(a.get('target','')+' '+a.get('state','')) and state_polarity(a.get('state',''),'C4') is False and a.get('quote','') in passages.get(a.get('source'),'') and bool(a.get('quote')) and state_polarity(a.get('quote',''),'C4') is False for a in nr)
    unknown_ok=not gold['require_unknown'] or prediction.get('unknowns_ko') in ('scope','relation','unspecified')
    return dict(tp=len(found),fp=fp,fn=len(gold['atoms'])-len(found),valid=valid,
        atom_exact=valid and not fp and found==set(gold['atoms']),logic_correct=bool(logic),
        evidence_correct=bool(valid and citations),nonrequirement_correct=bool(valid and nr_ok),
        unknown_correct=bool(valid and unknown_ok),case_correct=bool(logic and citations and nr_ok and unknown_ok),
        expected_atoms=len(gold['atoms']),admitted_tp=len(found),found=sorted(found),expression=expression)


def summarize(cases,rows,synthetic_only=False):
    # Reuse cohort/MR aggregation only, with this contract's frozen native judge.
    from unittest.mock import patch
    converted=[dict(r,draft=r.get('prediction')) for r in rows]
    with patch.object(E,'judge',judge):report=E.summarize(cases,converted)
    if synthetic_only:
        for score in report['scores'].values():
            score['above_90']=all(v is not None and v>.9 for v in (score['precision'],score['recall'],score['f1'],score['logic_accuracy'],score['case_accuracy']))
        report['evaluation']='Synthetic GT correctness only; metamorphic robustness is not a selection metric.'
    report.update(oracle=VERSION,scope='Native Nemotron source-condition schema, deterministic fictional source worlds; no Qwen score or real-CVE accuracy claim.')
    return report
