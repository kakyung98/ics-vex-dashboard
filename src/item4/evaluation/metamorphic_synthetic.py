"""Deterministic, source-bounded extraction benchmark, independent of model output.

This oracle describes fictional source requirements, never real exploitability.
Production extraction is imported only by the runner, not by the generator.
"""
from copy import deepcopy
from collections import Counter, defaultdict
from itertools import product
import hashlib
import json
import re

VERSION = 'item4-metamorphic-synthetic/1'
VARIANTS = ('reorder', 'irrelevant', 'rename', 'equivalent', 'remove_evidence')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def textnorm(value):
    return ' '.join(re.findall(r'[a-z0-9]+', value.casefold()))


def leaf(name): return {'condition': name}
def node(op, *args): return {'op': op, 'args': list(args)}


def make_case(family, index, variant='original'):
    """Split families of source worlds before deriving any related variants."""
    serial=family*40+index
    split='dev' if index<8 else 'test'
    tag=('Cedar' if variant=='rename' else 'Aster')+str(serial)
    definitions={
        'a': dict(category='C1',predicates=['feature_enabled'],target=tag+' feature',
                  positive=tag+' feature is enabled',negative=tag+' feature is disabled'),
        'b': dict(category='C7',predicates=['configuration_required'],target=tag+' mode',
                  positive=tag+' mode is active',negative=tag+' mode is inactive'),
        'c': dict(category='C2',predicates=['interface_available'],target=tag+' WebUI',
                  positive=tag+' WebUI input is available',negative=tag+' WebUI input is unavailable'),
    }
    extra={
        8:dict(category='C4',predicates=['authentication_required'],target=tag+' account',positive='authentication for '+tag+' account is required',negative='authentication for '+tag+' account is not required'),
        9:dict(category='C5',predicates=['privilege_required'],target=tag+' operation',positive='the assessed principal has permission to perform '+tag+' operation',negative='the assessed principal lacks permission to perform '+tag+' operation'),
        10:dict(category='C6',predicates=['user_performs_action','file_import'],target=tag+' project',positive='a user opens '+tag+' project',negative='a user does not open '+tag+' project'),
        11:dict(category='C3',predicates=['interface_reachable','network_reachable'],target=tag+' interface',positive=tag+' interface is reachable from the assessed origin',negative=tag+' interface is unreachable from the assessed origin'),
    }
    if family in extra:definitions['a']=extra[family]
    specs={
        0: (['a'],leaf('a')),
        1: (['a','b'],node('and',leaf('a'),leaf('b'))),
        2: (['a','b'],node('or',leaf('a'),leaf('b'))),
        3: (['a','b','c'],node('and',leaf('a'),node('or',leaf('b'),leaf('c')))),
        4: (['a'],node('not',leaf('a'))),
        5: ([],None),
        6: (['c'],leaf('c')),
        7: (['a','b'],node('and',leaf('a'),leaf('b'))),
        8: (['a'],leaf('a')),9: (['a'],leaf('a')),10: (['a'],leaf('a')),11: (['a'],leaf('a')),
    }
    wanted,expression=deepcopy(specs[family])
    # Two disjoint renderers: templates used in TEST never appear in DEV.
    def render(expr):
        if 'condition' in expr:return definitions[expr['condition']]['positive']
        if expr['op']=='not':return definitions[expr['args'][0]['condition']]['negative']
        parts=[render(x) for x in expr['args']]
        if expr['op']=='and':return ('both ('+' and '.join(parts)+')') if split=='dev' else ('all of the following: ('+'; and '.join(parts)+')')
        return ('at least one of ('+' or '.join(parts)+')') if split=='dev' else ('either ('+') or ('.join(parts)+'), including the case where both hold')
    expression_text=render(expression) if expression else None
    if variant=='equivalent' and expression:
        if expression.get('op') in ('and','or'):
            expression_text=render(dict(expression,args=list(reversed(expression['args']))))
        elif family==4:expression_text='it is not the case that '+definitions['a']['positive']
        else:expression_text='it is not the case that it is not the case that '+expression_text
    prefix=('The described attack path requires that ' if split=='dev' else 'For this described attack path, it is necessary that ')
    requirement=prefix+expression_text+'.' if expression else None
    if variant=='remove_evidence':
        wanted=[];expression=None;requirement=None
    paragraphs=[x for x in [requirement] if x]
    nonrequirements=[]
    if family==6:
        paragraphs.append('Authentication is not required for this described path.')
        nonrequirements=['authentication']
    if family==5 or variant=='remove_evidence':
        paragraphs.append(('A buffer overflow can cause a crash. Operational prerequisites are not specified.' if split=='dev' else 'A crash may result from a buffer overflow. The report does not state any operating prerequisites.'))
    if family==7:
        paragraphs.append('Installing the vendor update is recommended. This recommendation does not describe a prerequisite.')
    if variant=='irrelevant':
        paragraphs += ['The advisory was published on Tuesday. A successful attack can disrupt service. The vendor recommends installing an update.']
    if variant=='reorder':
        paragraphs=list(reversed(paragraphs))
        # Order changes must affect every nonempty source, including singleton paragraphs.
        paragraphs.insert(0,'The following text describes a fictional vulnerability.')
    text='Affected component: '+tag+' controller.\n\n'+'\n\n'.join(paragraphs)
    cve='CVE-2099-'+str(10000+serial)
    sid='synthetic:'+cve
    record=dict(cve=cve,products=[],sources=[dict(id=sid,text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        url='urn:ics-vex:synthetic:'+str(serial),product_keys=[],scope_binding='unresolved')])
    gold=dict(atoms={k:definitions[k] for k in wanted},expression=expression,nonrequirements=nonrequirements,
              require_unknown=not wanted,evidence_quotes=[requirement] if requirement else [])
    return dict(id=f'f{family}-{index:02d}__{variant}',base_id=f'f{family}-{index:02d}',family=family,split=split,
                variant=variant,synthetic=True,record=record,gold=gold)


def dataset():
    rows=[]
    for family in range(12):
        for index in range(32):
            rows.append(make_case(family,index))
            if index%8==0:rows.extend(make_case(family,index,v) for v in VARIANTS)
    return rows


def state(expr,values):
    if expr is None:return None
    if 'condition' in expr:return values[expr['condition']]
    args=[state(x,values) for x in expr['args']]
    if expr['op']=='not':return None if args[0] is None else not args[0]
    if expr['op']=='and':return False if False in args else None if None in args else True
    if expr['op']=='or':return True if True in args else None if None in args else False
    raise ValueError('Unknown Boolean operator')


def equivalent(left,right,variables):
    if left is None or right is None:return left is None and right is None
    try:
        return all(state(left,dict(zip(variables,v)))==state(right,dict(zip(variables,v)))
                   for v in product((True,False,None),repeat=len(variables)))
    except (KeyError,TypeError,ValueError):
        # Hallucinated/unmapped variables are failures, not reasons to stop or
        # remove the case from an MR denominator.
        return False


def judge(case,draft,*,valid=True):
    """Strict unique atom matching; citations cannot provide missing atom meaning.

    Match predicate/category plus the entire named synthetic target appearing in
    the generated target or statement. This finite naming contract is frozen
    before any prediction; unsupported and duplicate atoms are false positives.
    """
    gold=case['gold'];found=set();mapping={};fp=0;evidence_ok=True;admitted=set()
    atoms=(draft or {}).get('prerequisites',[])
    for p in atoms:
        def predicate_matches(g):
            if p.get('predicate') in g['predicates']:return True
            # Both registered C1 predicates can express the identical enabled
            # variable. Accept this alias only with explicit enabled wording.
            return (g['predicates']==['feature_enabled'] and p.get('predicate')=='configuration_required'
                and p.get('category')=='C1' and bool(re.search(r'\benabled\b',p.get('statement','')+' '+p.get('value',''),re.I)))
        candidates=[k for k,g in gold['atoms'].items() if
            predicate_matches(g) and p.get('category')==g['category'] and
            textnorm(g['target']) in textnorm(p.get('target','')+' '+p.get('statement',''))]
        key=candidates[0] if len(candidates)==1 else None
        # A target mention alone cannot turn an unknown/negative answer into a positive atom.
        wording=(p.get('statement','')+' '+p.get('value','')).casefold()
        positive=not re.search(r'\b(disabled|inactive|unavailable|unknown|not enabled|not active|not available)\b',wording)
        scope_ok=True
        if key:
            meaning=gold['atoms'][key]['positive'].casefold()
            if gold['atoms'][key]['predicates']==['feature_enabled']:
                scope_ok &= bool(re.search(r'\benabled\b',wording))
            if 'assessed principal' in meaning:
                scope_ok &= bool(re.search(r'\bassessed\s+(?:principal|actor)\b',wording))
                scope_ok &= bool(re.search(r'\b(?:has|holds|possesses|authorized|permitted)\b',wording))
            if 'assessed origin' in meaning:
                scope_ok &= bool(re.search(r'\b(?:assessed\s+(?:origin|starting point|source)|assessment\s+origin)\b',wording))
            if gold['atoms'][key]['category']=='C7':
                scope_ok &= bool(re.search(r'\b(?:active|activated|enabled)\b',wording))
            if 'a user opens' in meaning:
                scope_ok &= bool(re.search(r'\b(?:opens?|opened|opening)\b',wording))
        if key is None or key in found or not positive or not scope_ok or p.get('operator')!='eq' or p.get('expected') is not True:
            fp+=1;mapping[p.get('id')]='extra:'+str(fp);continue
        found.add(key);mapping[p['id']]=key
        if type(p.get('extraction_confidence')) in (float,int) and p['extraction_confidence']>0.8 and p.get('review_status')!='rejected':admitted.add(key)
        refs=p.get('source_refs',[]);quote=p.get('operational_quote','')
        evidence_ok &= bool(quote) and any(r.get('source_id')==s['id'] and
            s['text'].count(r.get('quote',''))==1 and quote in r.get('quote','') and
            any(textnorm(gold['atoms'][key]['target']) in textnorm(q) for q in [quote])
            for r in refs for s in case['record']['sources'])
    def convert(expr):
        if 'condition' in expr:return leaf(mapping[expr['condition']])
        return node(expr['op'],*[convert(x) for x in expr['args']])
    try:
        expressions=[convert(s['expression']) for s in (draft or {}).get('scenarios',[])]
        predicted=expressions[0] if len(expressions)==1 else node('or',*expressions) if expressions else None
        logic_ok=valid and fp==0 and found==set(gold['atoms']) and equivalent(predicted,gold['expression'],sorted(found))
    except (KeyError,TypeError,ValueError):predicted=None;logic_ok=False
    nr=(draft or {}).get('nonrequirements',[])
    nr_ok=bool(nr)==bool(gold['nonrequirements']) and (not nr or all(
        'authenticat' in n.get('statement','').casefold() and re.search(
            r'\b(?:not\s+(?:required|necessary|a prerequisite)|unnecessary|unauthenticated|without\s+authentication|no\s+(?:prior\s+)?authentication|do(?:es)?\s+not\s+require|optional)\b',n.get('statement',''),re.I)
        for n in nr))
    unknown_ok=not gold['require_unknown'] or bool((draft or {}).get('unknowns'))
    return dict(tp=len(found),fp=fp,fn=len(gold['atoms'])-len(found),valid=valid,
                atom_exact=valid and fp==0 and found==set(gold['atoms']),logic_correct=logic_ok,
                evidence_correct=valid and evidence_ok,nonrequirement_correct=valid and nr_ok,
                unknown_correct=valid and unknown_ok,admitted_tp=len(admitted),
                expected_atoms=len(gold['atoms']),found=sorted(found),expression=predicted,
                case_correct=logic_ok and evidence_ok and nr_ok and unknown_ok)


def summarize(cases,predictions):
    byid={c['id']:c for c in cases};groups=defaultdict(dict);scores={}
    for p in predictions:
        if p['id'] not in byid:raise ValueError('Prediction outside frozen dataset')
        key=(p['arm'],p.get('phase','baseline'))
        if p['id'] in groups[key]:raise ValueError('Duplicate prediction')
        groups[key][p['id']]=p
    for (arm,phase),rows in groups.items():
        for split in ('dev','test'):
            selected=[c for c in cases if c['split']==split]
            if not selected:continue
            # Missing predictions count as failures; never silently shrink denominators.
            results={c['id']:judge(c,(rows.get(c['id']) or {}).get('draft'),valid=(rows.get(c['id']) or {}).get('valid',False)) for c in selected}
            counts=Counter()
            family=defaultdict(Counter)
            for c in selected:
                r=results[c['id']]
                for k in ('tp','fp','fn','valid','atom_exact','logic_correct','evidence_correct','nonrequirement_correct','unknown_correct','admitted_tp','expected_atoms','case_correct'):
                    counts[k]+=r[k];family[str(c['family'])][k]+=r[k]
                family[str(c['family'])]['cases']+=1
            mr=defaultdict(Counter)
            for c in selected:
                if c['variant']=='original':continue
                original=results[c['base_id']+'__original'];changed=results[c['id']]
                # Check correctness as well as pair consistency: consistent emptiness cannot pass.
                ok=original['case_correct'] and changed['case_correct']
                mr[c['variant']]['total']+=1;mr[c['variant']]['passed']+=ok
                mr[c['variant']]['pair_valid']+=original['valid'] and changed['valid']
                if c['variant']!='remove_evidence':
                    mr[c['variant']]['structural_consistency']+=original['valid'] and changed['valid'] and original['found']==changed['found'] and equivalent(original['expression'],changed['expression'],sorted(set(original['found'])|set(changed['found'])))
            tp,fp,fn=counts['tp'],counts['fp'],counts['fn'];n=len(selected)
            total=sum(x['total'] for x in mr.values());passed=sum(x['passed'] for x in mr.values())
            f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
            scores[f'{phase}/{arm}/{split}']=dict(cases=n,predictions_present=sum(c['id'] in rows for c in selected),counts=dict(counts),
                precision=tp/(tp+fp) if tp+fp else None,recall=tp/(tp+fn) if tp+fn else None,f1=f1,
                logic_accuracy=counts['logic_correct']/n,case_accuracy=counts['case_correct']/n,
                valid_rate=counts['valid']/n,admitted_recall=counts['admitted_tp']/counts['expected_atoms'] if counts['expected_atoms'] else None,
                grounded_mr_rate=passed/total if total else None,mr={k:dict(v) for k,v in mr.items()},families={k:dict(v) for k,v in family.items()},
                above_90=all(x is not None and x>0.9 for x in (f1,counts['logic_correct']/n,passed/total if total else None)))
    return dict(version=VERSION,scores=scores,scope='Fictional bounded-source extraction; no real-asset exploitability or independent human accuracy claim.')
