"""Conservative predeclared fact/negation/evidence/logic scorer for sealed GT.

    Unrecognized paraphrases fail automatic matching and are reported; no
    post-test synonym edits are allowed. This is not a general NLI model.
"""
import re
from collections import Counter
from src.item4.evaluation import metamorphic_synthetic as E
from src.item4.evaluation.nemotron_source_synthetic import state_polarity

VERSION='sealed-source-gt/1'


def contains(text,phrase):
    return (' '+E.textnorm(phrase)+' ') in (' '+E.textnorm(text)+' ')


def cited(quote,passages,fact):
    if not quote or quote not in passages.get(fact['source'],''):return False
    # Each span was annotated with the source before model inference. A header,
    # merely matching target, or unrelated state cannot substitute for a span.
    return len(quote.split())<=25 and any(contains(quote,s) for s in fact['evidence'])


def fact_match(atom,fact):
    wording=atom.get('target','')+' '+atom.get('state','')
    return (atom.get('necessity')==fact['necessity']
        and any(contains(wording,a) for a in fact['aliases'])
        and all(any(contains(wording,a) for a in group) for group in fact.get('qualifiers',[]))
        and (not fact.get('state_terms') or any(contains(atom.get('state',''),v) for v in fact['state_terms']))
        and (not fact.get('actor') or atom.get('actor')==fact['actor'])
        and state_polarity(atom.get('state',''),'C4' if fact['necessity']=='nonrequirement' else fact['kind']) is fact['polarity'])


def judge(case,prediction,valid=True):
    p=prediction or {};g=case['gold'];facts=g['facts'];passages=case['passages'];found=set();mapping={};counts=Counter();errors=[]
    atoms=p.get('conditions',[]);ids=[a.get('id') for a in atoms];duplicate=len(ids)!=len(set(ids))
    claim_good=0
    for a in atoms:
        matches=[f for f in facts if fact_match(a,f)]
        key=matches[0]['id'] if len(matches)==1 else None
        source_ok=len(matches)==1 and a.get('source')==matches[0]['source']
        grounded=source_ok and cited(a.get('quote',''),passages,matches[0])
        if key is None or key in found:
            if a.get('necessity')=='required':counts['fp']+=1
            errors.append(dict(id=a.get('id'),reason='unmatched_or_duplicate_fact',target=a.get('target'),state=a.get('state')));continue
        f=matches[0];found.add(key);claim_good+=grounded
        if not grounded:errors.append(dict(id=a.get('id'),reason='unsupported_atom_quote'))
        if f['necessity']=='required':
            counts['tp']+=1;mapping[a['id']]=E.leaf(key) if f['polarity'] else E.node('not',E.leaf(key))
    expected={f['id'] for f in facts if f['necessity']=='required'};counts['fn']=len(expected-found)
    expected_nr={f['id'] for f in facts if f['necessity']=='nonrequirement'};nr_ok=expected_nr<=found and not any(a.get('necessity')=='nonrequirement' and not any(fact_match(a,f) for f in facts) for a in atoms)
    exprs=[];relations_ok=True;scenario_ids=[]
    for s in p.get('scenarios',[]):
        keys=s.get('conditions',[]);scenario_ids.append(s.get('id'))
        if not keys or len(keys)!=len(set(keys)) or any(k not in mapping for k in keys):relations_ok=False;continue
        terms=[mapping[k] for k in keys];exprs.append(terms[0] if len(terms)==1 else E.node('and',*terms))
        mapped={t['condition'] if 'condition' in t else t['args'][0]['condition'] for t in terms}
        options=[b for b in g['branches'] if set(b['facts'])==mapped]
        q=s.get('quote','');source=s.get('source')
        supported=bool(q) and q in passages.get(source,'') and any(source==b['source'] and any(contains(q,span) for span in b['evidence']) for b in options)
        relations_ok &= supported
        if not supported:errors.append(dict(id=s.get('id'),reason='unsupported_relation_quote_or_branch'))
    duplicate |= len(scenario_ids)!=len(set(scenario_ids))
    predicted=exprs[0] if len(exprs)==1 else E.node('or',*exprs) if exprs else None
    logic_ok=valid and not duplicate and not counts['fp'] and expected<=found and E.equivalent(predicted,g['expression'],sorted(expected))
    unknown_ok=p.get('unknowns_ko') in g.get('allowed_uncertainty',['none','scope','relation','unspecified'])
    evidence_ok=valid and claim_good==len(atoms) and relations_ok
    correct=bool(logic_ok and evidence_ok and nr_ok and unknown_ok and not errors)
    return dict(counts,correct=correct,logic_correct=bool(logic_ok),evidence_correct=bool(evidence_ok),nonrequirement_correct=bool(nr_ok),
        uncertainty_correct=unknown_ok,found=sorted(found),expected_required=len(expected),claim_count=len(atoms),grounded_claims=claim_good,
        relation_count=len(p.get('scenarios',[])),relation_grounding_correct=bool(relations_ok),valid=valid,errors=errors)


def summarize(cases,rows):
    byid={r['id']:r for r in rows};counts=Counter();failures=[];families={}
    for c in cases:
        row=byid.get(c['id'],{});j=judge(c,row.get('prediction'),row.get('valid',False))
        for k in ('tp','fp','fn','correct','logic_correct','evidence_correct','nonrequirement_correct','valid','claim_count','grounded_claims'):counts[k]+=j.get(k,0)
        families.setdefault(c['challenge'],Counter()).update(cases=1,correct=j['correct'])
        if not j['correct']:failures.append(dict(id=c['id'],challenge=c['challenge'],judgement=j,error=row.get('error')))
    tp,fp,fn=counts['tp'],counts['fp'],counts['fn'];n=len(cases)
    metrics=dict(precision=tp/(tp+fp) if tp+fp else 0,recall=tp/(tp+fn) if tp+fn else 0,f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0,
        logic_accuracy=counts['logic_correct']/n,evidence_contract_accuracy=counts['evidence_correct']/n,requirement_contract_accuracy=counts['correct']/n)
    return dict(version=VERSION,cases=n,predictions_present=len(byid),counts=dict(counts),metrics=metrics,
        above_90=all(v>.9 for v in metrics.values()),families={k:dict(v) for k,v in families.items()},failures=failures,
        excluded_fields=['CVSS axis classification','self-reported complete flag'],
        interpretation='Strict predeclared automatic matching; unparsed paraphrases are failures, not proof that their semantics are wrong. No post-test label or alias changes.')
