"""Observed-condition closed patterns, not mined causal prerequisites."""
from collections import defaultdict
from itertools import combinations
import re

from .cluster_question_pipeline import digest,screen_candidate

VERSION='observed-condition-closed-patterns/6'


def canonical_atom(row):
    """Conservative exact-text normalization with narrowly explicit paraphrases.

    Values, negation, actor and kind survive. Unknown targets remain unresolved;
    these keys group review work and never authorize shared asset answers.
    """
    text=' '.join(row['condition'].casefold().split()).rstrip(' .')
    kind=row['kind'];name=text;rule='exact_normalized_text'
    if kind=='access_position':
        for phrase,label in [
            (r'(?:a |the )?(?:device|server|service|system) (?:is |can be )?accessible (?:over|via|through) (?:a |the )?network','network-accessible'),
            (r'(?:an? )?attacker (?:has|requires|needs) (?:direct )?physical access(?: to (?:the )?device)?','physical-access'),
            (r'(?:an? )?attacker (?:has|requires|needs) local access(?: to (?:the )?device)?','local-access')]:
            if re.fullmatch(phrase,text):name=label;rule='bounded_explicit_access_paraphrase';break
    # Do not collapse "authenticated user" with "authenticated attacker".
    if kind=='attacker_auth_or_privilege' and re.fullmatch(r'(?:an? )?authenticated attacker(?: is required(?: to exploit (?:the )?vulnerability)?)?',text):
        name='authenticated-attacker';rule='explicit_attacker_authentication'
    # Bounded grammatical variants only; actors, operation, format and modality
    # are retained in the key. "load", "parse" and "open" are not synonyms.
    if kind in {'input_or_ingress','trigger','user_action'}:
        match=re.fullmatch(r'(parsing|processing|loading|opening) (?:a |an |the )?(?:(?:specially|specifically|carefully) )?crafted (?:(.*?) )?files?',text)
        if match:
            operation={'parsing':'parse','processing':'process','loading':'load','opening':'open'}[match[1]]
            name=f'{operation}:crafted-file:format={match[2] or "unspecified"}'
            rule='explicit_file_operation_and_format'
        match=re.fullmatch(r'(?:an? )?(?:(remote|local) )?(attacker|user|victim) (can |is able to |must |needs to )?(sends?|provides?|supplies?) (?:a |an |the )?(?:(?:specially|specifically|carefully) )?crafted (?:(.*?) )?(packets?|files?)',text)
        if match:
            modality={'can ':'capability','is able to ':'capability','must ':'requirement','needs to ':'requirement',None:'stated_action'}[match[3]]
            operation={'send':'send','sends':'send','provide':'provide','provides':'provide','supply':'supply','supplies':'supply'}[match[4]]
            name=f'actor={match[2]};position={match[1] or "unspecified"};modality={modality};{operation}:crafted-{match[6].rstrip("s")}:type={match[5] or "unspecified"}'
            rule='explicit_actor_modality_and_input'
    if kind=='user_action' and re.fullmatch(r'user interaction is (?:required|needed)(?: for exploitation)?',text):
        name='user-interaction-required';rule='explicit_user_interaction_requirement'
    signature=dict(kind=kind,necessity=row['necessity'],proposition=name)
    return dict(id='atom:'+digest(signature)[:24],**signature,normalization_rule=rule,
                target_status='requires_cve_specific_resolution',semantic_status='unreviewed_candidate')


def mine(rows,population,min_cves=3,max_pair_seeds=50000,group_ids=None):
    if min_cves<2:raise ValueError('Common patterns require distinct CVEs')
    population=list(population)
    if len(set(population))!=len(population):raise ValueError('Duplicate population CVE')
    expected=set(population);atoms={};transactions=defaultdict(set);byatom=defaultdict(list);triage=[]
    if group_ids is not None and set(group_ids)!=expected:raise ValueError('Source groups must cover the exact population')
    for row in rows:
        if row['cve'] not in expected:raise ValueError('Condition outside population')
        check=screen_candidate(row)
        if re.search(r'(?i)\b(?:unspecified|not specified|not stated|unknown)\b',row['condition']):
            check['flags'].append('missing_specificity_is_not_an_operating_fact')
        if re.search(r'(?i)\bnot (?:explicitly )?mentioned\b|\bno specific .+\bmentioned\b',row['condition']):
            check['flags'].append('absence_of_source_information_is_not_a_condition')
        if re.search(r'(?i)\b(?:buffer (?:over|under)flow|sql injection|not properly validated|improper (?:input )?validation|lack of proper validation|invalid pointer|denial.of.service)\b',row['condition']):
            check['flags'].append('possible_weakness_or_consequence_instead_of_prerequisite')
        if re.search(r'(?i)\bcan (?:exploit (?:the )?vulnerability|inject arbitrary sql|perform a flooding attack)\b|\bcurrent process context\b|\bcontext of (?:the )?current process\b|\b(?:all services|access) .+without authori[sz]ation\b',row['condition']):
            check['flags'].append('possible_attack_capability_or_execution_context_needs_review')
        if re.search(r'(?i)\b(?:authentication|privileges?) (?:is |are )?not required\b|\bno (?:specific )?(?:attacker )?(?:authentication|privileges?)',row['condition']):
            check['flags'].append('source_nonrequirement_needs_review_not_positive_prerequisite')
        triage.append(check)
        if check['flags']:continue
        atom=canonical_atom(row);aid=atom['id'];atoms[aid]=atom
        transactions[row['cve']].add(aid)
        byatom[aid].append(dict(cve=row['cve'],condition_id=row['condition_id'],condition=row['condition'],
            source_id=row['source_id'],source_span=row['source_span'],source_quote=row['source_quote']))
    extents={aid:{r['cve'] for r in members} for aid,members in byatom.items()}
    frequent={a:cs for a,cs in extents.items() if len(cs)>=min_cves}
    patterns={};seeds=0
    def close(extent):
        intent=set.intersection(*(transactions[c] for c in extent))
        key=tuple(sorted(intent))
        if key not in patterns:
            patterns[key]=dict(id='pattern:'+digest(key)[:24],atom_ids=list(key),cves=sorted(extent),
                support_count=len(extent),observed_support=len(extent)/max(1,len(transactions)),
                source_group_count=len({group_ids[c] for c in extent}) if group_ids is not None else None,
                population_observation_coverage=len(extent)/max(1,len(population)),
                closed_in_observed_transactions=True,necessity_inferred=False,formula_inferred=False)
    for extent in frequent.values():close(extent)
    # Enumerate only co-occurring pair seeds, not all pairs of vocabulary entries.
    pairs=set()
    for transaction in transactions.values():
        for pair in combinations(sorted(transaction & frequent.keys()),2):pairs.add(pair)
    truncated=False
    for a,b in sorted(pairs):
        if seeds>=max_pair_seeds:truncated=True;break
        seeds+=1;extent=frequent[a]&frequent[b]
        if len(extent)>=min_cves:close(extent)
    common=[]
    for aid,extent in sorted(frequent.items()):
        members=byatom[aid];proposition=atoms[aid]['proposition']
        common.append(dict(id='template:'+aid.split(':')[1],atom_id=aid,support_count=len(extent),
            source_group_count=len({group_ids[c] for c in extent}) if group_ids is not None else None,
            cves=sorted(extent),proposition=proposition,
            text='이 자산에서 원문에 명시된 조건이 성립합니까? '+members[0]['condition'],
            target=None,answer_type='yes_no_unknown',executable=False,
            required_review=['source meaning','specific target','answer implications','route necessity'],
            representative_sources=members[:3]))
    common_byatom={q['atom_id']:q['id'] for q in common}
    cves=[]
    for cve in population:
        observed=transactions.get(cve,set())
        cves.append(dict(cve=cve,atom_ids=sorted(observed),excluded=False,
            common_template_ids=sorted(common_byatom[a] for a in observed if a in common_byatom),
            specific_atom_ids=sorted(a for a in observed if a not in common_byatom),
            state='observed_candidates' if observed else 'conditions_unknown_or_flagged',
            formula=None,formula_status='must_come_from_source_review_not_cooccurrence'))
    catalog=[dict(atom,distinct_cves=len(extents[aid]),occurrences=len(byatom[aid]),
                  proposed_question='이 자산에서 다음 조건이 성립합니까? '+byatom[aid][0]['condition'],
                  sources=byatom[aid]) for aid,atom in sorted(atoms.items())]
    ranked=sorted(patterns.values(),key=lambda p:(-len(p['atom_ids']),-p['support_count'],p['id']))
    unique_occurrences=sum(len(t) for t in transactions.values())
    summary=dict(method=VERSION,population=len(population),input_condition_occurrences=len(rows),
        source_groups=len(set(group_ids.values())) if group_ids is not None else None,
        flagged_occurrences=sum(bool(r['flags']) for r in triage),candidate_atoms=len(atoms),
        cves_with_usable_candidates=len(transactions),common_question_templates=len(common),
        closed_observed_patterns=len(ranked),pair_seeds_evaluated=seeds,pair_search_truncated=truncated,
        enumeration_scope='Closures of frequent singleton and co-occurring pair seeds; not all possible closed itemsets',
        min_distinct_cves=min_cves,observed_denominator=len(transactions),
        common_question_occurrences=sum(len(c['common_template_ids']) for c in cves),
        specific_question_occurrences=sum(len(c['specific_atom_ids']) for c in cves),
        within_cve_duplicate_occurrences=len(rows)-sum(bool(r['flags']) for r in triage)-unique_occurrences,
        independent_semantic_accuracy=None,automatic_approvals=0)
    return dict(summary=summary,atoms=catalog,patterns=ranked,common_questions=common,cves=cves,triage=triage)
