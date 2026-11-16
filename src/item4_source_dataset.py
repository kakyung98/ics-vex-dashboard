"""Source checks and train-only question reuse for the frozen K=25 corpus.

Grounding is a reproducible automated check, never an expert semantic approval.
Question templates share wording; answers remain bound to each CVE/asset/context.
"""
import hashlib,itertools,json,re
from collections import defaultdict


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()


def norm(text):return ' '.join(text.casefold().split())


def leaf_ids(expr):
    if expr is None:return set()
    if 'condition' in expr:return {expr['condition']}
    return set().union(*(leaf_ids(c) for c in expr['args']))


def source_check(ref,sources):
    source=sources.get(ref.get('source_id'))
    if source is None:return False
    a,b=ref.get('span',[-1,-1])
    return (hashlib.sha256(source['text'].encode()).hexdigest()==source['text_sha256']
        and 0<=a<b<=len(source['text']) and source['text'][a:b]==ref.get('quote'))


def operator_count(expr):
    if expr is None or 'condition' in expr:return {}
    counts={expr['op']:1}
    for child in expr['args']:
        for k,v in operator_count(child).items():counts[k]=counts.get(k,0)+v
    return counts


def independent_truth_table(expr):
    """Native Boolean enumeration, independent of the tri-valued label oracle."""
    if expr is None:return []
    ids=sorted(leaf_ids(expr))
    def run(n,values):
        if 'condition' in n:return values[n['condition']]
        xs=[run(c,values) for c in n['args']]
        if n['op']=='not':
            if len(xs)!=1:raise ValueError('NOT arity')
            return not xs[0]
        if n['op']=='and':return all(xs)
        if n['op']=='or':return any(xs)
        raise ValueError('Unknown operator')
    return [dict(values=dict(zip(ids,values)),expected=run(expr,dict(zip(ids,values))))
        for values in itertools.product((False,True),repeat=len(ids))]


def align_cluster(condition,clause,candidates):
    """Link an atom to an existing frozen candidate; never assign a new cluster."""
    ref=condition['source_ref'];a,b=ref['span'];scored=[]
    atom=set(re.findall(r'\w+',condition['proposition'].casefold()))
    for c in candidates:
        if c['source_id']!=ref['source_id']:continue
        x,y=c['source_span']
        if max(a,x)>=min(b,y):continue
        words=set(re.findall(r'\w+',c['condition'].casefold()))
        shared=len(atom&words);similarity=shared/max(1,len(atom|words))
        if shared<2:continue
        scored.append((similarity,min(b,y)-max(a,x),-c['index'],c))
    if not scored:return None
    score,overlap,_,best=max(scored,key=lambda x:x[:3])
    return dict(cluster_id=best['cluster_id'],candidate_id=best['condition_id'],
        lexical_jaccard=score,overlap_characters=overlap,semantic_equivalence_reviewed=False)


def extract_record(record,inference,candidates):
    sources={s['id']:s for s in record['sources']};options=[];rejected=[]
    for passage in inference['passages']:
        byid={c['id']:c for c in passage['conditions']}
        for h in passage['hypotheses']:
            reason=[];ids=leaf_ids(h['expression']);conditions=[byid[i] for i in sorted(ids) if i in byid]
            refs=[h['source_ref'],h['cue']]+[c['source_ref'] for c in conditions]
            if len(conditions)!=len(ids):reason.append('unbound_formula_leaf')
            if not all(source_check(r,sources) for r in refs):reason.append('source_span_or_hash_mismatch')
            if h['scope_ambiguous']:reason.append('ambiguous_connective_attachment')
            if not 1<=len(ids)<=5:reason.append('retained_in_ledger_outside_prompt_atom_budget')
            if len(h['source_ref']['quote'])>650:reason.append('retained_in_ledger_outside_prompt_clause_budget')
            for c in conditions:
                text=c['proposition']
                if len(text)>180:reason.append('retained_in_ledger_outside_prompt_atom_text_budget')
                if re.search(r'\b(?:not (?:explicitly )?mentioned|unspecified|not specified)\b',text,re.I):reason.append('absence_of_statement_is_not_condition')
                if re.search(r'\b(?:could|may|would|exploited|leading to|causing|allows?|arbitrary (?:code|OS command)|remote code execution|denial.of.service)\b',text,re.I):
                    reason.append('consequence_or_unresolved_clause_mixed_with_prerequisite')
                if re.search(r'\bcan\s+(?:execute|gain|obtain|cause|crash|inject|compromise)\b',text,re.I):
                    reason.append('consequence_or_capability_requires_semantic_review')
                if not c.get('scope_inheritance') and len(re.findall(r'\w+',text))<2:reason.append('unresolved_fragment')
            if reason:
                rejected.append(dict(source_ref=h['source_ref'],expression=h['expression'],reasons=sorted(set(reason))));continue
            selected=[]
            for i,c in enumerate(conditions):
                binding=align_cluster(c,h['source_ref'],candidates)
                # Keep both the positive predicate and its original negated anchor.
                # Context is mandatory for inherited objects and shared qualifiers.
                selected.append(dict(id='P'+str(i+1),original_id=c['id'],proposition=c['proposition'],
                    inheritance=c.get('scope_inheritance'),source_ref=c['source_ref'],cluster_binding=binding,
                    context_ref=h['source_ref']))
            mapping={c['original_id']:c['id'] for c in selected}
            def remap(n):return {'condition':mapping[n['condition']]} if 'condition' in n else dict(op=n['op'],args=[remap(a) for a in n['args']])
            expr=remap(h['expression']);table=independent_truth_table(expr)
            relations=[r for r in passage['relations'] if source_check(r['source_ref'],sources)]
            options.append(dict(conditions=selected,expression=expr,source_ref=h['source_ref'],cue=h['cue'],
                derivation=h['derivation'],relations=relations,truth_table=table,source_grounding_passed=True,
                semantic_expert_validated=False,exhaustive_cve_formula=False,
                validation='source bytes/spans, explicit grammar, ambiguity screen and Boolean enumeration; semantic interpretation remains provisional'))
    options.sort(key=lambda x:(x['derivation']!='explicit_necessity',-len(x['conditions']),digest(x['source_ref'])))
    return dict(cve=record['cve'],selected=options[0] if options else None,alternatives=options[1:],rejected=rejected,
        original_cluster_ids=sorted({c['cluster_id'] for c in candidates}),
        missing_relation_is_not_not_affected=True,excluded=False)


def question_key(condition):
    # Shared template only: preserve positive predicate and inherited subject/verb.
    # The local source clause and asset target are always supplied in each binding.
    inheritance=condition.get('inheritance') or {}
    return digest([norm(condition['proposition']),{k:v for k,v in inheritance.items() if k!='source_ref'}])


def mine_common(ledgers,split):
    groups=defaultdict(dict)
    for row in ledgers:
        if split[row['cve']]!='train':continue
        # A CVE can belong to several condition clusters. Mine conditions shared
        # by the CVEs in EACH cluster, rather than pretending the atom and CVE
        # have a single exclusive class. Keep that membership proof explicitly.
        for selected in ([row['selected']] if row['selected'] else [])+row['alternatives']:
            for c in selected['conditions']:
                key=question_key(c)
                for cluster in row['original_cluster_ids']:
                    groups[cluster,key][row['cve']]=c
    catalog=[]
    for (cluster,key),members in sorted(groups.items()):
        if len(members)<2:continue
        example=next(iter(members.values()))
        catalog.append(dict(id='K'+str(cluster)+'-Q'+key[:12],cluster_id=cluster,
            predicate_key=key,positive_predicate=example['proposition'],
            question='Within the supplied CVE source context and assessed asset, does this condition hold: '+example['proposition']+'?',
            training_cve_support=len(members),training_cves=sorted(members),
            source_refs=[dict(cve=cve,**c['source_ref']) for cve,c in sorted(members.items())],
            membership_basis='CVE contains frozen candidate(s) in this cluster; condition itself need not be that candidate',
            share_answer_across_assets_or_cves=False,semantic_expert_validated=False))
    return catalog
