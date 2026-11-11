"""Token-level JSON shape constraints complement, never replace evidence checks."""
def obj(properties,required=None):return {'type':'object','properties':properties,'required':list(properties) if required is None else required,'additionalProperties':False}
def array(item,maximum=8,minimum=0):return {'type':'array','items':item,'maxItems':maximum,'minItems':minimum}
TEXT={'type':'string'}

def schema_for(role,packet):
    if role.startswith('identity-'):
        from src.identification_agent_contracts import schema
        return schema(role.removeprefix('identity-'),packet)
    if role=='l2-candidates':
        ids=[c['candidate_id'] for c in packet['candidates'] if not c['conflicts']]
        refs=[e['id'] for e in packet['evidence']]
        return obj({'ranked_candidate_ids':array({'type':'string','enum':ids or ['unavailable']},len(ids)),
                    'evidence_refs':array({'type':'string','enum':refs or ['unavailable']},8),
                    'status':{'type':'string','enum':['ranked','unresolved']}})
    if role.startswith('research-'):
        ids=[s['id'] for s in packet.get('sources',[])];refs=array({'type':'string','enum':ids or ['unavailable']},2,1)
        reason={'type':'string','maxLength':160 if role=='research-question-review' else 300}
        missing=array({'type':'string','maxLength':180},5)
        if role=='research-source-search':
            return obj({'queries':array({'type':'string','maxLength':80},6,1),'evidence_ids':refs})
        if role=='research-question-review':
            qids=[q['id'] for q in packet['questions']]
            review=obj({'question_id':{'type':'string','enum':qids or ['unavailable']},'support':{'type':'string','enum':['supported','unsupported','uncertain']},
                'answerability':{'type':'string','enum':['operator_answerable','requires_developer','uncertain']},'evidence_ids':refs,'reason':reason})
            cids=[c['id'] for c in packet.get('conditions',[])]
            condition=obj({'condition_id':{'type':'string','enum':cids or ['unavailable']},
                'support':{'type':'string','enum':['supported','unsupported','uncertain']},
                'necessity':{'type':'string','enum':['explicit_required','alternative','context_only','unknown']},
                'evidence_ids':refs,'reason':reason})
            return obj({'question_reviews':array(review,len(qids),len(qids)),
                'condition_reviews':array(condition,len(cids),len(cids)),'missing_evidence':missing})
        if role=='research-source-map':
            fids=[f['id'] for f in packet['functions']]
            mapping=obj({'function_id':{'type':'string','enum':fids or ['unavailable']},'evidence_ids':refs,
                'relation':{'type':'string','enum':['explicit_function_mention','patch_context','uncertain']},'reason':reason})
            return obj({'mappings':array(mapping,4 if fids else 0),'unresolved':missing})
        if role=='research-control':
            observation=obj({'evidence_id':{'type':'string','enum':ids or ['unavailable']},
                'kind':{'type':'string','enum':['input_source_candidate','guard_candidate','sink_candidate','analysis_gap']},'explanation':reason})
            return obj({'observations':array(observation,4 if ids else 0),'missing_evidence':missing})
    if role=='condition-evidence':
        from src.grounded_role_tasks import KINDS,weak_conditions
        ids=[s['id'] for s in packet['sources']];eligible=[s['id'] for s in packet['sources'] if s['condition_eligible']]
        names=sorted({f['name'] for s in packet['sources'] for f in weak_conditions(s['text'])['function_candidates']})
        refs=array({'type':'string','enum':eligible or ids},4,1)
        cond=obj({'kind':{'type':'string','enum':sorted(KINDS)},'evidence_ids':refs,'necessity':{'type':'string','enum':['explicit','uncertain']}})
        function=obj({'name':{'type':'string','enum':names or ['unavailable']},'evidence_ids':array({'type':'string','enum':ids},4,1)})
        return obj({'conditions':array(cond,8 if eligible else 0),'function_candidates':array(function,4 if names else 0),
            'function_status':{'type':'string','enum':['mentioned','unresolved'] if names else ['unresolved']},
            # 0.11.3 serializes boolean enums as Python "False". Use a JSON
            # boolean here; the evidence validator still requires false.
            'assessment':{'type':'string','enum':['partial']},'can_refute':{'type':'boolean'}})
    if role in {'operation-questions','item4-questions'}:
        ids=[s['id'] for s in packet['sources']]
        if not ids:return obj({'questions':array(obj({'question':TEXT}),0)})
        fields={'question':{'type':'string','maxLength':500},'evidence_ids':array({'type':'string','enum':ids},4,1),
            'purpose':{'type':'string','maxLength':240},'kind':{'type':'string','enum':['configuration','network_path','authentication','privileges','user_interaction','data_flow','discovery']},
            'answer_type':{'type':'string','enum':['yes_no_unknown','text']}}
        if role=='item4-questions':
            fields['answer_type']={'type':'string','enum':['yes_no_unknown']}
            fields['scope']={'type':'string','enum':['common','specific']}
            fields['question']['maxLength']=220;fields['purpose']['maxLength']=140
            fields['evidence_ids']['maxItems']=2
        return obj({'questions':array(obj(fields),4 if role=='item4-questions' else 6,2 if role=='item4-questions' else 0)})
    if role=='operation-assessment':
        ids=[q['id'] for q in packet['questions_and_answers']]
        return obj({'assessment':{'type':'string','enum':['likely_affected','likely_not_affected','likely_mitigated','likely_cannot_determine']},
            'explanation':{'type':'string','minLength':1,'maxLength':700},
            'answer_refs':array({'type':'string','enum':ids},4,1),
            'missing_evidence':array({'type':'string','maxLength':180},4)})
    if role=='vex-writer':
        justification=packet['decision'].get('justification');props={
            'vulnerability':{'type':'string','enum':[packet['vulnerability']]},'product':{'type':'string','enum':[packet['product']]},
            'status':{'type':'string','enum':[packet['decision']['status']]},
            'justification':{'type':'null'} if justification is None else {'type':'string','enum':[justification]},
            'impact_statement':{'type':'string','minLength':1,'maxLength':1000},
            'evidence_refs':array({'type':'string','enum':[e['id'] for e in packet['evidence']]},4,1),
            'action_statement':{'anyOf':[{'type':'string','maxLength':500},{'type':'null'}]},
            'missing_evidence':array({'type':'string','maxLength':180},4)}
        return obj(props,required=[k for k in props if k!='missing_evidence'])
    return None

def prefix_function(runtime,role,packet):
    schema=schema_for(role,packet)
    if schema is None:return None
    return prefix_for_schema(runtime,schema)


def prefix_for_schema(runtime,schema):
    from lmformatenforcer import JsonSchemaParser
    # lm-format-enforcer 0.11 uses a tokenizer type's pre-Transformers-5
    # import location. Bridge that alias without changing either package.
    import transformers.tokenization_utils as tokenizer_compat
    if not hasattr(tokenizer_compat,'PreTrainedTokenizerBase'):
        from transformers.tokenization_utils_base import PreTrainedTokenizerBase
        tokenizer_compat.PreTrainedTokenizerBase=PreTrainedTokenizerBase
    from lmformatenforcer.integrations.transformers import build_transformers_prefix_allowed_tokens_fn,build_token_enforcer_tokenizer_data
    if not hasattr(runtime,'_format_tokenizer_data'):runtime._format_tokenizer_data=build_token_enforcer_tokenizer_data(runtime.tok)
    return build_transformers_prefix_allowed_tokens_fn(runtime._format_tokenizer_data,JsonSchemaParser(schema))
