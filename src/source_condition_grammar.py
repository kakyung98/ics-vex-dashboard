"""Bounded source-clause proposals supplement incomplete model extraction.

Only positive literal matches are emitted; no match never means absence. Rules
do not infer target bindings, AND/OR, exhaustive routes or review approvals.
"""
import hashlib,re
from .cluster_question_pipeline import digest

RULES=[
    ('explicit_user_interaction','user_action','explicitly_required',
     r'(?i)\b(?:successful )?exploitation (?:of (?:this|the) vulnerability )?requires user interaction\b',
     'User interaction is required'),
    ('explicit_physical_access','access_position','explicitly_required',
     r'(?i)\b(?:successful )?exploitation (?:of (?:this|the) vulnerability )?requires physical access\b',
     'Physical access is required'),
    ('explicit_local_access','access_position','explicitly_required',
     r'(?i)\b(?:successful )?exploitation (?:of (?:this|the) vulnerability )?requires local access\b',
     'Local access is required'),
    ('literal_authenticated_attacker','attacker_auth_or_privilege','described_not_proven_required',
     r'(?i)\ban? authenticated attacker\b','Authenticated attacker'),
    ('literal_local_attacker','access_position','described_not_proven_required',
     r'(?i)\ban? local attacker\b','A local attacker'),
    ('literal_physical_attacker','access_position','described_not_proven_required',
     r'(?i)\ban? attacker with physical access\b','Attacker with physical access'),
]


def extract(records):
    result=[];coverage=[]
    for record in records:
        found=0
        for source in record['sources']:
            if hashlib.sha256(source['text'].encode()).hexdigest()!=source['text_sha256']:
                raise ValueError('Source changed: '+source['id'])
            if record.get('original_nvd_status')=='Rejected' or record.get('identity_ambiguous'):continue
            for rule,kind,necessity,pattern,condition in RULES:
                for match in re.finditer(pattern,source['text']):
                    a,b=match.span();quote=source['text'][a:b]
                    # Negated attack clauses are not positive facts ("no exploitation requires...").
                    prefix=source['text'][max(0,a-35):a]
                    if re.search(r'(?i)\b(?:not|no|never|prevent|prevents|avoid|mitigate)\s*$',prefix):continue
                    result.append(dict(condition_id='rule:'+digest([record['cve'],source['id'],a,b,rule]),
                        cve=record['cve'],condition=condition,kind=kind,necessity=necessity,
                        source_id=source['id'],source_span=[a,b],source_quote=quote,
                        extraction_origin='bounded_source_grammar',grammar_rule=rule,
                        validation_status='pending_review',clustering_allowed=False,
                        semantic_necessity_verified=False))
                    found+=1
        coverage.append(dict(cve=record['cve'],literal_scan_complete=True,proposals=found,
            semantic_extraction_complete=False,excluded=False))
    return result,coverage
