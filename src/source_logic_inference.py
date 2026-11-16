"""Infer grounded Boolean prerequisite hypotheses from source clause structure.

Connective scope and nonrequirements are represented explicitly. Relations are
inferred here; neither clustering nor an approval checkbox supplies the AST.
"""
from dataclasses import dataclass
import hashlib,re

VERSION='source-clause-boolean-inference/3'


def node(op,args):
    args=[a for a in args if a is not None]
    if not args:return None
    if len(args)==1 and op!='not':return args[0]
    return dict(op=op,args=args)


def trim(text,a,b):
    while a<b and (text[a].isspace() or text[a] in ',;.'):a+=1
    while b>a and (text[b-1].isspace() or text[b-1] in ',;.'):b-=1
    return a,b


def boundaries(text,pattern,a,b):
    """Find connective tokens outside parenthetical explanations/functions."""
    depth=0;levels={}
    for i in range(a,b):
        levels[i]=depth
        if text[i]=='(':depth+=1
        elif text[i]==')':depth=max(0,depth-1)
    return [m for m in re.finditer(pattern,text[a:b],re.I) if levels[a+m.start()]==0]


@dataclass
class Parser:
    text:str
    source_id:str
    offset:int=0

    def __post_init__(self):
        self.conditions=[];self.nonrequirements=[];self.warnings=[];self.relations=[]

    def ref(self,a,b):return dict(source_id=self.source_id,span=[self.offset+a,self.offset+b],quote=self.text[a:b])

    def leaf(self,a,b,positive=None,negated=False,inheritance=None):
        a,b=trim(self.text,a,b)
        if a==b:return None
        raw=self.text[a:b]
        cid='inferred:'+hashlib.sha256((self.source_id+':'+str(self.offset+a)+':'+str(self.offset+b)).encode()).hexdigest()[:28]
        self.conditions.append(dict(id=cid,proposition=positive or raw,source_ref=self.ref(a,b),
            polarity_in_source='negative' if negated else 'positive',scope_inheritance=inheritance,
            question='이 자산에서 다음 원문 조건이 성립합니까? '+(positive or raw),
            validation_status='inferred',human_reviewed=False,target_status='bind_to_assessed_asset'))
        return node('not',[{'condition':cid}]) if negated else {'condition':cid}

    def relation(self,op,parts,match):
        expr=node(op,parts)
        if expr and 'op' in expr:self.relations.append(dict(operator=op,source_ref=self.ref(*match),basis='scoped_source_connective'))
        return expr

    def parse(self,a,b,depth=0):
        if depth>20:raise ValueError('Excessively nested source relation')
        a,b=trim(self.text,a,b);body=self.text[a:b]
        if not body:return None
        neither=re.match(r'neither\s+',body,re.I)
        if neither:
            nors=boundaries(self.text,r'\bnor\b',a+neither.end(),b)
            if nors:
                start=a+neither.end();cuts=[start]+[start+m.end() for m in nors];ends=[start+m.start() for m in nors]+[b]
                return node('not',[node('or',[self.parse(x,y,depth+1) for x,y in zip(cuts,ends)])])
        not_only=re.match(r'not only\s+',body,re.I)
        if not_only:
            also=re.search(r'\bbut also\s+',body,re.I)
            if also:return node('and',[self.parse(a+not_only.end(),a+also.start(),depth+1),self.parse(a+also.end(),b,depth+1)])
        # Missing requirements are NOT negative state requirements.
        if re.fullmatch(r'(?:but\s+)?no\s+(?:system\s+|user\s+)?(?:privileges?|user interaction|authentication)',body,re.I):
            self.nonrequirements.append(dict(source_ref=self.ref(a,b),meaning='not_required',not_a_negative_literal=True));return None
        # Parentheses that actually enclose the entire condition preserve scope.
        if body.startswith('(') and body.endswith(')'):
            level=0;whole=True
            for i,c in enumerate(body):
                level+=(c=='(')-(c==')')
                if level==0 and i<len(body)-1:whole=False;break
            if whole:return self.parse(a+1,b-1,depth+1)
        # A shared negated verb scopes the object disjunction: not(use X or Y).
        negative_objects=re.search(r'\b(?:do|does) not (?:use|include|contain)\s+',body,re.I)
        if negative_objects and re.search(r'\bor\b',body[negative_objects.end():],re.I):
            start=a+negative_objects.end();ors=boundaries(self.text,r'\bor\b',start,b)
            if ors:
                cuts=[start]+[start+m.end() for m in ors];ends=[start+m.start() for m in ors]+[b]
                children=[self.leaf(x,y,inheritance=dict(shared_positive_subject=body[:negative_objects.start()],
                    shared_positive_verb=negative_objects.group().replace(' not ', ' '),scope='object_disjunction')) for x,y in zip(cuts,ends)]
                return self.relation('not',[self.relation('or',children,(start+ors[0].start(),start+ors[-1].end()))],
                    (a+negative_objects.start(),a+negative_objects.end()))
        # Contrastive ellipsis: enabled on server BUT NOT on client.
        contrast=re.search(r'\bbut\s+not\s+',body,re.I)
        if contrast:
            left=self.parse(a,a+contrast.start(),depth+1);right_start=a+contrast.start()+len('but ')
            prefix=body[:contrast.start()].strip();shared=re.split(r'\bon\b',prefix,flags=re.I)[0].strip()
            right=self.leaf(right_start,b,positive=shared+' '+re.sub(r'^not\s+','',self.text[right_start:b],flags=re.I),
                negated=True,inheritance=dict(shared_predicate=shared,source_ref=self.ref(a,a+contrast.start())))
            return self.relation('and',[left,right],(a+contrast.start(),a+contrast.end()))
        # Verb-object coordination inside one capability is kept atomic.
        if re.match(r'(?:the )?ability\b',body,re.I) and re.search(r'\b(?:in|into)\b.+\band\b',body,re.I):
            return self.leaf(a,b)
        # Explicit EITHER gives OR scope over whole alternatives (including AND).
        either=re.match(r'(?:.*?\b)?either\s+',body,re.I)
        if either:
            start=a+either.end();ors=boundaries(self.text,r'\bor\b',start,b)
            if ors:
                cuts=[start]+[start+m.end() for m in ors];ends=[start+m.start() for m in ors]+[b]
                return self.relation('or',[self.parse(x,y,depth+1) for x,y in zip(cuts,ends)],(start+ors[0].start(),start+ors[-1].end()))
        # Independent conjuncts are split before shared-head OR lists: A AND calls(B OR C).
        ands=boundaries(self.text,r',?\s*\band\b\s+(?:that\s+)?|,?\s*\bbut\b\s+(?=no\b)',a,b)
        if ands:
            cuts=[a]+[a+m.end() for m in ands];ends=[a+m.start() for m in ands]+[b]
            return self.relation('and',[self.parse(x,y,depth+1) for x,y in zip(cuts,ends)],(a+ands[0].start(),a+ands[-1].end()))
        ors=boundaries(self.text,r'\bor\b',a,b)
        if ors:
            cuts=[a]+[a+m.end() for m in ors];ends=[a+m.start() for m in ors]+[b]
            children=[self.parse(x,y,depth+1) for x,y in zip(cuts,ends)]
            if any(c is None for c in children):
                self.warnings.append('A disjunction containing a nonrequirement has unresolved semantic scope');return None
            return self.relation('or',children,(a+ors[0].start(),a+ors[-1].end()))
        without=re.search(r'\bwithout\s+',body,re.I)
        if without:
            prefix=body[:without.start()].strip();tail=a+without.end()
            negative=self.leaf(tail,b,negated=True)
            if prefix.casefold() in {'sent','being sent','used','being used','operating'}:return negative
            return self.relation('and',[self.parse(a,a+without.start(),depth+1),negative],(a+without.start(),tail))
        negative=re.search(r'^not\b|\b(?:is|are|was|were|does|do|has|have) not\b|\bnot (?:enabled|configured|used|received|sanitized|installed|present|authenticated)\b|\bdisabled\b',body,re.I)
        if negative:
            positive=re.sub(r'\bnot\s+','',body,flags=re.I)
            positive=re.sub(r'\bdisabled\b','enabled',positive,flags=re.I)
            return self.leaf(a,b,positive=positive,negated=True)
        return self.leaf(a,b)


def infer_passage(text,source_id,cve='',offset=0):
    parser=Parser(text,source_id,offset);hypotheses=[];diagnostics=[]
    # Nonrequirement statements are captured even outside a requires clause.
    for m in re.finditer(r'\b(?:does|do) not require authentication\b',text,re.I):
        parser.nonrequirements.append(dict(source_ref=parser.ref(*m.span()),meaning='not_required',not_a_negative_literal=True))
    # A validation guard's "only if" is not automatically an exploit prerequisite.
    validation_guard=bool(re.search(r'\brequires?\s+(?:a\s+)?correct MAC\s+only if\b',text,re.I))
    if not validation_guard and not re.search(r'\beven if\b',text,re.I):
        gates=[]
        for m in re.finditer(r'\b(?:successful\s+)?exploitation(?:\s+of\s+(?:this|the)\s+vulnerability)?\s+requires?\s+|\b(?:this\s+)?vulnerability\s+requires?\s+|\b(?:an? |the )?attacker\s+(?:must have|must|would need|needs?)(?:\s+to)?\s+|\bthe crafted packet\s+needs to have\s+',text,re.I):
            gates.append((m.end(),len(text),'explicit_necessity',m.span()))
        if not gates:
            # Conditional contexts: keep all scope and never claim exhaustiveness.
            for m in re.finditer(r'\b(?:only when|only if|provided that|when|if|unless)\s+',text,re.I):
                if re.search(r'\beven\s*$',text[:m.start()],re.I):continue
                gates.append((m.end(),len(text),'unless_guard' if m.group().strip().casefold()=='unless' else 'conditional_context',m.span()))
                break
        for a,b,kind,cue in gates:
            # Stop at an independent consequence, recovery instruction or sentence end.
            tail=text[a:b]
            ending=re.search(r'\bthen\b|,\s*(?:which|allow(?:s|ing)?|could|can|does|do|improperly|lacks|uses|makes|creates|a DoS|it|the|this|there|they|will|would)\b|\s+and\s+(?:impacts|allows|causes|enables|results)\b|\s+to compromise the system\b|\.?CVE-\d{4}-\d+ has been assigned\b|[.!?](?=\s|$)|;\s*(?:users|administrators)\b',tail,re.I)
            if ending:b=a+ending.start()
            a,b=trim(text,a,b)
            if not text[a:b]:continue
            if re.fullmatch(r'(?:successfully\s+)?exploited|(?:this|the) vulnerability is exploited',text[a:b],re.I):
                diagnostics.append('Successful exploitation itself is not an independent operating precondition');continue
            try:
                expression=parser.parse(a,b)
                if expression and kind=='unless_guard':expression=node('not',[expression])
                if expression:
                    scoped=text[a:b]
                    ambiguous=(bool(boundaries(text,r'\band\b',a,b)) and bool(boundaries(text,r'\bor\b',a,b))
                        and not re.search(r'\beither\b|\band that\b',scoped,re.I) and '(' not in scoped)
                    if ambiguous:parser.warnings.append('Mixed AND/OR without explicit attachment has ambiguous scope; auto-application is disabled')
                    alternatives=[]
                    if ambiguous:
                        ors=boundaries(text,r'\bor\b',a,b)
                        cuts=[a]+[a+m.end() for m in ors];ends=[a+m.start() for m in ors]+[b]
                        other=node('or',[parser.parse(x,y) for x,y in zip(cuts,ends)])
                        alternatives=[dict(expression=expression,attachment='AND over OR constituents'),
                                      dict(expression=other,attachment='OR over AND constituents')]
                    hypotheses.append(dict(expression=expression,source_ref=parser.ref(a,b),cue=parser.ref(*cue),
                        derivation=kind,coverage_complete=False,scope='described_clause_or_route',
                        scope_ambiguous=ambiguous,auto_applicable=not ambiguous,
                        alternatives=alternatives,
                        confidence_basis='explicit grammatical cue; semantic exhaustiveness not established'))
            except ValueError as exc:diagnostics.append(str(exc))
    elif validation_guard:diagnostics.append('Validation dependency retained separately; not promoted to exploit prerequisites')
    else:diagnostics.append('Concessive even-if clause is not a required configuration state')
    used=set()
    def visit(expr):
        if 'condition' in expr:used.add(expr['condition'])
        else:
            for child in expr['args']:visit(child)
    for h in hypotheses:
        visit(h['expression'])
        for alternative in h['alternatives']:visit(alternative['expression'])
    conditions=list({c['id']:c for c in parser.conditions if c['id'] in used}.values())
    for c in conditions:
        c['context_refs']=[h['source_ref'] for h in hypotheses if h['source_ref']['span'][0]<=c['source_ref']['span'][0]<c['source_ref']['span'][1]<=h['source_ref']['span'][1]]
        # Shared grammatical qualifiers remain visible even for an alternative
        # leaf, e.g. BOTH SSL_read and SSL_write AFTER a fatal error.
        c['qualification_policy']='Interpret within all linked clause contexts; no dropped shared qualifiers'
    return dict(cve=cve,method=VERSION,hypotheses=hypotheses,conditions=conditions,
        relations=parser.relations,nonrequirements=parser.nonrequirements,diagnostics=diagnostics+parser.warnings,
        status='inferred' if hypotheses else 'nonrequirements_only' if parser.nonrequirements else 'unresolved',
        human_reviewed=False,exhaustive_cve_formula=False)


def infer_record(record):
    results=[]
    if record.get('original_nvd_status')=='Rejected' or record.get('identity_ambiguous'):
        return dict(cve=record['cve'],method=VERSION,status='identity_unresolved',passages=[],source_scan_complete=True,
                    exhaustive_cve_formula=False,excluded=False)
    for source in record['sources']:
        if hashlib.sha256(source['text'].encode()).hexdigest()!=source['text_sha256']:raise ValueError('Source hash mismatch')
        # Independent sentences/sources are not silently joined with AND or OR.
        start=0
        for m in re.finditer(r'(?<=[.!?])\s+|\n+',source['text']):
            end=m.start();segment=source['text'][start:end]
            if segment.strip():
                value=infer_passage(segment,source['id'],record['cve'],start)
                if value['hypotheses'] or value['nonrequirements']:results.append(value)
            start=m.end()
        segment=source['text'][start:]
        if segment.strip():
            value=infer_passage(segment,source['id'],record['cve'],start)
            if value['hypotheses'] or value['nonrequirements']:results.append(value)
    return dict(cve=record['cve'],method=VERSION,status='inferred' if any(p['hypotheses'] for p in results) else 'unresolved',
        passages=results,source_scan_complete=True,exhaustive_cve_formula=False,excluded=False,
        cross_source_relation='not_assumed; competing partial clauses retained separately')
