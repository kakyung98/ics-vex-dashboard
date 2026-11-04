"""Structural checks and curriculum agreement, not independent semantic accuracy."""
import json

def check_questions(packet,pred):
    rows=pred.get('questions') if isinstance(pred,dict) and set(pred)=={'questions'} else None
    schema=isinstance(rows,list) and 3<=len(rows)<=6
    if not schema:return {'schema_valid':False,'quotes_supported':False,'operational_wording':False}
    schema=all(isinstance(q,dict) and set(q)=={'question','evidence','purpose'} and
               all(isinstance(q[k],str) and 0<len(q[k])<=1200 for k in q) for q in rows)
    if not schema:return {'schema_valid':False,'quotes_supported':False,'operational_wording':False}
    schema=len({q['question'] for q in rows})==len(rows)
    return {'schema_valid':schema,'quotes_supported':all(q['evidence'].strip() and q['evidence'] in packet.get('description','') for q in rows),
        'operational_wording':all(q['question'].startswith('On this asset, ') and not any(w in q['question'].lower() for w in ['vulnerabilit','exploit']) for q in rows)}

def check_assessment(packet,pred):
    keys={'assessment','explanation','answer_refs','missing_evidence'}
    schema=isinstance(pred,dict) and set(pred)==keys
    if not schema:return {'schema_valid':False,'answer_refs_valid':False,'unknown_safety':False}
    schema=isinstance(pred['assessment'],str) and pred['assessment'] in {'likely_affected','likely_not_affected','likely_mitigated','likely_cannot_determine'} and isinstance(pred['explanation'],str) and 0<len(pred['explanation'])<=5000 and isinstance(pred['answer_refs'],list) and bool(pred['answer_refs']) and all(isinstance(x,str) for x in pred['answer_refs']) and isinstance(pred['missing_evidence'],list) and all(isinstance(x,str) for x in pred['missing_evidence'])
    if not schema:return {'schema_valid':False,'answer_refs_valid':False,'unknown_safety':False}
    qa=packet.get('questions_and_answers',[]);known={q['id']:q for q in qa}
    refs_ok=set(pred['answer_refs'])<=set(known)
    usable=any(q.get('answer',{}).get('value') not in {None,'','unknown'} and q.get('answer',{}).get('evidence','').strip() for q in qa)
    return {'schema_valid':True,'answer_refs_valid':refs_ok,
            'unknown_safety':pred['assessment']=='likely_cannot_determine' or bool(usable and packet.get('question_generation_valid'))}

def check(role,packet,pred):
    return check_questions(packet,pred) if role=='operation-questions' else check_assessment(packet,pred)

def evaluate(role,rows,texts):
    from src.grounded_role_tasks import parse
    if len(rows)!=len(texts):raise ValueError('Prediction count mismatch')
    records=[]
    for row,text in zip(rows,texts):
        pred=parse(text);ref=json.loads(row['messages'][-1]['content']);checks=check(role,row['packet'],pred)
        records.append({'id':row['id'],'checks':checks,'prediction':pred,'reference':ref,'raw':text,
                        'reference_exact_agreement':pred==ref,
                        'advisory_label_agreement':isinstance(pred,dict) and pred.get('assessment')==ref.get('assessment') if role=='operation-assessment' else None})
    metrics={k:sum(bool(r['checks'][k]) for r in records)/len(records) for k in records[0]['checks']} if records else {}
    metrics.update(examples=len(rows),reference_exact_agreement=sum(r['reference_exact_agreement'] for r in records)/len(rows) if rows else None,
                   expert_semantic_accuracy_evaluated=False,interpretation='Controlled synthetic curriculum validation only; not real-CVE exploitability accuracy.')
    if role=='operation-assessment':metrics['advisory_label_agreement']=sum(r['advisory_label_agreement'] for r in records)/len(rows) if rows else None
    return metrics,records
