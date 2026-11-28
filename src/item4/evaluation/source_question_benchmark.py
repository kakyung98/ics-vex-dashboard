"""Synthetic confidence-boundary and source-logic contracts, not model accuracy."""
from src.item4.assets.source_question_policy import admitted,POLICY
from src.item4.decision.condition_logic_evaluation import logic

VERSION='item4-source-question-contract/1'


def run():
    rows=[]
    for score,expected in [(None,False),(0,False),(79,False),(80,False),(81,True),(95,True),(100,True),(101,False),(True,False),(0.95,False)]:
        rows.append(dict(id='confidence:'+str(score),correct=admitted(score)==expected))
    for op,a,b,expected in [('and','true','unknown','unknown'),('and','false','unknown','false'),('or','true','unknown','true'),('or','false','unknown','unknown')]:
        actual=logic(dict(op=op,args=[dict(condition='a'),dict(condition='b')]),dict(a=a,b=b))
        rows.append(dict(id=f'{op}:{a}:{b}',correct=actual==expected))
    rows.append(dict(id='not:unknown',correct=logic(dict(op='not',args=[dict(condition='a')]),dict(a='unknown'))=='unknown'))
    return dict(version=VERSION,question_policy=POLICY,cases=len(rows),correct=sum(r['correct'] for r in rows),rows=rows,
        llm_called=False,independent_extraction_accuracy_measured=False,independent_field_accuracy_measured=False,
        scope='Synthetic admission and Boolean-logic contracts only; not confidence calibration or semantic accuracy')
