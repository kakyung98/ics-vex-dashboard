"""Explain validation grounding failures without changing scores or loading test data."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.grounded_role_tasks import KINDS
from src.training_io import read_json,atomic_json


def normalized(s):return re.sub(r'\s+', ' ', s).strip()


def main():
    source=ROOT/'data/grounded_role_sft_v1/cve-conditions/validation.jsonl'
    rows={r['id']:r for r in (json.loads(l) for l in source.read_text(encoding='utf-8').splitlines())}
    report_path=ROOT/'results/grounded_role_finetune_v1/cve-conditions/validation_report.json'
    report=read_json(report_path)
    result={'split':'validation','test_loaded':False,'original_scores_modified':False,
            'semantic_accuracy_measured':False,
            'validation_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'original_report_sha256':hashlib.sha256(report_path.read_bytes()).hexdigest(),'models':{}}
    for mode in ['baseline','tuned']:
        count=Counter();examples=[]
        for record in report[mode+'_predictions']:
            desc=rows[record['id']]['packet']['description'];pred=record['prediction']
            count['cases']+=1
            if not isinstance(pred,dict):count['unparseable_json']+=1;continue
            for field in ['conditions','function_candidates']:
                values=pred.get(field,[])
                if not isinstance(values,list):count['invalid_list_type']+=1;continue
                for span in values:
                    if not isinstance(span,dict):count['invalid_span_type']+=1;continue
                    count['spans']+=1
                    quote=span.get('evidence')
                    if not isinstance(quote,str) or not quote:count['empty_or_invalid_quote']+=1;continue
                    if quote in desc:count['literal_supported_spans']+=1
                    elif normalized(quote) in normalized(desc):count['whitespace_only_mismatch']+=1
                    else:
                        count['nonliteral_quote_spans']+=1
                        if len(examples)<6:examples.append({'id':record['id'],'field':field,'quote':quote,'description':desc})
                    if field=='conditions' and span.get('kind') not in KINDS:count['invalid_condition_kind']+=1
                    if field=='function_candidates' and (not isinstance(span.get('name'),str) or span['name'] not in quote):count['function_name_not_in_quote']+=1
            for k,v in record['checks'].items():count[k+'_cases']+=int(v)
        count['literal_span_support_rate']=count['literal_supported_spans']/count['spans'] if count['spans'] else 0
        result['models'][mode]={'counts':dict(count),'nonliteral_examples':examples}
    dest=ROOT/'results/grounded_role_finetune_v1/cve-conditions/grounding_audit.json'
    atomic_json(dest,result)
    print(json.dumps({mode:obj['counts'] for mode,obj in result['models'].items()},indent=2))


if __name__=='__main__':main()
