"""Compare prompt token IDs across the two installed Transformers versions."""
import sys,json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from transformers import AutoTokenizer
from src.item4.analysis import exploitation_prerequisites as V2
from src.item4.analysis import asset_operating_question_generation as V3
from copy import deepcopy


def main():
    data=json.loads((ROOT/'inputs.json').read_text());tok=AutoTokenizer.from_pretrained(str(ROOT/'tokenizer'),local_files_only=True)
    result={}
    def add(key,system,packet):
        ids=tok.apply_chat_template([dict(role='system',content=system),dict(role='user',content=json.dumps(packet,ensure_ascii=False))],tokenize=True,add_generation_prompt=True,enable_thinking=False)
        if hasattr(ids,'keys'):ids=ids['input_ids']
        result[key]=hashlib.sha256(json.dumps(ids).encode()).hexdigest()
    for c in data['cases']:
        for kind in (['original','double_spaces','linebreaks'] if c['robustness_selected'] else ['original']):
            record=deepcopy(c['record'])
            if not record.get('sources'):continue
            for s in record['sources']:
                if kind=='double_spaces':s['text']=s['text'].replace(' ','  ')
                if kind=='linebreaks':s['text']=s['text'].replace(' ','\n')
                s['text_sha256']=hashlib.sha256(s['text'].encode()).hexdigest()
            add(c['id']+'__'+kind,V2.SYSTEM,V2.extraction_packet(record))
    for q in data['v3']:
        for kind in ['with_context','without_context']:
            p=deepcopy(q['packet'])
            if kind=='without_context':p['asset_classification']=dict(status='unresolved',asset_type_id=None)
            add('v3__'+q['id']+'__'+kind,V3.SYSTEM,p)
    payload=dict(prompts=len(result),token_id_hashes=result,special_ids=tok.all_special_ids)
    output=ROOT/sys.argv[1];output.write_text(json.dumps(payload),encoding='utf-8');print(json.dumps(dict(prompts=len(result),output=str(output),special_ids=tok.all_special_ids)))


if __name__=='__main__':main()
