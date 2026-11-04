"""Run the user-authorized 20-case API pilot, with explicit resume receipts."""
import argparse,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.cross_model_review import availability,configuration,review_one
from src.training_io import atomic_json
from src.vex_roles import fingerprint


def main():
    p=argparse.ArgumentParser();p.add_argument('--limit',type=int,default=20);p.add_argument('--check',action='store_true')
    p.add_argument('--retry-incomplete',action='store_true');a=p.parse_args()
    if not 1<=a.limit<=20:raise ValueError('This command is restricted to the 20-case pilot.')
    folder=ROOT/'results/operational_blind_review_pilot';state={'status':'preflight','providers':availability(),'actual_cases_dispatched':0}
    if a.check or not all(v['ready'] for v in state['providers'].values()):
        state['status']='ready' if all(v['ready'] for v in state['providers'].values()) else 'awaiting_credentials_and_model_ids'
        atomic_json(folder/'api_status.json',state);print(json.dumps(state,indent=2));return
    packet=json.loads((folder/'claude_input.json').read_text(encoding='utf-8'))
    if packet!=json.loads((folder/'gemini_input.json').read_text(encoding='utf-8')):raise ValueError('Reviewer inputs differ.')
    records=folder/'api_reviews';records.mkdir(exist_ok=True);configs=configuration()
    state.update(status='running',started_at=time.time(),providers={p:{'model':v['model']} for p,v in configs.items()})
    atomic_json(folder/'api_status.json',state)
    for item in packet['inputs'][:a.limit]:
        file=records/(item['cve']+'.json')
        one={**packet,'inputs':[item]}
        # Any existing receipt prevents silent rebilling, even on failure.
        if file.exists():
            previous=json.loads(file.read_text(encoding='utf-8'))
            if previous.get('input_sha256')!=fingerprint(one):raise ValueError('Inputs changed; use a new pilot output directory.')
        if file.exists() and not a.retry_incomplete:continue
        if file.exists() and json.loads(file.read_text(encoding='utf-8'))['status']=='model_reviewed':continue
        atomic_json(file,{'id':item['id'],'input_sha256':fingerprint(one),'status':'dispatching',
                         'human_gold':False,'note':'A crash after dispatch may have billed requests; resume will not silently redispatch.'})
        output=review_one(one,configs)
        atomic_json(file,output);state['actual_cases_dispatched']+=1;atomic_json(folder/'api_status.json',state)
        print(item['cve']+': '+output['status'],flush=True)
    state.update(status='pilot_finished_review_required',elapsed_seconds=round(time.time()-state['started_at'],1),human_gold=False)
    atomic_json(folder/'api_status.json',state)

if __name__=='__main__':main()
