"""Build independent #4 rule fixtures, or evaluate a real multi-role LLM."""
from pathlib import Path
import argparse
import json
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from src.item4.evaluation import benchmark_rule_oracle as C; from src.item4.evaluation import rule_evaluation_runner as E


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--output',type=Path,default=ROOT/'results/item4_rule_evaluation_v1')
    cli.add_argument('--run-model',action='store_true')
    cli.add_argument('--oracle-conditions',action='store_true')
    cli.add_argument('--track',choices=['routing','extraction','integration','end_to_end','all'],default='all')
    cli.add_argument('--split',choices=['train','dev','test'],default='test')
    cli.add_argument('--limit',type=int,default=16)
    cli.add_argument('--nemotron-manifest',type=Path)
    cli.add_argument('--port',type=int,default=18128)
    args=cli.parse_args()
    if args.limit<1:cli.error('--limit must be positive')
    cases,manifest=E.generate();args.output.mkdir(parents=True,exist_ok=True)
    for name,value in [('manifest',manifest),('policy',dict(version=C.VERSION,rules=C.POLICY)),('output_schemas',C.SCHEMAS)]:
        (args.output/(name+'.json')).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    with (args.output/'cases.private.jsonl').open('w',encoding='utf-8') as private, (args.output/'cases.public.jsonl').open('w',encoding='utf-8') as public:
        for c in cases:
            private.write(json.dumps(c,ensure_ascii=False)+'\n')
            public.write(json.dumps(E.C.public_case(c),ensure_ascii=False)+'\n')
    if args.run_model:
        # Deterministically select across routing rules and asset types before adding more.
        eligible=[c for c in cases if c['split']==args.split];groups={}
        for c in eligible:groups.setdefault(c['expected']['rule_id'],[]).append(c)
        selected=[]
        while groups and len(selected)<args.limit:
            for key in list(groups):
                selected.append(groups[key].pop(0))
                if not groups[key]:del groups[key]
                if len(selected)==args.limit:break
        if args.nemotron_manifest:
            from src.item4.models.nemotron_inference_provider import NemotronBatch
            provider=NemotronBatch(args.port,args.nemotron_manifest,concurrency=1)
            def runner(system,packet,*,role):
                result=provider([dict(system=system,packet=packet)])[0]
                if isinstance(result,Exception):raise result
                return result
        else:
            from src.item4.models.json_inference_client import generate as runner
        tracks=['routing','extraction','integration','end_to_end'] if args.track=='all' else [args.track]
        reports={}
        for track in tracks:
            output=args.output/('model-'+track)
            reports[track]=E.run_extraction(selected,runner,output) if track=='extraction' else E.run(
                selected,runner,output,oracle_conditions=track=='integration' or args.oracle_conditions,
                routing_only=track=='routing')
        print(json.dumps(reports,ensure_ascii=False,indent=2))
        if any(not r.get('model_performance_measured') or r.get('model_failed',0)>0 or
               (track=='extraction' and r.get('completed',0)<r.get('cases',0))
               for track,r in reports.items()):
            raise SystemExit(2)
    else:
        print(json.dumps(dict(manifest,llm_execution_attempted=False,model_performance_measured=False),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
