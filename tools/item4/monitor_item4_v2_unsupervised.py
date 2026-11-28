"""Job-local completion watcher: fetch and verify actual results, never schedule."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import json
import time

from tools.common.ncp_api_transport import execute
from tools.item4.deploy_item4_v2_unsupervised import WORK,CONFIG,LOCAL,fetch


def snapshot():
    script='''from pathlib import Path
import json
w=Path(WORK)
print(json.dumps({name:json.loads((w/name).read_text()) for name in
 ['pipeline_status.json','training/status.json','evaluation/status.json'] if (w/name).exists()}))
'''.replace('Path(WORK)','Path('+repr(WORK)+')')
    return json.loads(execute(CONFIG,script,timeout=25))


def main():
    failures=0
    while True:
        try:
            state=snapshot();failures=0
        except Exception as exc:
            failures+=1
            print(json.dumps(dict(stage='retrying_transport',failure_count=failures,error=type(exc).__name__)),flush=True)
            time.sleep(30);continue
        (LOCAL/'remote_status.json').write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8')
        pipe=state.get('pipeline_status.json',{});phase=state.get('evaluation/status.json',state.get('training/status.json',{}))
        concise=dict(status=pipe.get('status'),stage=pipe.get('stage'),
            completed_cves=phase.get('completed_cves'),completed_cases=phase.get('completed_cases'),
            elapsed_seconds=phase.get('elapsed_seconds'))
        print(json.dumps(concise),flush=True)
        if pipe.get('status')=='failed':raise RuntimeError(pipe.get('error','Remote pipeline failed'))
        if pipe.get('status')=='complete':break
        time.sleep(30)
    fetch()
    print(json.dumps(dict(status='fetched_and_verified',report=str(LOCAL/'verification.json'))),flush=True)


if __name__=='__main__':main()
