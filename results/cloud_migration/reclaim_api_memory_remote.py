from pathlib import Path
import json,os,signal,subprocess,sys,time
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
p=r/'project'
run=p/'results/h200_full_population_20261116_130409'
pid=int((r/'api.pid').read_text())
args=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
assert any(Path(os.fsdecode(a)).resolve()==(p/'tools/ncp_serve.py').resolve() for a in args if a)
rss=next(x for x in Path(f'/proc/{pid}/status').read_text().splitlines() if x.startswith('VmRSS:'))
guard='''from pathlib import Path
import json,time,subprocess
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
run=r/'project/results/h200_full_population_20261116_130409'
while True:
 state=json.loads((run/'status.json').read_text())
 if state['status'] in ['complete','failed']:break
 proc=Path('/proc')/str(state['pid'])
 if not proc.exists() or (proc/'stat').read_text().rsplit(')',1)[1].split()[0]=='Z':break
 time.sleep(5)
subprocess.run([str(r/'venv/bin/python'),str(r/'project/tools/ncp_service.py'),'start'],check=True)
(run/'api_restored.json').write_text(json.dumps(dict(restored=True,after_status=state['status'])))
'''
file=run/'restore_api_after_evaluation.py';file.write_text(guard)
log=(run/'api_restore.log').open('wb')
watcher=subprocess.Popen([sys.executable,str(file)],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
os.kill(pid,signal.SIGTERM)
report=dict(API_temporarily_stopped=True,owned_API_pid=pid,prior_API_resident_memory=rss,
           existing_user_kernel_untouched=True,restoration_guard_pid=watcher.pid)
(run/'resource_policy.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
