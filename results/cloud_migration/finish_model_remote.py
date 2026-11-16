from pathlib import Path
import tarfile
import subprocess
import json
r=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
with tarfile.open(r/'incoming/base_model.tar') as archive:
 for member in archive:
  if not member.isfile() and not member.isdir():raise ValueError('Non-regular base model archive entry')
  archive.extract(member,r,filter='data')
subprocess.run([str(r/'venv/bin/python'),str(r/'project/tools/ncp_cloud_setup.py')],cwd=r/'project',check=True)
# Older training entry points use the pinned standard Hugging Face cache location.
cache=Path.home()/'.cache/huggingface/hub/models--unsloth--Qwen2.5-Coder-14B-Instruct-bnb-4bit/snapshots/ecfc63c083900ce4f19daad695e711f38ab98fcf'
if not cache.exists():
 cache.parent.mkdir(parents=True,exist_ok=True)
 cache.symlink_to(r/'base_model',target_is_directory=True)
print(json.dumps(dict(model_relocated=True,base_files=11,cache_path=str(cache))))
