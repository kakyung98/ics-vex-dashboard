from pathlib import Path
import tarfile
import json
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
with tarfile.open(root/'incoming/project.tar.gz') as archive:
    for member in archive:
        if not member.isfile() and not member.isdir():
            raise ValueError('Non-regular project archive entry')
        archive.extract(member, root, filter='data')
print(json.dumps(dict(project=str(root/'project'), extracted=True)))
