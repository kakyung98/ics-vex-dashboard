"""Select the corrected context arm by input availability, never output success."""
import json
from pathlib import Path


def effective_questions(output_root):
    output_root=Path(output_root);home=output_root/'outputs'
    fixtures=json.loads((output_root/'named_context_inputs.json').read_text(encoding='utf-8'))
    needs_name={r['id']:r['named_context_available'] for r in fixtures}
    result=[]
    for p in sorted(home.glob('v3__*__with_context.json')):
        original=json.loads(p.read_text(encoding='utf-8'));cve=original['id']
        if needs_name[cve]:
            path=home/('v3__'+cve+'__named_context.json')
            if not path.exists():continue
            row=json.loads(path.read_text(encoding='utf-8'))
            if row['status']=='context_unavailable':raise ValueError('Available context unexpectedly skipped')
            row['effective_context']='named_context'
        else:
            row=original;row['effective_context']='unresolved_context'
        result.append(row)
    return result
