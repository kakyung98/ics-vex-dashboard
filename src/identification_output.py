"""Separate confirmed CVE mappings from unresolved review candidates."""

def split_findings(findings):
    return ([r for r in findings if r.get('match_status')=='match'],
            [r for r in findings if r.get('match_status')=='unknown'])
