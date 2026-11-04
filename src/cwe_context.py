"""Weakness classification and review guidance; never a new exploit prerequisite."""
import re

PROFILES={
 'CWE-78':('OS command injection',['Identify the affected command-building interface.','Obtain vendor evidence for whether external input reaches command construction.']),
 'CWE-787':('Out-of-bounds write',['Identify the affected parser/buffer operation and firmware build.','Check vendor trigger, length/bounds conditions and remediation evidence.']),
 'CWE-125':('Out-of-bounds read',['Identify the affected read/parser operation.','Check input bounds and affected-build evidence from the vendor.']),
 'CWE-190':('Integer overflow or wraparound',['Identify the affected arithmetic and input-size conditions.','Obtain architecture, integer-width and vendor fix evidence.']),
 'CWE-416':('Use after free',['Identify object lifetime and the affected feature.','Obtain vendor sequence/concurrency and affected-build evidence.']),
 'CWE-287':('Improper authentication',['Identify the affected authentication interface.','Check vendor-described bypass conditions; authentication enabled is not proof of safety.']),
 'CWE-22':('Path traversal',['Identify the affected file/path interface.','Obtain vendor path-normalization, privilege and filesystem-scope evidence.']),
 'CWE-20':('Improper input validation',['Obtain a more specific vendor weakness/trigger description.','Identify the actual affected interface and required input properties.']),
}


def ids(value):
    if isinstance(value,(list,tuple,set)):return sorted({c for v in value for c in ids(v)})
    return sorted(set(re.findall(r'\bCWE-[1-9]\d*\b',str(value or '').upper())))


def context(cve,*,nvd=None,corpus_cwe=None,supplied=None):
    nvd=nvd or {};sources={}
    for label,value,url in [('NVD',nvd.get('cwes',[]),'https://nvd.nist.gov/vuln/detail/'+cve),
                            ('corpus',corpus_cwe,None),('request',supplied,None)]:
        for c in ids(value):sources.setdefault(c,[]).append({'source':label,'url':url})
    entries=[]
    for c,origin in sorted(sources.items()):
        name,questions=PROFILES.get(c,(c,['Obtain the vendor-specific trigger and affected-feature evidence for this weakness.']))
        entries.append({'id':c,'name':name,'definition_url':'https://cwe.mitre.org/data/definitions/'+c[4:]+'.html',
                        'sources':origin,'review_questions':questions,
                        'classification_only':True,'can_refute':False,
                        'mapping_specificity':'broad' if c=='CWE-20' else 'as_reported'})
    return {'status':'available' if entries else 'unknown','entries':entries,'can_refute':False,
            'note':'CWE describes a weakness class, not this CVE\'s complete exploitation conditions. No CWE-derived review question changes VEX status.'}
