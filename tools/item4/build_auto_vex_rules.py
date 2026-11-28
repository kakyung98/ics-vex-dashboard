"""Pin vendor sources and explicitly compile operational predicates. No LLM.

This is a small audited rule registry, not a claim that every English CVE can
be parsed safely. Unsupported CVEs remain in the target population as unknown.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,urllib.request,re
from bs4 import BeautifulSoup
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'data/nist_auto_vex'
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def main():
    OUT.mkdir(parents=True,exist_ok=True);sources={}
    for key,url in [('ossl_jun','https://openssl-library.org/news/secadv/20140605.txt'),('heartbleed','https://openssl-library.org/news/secadv/20140407.txt'),('ossl_jan','https://openssl-library.org/news/secadv/20150108.txt'),('pan','https://security.paloaltonetworks.com/CVE-2024-3400')]:
        path=OUT/(key+'.json')
        if path.exists():source=json.loads(path.read_text(encoding='utf-8'))
        else:
            with urllib.request.urlopen(url,timeout=30) as response:raw=response.read().decode('utf-8')
            text=BeautifulSoup(raw,'html.parser').get_text(' ',strip=True) if key=='pan' else raw
            source=dict(url=url,text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest(),retrieved_at=datetime.now(timezone.utc).isoformat())
            path.write_text(json.dumps(source,ensure_ascii=False,indent=2),encoding='utf-8')
        assert hashlib.sha256(source['text'].encode()).hexdigest()==source['text_sha256'];sources[key]=source
    def ref(key,quote):
        text=sources[key]['text'];start=text.index(quote)
        return dict(source_id=key,url=sources[key]['url'],source_sha256=sources[key]['text_sha256'],span=[start,start+len(quote)],quote=quote)
    def section(cve,key):
        text=sources[key]['text'];start=text.index(cve);end=text.find('\n\n',start)
        # Use the complete advisory with exact spans for prerequisite and fix clauses.
        return ref(key,text[start:end if end!=-1 else len(text)])
    def atom(id,label,field,key,quote,values=None,yes=None,absence='complete'):
        options=values or {'enabled':'Enabled','disabled':'Disabled','unknown':'Unknown / not verified','conflicting':'Conflicting records'}
        return dict(id=id,label=label,nist_fields=[field],options=options,true_values=yes or ['enabled'],false_values=[v for v in options if v not in (yes or ['enabled']) and v not in ('unknown','conflicting','mixed')],absence_coverage=absence,source=ref(key,quote),evidence_kinds=['configuration_record','vendor_document','assessment_record'])
    leaf=lambda id:dict(condition=id)
    AND=lambda *ids:dict(op='and',args=[leaf(i) for i in ids])
    OR=lambda *ids:dict(op='or',args=[leaf(i) for i in ids])
    fixed={'0.9.8':'za','1.0.0':'m','1.0.1':'h'}
    rules={}
    def rule(cve,key,floors,questions,expr,quote,complete=True):
        x=dict(cve=cve,product='OpenSSL',product_aliases=['openssl','openssl library','openssl project openssl','openssl openssl'],version_scheme='openssl_letter',fixed_releases=floors,questions=questions,expression=expr,coverage_complete=complete,source=ref(key,quote),fix_sources=[],review_basis='Explicit vendor scope and remediation translated to typed predicates; independent expert validation outstanding.')
        # Fix statements are pinned verbatim; thresholds are not inferred from NVD scores.
        for branch,suffix in floors.items():
            target=branch+suffix
            match=re.search(r'OpenSSL '+re.escape(branch)+r'[^\n]*upgrade to '+re.escape(target)+r'\.',sources[key]['text'])
            if not match:raise ValueError('Missing vendor fix clause: '+target)
            x['fix_sources'].append(ref(key,match.group()))
        rules[cve]=x
    q='This flaw only affects multithreaded applications using OpenSSL 1.0.0\nand 1.0.1, where SSL_MODE_RELEASE_BUFFERS is enabled, which is not the\ndefault and not common.'
    rule('CVE-2010-5298','ossl_jun',{'1.0.0':'m','1.0.1':'h'},[
        atom('release_buffers','Is SSL_MODE_RELEASE_BUFFERS enabled on this OpenSSL instance?','C13-02.02','ossl_jun',q),
        atom('multithreaded','Does the application using this instance run with multiple threads?','C13-02.02','ossl_jun',q,{'multi':'Multithreaded','single':'Single-threaded','mixed':'Both / scope unresolved','unknown':'Unknown','conflicting':'Conflicting records'},['multi'])],AND('multithreaded','release_buffers'),q)
    q='This flaw\nonly affects OpenSSL 1.0.0 and 1.0.1 where SSL_MODE_RELEASE_BUFFERS is\nenabled, which is not the default and not common.'
    rule('CVE-2014-0198','ossl_jun',{'1.0.0':'m','1.0.1':'h'},[atom('release_buffers','Is SSL_MODE_RELEASE_BUFFERS enabled on this OpenSSL instance?','C13-02.02','ossl_jun',q)],leaf('release_buffers'),q)
    role={'client':'TLS client','server':'TLS server only','both':'Both client and server','none':'Neither role','mixed':'Scope unresolved','unknown':'Unknown','conflicting':'Conflicting records'}
    q='OpenSSL TLS clients enabling anonymous ECDH ciphersuites are subject to a\ndenial of service attack.'
    rule('CVE-2014-3470','ossl_jun',fixed,[atom('tls_client','Which TLS role does this instance perform?','C16-06.02','ossl_jun',q,role,['client','both']),atom('anonymous_ecdh','Are anonymous ECDH ciphersuites enabled for this TLS client?','C13-02.02','ossl_jun',q)],AND('tls_client','anonymous_ecdh'),q)
    q='Only applications using OpenSSL as a DTLS client are affected.'
    rule('CVE-2014-0221','ossl_jun',fixed,[atom('dtls_role','Which DTLS role does this OpenSSL instance perform?','C16-06.02','ossl_jun',q,{'client':'DTLS client','server':'DTLS server only','both':'DTLS client and server','none':'DTLS is not used','mixed':'Scope unresolved','unknown':'Unknown','conflicting':'Conflicting records'},['client','both'])],leaf('dtls_role'),q)
    q='Only applications using OpenSSL as a DTLS client or server affected.'
    rule('CVE-2014-0195','ossl_jun',fixed,[atom('dtls_client','Is this OpenSSL instance used as a DTLS client?','C16-06.02','ossl_jun',q),atom('dtls_server','Is this OpenSSL instance used as a DTLS server?','C16-06.02','ossl_jun',q)],OR('dtls_client','dtls_server'),q)
    q='Users unable to immediately\nupgrade can alternatively recompile OpenSSL with -DOPENSSL_NO_HEARTBEATS.'
    # The public advisory explicitly identifies 1.0.1 through 1.0.1f and a fix in 1.0.1g.
    x=dict(cve='CVE-2014-0160',product='OpenSSL',product_aliases=['openssl','openssl library','openssl project openssl','openssl openssl'],version_scheme='openssl_letter',fixed_releases={'1.0.1':'g'},questions=[atom('heartbeat_support','Does the deployed build include TLS heartbeat support? Check build/vendor records, not heartbeat traffic volume.','C16-06.02','heartbleed',q,{'included':'Heartbeat support included','excluded_build':'Build excludes heartbeats with OPENSSL_NO_HEARTBEATS','unknown':'Unknown','conflicting':'Conflicting records'},['included'])],expression=leaf('heartbeat_support'),coverage_complete=True,source=ref('heartbleed','Only 1.0.1 and 1.0.2-beta releases of OpenSSL are affected including\n1.0.1f and 1.0.2-beta1.'),fix_sources=[ref('heartbleed','Affected users should upgrade to OpenSSL 1.0.1g.')],review_basis='Vendor build exclusion; beta/prerelease versions are deliberately unsupported.')
    rules[x['cve']]=x
    q='When openssl is built with the no-ssl3 option and a SSL v3 ClientHello is\nreceived the ssl method would be set to NULL which could later result in\na NULL pointer dereference.'
    # SSLv3 being disabled is a prerequisite here, not a mitigation. No attacker-packet question.
    rule('CVE-2014-3569','ossl_jan',{'0.9.8':'zd','1.0.0':'p','1.0.1':'k'},[atom('ssl3_build_support','Does this deployed OpenSSL build include SSLv3 support?','C16-06.02','ossl_jan',q,{'enabled':'SSLv3 support included in the build','disabled':'Built with no-ssl3','unknown':'Unknown','conflicting':'Conflicting records'},['enabled'])],dict(op='not',args=[leaf('ssl3_build_support')]),q)
    key='pan';q='This issue is applicable only to PAN-OS 10.2, PAN-OS 11.0, and PAN-OS 11.1 firewalls configured with GlobalProtect gateway or GlobalProtect portal (or both).'
    x=dict(cve='CVE-2024-3400',product='PAN-OS',product_aliases=['pan os','panos','palo alto networks pan os','paloalto pan os'],version_scheme='panos_hotfix',fixed_releases={'10.2':{'0':3,'1':2,'2':5,'3':13,'4':16,'5':6,'6':3,'7':8,'8':3,'9':1},'11.0':{'0':3,'1':4,'2':4,'3':10,'4':1},'11.1':{'0':3,'1':1,'2':3}},unaffected_branches=['9.0','9.1','10.0','10.1'],questions=[atom('gp_gateway','Is a GlobalProtect gateway configured? Inspect Network > GlobalProtect > Gateways.','C13-02.02',key,q,{'configured':'At least one gateway is configured','none':'No gateway entries in the complete configuration','unknown':'Unknown','conflicting':'Conflicting records'},['configured']),atom('gp_portal','Is a GlobalProtect portal configured? Inspect Network > GlobalProtect > Portals.','C13-02.02',key,q,{'configured':'At least one portal is configured','none':'No portal entries in the complete configuration','unknown':'Unknown','conflicting':'Conflicting records'},['configured'])],expression=OR('gp_gateway','gp_portal'),coverage_complete=True,source=ref(key,q),fix_sources=[ref(key,'This issue is fixed in PAN-OS 10.2.9-h1, PAN-OS 11.0.4-h1, PAN-OS 11.1.2-h3, and in all later PAN-OS versions.')],nonrequirements=[ref(key,'Device telemetry does not need to be enabled for PAN-OS firewalls to be exposed to attacks related to this vulnerability.')],review_basis='Explicit vendor necessary/sufficient affected configuration; fixed thresholds checked against every listed maintenance release.')
    # Include the full vendor product table as provenance for the hotfix map.
    text=sources[key]['text'];start=text.index('Product Status');end=text.index('Required Configuration for Exposure',start)
    x['fix_sources'].append(ref(key,text[start:end]));rules[x['cve']]=x
    for cve in ['CVE-2010-5298','CVE-2014-0198']:rules[cve]['unaffected_branches']=['0.9.8']
    rules['CVE-2014-0160']['unaffected_branches']=['0.9.8','1.0.0']
    for cve in ['CVE-2014-3470','CVE-2014-0221','CVE-2014-0195']:
        for question in rules[cve]['questions']:
            if question['id'] in ('tls_client','dtls_role','dtls_client','dtls_server'):question['nist_fields']=['C13-08.02']
    for branch,patches in rules['CVE-2024-3400']['fixed_releases'].items():
        for patch,hotfix in patches.items():assert f'>= {branch}.{patch}-h{hotfix}' in sources['pan']['text']
    result=dict(version='source-bound-auto-vex-rules/1',sources={k:dict(file=k+'.json',url=s['url'],sha256=s['text_sha256']) for k,s in sources.items()},rules=rules,independently_expert_validated=False)
    result['sha256']=digest(result);(OUT/'rules.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(rules=len(rules),sha256=result['sha256'])))
if __name__=='__main__':main()
