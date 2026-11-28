"""Generic source collection and scope/integrity regressions, without live HTTP."""
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import pytest
from src.item4.analysis import cve_reference_sources as R
from src.item4.workflow import source_analysis_jobs as Q


def csaf(cve,text,other=None):
    vulns=[dict(cve=cve,notes=[dict(category='summary',text=text)])]
    if other:vulns.append(dict(cve=other,notes=[dict(category='summary',text='Other product needs physical access.')]))
    return dict(document=dict(csaf_version='2.0',notes=[dict(category='summary',text='Shared document context must not leak across CVEs.')]),vulnerabilities=vulns)


@pytest.mark.parametrize('cve',['CVE-2026-9876543','CVE-2025-888888'])
def test_new_cve_outside_fixed_population_discovers_cna_and_vendor_advisory(cve,tmp_path,monkeypatch):
    api='https://cveawg.mitre.org/api/cve/'+cve;vendor='https://vendor.example/security/advisory.json'
    cna=dict(cveMetadata=dict(cveId=cve,state='PUBLISHED'),containers=dict(cna=dict(
        descriptions=[dict(lang='en',value='An Acme gateway has a vulnerability.')],references=[dict(url=vendor,tags=['vendor-advisory'])])))
    docs={api:cna,vendor:csaf(cve,'Exploitation requires the diagnostic service enabled.')};calls=[]
    def fetch(url):calls.append(url);return json.dumps(docs[url]).encode(),'application/json',url
    rows,receipt=R.collect(cve,fetcher=fetch,cache=tmp_path,network=True)
    assert calls==[api,vendor]
    assert any('diagnostic service enabled' in s['text'] for s in rows)
    assert all(s['cve_binding']==cve for s in rows)
    assert not any('confidence' in s or 'prerequisites' in s for s in rows)
    for s in rows:R.verify(s)
    assert receipt['complete'] is False


def test_multi_cve_advisory_never_assigns_shared_summary_or_other_cve_note():
    rows=R.csaf_sources('CVE-2026-11111',csaf('CVE-2026-11111','Target service requires authentication.','CVE-2026-22222'),'https://vendor.example/a','x','h')
    assert len(rows)==1 and rows[0]['text']=='Target service requires authentication.'
    assert rows[0]['provenance']['locator']['pointer']=='/vulnerabilities/0/notes/0/text'


def test_remediation_is_not_a_prerequisite_source():
    doc=csaf('CVE-2026-11111','Target input is described.')
    doc['vulnerabilities'][0]['notes'].append(dict(category='description',title='Mitigation',text='Disable FTP.'))
    rows=R.csaf_sources('CVE-2026-11111',doc,'https://vendor.example/a','x','h')
    assert all('Disable FTP' not in s['text'] for s in rows)


def test_pdf_uses_only_target_cve_description_and_stops_at_mitigation():
    cve='CVE-2026-11111'
    texts=[cve+'\nVulnerability Description\nThe diagnostic input receives requests.\nMitigation\nDisable FTP.',
           cve+' and CVE-2026-22222\nDescription\nAmbiguous shared passage.',
           'CVE-2026-22222\nDescription\nOther CVE requires local access.']
    pages=[SimpleNamespace(extract_text=lambda t=t:t) for t in texts]
    with patch('pypdf.PdfReader',return_value=SimpleNamespace(pages=pages)):
        rows=R.document_sources(cve,b'%PDF-fixture','application/pdf','https://vendor.example/a.pdf','x','h')
    assert len(rows)==1 and rows[0]['text']=='The diagnostic input receives requests.'
    assert rows[0]['provenance']['locator']['page']==1


def test_html_multi_cve_sections_cannot_leak_or_import_mitigation():
    raw=b'<main><h1>Advisory CVE-2026-11111 and CVE-2026-22222</h1><h2>CVE-2026-11111</h2><p>Target diagnostic input.</p><h2>Mitigation</h2><p>Disable FTP.</p><h2>CVE-2026-22222</h2><p>Other CVE requires local access.</p></main>'
    rows=R.document_sources('CVE-2026-11111',raw,'text/html','https://vendor.example/a','x','h')
    # The document title is shared; its empty body is ignored.
    assert len(rows)==1 and rows[0]['text']=='Target diagnostic input.'


def test_network_failure_is_retained_and_does_not_generate_facts(tmp_path):
    def offline(url):raise OSError('unavailable')
    rows,receipt=R.collect('CVE-2026-9876543',fetcher=offline,cache=tmp_path,network=True)
    assert rows==[] and receipt['attempts'][0]['status']=='failed'


def test_changed_raw_document_or_passage_is_rejected(tmp_path):
    cve='CVE-2026-9876543';url='https://vendor.example/a'
    info=R.ingest(url,json.dumps(csaf(cve,'Service is available.')).encode(),'application/json',cache=tmp_path)
    rows,_=R.collect(cve,cache=tmp_path,network=False);assert rows
    bad=deepcopy(rows[0]);bad['text']='Invented condition.'
    with pytest.raises(ValueError,match='passage'):R.verify(bad)
    Path(info['raw_path']).write_bytes(b'changed')
    with pytest.raises(ValueError,match='bytes changed'):R.verify(rows[0])


def test_missing_local_description_does_not_stop_generic_collection(monkeypatch):
    cve='CVE-2026-9876543'
    row=R._source(cve,'The diagnostic interface is available.','https://vendor.example/a','x','h',dict(pointer='/x'))
    with (patch.object(Q,'description_packet',return_value=dict(cve=cve,status='unresolved',reason='No local description')),
         patch.object(Q.descriptions,'detail',side_effect=KeyError('outside population')),
         patch.object(Q.references,'collect',return_value=([row],dict(cve=cve,source_count=1,attempts=[])))):
        packet,receipt=Q.evidence_packet(cve)
    assert packet['sources']==[row] and packet['products']==[] and 'status' not in packet


def test_model_failure_keeps_collected_sources_and_receipt():
    cve='CVE-2026-9876543';packet=dict(cve=cve,products=[],sources=[{'id':'pinned-source'}])
    receipt=dict(cve=cve,source_count=1,attempts=[])
    with (patch.object(Q,'evidence_packet',return_value=(packet,receipt)),
          patch.object(Q.vep,'resolve',side_effect=ValueError('model unavailable'))):
        result=Q.extract_description(cve)
    assert result['status']=='unresolved' and result['extraction_state']=='extraction_failed'
    assert result['evidence_packet']==packet and result['source_collection']==receipt


def test_empty_local_description_still_collects_additional_evidence():
    cve='CVE-2026-9876543';rows=[dict(id='extra',text_sha256='hash')]
    with (patch.object(Q.descriptions,'detail',return_value=dict(description='',original_nvd_status='Analyzed')),
          patch.object(Q.population,'get',return_value=None),
          patch.object(Q.references,'collect',return_value=(rows,dict(source_count=1))) as collector):
        packet,_=Q.evidence_packet(cve)
    collector.assert_called_once()
    assert packet['sources']==rows


def test_authoritative_rejection_cannot_be_overridden_by_cached_advisory(tmp_path):
    cve='CVE-2026-9876543'
    R.ingest('https://vendor.example/a',json.dumps(csaf(cve,'Old advisory requires HTTP enabled.')).encode(),'application/json',cache=tmp_path)
    R.ingest('https://cveawg.mitre.org/api/cve/'+cve,json.dumps(dict(cveMetadata=dict(cveId=cve,state='REJECTED'))).encode(),'application/json',cache=tmp_path)
    rows,receipt=R.collect(cve,cache=tmp_path,network=False)
    assert rows==[] and receipt['cve_record_state']=='REJECTED'


@pytest.mark.parametrize('url',['http://example.com/a','https://localhost/a','https://u:p@example.com/a','https://example.com:8100/a'])
def test_reference_urls_cannot_read_private_or_credentialed_endpoints(url):
    with pytest.raises(ValueError):R.public_url(url)


@pytest.mark.parametrize('cve,bom_format',[
    ('CVE-2026-9876543','CycloneDX'),('CVE-2025-888888','SPDX')])
def test_unseen_bom_cve_reaches_v2_and_v3_from_collected_evidence(cve,bom_format,tmp_path):
    """Real handoffs; model responses are synthetic, not model accuracy evidence."""
    from src.item4.analysis import exploitation_prerequisites as V
    from src.item4.assets import asset_observations as A
    from tests.item4.test_item4_asset_key_workflow import fixture_job,generate_fixture_questions
    job,_=fixture_job()
    text='Exploitation requires HTTP enabled.'
    R.ingest('https://vendor.example/new-advisory',json.dumps(csaf(cve,text)).encode(),
             'application/json',cache=tmp_path)
    sources,receipt=R.collect(cve,cache=tmp_path,network=False)
    source=next(s for s in sources if s['text']==text)
    draft=deepcopy(job['conditions'][0]['prerequisite']['draft']);draft['cve']=cve
    for atom in draft['prerequisites']:
        atom['source_refs']=[dict(source_id=source['id'],quote=text)]
    for scenario in draft['scenarios']:
        scenario.update(product_keys=[],product_binding='unresolved',source_refs=deepcopy(draft['prerequisites'][0]['source_refs']))
    received=[]
    def model(packet):
        received.append(packet);V.validate(draft,packet)
        artifact=dict(draft=draft,source_record_sha256=V.digest(packet))
        artifact['sha256']=V.digest(artifact);return artifact
    if bom_format=='CycloneDX':
        bom=deepcopy(job['input_bom']);bom['vulnerabilities'][0]['id']=cve
    else:
        bom=dict(spdxVersion='SPDX-2.3',documentDescribes=['asset'],packages=[
            dict(SPDXID='asset',name='Unseen gateway',versionInfo='1.0',cves=[cve])])
        job['asset_classification']=dict(status='unresolved',asset_type_id=None,
            reason='Previously unseen asset type')
    components,declared=Q.inventory(bom)
    assert [x['cve'] for x in declared]==[cve]
    with (patch.object(Q,'description_packet',return_value=dict(cve=cve,status='unresolved')),
          patch.object(Q.descriptions,'detail',side_effect=KeyError('outside population')),
          patch.object(Q.references,'collect',return_value=(sources,receipt)),
          patch.object(Q.vep,'resolve',side_effect=model)):
        result=Q.extract_declared(cve,components)
    assert received and result['status']=='extracted'
    job.update(input_bom=bom,bom_sha256=Q.digest(bom),declared_cves=declared,conditions=[result])
    generate_fixture_questions(job);A.prepare(job,Q.digest)
    assert len(job['asset_questions'])==1
    assert job['asset_questions'][0]['cve']==cve
    if bom_format=='SPDX':assert job['asset_questions'][0]['asset_type_id'] is None
