import json,hashlib
from src.source_mapping_assist import apply


def test_mapping_proposal_binds_current_bytes_without_promoting_clearance_authority(tmp_path):
    source=tmp_path/'source';source.mkdir();file=source/'unit.c';file.write_text('int target(void){return 1;}')
    reports=tmp_path/'proposals';reports.mkdir()
    report={'cve':'CVE-2099-12345','mapping_contract_valid':True,
        'function_packet':{'functions':[{'id':'F1','name':'target','file':'unit.c','source_sha256':hashlib.sha256(file.read_bytes()).hexdigest()}]},
        'mapping_output':{'prediction':{'mappings':[{'function_id':'F1','relation':'uncertain'}]}}}
    (reports/'CVE-2099-12345.source.json').write_text(json.dumps(report))
    original={'cve':'CVE-2099-12345','functions':[],'llm_candidate_functions':[]}
    case=apply([original.copy()],source,reports)[0]
    assert case==original  # Even byte-matched historical model proposals are retired.
    file.write_text('int other(void){return 2;}')
    case=apply([original.copy()],source,reports)[0]
    assert case['llm_candidate_functions']==[]
    assert 'source_mapping_assistance' not in case
