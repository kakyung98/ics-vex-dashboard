"""English product copy for the integrated web UI; user input is never translated."""
import re

COPY={
 '시스템보안연구센터':'SSRC', '구성요소':'Components',
 '진입점 <b>':'Entry points: <b>',
 '상한에 걸려 일부만 처리했습니다: ':'Processing limit reached; some files were not indexed: ',
 '미입력 항목은 <b>모름</b>으로 처리되어 아무것도 해제하지 않습니다. ':'Missing values are treated as <b>unknown</b> and cannot clear a vulnerability. ',
 '&ldquo;이 빌드에 아예 없음&rdquo; 항목만 <span class="mono">not_affected</span>의 근거가 됩니다 — ':'Only structural absence can support <span class="mono">not_affected</span>. ',
 '설정으로 꺼둔 것은 완화로만 기록됩니다.':'A disabled setting is recorded as mitigation only.',
 '(상태를 바꾸지 않음)':'(does not change applicability)',
 'admin (관리자)':'Administrator','operator (취급자)':'Operator','none (없음)':'None',
 'SBOM에서 CVE 후보까지':'From SBOM to CVE candidates',
 '세 에이전트가 제품명·버전·CPE를 정리하고, NVD·CISA 근거로 후보를 조회합니다.':'Resolve component names, preserve versions, and retrieve candidates from NVD and CISA evidence.',
 '모델 정보 확인 중':'Checking model availability',
 '실험 모델 · 후보 식별용':'Experimental model · Candidate identification',
 'v2는 NVD 파생·합성 데이터로 학습했습니다. 실제 SBOM에서의 일반화 성능은 미검증이며, 결과는 최종 VEX 판정이 아닙니다. 후보가 없어도 안전함을 뜻하지 않습니다.':'v2 was trained on NVD-derived synthetic data. Generalization to real SBOMs is unverified. Candidate retrieval is not a final VEX judgment, and an empty result does not establish safety.',
 '01　SBOM 입력':'01  SBOM input','샘플 입력':'Load sample',
 'JSON 파일을 올리거나 끌어놓으세요':'Upload or drop a JSON file',
 'CycloneDX · SPDX / 구성요소 최대 100개':'CycloneDX · SPDX / Up to 100 components',
 'SBOM 파일 선택':'Choose an SBOM file',
 '실제 장비의 SBOM 파일을 입력할 수 있습니다. ‘샘플 입력’은 기능 확인을 위한 가상 SBOM입니다.':'Upload an SBOM from your asset or paste JSON below. The sample is synthetic and intended only to check the workflow.',
 'CVE 후보 식별 시작 →':'Identify CVE candidates →','결과 JSON 저장':'Download results JSON',
 '02　식별 방식':'02  Identification method',
 'Qwen v2 · 튜닝 에이전트 (실험)':'Qwen v2 · Fine-tuned agents (experimental)',
 'Qwen 기본 모델':'Qwen base model','기존 규칙 기반':'Rule-based baseline',
 '튜닝 모델은 로컬 GPU에서 실행합니다. 첫 실행에는 모델 로딩 시간이 필요합니다.':'Models run on the local GPU. The first request includes model loading time.',
 '03　취약점 근거 조회':'03  Evidence source',
 '로컬 NVD · CISA 수집본':'Local NVD + CISA snapshots',
 'NVD 온라인 + CISA 수집본':'Live NVD + local CISA snapshot',
 '조회 안 함 · 식별 유보':'No lookup · Defer identification',
 '제품 CPE와 제조사·제품명이 일치하는 CISA 권고를 조회합니다. 버전이 불명이어도 후보를 찾으며 영향 여부는 추가 확인으로 남깁니다.':'Look up product CPEs and CISA advisories with matching vendor and product phrases. Unknown versions allow candidate retrieval, but applicability remains unconfirmed.',
 'NVD API와 로컬 CISA 권고 자료를 조회합니다. NVD 요청 제한으로 수 분 이상 걸릴 수 있으며 조회 오류는 근거로 사용하지 않습니다.':'Query the NVD API and the local CISA advisory snapshot. Rate limits may add several minutes. Lookup failures are not evidence.',
 '근거 조회를 생략합니다. 모델이 제품을 제안해도 최종 식별은 유보됩니다.':'Skip evidence lookup. Model suggestions alone cannot establish product identity.',
 '에이전트 준비 상태':'Agent availability','저장된 가중치를 확인하고 있습니다.':'Checking saved adapter weights.',
 '제품명 정규화':'Name normalization','버전·리비전 보존':'Version preservation','버전 정규화':'Version normalization',
 'CPE 사전 검증':'CPE dictionary verification','CVE 후보 조회':'CVE candidate retrieval',
 '분석 진행 상태':'Analysis progress','SBOM을 입력하고 식별을 시작하세요.':'Provide an SBOM to begin identification.',
 '식별 결과':'Identification results','전체 결과 JSON 보기':'View full result JSON',
 '분석 진행 중…':'Analysis in progress…','구성요소 ${a.length}개':'${a.length} components',
 '기능 확인용 가상 SBOM · curl 구성요소 1개':'Synthetic workflow sample · One curl component',
 '모델 준비 / 구성요소 분석':'Preparing model / Processing component',
 '분석 경로 확인':'Checking workflow / Preparing model',
 'L2 제품명 정규화 완료':'L2 name normalization completed',
 'L3 버전 정규화 완료':'L3 version normalization completed',
 'L4 CPE 후보 검증 완료':'L4 CPE verification completed',
 '식별 근거 검증 완료':'Identity evidence checked','CVE 조건 대조 완료':'CVE condition evaluation completed',
 '구성요소 처리 완료':'Component processed','다른 작업 완료를 기다리고 있습니다':'Waiting for the current task to finish',
 '가중치 준비됨':'Weights available','가중치 확인 필요':'Weights unavailable',
 '제품명 정규화':'Name normalization','CPE 식별':'CPE identification','준비됨':'Ready','미준비':'Unavailable',
 '역할별 학습':'Training per agent:','합성 검증':'Synthetic validation','합성 시험':'Synthetic test',
 '건. 실제 SBOM 평가와 구분합니다.':' examples. These results do not measure real-SBOM performance.',
 '모델 상태 조회 실패':'Could not retrieve model status',
 '이름 없음':'Unnamed component','버전 미기재':'Version not provided','분석 오류':'Analysis error',
 'NVD 제품 확인':'NVD product identified','CISA 권고 연결 · CPE 미확인':'CISA advisory linked · CPE unconfirmed',
 '식별 유보':'Identification deferred','L2 · 제품명 제안':'L2 · Name suggestion',
 'L3 · 설치 버전':'L3 · Installed version','L4 · NVD CPE 식별':'L4 · NVD CPE identity',
 '미확인 / 유보':'Unconfirmed / Deferred','미실행 · 앞 단계가 미확정':'Not executed · Upstream stage unresolved',
 '실행 기록 없음':'No execution record','실행됨':'Executed',
 ' · 입력 버전이 없어 유보':' · Deferred: installed version unknown',
 ' · NVD 후보 ':' · NVD candidates: ','개${!valid?':'${!valid?',
 ' · 식별 유보':' · Identity deferred',
 '모델 출력을 확정 근거로 수용하지 않음':'Model output not accepted as conclusive evidence',
 '모델 출력 포함':'Model response available','모델 출력 보기':'View model response',
 '설치 버전 미확인: 제품·권고 근거로 후보를 조회하되 영향 여부는 유보합니다.':'Installed version is unknown. Product/advisory candidates are retrieved without confirming applicability.',
 'CPE 확인 유보 근거:':'CPE deferral reason:',
 'CISA 권고의 제조사·제품명 일치 근거 (NVD CPE 확인과 별도)':'CISA vendor/product phrase evidence (separate from NVD CPE verification)',
 '이 경로에서 확인된 CVE 후보가 없습니다. 식별 유보와 자료 범위를 확인하세요. 취약점이 없다는 판정은 아닙니다.':'No CVE candidates were retrieved through this path. Review unresolved identities and source coverage. This is not a finding of no vulnerabilities.',
 '조건 대조':'Condition assessment','근거 출처':'Evidence source','식별자 없음':'Identifier unavailable',
 '제품·버전 조건 일치':'Product/version conditions match','조건 범위 외':'Outside condition range',
 '영향 여부 추가 확인':'Applicability unconfirmed','후보 더 보기':'Show more candidates',
 '구성요소–CVE 후보 ${records.length}건':'${records.length} component–CVE candidates',
 'CISA 권고 연결은 제조사·제품명에 근거한 후보 조회입니다. 설치 버전의 영향 여부나 NVD CPE 식별을 확정하지 않습니다.':'CISA links are candidates based on vendor/product phrases. They do not confirm installed-version applicability or NVD CPE identity.',
 '일부 구성요소의 분석이 실패했습니다. 각 오류를 확인하세요.':'Some components could not be processed. Review their individual errors.',
 'CISA 권고 연결':'CISA advisory links','고유 CVE 후보':'Unique CVE candidates','구성요소–CVE 연결':'Component–CVE links',
 '규칙 기반':'Rules','Qwen 기본':'Qwen base','튜닝 Qwen':'Fine-tuned Qwen',
 "+'초'":"+'s'",'건 · ':' examples · ',"'개'":"''",
 '개 처리':' processed','분석 실패:':'Analysis failed:',
 '분석 완료 ·':'Analysis completed ·',' · 오류 ':' · Errors: ',
 '작업 상태 조회 실패:':'Could not retrieve task status:',
 'SBOM은 JSON 객체여야 합니다.':'The SBOM must be a JSON object.',
 '작업을 등록하고 있습니다…':'Submitting identification task…','입력을 확인하세요:':'Check your input:',
 'SBOM JSON':'SBOM JSON',
 '1단계 · SBOM → CVE 후보 식별':'Step 1 · SBOM → CVE candidates',
 'SBOM → L2/L3/L4 식별 → CVE 후보 → 소스코드 또는 운영 맥락에 근거한 VEX 검토':'SBOM → L2/L3/L4 identification → CVE candidates → Evidence-based VEX review',
 '2단계 VEX 검토를 위한 후보와 근거를 연결하는 중…':'Preparing candidate evidence for Step 2 · VEX review…',
 '후보 연결 실패':'Candidate handoff failed',
 '2단계 · 식별 후보 → VEX 검토':'Step 2 · CVE candidates → VEX review',
 '이 단계는 방금 식별한 후보만 전달받습니다. 기존 매처를 다시 실행하거나 SBOM에 들어 있는 취약점 정답을 가져오지 않습니다.':'This step uses only the candidates identified above. It does not rerun the legacy matcher or import vulnerability answers from the input SBOM.',
 '전달할 CVE 후보가 없습니다. 위의 식별 근거와 유보 사유를 확인하세요.':'No candidates are available for VEX review. Check the identification evidence and deferral reasons above.',
 '고유 CVE ':'Unique CVEs: ','개 · 구성요소 연결 ':' · Component links: ',
 '건. 후보의 초기 VEX 상태는 모두 under_investigation입니다.':'. Initial VEX status is under_investigation for every candidate.',
 '설치 버전 근거':'Installed-version evidence','초기 VEX':'Initial VEX',
 'NVD 제품·버전 조건 확인':'NVD product/version conditions verified',
 '미확인 — 추가 근거 필요':'Unconfirmed — more evidence required',
 'VEX 연결 실패:':'VEX handoff failed:',
 '2단계 · 판정 근거 선택':'Step 2 · Select VEX evidence',
 '이 자산 소프트웨어의 <b>소스코드</b>를 가지고 계신가요? ':'Do you have the <b>source code</b> for this asset? ',
 '소스가 있으면 호출그래프·CFG로 판정하고, 없으면 자산 운영정보로 공격 전제조건을 대조합니다.':'Review patch, build and source evidence when source is available, or compare attack prerequisites with asset operational context.',
 '예 — 소스코드 ZIP 업로드':'Yes — Upload source ZIP','아니오 — 자산 운영정보 입력':'No — Enter operational context',
 '소스코드 ZIP — 제품 소스 트리를 통째로 압축해 올려주세요':'Source ZIP — Upload the product source tree',
 '이 ZIP이 <b>제품 소스 전체</b>입니다':'This ZIP contains the <b>complete product source tree</b>',
 '체크하지 않으면 &ldquo;함수를 찾지 못함&rdquo;이 &ldquo;올리지 않음&rdquo;과 ':'Without this declaration, a function not found cannot be distinguished from an omitted file. ',
 '구분되지 않아 해당 판정을 유보합니다.':'The corresponding conclusion will be deferred.',
 '업로드 후 분석 ▶':'Upload and index source ▶','파일 ':'Files: ','함수 ':'Functions: ',
 '간접 호출 자리 ':'Indirect call sites: ','CFG로 VEX 판정 ▶':'Evaluate VEX using source/CFG ▶',
 '자산 운영정보 양식을 불러오는 중…':'Loading the operational context form…',
 'ZIP 파일을 선택해주세요':'Choose a ZIP file first','업로드·색인 중… (큰 트리는 시간이 걸립니다)':'Uploading and indexing… Large source trees may take longer.',
 '업로드 실패 ':'Upload failed: ','판정 중…':'Evaluating evidence…','판정 실패 ':'Evaluation failed: ',
 '운영맥락으로 VEX 판정 ▶':'Evaluate VEX using operational context ▶',
 '— 미입력 —':'— Unknown / not provided —','>예</option>':'>Yes</option>','>아니오</option>':'>No</option>',
 '쉼표로 구분 — 비워두면 미입력':'Comma-separated values; leave blank when unknown',
 '출처: ':'Source: ','코드 근거':'Source-code evidence','운영맥락 근거':'Operational context evidence',
 '전체 <b>':'Total <b>','판정 <b>':'Decided <b>','유보 <b>':'Deferred <b>',
 '정당화':'Justification','근거':'Evidence',
}


def english_ui(text):
    for original,translated in sorted(COPY.items(),key=lambda item:-len(item[0])):
        text=text.replace(original,translated)
    return text


GROUPS={'identity':'Asset identity','oc1':'OC1 · Functions and code execution',
        'oc2':'OC2 · Communication protocols','oc3':'OC3 · Attack-path accessibility',
        'oc4':'OC4 · Authentication and privileges','oc5':'OC5 · Configuration and execution prerequisites',
        'priority':'Remediation priority (separate from applicability)'}

FIELD_LABELS={
 'vendor_id':'Manufacturer','product_id':'Model','firmware_version':'Firmware / software version',
 'os_name':'Operating system','os_version':'OS version','running_services':'Running services',
 'running_services_absent':'Services absent from this build','enabled_features':'Enabled features / modules',
 'enabled_features_absent':'Features absent from this build','asset_role_type':'Asset role / type',
 'active_protocols':'Active communication protocols','supported_protocols':'Supported but inactive protocols',
 'protocols_absent':'Protocol stacks absent from this build','primary_communication_method':'Primary communication medium',
 'network_interfaces':'Installed network interfaces','no_network_interface':'No network interface is installed',
 'listening_ports':'Listening ports','network_zone':'Network zone','vlan_id':'VLAN ID','reachable_from':'Reachable from',
 'path_controls':'Attack-path controls','authentication_enabled':'Authentication required',
 'anonymous_access_allowed':'Anonymous access allowed','effective_privileges':'Effective privileges',
 'no_account_subsystem':'No account subsystem exists on this interface','interactive_operator':'Interactive operator present',
 'config_settings':'CVE-specific configuration','physical_or_virtual':'Physical / virtual deployment',
 'hypervisor':'Hypervisor','asset_criticality':'Asset criticality','availability_tolerance':'Availability tolerance',
 'safety_function':'Safety function',
}

HELP={
 'running_services':'List services that are actually running, not merely installed.',
 'running_services_absent':'Use only for services not included in the firmware/image. Disabled services are not absent.',
 'enabled_features':'List enabled features such as web management or an OPC UA server.',
 'enabled_features_absent':'Use only for features omitted from the build or product specification.',
 'active_protocols':'Protocols carrying actual traffic, such as Modbus/TCP, DNP3, OPC UA or HTTP.',
 'supported_protocols':'Available stacks currently disabled; this is mitigation, not structural absence.',
 'protocols_absent':'Use only when the protocol stack is not implemented in this firmware.',
 'no_network_interface':'A hardware property. Leave unknown unless absence has been verified.',
 'no_account_subsystem':'This is different from disabling authentication or denying an account.',
 'authentication_enabled':'Authentication for the specific vulnerable service or feature.',
 'anonymous_access_allowed':'Whether unauthenticated access to the relevant feature is allowed.',
 'effective_privileges':'Privileges actually held by the relevant access principal.',
 'config_settings':'Enter key=value pairs for relevant configuration, not assumptions.',
 'asset_criticality':'Used for remediation priority, not as proof of exploitability.',
}


def english_groups(groups):
    for group in groups:
        group['label']=GROUPS.get(group['group'],group['group'])
        for field in group['fields']:
            field['label']=FIELD_LABELS.get(field['key'],field['key'].replace('_',' ').capitalize())
            field['help']=HELP.get(field['key'],'Leave blank when the value is unknown. Use verified asset information.')
            if field.get('source','').startswith('EXTENDED'):
                field['source']='Extended field: configuration backup, vendor hardening guidance or on-site verification'
            else:
                field['source']=field.get('source','').replace('(파생)','(derived)').replace('(확장)','(extended)')
    return groups


def english_statement(statement):
    # Keep the original diagnostic for audit; render a structured English account.
    if re.search('[가-힣]',statement.get('reason','')):
        statement['reason_original']=statement['reason']
        if statement.get('identification_gate'):
            reason='Operational prerequisites are satisfied, but product/version applicability remains unconfirmed.'
        elif '제품 전체' in statement['reason']:
            reason='The uploaded tree was not declared complete. Missing functions cannot establish code absence.'
        elif '취약 함수를 특정' in statement['reason']:
            reason='The vulnerable function could not be identified from the available CVE evidence.'
        elif '간접 호출' in statement['reason']:
            reason='Indirect calls leave the call graph incomplete; missing paths do not prove unreachability.'
        elif statement.get('missing'):
            reason='Evidence is missing for the required attack prerequisites. Review the missing conditions.'
        else:
            reason={'affected':'The available evidence satisfies the evaluated attack prerequisites.',
                    'not_affected':'The supplied evidence refutes an evaluated attack prerequisite; review the justification and scope.',
                    'fixed':'Remediation is supported by the supplied evidence.',
                    'under_investigation':'The available evidence is insufficient for a conclusive VEX judgment.'}.get(statement['status'],'Review the evidence details.')
        statement['reason']=reason
    return statement
