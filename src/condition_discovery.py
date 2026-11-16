"""Source-span condition candidates and evidence demands, not a VEX judge.

Rule-assisted extraction precedes unsupervised grouping. The atomic schema is
researcher defined; it is NOT the old weakness or workflow label set. Absence of
a match means unknown. A matched condition is not a proven necessary condition.
"""
import hashlib
import re


def atom(key, axis, pattern, records, question):
    return dict(key=key, axis=axis, pattern=pattern, evidence_demands=records,
                question=question, necessity='not_established', can_refute=False)


ATOMS = [
    atom('access.remote_actor','access',r'\bremote (?:authenticated |unauthenticated )?(?:attackers?|users?|adversar(?:y|ies))\b',
         ['input_sources','ingress_paths'],'원문의 원격 공격자가 입력에 영향을 주는 실제 경로는 무엇인가? 파일·정비자료 반입과 서비스 접속을 구분한다.'),
    atom('access.network_position','access',r'\b(?:with|requires?|must (?:have|obtain)) (?:\w+ ){0,3}network access\b|\baccess to (?:the )?(?:same|local) network\b',
         ['network_routes','maintenance_routes'],'원문이 요구하는 네트워크 위치와 정비·대체 연결을 포함한 접근 경로는 무엇인가?'),
    atom('access.adjacent','access',r'\b(?:same (?:local )?(?:network|subnet|broadcast domain)|adjacent (?:network|attacker)|network.adjacent|local network segment)\b',
         ['network_segments','layer2_controls'],'같은 네트워크·서브넷에 접근 가능한 주체와 분리 구성은 무엇인가?'),
    atom('access.local_actor','access',r'\blocal (?:authenticated |unprivileged |privileged )?(?:attackers?|users?|adversar(?:y|ies))\b',
         ['host_accounts','host_access'],'해당 호스트에 로컬로 접근할 수 있는 계정과 실행 경로는 무엇인가?'),
    atom('access.physical','access',r'\b(?:requires?|with|has|have|gain) physical access\b|\bphysically (?:accessible|accessing|present)\b',
         ['physical_ports','maintenance_procedures'],'원문이 지정한 물리 포트·장비에 접근할 수 있는 주체와 정비 절차는 무엇인가?'),
    atom('actor.authenticated','actor',r'\bauthenticated (?:remote |local )?(?:attackers?|users?|adversar(?:y|ies))\b|\b(?:requires?|requiring) authentication\b',
         ['account_roles','session_configuration'],'해당 기능에 필요한 로그인·세션·계정 역할은 무엇인가?'),
    atom('actor.unauthenticated','actor',r'\bunauthenticated (?:remote |local )?(?:attackers?|users?|adversar(?:y|ies))\b|\bwithout (?:any )?authentication\b|\brequires? no authentication\b|\bno authentication (?:is )?(?:required|needed)\b',
         ['authentication_configuration','invocation_permissions'],'원문이 인증 없이 입력·호출 가능하다고 설명한 기능과 실제 접근 주체는 무엇인가?'),
    atom('actor.no_privileges','actor',r'\brequires? no privileges\b|\bno privileges (?:are )?(?:required|needed)\b|\bwithout (?:prior |special |any )?privileges\b',
         ['account_roles','privilege_assignments'],'원문이 별도 권한 불필요로 설명한 기능의 실제 계정·역할 조건은 무엇인가? 인증 불필요와는 구분한다.'),
    atom('actor.valid_credentials','actor',r'\b(?:with|requires?|must (?:have|obtain|possess)) (?:a |the )?valid (?:credentials?|username|account|password)\b',
         ['account_roles','credential_access'],'원문이 요구하는 유효한 계정·사용자명·인증정보에 접근 가능한 주체는 누구인가?'),
    atom('actor.admin_required','actor',r'\b(?:privileged|administrative|administrator|root) (?:local )?(?:attackers?|users?)\b|\b(?:requires?|with|must have) (?:local )?(?:administrator|administrative|root) (?:access|privileges|permissions)\b',
         ['account_roles','privilege_assignments'],'공격 전에 필요한 관리자·특권 계정의 실제 부여·접근 범위는 무엇인가?'),
    atom('actor.unprivileged','actor',r'\b(?:unprivileged|non.administrative|non.administrator|low.privileged) (?:local )?(?:attackers?|users?)\b',
         ['account_roles','privilege_assignments'],'비관리자·낮은 권한 계정이 해당 기능을 호출할 수 있는 범위는 무엇인가?'),
    atom('interaction.required','interaction',r'\b(?:requires?|requiring) (?:a |an )?(?:authenticated )?user (?:interaction|action)\b|\buser interaction is required\b|\b(?:user|victim)s? (?:must|is required to) (?:open|click|visit|import|load|run)\b',
         ['operator_workflows','automatic_processing'],'원문이 요구하는 사용자 작업은 무엇이며 자동 처리·미리보기·정비 작업에도 같은 경로가 있는가?'),
    atom('interaction.none','interaction',r'\b(?:no|without) user interaction\b|\buser interaction is not (?:required|needed)\b',
         ['automatic_processing','service_exposure'],'사용자 작업 없이 처리되는 해당 기능·입력 경로의 실제 구성은 무엇인가?'),
    atom('interaction.logged_in_victim','interaction',r'\b(?:user|victim) (?:must|needs? to) be logged (?:in|into)\b|\b(?:authenticated|logged.in) (?:user|victim) (?:opens?|visits?|clicks?)\b',
         ['operator_workflows','session_configuration'],'원문이 요구하는 운영자의 로그인 상태와 화면·링크 이용 절차는 무엇인가?'),
    atom('input.file','input',r'\b(?:specially[ -]crafted|crafted|malicious|malformed|untrusted) (?:[\w.-]+ ){0,3}(?:files?|projects?|documents?|archives?|images?|fonts?)\b',
         ['file_ingress','file_processing_configuration'],'인용된 파일·프로젝트 형식의 반입 출처, 변경 가능한 주체와 처리 기능은 무엇인가?'),
    atom('input.request','input',r'\b(?:specially[ -]crafted|crafted|malicious|malformed) (?:[\w.-]+ ){0,3}(?:requests?|packets?|messages?|queries|payloads?)\b',
         ['message_sources','input_receiver_configuration'],'원문이 지정한 요청·패킷·메시지를 보낼 수 있는 주체와 실제 수신 기능은 무엇인가?'),
    atom('input.link','input',r'\b(?:malicious|crafted|untrusted) (?:web )?(?:links?|URLs?|websites?|web pages?)\b',
         ['content_ingress','url_processing_configuration'],'인용된 링크·URL의 유입 경로와 실제 처리 주체(브라우저·서버·클라이언트)는 무엇인가?'),
    atom('input.archive','input',r'\b(?:malicious|crafted|untrusted) archives?\b|\b(?:extracting|extraction of|unpacking) (?:a |an |the )?(?:crafted |malicious )?archives?\b',
         ['archive_ingress','extraction_configuration','filesystem_permissions'],'아카이브 반입·추출 기능과 추출 계정의 파일 쓰기 권한은 무엇인가?'),
    atom('input.update_artifact','input',r'\b(?:malicious|crafted|untrusted|unsigned) (?:firmware|updates?|packages?|plugins?|modules?|DLLs?)\b',
         ['artifact_ingress','signature_configuration','loader_configuration'],'원문이 지정한 업데이트·모듈을 누가 반입·교체할 수 있고 어떻게 로드하는가?'),
    atom('input.command_parameter','input',r'\b(?:user.supplied|attacker.controlled|malicious) (?:command|parameter|argument|package name|input)\b',
         ['input_sources','invocation_permissions'],'인용된 입력·인수의 출처와 해당 기능을 호출할 수 있는 계정은 무엇인가?'),
    atom('input.certificate','input',r'\b(?:crafted|malicious|untrusted|self.signed) certificates?\b',
         ['certificate_sources','trust_configuration'],'원문이 지정한 인증서 입력 출처와 실제 신뢰 저장소·검증 설정은 무엇인가?'),
    atom('trigger.file_processing','trigger',r'\b(?:when|while|by|upon) (?:a |an |the )?(?:user )?(?:opening|loading|importing|parsing|processing) (?:a |an |the )?(?:[\w.-]+ ){0,5}(?:file|project|document|archive|image)\b',
         ['file_processing_configuration','operator_workflows','automatic_processing'],'파일을 여는·가져오는·파싱하는 실제 기능과 자동·수동 처리 경로는 무엇인가?'),
    atom('trigger.send_input','trigger',r'\b(?:by|via) (?:sending|submitting|providing|injecting|transmitting)\b',
         ['message_sources','invocation_permissions'],'원문에 인용된 입력 전송·제출 작업을 누가 어느 인터페이스에서 수행할 수 있는가?'),
    atom('trigger.repeated','trigger',r'\b(?:repeated|multiple|successive|continuous|large number of) (?:crafted |malformed )?(?:requests?|packets?|connections?|login attempts?)\b',
         ['traffic_logs','rate_limit_configuration'],'인용된 반복 입력·연결 패턴과 실제 유입·제한 설정은 무엇인가?'),
    atom('trigger.concurrent','trigger',r'\b(?:when|while|if|by) [^.;\n]{0,80}\b(?:concurrently|simultaneously|racing)\b|\bconcurrent (?:calls?|requests?|operations?)\b',
         ['execution_workflows','concurrency_logs'],'원문이 지정한 동시 작업·호출이 발생하는 실제 실행 절차와 기록은 무엇인가?'),
    atom('control.path_write','control',r'\b(?:user.writable|attacker.controlled|world.writable) (?:directories|directory|paths?|files?)\b|\b(?:with|requires?) (?:write|modification) (?:access|permissions?) (?:to|on)\b',
         ['filesystem_permissions','search_path_configuration'],'원문이 지정한 디렉터리·검색 경로를 변경할 수 있는 계정과 ACL은 무엇인가?'),
    atom('control.symlink','control',r'\b(?:if|when|with|via|by) [^.;\n]{0,70}\b(?:symbolic links?|symlinks?)\b',
         ['filesystem_permissions','symlink_configuration'],'인용된 경로에서 심볼릭 링크를 만들거나 바꿀 수 있는 주체와 실제 구성을 확인할 수 있는가?'),
    atom('control.interception','control',r'\b(?:man.in.the.middle|on.path) (?:attackers?|attacks?)\b|\b(?:attacker|adversary) [^.;\n]{0,60}\bintercept (?:the )?(?:traffic|communications?)\b',
         ['network_routes','transit_protection','trust_configuration'],'원문이 설명한 통신 중간자 위치와 해당 연결의 보호·신뢰 구성을 확인할 수 있는가?'),
    atom('control.backup_access','control',r'\b(?:if|when|with|requires?) [^.;\n]{0,90}\baccess to (?:an? |the )?(?:unencrypted |system |password ){0,2}(?:backups?|hashes?)\b',
         ['backup_permissions','backup_protection'],'원문이 요구하는 백업·해시 파일에 접근 가능한 주체와 보호 상태는 무엇인가?'),
    atom('control.offline_guessing','control',r'\boffline (?:brute.force|password|dictionary|guessing) attacks?\b',
         ['secret_material_access','password_hash_configuration'],'오프라인 공격에 필요한 해시·암호화 자료의 접근 경로와 저장·해시 구성은 무엇인가?'),
    atom('configuration.state','configuration',r'\b(?:only if|if|when|while|with) [^.;\n]{0,100}\b(?:enabled|disabled|activated|configured|installed|loaded)\b',
         ['feature_configuration','active_runtime_configuration'],'인용된 조건문에 명시된 기능·옵션의 실제 활성·설치·실행 상태는 무엇인가?'),
    atom('configuration.port_open','configuration',r'\b(?:only if|if|when|requires?) [^.;\n]{0,90}\bport [^.;\n]{0,35}\b(?:open|opened|enabled|exposed)\b',
         ['service_exposure','firewall_configuration','active_runtime_configuration'],'원문이 지정한 포트의 실제 리스닝·방화벽·인터페이스별 설정은 무엇인가?'),
    atom('configuration.debug','configuration',r'\b(?:if|when|with) [^.;\n]{0,60}\bdebug (?:port|interface|mode)\b|\bdebug (?:port|interface) [^.;\n]{0,45}\benabled\b',
         ['debug_interface_configuration','maintenance_procedures'],'원문이 지정한 디버그 포트·모드의 활성 상태와 접근 가능한 주체는 무엇인가?'),
    atom('configuration.xml_options','configuration',r'\b(?:with|when|if) [^.;\n]{0,70}\b(?:DTD|XInclude|external entity) [^.;\n]{0,45}\b(?:enabled|expansion|validation)\b',
         ['parser_configuration','file_processing_configuration'],'원문이 지정한 XML 파서의 DTD·XInclude·외부 엔터티 옵션과 호출 기능은 무엇인가?'),
    atom('configuration.no_lockout','configuration',r'\b(?:no|without|lack of|lacks?) (?:an? )?(?:account lockout|rate.limit(?:ing)?|login attempt limit)\b',
         ['login_policy','rate_limit_configuration'],'원문이 지적한 로그인 잠금·시도 제한의 실제 설정은 무엇인가?'),
    atom('configuration.nondefault','configuration',r'\bnon.default (?:configuration|settings?)\b|\bnot enabled by default\b',
         ['feature_configuration','configuration_change_records'],'원문이 지정한 비기본 설정의 활성 여부와 변경 이력은 무엇인가?'),
    atom('state.maintenance','state',r'\b(?:in|during|when in|requires?) (?:maintenance|recovery|debug|bootloader|programming) mode\b',
         ['operating_modes','maintenance_procedures'],'원문이 지정한 정비·복구·프로그래밍 모드의 사용 조건과 절차는 무엇인가?'),
    atom('state.restart','state',r'\b(?:during|when|upon|after) (?:a |the )?(?:reboot|restart|boot|startup)\b',
         ['operating_modes','startup_configuration'],'인용된 부팅·재시작 단계에서 실행되는 기능과 실제 절차는 무엇인가?'),
    atom('runtime.service_privilege','runtime',r'\b(?:service|process|application|daemon|program) (?:runs?|is running|executes?) (?:as|with|under) (?:the )?(?:root|SYSTEM|LocalSystem|administrator|elevated privileges)\b',
         ['runtime_accounts','privilege_assignments'],'영향 서비스·프로세스가 실제 실행되는 계정과 권한은 무엇인가?'),
]

COMPILED = [(s, re.compile(s['pattern'], re.I)) for s in ATOMS]


def excluded_intervals(text):
    """Ignore template/scoring/fix/log zones without altering source offsets."""
    intervals = []
    prefix = re.match(r'(?is)\s*A vulnerability has been identified in .{0,25000}?\)\.\s+', text)
    if prefix:
        intervals.append((0, prefix.end(), 'product_list'))
    for match in re.finditer(r'(?i)\b(?:CVSS|at the time of advisory publication|no public exploitation|successful exploitation could|successful exploitation may)\b[^\n]*', text):
        # Scoring text may be inline; its own sentence is not an exploitation condition.
        end = text.find('. ', match.start())
        intervals.append((match.start(), len(text) if end < 0 else end+1, 'scoring_or_publication'))
    trace = re.search(r'(?i)\b(?:Call Trace|Panic trace|Backtrace):', text)
    if trace:
        intervals.append((trace.start(), len(text), 'stack_trace_tail'))
    for match in re.finditer(r'(?i)\b(?:recommend(?:s|ed)?|mitigations?|workaround|users should|update to|upgrade to)\b[^.\n]*', text):
        intervals.append((match.start(), match.end(), 'remediation'))
    return intervals


def context_span(text, start, end):
    left = max(text.rfind('. ', 0, start), text.rfind('\n', 0, start))
    right = text.find('. ', end)
    return max(start-300, 0, left+2 if left >= 0 and text[left:left+2] == '. ' else left+1), min(end+300, len(text) if right < 0 else right+1)


def extract_source(source):
    text = source['text']
    if hashlib.sha256(text.encode('utf-8')).hexdigest() != source['text_sha256']:
        raise ValueError('Source text hash mismatch: '+source['id'])
    excluded = excluded_intervals(text)
    findings, rejected = [], []
    for spec, regex in COMPILED:
        for match in regex.finditer(text):
            if any(match.start() < b and match.end() > a for a,b,_ in excluded):
                continue
            before = text[max(0,match.start()-55):match.start()]
            after = text[match.end():match.end()+70]
            reason = None
            if re.search(r'(?i)\b(?:no|not|never|does not|do not|without|no need to)\s*$|\bnot\s+(?:actually|normally|necessarily|typically)\s*$', before):
                reason = 'negated_or_nonrequired'
            if re.search(r'(?i)\b(?:gain|obtain|escalate to|grant)\s+(?:\w+\s+){0,2}$', before) and spec['axis'] in {'actor','access'}:
                reason = 'post_exploitation_outcome'
            if spec['key']=='actor.admin_required' and re.search(r'(?i)\b(?:execute|run|gain|obtain|grant|escalate)\b[^.;\n]{0,100}$', before):
                reason = 'post_exploitation_outcome'
            if spec['key']=='actor.admin_required' and re.search(r'(?i)\bnon[- ]$',before):
                reason = 'non_administrative_actor'
            if spec['key']=='actor.authenticated' and re.search(r'(?i)\b(?:bypass|without)\s+(?:\w+\s+){0,2}$', before):
                reason = 'authentication_bypass_not_required_authentication'
            if spec['key']=='interaction.required' and re.match(r'(?i)\s*(?:is )?not (?:required|needed)', after):
                reason = 'negated_interaction'
            a,b = context_span(text, match.start(), match.end())
            quote = text[a:b]
            if re.search(r'(?i)\b(?:is not affected|not vulnerable|unaffected)\b', quote):
                reason = 'nonimpact_statement'
            if reason:
                rejected.append(dict(feature=spec['key'],source_id=source['id'],span=list(match.span()),quote=match.group(),reason=reason))
                continue
            qualifier = ('explicit_necessity_cue' if re.search(r'(?i)\b(?:requires?|only if|must|necessary)\b', quote)
                         else 'conditional_cue' if re.search(r'(?i)\b(?:when|while|if|with)\b', quote)
                         else 'described_actor_input_or_capability')
            findings.append(dict(feature=spec['key'], axis=spec['axis'], source_id=source['id'],
                source_kind=source['origin']['kind'], span=list(match.span()), quote=match.group(),
                context_span=[a,b],context_quote=quote, qualifier=qualifier,
                necessity='not_established', semantic_review_required=True, can_refute=False,
                evidence_demands=list(spec['evidence_demands']), question=spec['question']))
            # Keep the original state polarity in the finding. Similar record
            # demands may be grouped, but enabled and disabled are never equal facts.
            if spec['axis']=='configuration':
                value=match.group().lower()
                findings[-1]['source_state']=('disabled_or_not_enabled' if re.search(r'\bdisabled\b|\bnot\s+enabled\b',value)
                    else 'enabled' if re.search(r'\benabled\b|\bactivated\b',value)
                    else 'installed' if 'installed' in value else 'loaded' if 'loaded' in value
                    else 'opened' if re.search(r'\bopen(?:ed)?\b',value) else 'specified_in_quote')
    return findings, rejected


def condition_profile(cve, sources):
    findings, rejected = [], []
    for source in sources:
        if source['cve'] != cve:
            raise ValueError('CVE source scope mismatch')
        f, r = extract_source(source)
        findings.extend(f)
        rejected.extend(r)
    features = sorted({f['feature'] for f in findings})
    demands = sorted({d for f in findings for d in f['evidence_demands']})
    axes = sorted({f['axis'] for f in findings})
    flags = []
    for keys in [('actor.authenticated','actor.unauthenticated'),('interaction.required','interaction.none')]:
        if set(keys) <= set(features):
            flags.append('multiple_or_conflicting_source_contexts:'+','.join(keys))
    status = 'multi_axis_candidate' if len(axes)>=2 else 'single_axis_insufficient' if axes else 'no_explicit_condition_candidate'
    return dict(cve=cve, status=status, features=features, axes=axes, evidence_demands=demands,
        findings=findings, rejected_matches=rejected, review_flags=flags,
        route_logic='not_established', operational_truth='not_observed', vex_status=None)
