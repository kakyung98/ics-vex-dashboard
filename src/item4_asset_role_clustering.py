"""Evidence-scoped asset roles and identity-reduced mechanism text.

Rules identify explicit product roles, not real installation/Purdue levels.
No learned role classifier and no language model are used.
"""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import ahocorasick

class IdentityMask:
    """Linear multi-pattern scan with whole-name boundaries and longest matches."""
    def __init__(self,terms):
        self.automaton=ahocorasick.Automaton()
        for term in terms:self.automaton.add_word(term.lower(),term.lower())
        self.automaton.make_automaton()
    def sub(self,replacement,text):
        lowered=text.lower();matches=[]
        for end,term in self.automaton.iter(lowered):
            start=end-len(term)+1;end+=1
            if (start==0 or not lowered[start-1].isalnum()) and (end==len(lowered) or not lowered[end].isalnum()):matches.append((start,end))
        matches.sort(key=lambda t:(t[0],-t[1]));parts=[];position=0
        for start,end in matches:
            if start<position:continue
            parts.extend([text[position:start],replacement]);position=end
        parts.append(text[position:]);return ''.join(parts)

ROLE_PATTERNS = {
    'plc': r'\bprogrammable\s+(?:logic\s+)?controllers?\b|\bplcs?\b',
    'rtu': r'\bremote\s+(?:terminal|telemetry)\s+units?\b|\brtu(?:\d+[a-z]*)?\b',
    'hmi': r'\bhuman[ -]machine\s+interfaces?\b|\bhmi\b',
    'engineering_tool': r'\bengineering\s+(?:workstation|software|tool|system)s?\b|\b(?:programming|configuration|development)\s+(?:software|tool|environment|system)s?\b|\b(?:hmi|scada)\s+(?:designer|engineering)\b|\bide\b|\bplcsim\b',
    'scada_supervisory': r'\bscada\b|\bsupervisory\s+control\b',
    'dcs': r'\bdistributed\s+control\s+systems?\b|\bdcs\b',
    'historian': r'\bhistorian\b',
    'safety_system': r'\bsafety\s+(?:instrumented\s+system|controller|logic\s+solver)s?\b|\bsis\b',
    'ied_protection': r'\bintelligent\s+electronic\s+devices?\b|\bied\b|\bprotection\s+relays?\b|\bprotective\s+relays?\b',
    'industrial_network': r'\bethernet\s+switch(?:es)?\b|\b(?:managed|industrial|network)\s+(?:ethernet\s+)?switch(?:es)?\b|\brouters?\b|\bfirewalls?\b|\bwireless\s+access\s+points?\b',
    'communication_middleware': r'\bgateways?\b|\bopc[ -]*(?:(?:ua|da|hda|a&e)[ -]*)?(?:servers?|clients?|communications?)\b|\bprotocol\s+converters?\b',
    'communication_module': r'\b(?:communication|communications|ethernet|serial|rtu)\s+(?:modules?|cards?)\b',
    'field_io': r'\b(?:remote|distributed)\s+i/?o\b|\bi/?o\s+(?:modules?|devices?)\b|\bsensors?\b|\bactuators?\b',
    'drive_motion': r'\b(?:variable\s+frequency|servo|motor)\s+drives?\b|\b(?:motion|robot)\s+controllers?\b',
    'medical_device': r'\binfusion\s+pumps?\b|\bpatient\s+monitors?\b|\bventilators?\b|\bmedical\s+devices?\b',
    'measurement_device':r'\b(?:power|energy|flow|gas|water)\s+meters?\b|\b(?:power|quality|measurement)\s+(?:monitoring\s+)?devices?\b|\b(?:pressure|temperature|flow|level)\s+transmitters?\b|\banaly[sz]ers?\b',
    'broadcast_system':r'\b(?:fm|dab|tv|radio)\s+transmitters?\b',
    'industrial_compute':r'\bindustrial\s+(?:pc|computers?)\b|\bembedded\s+(?:pc|computers?)\b|\bmes\s+pc\b',
    'network_management':r'\bnetwork\s+management\s+(?:system|software|platform)s?\b',
    'building_automation':r'\bbuilding\s+(?:automation|management|operation|control)\b|\bhvac\b|\bbacnet\s+controllers?\b',
    'operations_management':r'\bmanufacturing\s+execution\s+systems?\b|\bmes\b|\benergy\s+management\b|\basset\s+management\b|\bmaintenance\s+management\b',
    'physical_security':r'\b(?:ip|network|surveillance|security)\s+cameras?\b|\bvideo\s+(?:surveillance|management|recorders?)\b|\baccess\s+control\s+(?:system|device|panel)s?\b',
    'engineering_viewer':r'\b(?:cad|engineering|3d)\s+(?:file\s+)?viewers?\b|\bengineering\s+visualization\b',
    'engineering_design_simulation':r'\b(?:cad|cae|cam)\s+(?:software|system|application|tool)s?\b|\bplant\s+simulation\b|\bfinite\s+element\s+(?:analysis|modeling)\b',
    'network_services':r'\b(?:dhcp|dns|ntp|radius|syslog|sftp|tftp)\s+servers?\b|\bindustrial\s+network\s+services\b',
    'database_application':r'\b(?:mysql|mariadb|postgresql|database\s+servers?)\b',
    'operating_system':r'\b(?:linux|android|windows|unix|vxworks|wind river|nucleus rtos)\b',
    'software_library':r'\b(?:openssl|glibc|libxml2|libexpat|sqlite|libcurl|libarchive|busybox|expat|zlib)\b|\bsoftware\s+librar(?:y|ies)\b|\btcp/ip\s+stacks?\b',
    'workstation_unspecified': r'\bworkstations?\b',
    'controller_unspecified': r'\bcontrollers?\b',
    'server_application_unspecified': r'\bservers?\b',
}
ROLE_RULES = {r:re.compile(p,re.I) for r,p in ROLE_PATTERNS.items()}
PURDUE_CANDIDATES = {'plc':[1], 'rtu':[1], 'hmi':[2], 'scada_supervisory':[2],
                     'historian':[2,3], 'field_io':[0,1], 'ied_protection':[1],
                     'engineering_tool':[2,3], 'safety_system':[1,2]}

# Checked official family descriptions supplement explicit product-head role terms.
# A family is matched only to a CVE's known_affected product, never just the vendor.
FAMILY_CATALOG=[
 dict(id='simatic_s7_1500',pattern=r'\b(?:simatic|siplus)\s+s7-1500\b',role='plc',url='https://www.siemens.com/global/en/products/automation/systems/industrial/plc/simatic-s7-1500.html',support='S7-1500 is described as a programmable logic controller; excludes tool/module names.'),
 dict(id='simatic_s7_1500_mfp',pattern=r'\b(?:simatic|siplus)\s+s7-1500\s+cpu\s+1518',role='plc',url='https://docs.tia.siemens.cloud/r/simatic_s7_1500_et_200mp_manual_collection_itit_20/device-specific-information/central-processing-units/cpu-1518-4-pn/dp-mfp-6es7518-4ax00-1ab0/product-overview/applications-of-the-s7-1500-cpus',support='MFP CPU models are part of the S7-1500 control system; hosted OS flaws remain associated with affected PLC product.'),
 dict(id='scalance_x',pattern=r'\bscalance\s+x',role='industrial_network',url='https://sieportal.siemens.com/en-in/products-services/10488412?tree=CatalogTree',support='SCALANCE X product family comprises Industrial Ethernet switches.'),
 dict(id='ruggedcom_rst2428p',pattern=r'\bruggedcom\s+rst2428p\b',role='industrial_network',url='https://support.industry.siemens.com/cs/attachments/109983578/C79000-G8976-1528-07_RST2428P_EquipmentManual.pdf',support='RST2428P manual identifies a managed industrial Ethernet switch; does not match APE.'),
 dict(id='ruggedcom_ape1808',pattern=r'\bruggedcom\s+ape1808\b',role='industrial_compute',url='https://cache.industry.siemens.com/dl/files/739/109769739/att_1006885/v1/C79000-G8976-1415_APE1808_ConfigurationManual.pdf?download=true',support='APE1808 is an x64 application-processing computer module, not classified as a switch.'),
 dict(id='sic am_p85x',pattern=r'\bsicam\s+p85[05]\b',role='measurement_device',url='https://cert-portal.siemens.com/productcert/html/ssa-572005.html',support='P850/P855 described as multifunctional electrical measuring devices.'),
 dict(id='jt2go',pattern=r'\bjt2go\b',role='engineering_viewer',url='https://www.plm.automation.siemens.com/media/global/es/JT2Go%20Desktop-What%20Features%20are%20Included%2001042022_tcm54-58015.pdf',support='JT2Go is an engineering data viewing tool; not an HMI or controller.'),
 dict(id='wincc_platform',pattern=r'\bwincc\b',role='hmi_scada_platform',url='https://www.siemens.com/en-us/products/simatic-wincc/',support='WinCC supports HMI and SCADA. Family alone does not establish one runtime role; composite platform label retained.'),
 dict(id='modicon_controller',pattern=r'\bmodicon\s+(?:m\d|quantum|premium|momentum|ts x|tm\d)',role='plc',url='https://www.se.com/us/en/work/products/master-ranges/modicon/',support='Modicon programmable-controller family; exact controller-model prefixes only.'),
 dict(id='compact_controllogix',pattern=r'\b(?:compactlogix|controllogix)\b',role='plc',url='https://www.rockwellautomation.com/en-us/products/hardware/programmable-controllers.html.html',support='CompactLogix and ControlLogix programmable controllers; modules/tools excluded.'),
 dict(id='centum_system',pattern=r'\bcentum\s+(?:vp|cs\s*3000)\b',role='dcs',url='https://www.yokogawa.com/solutions/products-and-services/control/control-and-safety-system/distributed-control-systems-dcs/',support='CENTUM is a DCS family. Named engineering/workstation components keep their specific role instead.'),
 dict(id='deltav_system',pattern=r'\bdeltav\b',role='dcs',url='https://www.emerson.com/en/automation-systems/distributed-control-systems-dcs/deltav-distributed-control-system',support='DeltaV is a DCS platform. Named tools/workstations keep their more specific role.'),
 dict(id='sinec_nms',pattern=r'\bsinec\s+nms\b',role='network_management',url='https://www.siemens.com/en-us/products/sinec/sinec-nms/',support='Industrial network monitoring and management system.'),
 dict(id='sinec_ins',pattern=r'\bsinec\s+ins\b',role='network_services',url='https://www.siemens.com/en-gb/products/sinec/sinec-ins/',support='Industrial network-service package, including DHCP, DNS, NTP and authentication/logging services.'),
 dict(id='cn4100',pattern=r'\bsimatic\s+cn\s*4100\b',role='communication_middleware',url='https://sieportal.siemens.com/en-bg/products-services/10573259',support='Communication node connecting plant and third-party networks.'),
 dict(id='webaccess_scada',pattern=r'\b(?:advantech\s+)?webaccess\b(?!\s*(?:/|-)\s*(?:vpn|hmi))',role='scada_supervisory',url='https://www.advantech.com/emt/industrial-automation/webaccess/webaccessscada',support='WebAccess product family is a browser-based SCADA package.'),
 dict(id='diaenergie',pattern=r'\bdiaenergie\b',role='operations_management',url='https://www.deltaww.com/en-US/products/DIAEnergie-Industrial-Energy-Management-System',support='Industrial energy management application.'),
 dict(id='solid_edge',pattern=r'\bsolid\s+edge\b',role='engineering_design_simulation',url='https://solidedge.siemens.com/en/solutions/products/3d-design/',support='CAD and product engineering software; not a runtime HMI.'),
 dict(id='simcenter_femap',pattern=r'\b(?:simcenter\s+)?femap\b',role='engineering_design_simulation',url='https://www.siemens.com/en-us/products/simcenter/mechanical-simulation/femap/standalone/',support='Finite-element modeling and analysis pre/postprocessor.'),
 dict(id='plant_simulation',pattern=r'\btecnomatix\s+plant\s+simulation\b',role='engineering_design_simulation',url='https://www.siemens.com/en-us/products/tecnomatix/plant-simulation-software/',support='Plant simulation engineering application.'),
 dict(id='teamcenter_visualization',pattern=r'\bteamcenter\s+(?:lifecycle\s+)?visualization\b',role='engineering_viewer',url='https://www.siemens.com/en-us/products/teamcenter/solutions/product-visualization-digital-mockup-software/',support='Product visualization and digital mockup application.'),
 dict(id='parasolid',pattern=r'\bparasolid\b',role='software_library',url='https://solidedge.siemens.com/en/solutions/products/3d-design/',support='Geometric modeling kernel integrated into engineering applications.'),
 dict(id='scalance_w1750d',pattern=r'\bscalance\s+w1750d\b',role='industrial_network',url='https://cert-portal.siemens.com/productcert/html/ssa-516174.html',support='Industrial WLAN access point; not inferred from SCALANCE vendor alone.'),
]

def checked_family_role(name,existing):
    if set(existing)-{'controller_unspecified','server_application_unspecified','operating_system'}:return None
    if re.search(r'\b(?:plcsim|engineering|development|programming|configuration|simulation|modules?|adapters?|cards?|drivers?|librar(?:y|ies)|workstations?)\b',name,re.I):return None
    head=re.split(r'\b(?:containing|using|for)\b',name,1,flags=re.I)[0]
    for entry in FAMILY_CATALOG:
        if re.search(entry['pattern'],head,re.I):return entry
    return None

def product_roles(name):
    """Classify product-head text; protocols/components do not imply asset roles."""
    head=re.split(r'\b(?:containing|using|with the|including the|for)\b',name,1,flags=re.I)[0]
    matches={role:m.group() for role,p in ROLE_RULES.items() if (m:=p.search(head))}
    if re.search(r'\bmodbus\s+rtu\b',head,re.I): matches.pop('rtu',None)
    if re.search(r'\bnon[ -]medical\b',head,re.I):matches.pop('medical_device',None)
    if re.search(r'\b(?:domain|usb|storage|disk|raid|interrupt|memory)\s+controllers?\b',head,re.I): matches.pop('controller_unspecified',None)
    if re.search(r'\b(?:plcsim|plcnext\s+engineer)\b',head,re.I):
        matches.pop('plc',None)
        matches['engineering_tool']='simulation/engineering product head'
    if 'engineering_tool' in matches:
        # A programming/simulation tool targets controllers; it is not a PLC asset.
        matches.pop('plc',None)
        matches.pop('hmi',None)
    if 'communication_module' in matches or 'field_io' in matches:
        matches.pop('plc',None);matches.pop('rtu',None)
    if 'workstation_unspecified' in matches:
        # A SIS workstation is not the safety controller itself.
        matches.pop('safety_system',None)
    if any(r in matches for r in ['plc','rtu','safety_system','drive_motion']): matches.pop('controller_unspecified',None)
    if 'engineering_tool' in matches: matches.pop('workstation_unspecified',None)
    if len(matches)>1:
        for r in ['server_application_unspecified','operating_system','software_library']:
            matches.pop(r,None)
    return matches

def flatten_products(tree):
    products={};vendors=set();names=set()
    def walk(branches,path=()):
        for b in branches:
            name=b.get('name','');path2=path+((b.get('category',''),name),)
            if b.get('category')=='vendor' and name:vendors.add(name)
            if b.get('category')=='product_name' and name:names.add(name)
            if 'product' in b:
                p=b['product'];prod=next((n for cat,n in reversed(path2) if cat=='product_name'),p.get('name',''))
                products[p['product_id']]=dict(name=prod,full_name=p.get('name',''),path=path2)
            walk(b.get('branches',[]),path2)
    walk(tree.get('branches',[]))
    for p in tree.get('full_product_names',[]):
        products.setdefault(p['product_id'],dict(name=p.get('name',''),full_name=p.get('name',''),path=()))
        names.add(p.get('name',''))
    return products,vendors,names

def collect_sources(ids, cache, raw_root):
    target=set(ids);evidence=defaultdict(list);descriptions=defaultdict(list);vendors=set();products=set();links=defaultdict(set)
    source_audit=[]
    for aid,row in sorted(cache.items()):
        relevant=target&set(row.get('cves',[]))
        if not relevant:continue
        if row.get('vendor'):vendors.add(row['vendor'])
        f=Path(raw_root)/(aid+'.json')
        raw=json.loads(f.read_text(encoding='utf-8')) if f.exists() else None
        source_audit.append(dict(advisory_id=aid,archived_csaf=bool(raw),url=row.get('url'),
            sha256=hashlib.sha256(f.read_bytes()).hexdigest() if raw else hashlib.sha256(json.dumps(row,sort_keys=True).encode()).hexdigest()))
        for c in relevant:links[c].add(aid)
        if raw:
            mapping,vs,ps=flatten_products(raw.get('product_tree',{}));vendors.update(vs);products.update(ps)
            for v in raw.get('vulnerabilities',[]):
                c=v.get('cve')
                if c not in relevant:continue
                notes=[n.get('text','') for n in v.get('notes',[]) if n.get('category') in {'summary','description'} and n.get('text')]
                descriptions[c].extend(dict(text=t,advisory_id=aid,source='csaf_cve_note') for t in notes)
                for pid in v.get('product_status',{}).get('known_affected',[]):
                    p=mapping.get(pid)
                    if not p:continue
                    roles=product_roles(p['name'])
                    family=checked_family_role(p['name'],roles)
                    if family:
                        roles={family['role']:'verified family: '+family['id']}
                    # Unknown product links are retained for audit, not guessed.
                    evidence[c].append(dict(advisory_id=aid,product_id=pid,product_name=p['name'],
                        source='csaf_known_affected_product',roles=roles,confidence='official_family_mapping' if family else ('explicit_product_role' if roles else 'unresolved_product_role'),
                        family_catalog_id=family['id'] if family else None,family_source_url=family['url'] if family else None))
        for v in row.get('vulns',[]):
            c=v.get('cve');t=v.get('description','')
            if c in relevant and t:
                descriptions[c].append(dict(text=t,advisory_id=aid,source='cisa_cache_cve_description'))
        # Advisory title/body mentions are intentionally not propagated to every CVE.
    return dict(evidence=evidence,descriptions=descriptions,vendors=sorted(vendors),products=sorted(products),links=links,source_audit=source_audit)

BOILERPLATE=re.compile(r'\b(?:no known public exploits?|known publicly available exploits?|specifically target|cvss|vector string|base score|calculated vector|ics-cert recommends|cisa recommends|recommended practices|headquarters|critical infrastructure sectors|industrial security concept|defense.in.depth|contact (?:the )?(?:vendor|support)|update to (?:the )?latest|apply (?:the )?(?:latest|security) updates?|security advisory|all versions? (?:prior|before)|additional resources)\b',re.I)

def build_identity_mask(vendors,products):
    # Whole product names plus model-shaped tokens; never remove generic mechanism words.
    words=set();phrases=set()
    protected={'server','client','controller','control','security','software','system','systems','application','devices','device','network','communications','industrial','automation','power','logic','memory','file','service','gateway','protocol','web','data','monitor','monitoring','interface','access','remote','local','user','code','input','output','buffer','stack','heap','linux','windows','android','plc','hmi','rtu'}
    for v in vendors:
        v=re.sub(r'\b(?:inc|ltd|corp|corporation|company|llc|gmbh|ag|co)\b\.?',' ',v.lower())
        for w in re.findall(r'[a-z][a-z0-9_-]{2,}',v):
            if w not in protected:words.add(w)
    for p in products:
        p=re.sub(r'\([^)]*\)',' ',p.lower());p=re.sub(r'\s+',' ',p).strip()
        # Long identity phrases are masked without deleting isolated technical nouns.
        if 4<=len(p)<=180 and any(w not in protected for w in p.split()):phrases.add(p)
        for w in re.findall(r'\b[a-z][a-z0-9_-]{2,}\b',p):
            if w not in protected and (any(ch.isdigit() for ch in w) or w in {'simatic','siprotec','sic am','sicore','sic ave','wincc','sinec','sinumerik','ruggedcom','scalance','modicon','vijeo','ecostruxure','factorytalk','codesys','festo','siemens','schneider','yokogawa','rockwell','wonderware','advantech','moxa'}):words.add(w)
    terms=sorted(phrases|words,key=lambda x:(-len(x),x))
    return IdentityMask(terms),dict(vendor_word_count=len(words),product_phrase_count=len(phrases),masked_terms=terms)

def mechanism_text(text, identity_mask):
    text=re.sub(r'<[^>]+>',' ',text)
    text=re.sub(r'https?://\S+|\bcve-\d{4}-\d+\b|\bcwe-\d+\b|\b(?:zdi-can|ssa)-\d+\b',' ',text,flags=re.I)
    text=re.sub(r'CVSS[^\n.]*?(?:\([^)]*\)|$)',' ',text,flags=re.I)
    text=re.sub(r'\b(?:AV|AC|PR|UI|AU|S|C|I|A):[A-Z](?:/[A-Z]{1,3}:[A-Z])+',' ',text,flags=re.I)
    # CVE-specific notes are primary. Remove sentence-level boilerplate, not advisory bodies.
    chunks=re.split(r'(?<=[.!?])\s+|[\r\n]+',text)
    kept=[s for s in chunks if not BOILERPLATE.search(s)]
    text=' '.join(kept)
    text=identity_mask.sub(' ',text)
    text=re.sub(r'\([^)]*(?:versions?|before|prior|build)[^)]*\)',' ',text,flags=re.I)
    text=re.sub(r'\b(?:versions?|builds?|releases?)\s+(?:prior to|before|through|up to|and including|v?\d)[^,;:.]*(?:\.[0-9a-z]+)*',' ',text,flags=re.I)
    text=re.sub(r'\bv?\d+(?:\.[\da-z*]+)+(?:[-_][\da-z]+)?\b',' ',text,flags=re.I)
    text=re.sub(r'\b(?:a vulnerability has been identified in|a vulnerability exists in|the affected products?|all versions?|product android|android id|references upstream kernel)\b',' ',text,flags=re.I)
    text=re.sub(r'[^a-zA-Z0-9_+\-\s/]', ' ', text).lower()
    return re.sub(r'\s+',' ',text).strip()

def cohort_indices(records):
    cohorts=defaultdict(list)
    for i,r in enumerate(records):
        for role in r['roles']:cohorts[role].append(i)
    return {k:v for k,v in sorted(cohorts.items())}
