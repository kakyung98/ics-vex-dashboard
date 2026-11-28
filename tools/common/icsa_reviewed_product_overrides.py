"""Additional source-checked extraction corrections from the whole-corpus review.

Pairs must occur literally in cached advisory HTML. Uncertain product association
is retained as unknown; these are not deployed-inventory or VEX assertions.
"""
PRODUCTS = {
 'icsa-10-090-01': [('Windows', 'unknown')],
 'icsa-10-201-01c': [
  ('Windows XP', 'Service Pack 3'),
  ('Windows XP Professional x64 Edition', 'Service Pack 2'),
  ('Windows Server 2003', 'Service Pack 2'),
  ('Windows Server 2003 x64 Edition', 'Service Pack 2'),
  ('Windows Server 2003', 'SP2 for Itanium-based Systems'),
  ('Windows Vista', 'Service Pack 1'), ('Windows Vista', 'Service Pack 2'),
  ('Windows Vista x64 Edition', 'Service Pack 1'), ('Windows Vista x64 Edition', 'Service Pack 2'),
  ('Windows Server 2008 for 32-bit Systems', 'unknown'), ('Windows Server 2008 for 32-bit Systems', 'Service Pack 2'),
  ('Windows Server 2008 for x64-based Systems', 'unknown'), ('Windows Server 2008 for x64-based Systems', 'Service Pack 2'),
  ('Windows Server 2008 for Itanium-based Systems', 'unknown'), ('Windows Server 2008 for Itanium-based Systems', 'Service Pack 2'),
  ('Windows 7 for 32-bit Systems', 'unknown'), ('Windows 7 for x64-based Systems', 'unknown'),
  ('Windows Server 2008 R2 for x64-based Systems', 'unknown'), ('Windows Server 2008 R2 for Itanium-based Systems', 'unknown'),
  ('Windows 2000', 'unknown'), ('Windows XP', 'SP2'),
  ('SIMATIC® WinCC', 'unknown'), ('SIMATIC® Siemens STEP 7', 'unknown')],
 # A solar-weather notice lists affected asset categories, not named products.
 # Preserve the full source statements in the extraction ledger, not fake products.
 'icsa-11-084-01': [],
 'icsa-11-168-01a': [('InduSoft ISSymbol ActiveX Control', 'build 301.1009.2904.0'),
                    ('InduSoft Thin Client', '7.0'), ('InduSoft Web Studio', '7.0B2')],
 'icsa-13-011-01': [('CODESYS Control Runtime embedded', 'Versions prior to 2.3.2.8'),
                   ('CODESYS Control Runtime full', 'Versions prior to 2.4.7.40'),
                   ('CODESYS Control RTE', 'Versions prior to 2.3.7.17'), ('CoDeSys Runtime Toolkit', 'unknown')],
 'icsa-13-024-01': [('ADP', 'V6.5.0-180_R1967'), ('ADP', 'V6.5.1-186_R2942'), ('H-Designer', '6.5.0 B180_R1967')],
}
REASONS = {
 'icsa-10-090-01': 'A literature citation page number was parsed as a product release; preserve the stated Windows target only.',
 'icsa-10-201-01c': 'Split explicitly listed Windows service packs and retain unconfirmed/interacting products with unknown CVE association.',
 'icsa-11-084-01': 'Solar-weather impact notice: named software/hardware product inventory is unavailable; generic asset categories remain in source evidence.',
 'icsa-11-168-01a': 'Separate the ActiveX build from the product name.',
 'icsa-13-011-01': 'Replace a descriptive sentence with the named toolkit; keep all three explicit runtime version ranges.',
 'icsa-13-024-01': 'Separate explicit ADP and H-Designer version labels from product names.',
}

for aid in ['icsa-14-329-02', 'icsa-14-329-02a', 'icsa-14-329-02b']:
    wincc = [('SIMATIC WinCC', 'V7.0 SP3 and earlier: All versions'),
             ('SIMATIC WinCC', 'V7.2: All versions prior to V7.2 Update 9'),
             ('SIMATIC WinCC', 'V7.3: All versions prior to V7.3 Update 2')]
    if aid != 'icsa-14-329-02b': wincc.insert(0, ('SIMATIC WinCC', 'V7.0 SP2 and earlier: All versions'))
    pcs = 'SIMATIC PCS 7' if aid.endswith('b') else 'SIMATIC PCS7'
    PRODUCTS[aid] = wincc + [(pcs, 'V7.1 SP4 and earlier: All versions'),
        (pcs, 'V8.0: All versions prior to V8.0 SP2 with WinCC V7.2 Update 9'),
        (pcs, 'V8.1: All versions with WinCC V7.3 prior to Update 2' if aid.endswith('b') else 'V8.1: All versions with WinCC V7.3 prior to V8.1 Update 2'),
        ('TIA Portal V13 (including WinCC Professional Runtime)', 'All versions prior to V13 Update 6')]
    REASONS[aid] = 'Preserve parent product names for nested version lists; restore TIA Portal instead of fake products named V7.2 or All.'
PRODUCTS['icsa-16-348-05'] = [
 ('SIMATIC S7-300 CPU family (incl. related ET200 CPUs and SIPLUS variants)', 'all versions'),
 ('SIMATIC S7-400 PN/DP V6 and below CPU family (incl. SIPLUS variants)', 'all versions'),
 ('SIMATIC S7-400 PN/DP V7 CPU family (incl. SIPLUS variants)', 'all versions'),
 ('SIMATIC S7-410 V8 CPU family (incl. SIPLUS variants)', 'all versions (only affected by CVE-2016-9159)')]
REASONS['icsa-16-348-05'] = 'Keep the all-versions quantifier and the CVE-specific qualifier together.'
PRODUCTS['icsa-17-094-04'] = [('Stratix 5900', 'All Versions prior to 15.6.3')]
REASONS['icsa-17-094-04'] = 'Remove version quantifier All from the product name and preserve it in the version expression.'
PRODUCTS['icsa-16-327-02'] = [
 ('SIMATIC CP 343-1 Advanced (incl. SIPLUS NET variant)', 'All versions prior to v3.0.53'),
 ('SIMATIC CP 443-1 Advanced (incl. SIPLUS NET variant)', 'All versions prior to v3.2.17'),
 ('SIMATIC S7-300 CPU family (incl. SIPLUS NET variant)', 'All firmware versions'),
 ('SIMATIC S7-400 CPU family (incl. SIPLUS NET variant)', 'All firmware versions')]
REASONS['icsa-16-327-02'] = 'Keep explicit CPU product names without sentence delimiters.'
PRODUCTS['icsa-11-096-01'] = [
 ('Indusoft SCADA web studio', '7.0'), ('SCADA Trace Mode Data Center', 'unknown'),
 ('IGSS SCADA odbc server', 'unknown'), ('OPC Modbus Ethernet OPC Server', 'unknown'),
 ('Automated Solutions Modbus/TCP OPC Server', 'unknown'), ('BACnet OPC client', 'before 1.0.25'),
 ('Advantech Studio', '6.1'), ('ICONICS Dialog Wrapper Module ActiveX control', 'unknown'),
 ('BECK GMBH, INDUSTRIAL PC', 'unknown'), ('SafeNet Sentinel Protection Server', '<= 7.4.1.0'),
 ('Sentinel Keys Server', '<= 1.0.4.0'), ('DATARATE SCADA', '<= 2.5'),
 ('SCADA MOXA Device Manager Tool', '2.1'), ('Ecava IntegraXor', 'unknown'),
 ('GE Fanuc Real Time Information Portal', '2.6'), ('Citect SCADA ODBC', 'unknown'),
 ('Invensys Wonderware InFusion SCADA (and other products) ActiveX', 'unknown'), ('DATAC RealWin SCADA', '1.06')]
REASONS['icsa-11-096-01'] = 'Restore named target products from the advisory table; CANVAS is the exploit framework and ITS scada is explicitly a demo, not a produced ICS product.'

def apply_review_policy(document,advisory_id=None):
    """Mark absent workbook fields without claiming identifiers or deployment facts."""
    def props(node):return {p['name']:p['value'] for p in node.get('properties',[])}
    def put(node,key,value):
        node['properties']=[p for p in node.get('properties',[]) if p['name']!=key]+[{'name':key,'value':value}]
    for component in [document['metadata']['component'],*document.get('components',[])]:
        missing=[field for field in ['scope','purl','cpe','hashes'] if field not in component]
        missing += [kind+'.contact.email' for kind in ['manufacturer','supplier']
                    if not any(c.get('email') for c in component.get(kind,{}).get('contact',[]))]
        if not any('id' in l.get('license',{}) for l in component.get('licenses',[])):missing.append('licenses.license.id')
        put(component,'dataset:unknown-fields',','.join(missing))
    unknown=props(document).get('dataset:unknown-fields','').split(',')
    unknown=[('metadata.'+field if field.startswith('distributionConstraints.') else field) for field in unknown]
    if not any('phase' in x for x in document['metadata'].get('lifecycles',[])):unknown.append('metadata.lifecycles.phase')
    put(document,'dataset:unknown-fields',','.join(sorted(set(unknown)-{''})))
    if advisory_id=='icsa-10-070-01a':
        for component in document.get('components',[]):
            original_vendor=component['manufacturer']['name']
            component['manufacturer']['name']='Rockwell Automation'
            put(component,'dataset:manufacturer-source-label',original_vendor)
            put(component,'dataset:manufacturer-source-quote','Rockwell Automation provides industrial automation control and information products worldwide across a wide range of industries.')
            if component['name']=='EDS Hardware Installation Tool':
                put(component,'dataset:source-file-aliases','[{"name":"RSHWare.exe","version":"1.0.4.0","relationship":"executable alias of EDS Hardware Installation Tool"}]')
                put(component,'dataset:source-file-alias-quote','ICS-CERT has verified that the vulnerability exists in RSLinx Classic Version 2.41.00 (RSHWare.exe Version 1.0.4.0).')
    for component in document.get('components',[]):
        if component['name']=='SCX' and advisory_id in ['icsa-10-314-01a','icsa-11-173-01']:
            put(component,'dataset:source-supplier-candidates','["Serck UK","Serck Aus"]')
        if component['name']=='NTP' and advisory_id=='icsa-14-353-01b':
            put(component,'dataset:source-project-contributors','["University of Delaware","Network Time Foundation"]')
    if advisory_id in REASONS:put(document,'dataset:whole-corpus-review-reason',REASONS[advisory_id])
    if advisory_id in NON_PRODUCT_NOTICES and not document['components']:put(document,'dataset:source-status','non-product-notice')
    return document
PRODUCTS.update({
 'icsa-10-238-01b': [('Windows','unknown'),('Windows XP','unknown'),('Microsoft SQL Server','unknown')],
 'icsa-10-272-01': [('Siemens SIMATIC WinCC','unknown'),('SIMATIC STEP 7','unknown'),('Windows XP','unknown')],
 'icsa-11-041-01a': [('Microsoft Windows','unknown'),('Microsoft Active Directory','unknown')],
})
REASONS.update({
 'icsa-10-238-01b': 'No affected-products heading: retain explicitly described Windows and SQL Server target platforms; do not invent versions or Siemens product models.',
 'icsa-10-272-01': 'No affected-products heading: retain named WinCC, STEP 7 and Windows platforms. XP SP3 is a test environment, not an asserted affected-version range.',
 'icsa-11-041-01a': 'No affected-products heading: retain explicitly targeted Windows and Active Directory; exclude attacker tools from product inventory.',
})
NON_PRODUCT_NOTICES = {
 'icsa-10-228-01': 'General warning about contractor-created administrator accounts; no named affected product inventory.',
 'icsa-11-025-01': 'GPS testing/outage notice; no named receiver product inventory.',
 'icsa-11-084-01': 'Solar-weather impact notice with generic asset categories; no named affected product inventory.',
 'icsa-13-291-01b': 'DNP3 implementation overview lists vendors and related advisories, not named product/version inventory. Do not use vendor names as products.',
 'icsa-14-178-01': 'Havex analysis describes OPC protocol use and redacted vendor targets; no named affected product inventory.',
}
for aid,reason in NON_PRODUCT_NOTICES.items():
    PRODUCTS[aid]=[]
    REASONS[aid]=reason
PRODUCTS['icsa-16-313-02'] = [('Primary Setup Tool (PST)', 'All versions prior to v4.2 HF1'), ('SIMATIC IT Production Suite', 'All versions prior to v7.0 SP1 HFX 2'), ('SIMATIC NET PC-Software', 'All versions prior to v14'), ('SIMATIC PCS 7', 'v7.1 and earlier versions'), ('SIMATIC PCS 7 v8.0', 'All versions'), ('SIMATIC PCS 7 v8.1', 'All versions'), ('SIMATIC PCS 7 v8.2', 'All versions prior to v8.2 SP1'), ('SIMATIC STEP 7 (TIA Portal) v13', 'All versions prior to v13 SP2'), ('SIMATIC STEP 7 v5.X', 'All versions prior to v5.5 SP4 HF11'), ('SIMATIC WinAC RTX (F) 2010 SP2', 'All versions prior to SIMATIC WinAC RTX 2010 SP3'), ('SIMATIC WinCC (TIA Portal) Basic, Comfort, Advanced', 'All versions prior to v14'), ('SIMATIC WinCC (TIA Portal) Professional v13', 'All versions prior to v13 SP2'), ('SIMATIC WinCC (TIA Portal) Professional v14', 'All versions prior to v14 SP1'), ('SIMATIC WinCC Runtime Professional v13', 'All versions prior to v13 SP2'), ('SIMATIC WinCC Runtime Professional v14', 'All versions prior to v14 SP1'), ('SIMATIC WinCC v7.0 SP2 and earlier', 'prior to v7.0 SP2 Update 12'), ('SIMATIC WinCC v7.0 SP3', 'All versions prior to v7.0 SP3 Update 8'), ('SIMATIC WinCC v7.2', 'All versions prior to v7.2 Update 14'), ('SIMATIC WinCC v7.3', 'All versions prior to v7.3 Update 11'), ('SIMATIC WinCC v7.4', 'All versions prior to v7.4 SP1'), ('SIMIT', 'All versions prior to v9.0 SP1'), ('SINEMA Remote Connect Client', 'All versions prior to v1.0 SP3'), ('SINEMA Server', 'All versions prior to v13 SP2'), ('SOFTNET Security Client v5.0', 'All versions'), ('Security Configuration Tool (SCT)', 'All versions prior to v4.3 HF1'), ('TeleControl Server Basic', 'All versions prior to v3.0 SP2')]
REASONS['icsa-16-313-02'] = 'Separate the explicitly stated v7.1-and-earlier version range from the SIMATIC PCS 7 product name; retain every other source product/range.'

PRODUCTS['icsa-10-070-01a'] = [('EDS Hardware Installation Tool','1.0.5.1 and earlier'),('RSLinx Classic','2.41.00')]
REASONS['icsa-10-070-01a'] = 'RSHWare.exe is the EDS Hardware Installation Tool executable, not an independent product. Preserve file name/version as a source-backed alias; use the explicitly stated Rockwell Automation manufacturer.'

PRODUCTS['icsa-10-314-01a'] = [('ClearSCADA', '2005 (all versions)'), ('ClearSCADA', '2007 (all versions)'), ('ClearSCADA', '2009 (all versions except R2.3 and R1.4)'), ('SCX', 'all versions of SCX (from Serck UK or Serck Aus) that are older than the following (these SCX versions bundle ClearSCADA in the package): SCX Version 67 R4.5 SCX Version 68 R3.9')]
REASONS['icsa-10-314-01a'] = 'Retain the source SCX 67 R4.5 / 68 R3.9 threshold expression; attribute ClearSCADA to Control Microsystems and keep SCX manufacturer unknown because the source lists Serck UK or Serck Aus suppliers.'

PRODUCTS['icsa-11-173-01'] = [('ClearSCADA', '2010 R1.0'), ('ClearSCADA', '2009'), ('ClearSCADA', '2007'), ('ClearSCADA', '2005'), ('SCX', 'all versions of SCX (from Serck UK or Serck Aus) that are older than the following (these SCX versions contain ClearSCADA in the bundle): SCX Version 67 R4.5 SCX Version 68 R3.9')]
REASONS['icsa-11-173-01'] = 'Retain the source SCX 67 R4.5 / 68 R3.9 threshold expression; attribute ClearSCADA to Control Microsystems and keep SCX manufacturer unknown because the source lists Serck UK or Serck Aus suppliers.'
