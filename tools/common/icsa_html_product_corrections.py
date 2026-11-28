"""Source-anchored corrections for older prose advisories lacking CSAF trees.

Names and version text are checked against the cached original HTML at extraction.
This is curated extraction, not a claim of independent semantic approval.
"""
PRODUCTS = {
 'icsa-10-070-01a': [('EDS Hardware Installation Tool','1.0.5.1 and earlier'),('RSLinx Classic','2.41.00'),('RSHWare.exe','1.0.4.0')],
 'icsa-10-070-02': [('PLC-5','unknown'),('SLC 5/0x','unknown'),('RSLogix','unknown'),('1785-Lx','unknown'),('1747-L5x','unknown')],
 'icsa-10-097-01': [('netCADOPS','All releases')],
 'icsa-10-214-01': [('VxWorks','unknown')],
 'icsa-10-264-01': [('BACnet OPC Client','1.0.24')],
 'icsa-10-313-01': [('RealWin','up to and including Version 2.1.8 (Build 6.1.8)')],
 'icsa-10-314-01a': [('ClearSCADA','2005 (all versions)'),('ClearSCADA','2007 (all versions)'),('ClearSCADA','2009 (all versions except R2.3 and R1.4)'),('SCX','unknown')],
 'icsa-10-362-01': [('IntegraXor','prior to Version 3.6 (Build 4000.0)')],
 'icsa-11-018-01': [('OPC SCADA Viewer','prior to Version 1.5.2 (Build 110)')],
 'icsa-11-056-01a': [('Movicon','11.2 prior to Build 1084')],
 'icsa-11-091-01a': [('Tecnomatix FactoryLink','prior to and including Version 8.0.1.1473')],
 'icsa-11-096-01': [('CANVAS','unknown')],
 'icsa-11-103-01a': [('ScanServer ActiveX','unknown'),('Web Toolkit','780.0.20.5'),('SymmetrE','all versions')],
 'icsa-11-108-01': [('GENESIS32','9.21 and prior'),('GENESIS64','10.51 and prior'),('GENESIS32','8.05, 9.1, 9.2, and 10'),('GENESIS 64','8.05, 9.1, 9.2, and 10')],
 'icsa-11-110-01': [('RealWin','1.06A and earlier')],
 'icsa-11-126-01': [('IGSS SCADA HMI','prior to Version 9.0.0.11083')],
 'icsa-11-132-01a': [('IGSS SCADA HMI','Version 7 prior to Revision 10033'),('IGSS SCADA HMI','Version 8 prior to Revision 11102'),('IGSS SCADA HMI','Version 9 prior to Revision 11143')],
 'icsa-11-147-01b': [('IntegraXor','prior to Version 3.60 (Build 4090)')],
 'icsa-11-147-02': [('IntegraXor','prior to Version 3.60 (Build 4080)')],
 'icsa-11-173-01': [('ClearSCADA','2010 R1.0'),('ClearSCADA','2009'),('ClearSCADA','2007'),('ClearSCADA','2005'),('SCX','unknown')],
 'icsa-11-175-02': [('ProTool','6.0 SP3'),('WinCC flexible','2004'),('WinCC flexible','2005'),('WinCC flexible','2005 SP1'),('WinCC flexible','2007'),('WinCC flexible','2008'),('WinCC flexible','2008 SP1'),('WinCC flexible','2008 SP2')],
 'icsa-11-189-01': [('Interactive Graphical SCADA System (IGSS)','prior to 9.0.0.11143')],
 'icsa-11-223-01a': [('S7-200','unknown'),('S7-300','unknown'),('S7-400','unknown'),('S7-1200','unknown')],
 'icsa-11-273-01': [('GENESIS32','V8.05, V9.0, V9.1, and V9.2'),('ScriptWorX32','unknown'),('AlarmWorX32','unknown'),('TrendWorX32','unknown'),('GraphWorX32','unknown')],
 'icsa-11-285-01': [('EBI','R310.1 - TEMA 4.8'),('EBI','R310.1 - TEMA 4.9'),('EBI','R310.1 - TEMA 4.10'),('EBI','R400.2 SP1 - TEMA 5.2'),('EBI','R410.1 - TEMA 5.3.0'),('EBI','R410.2 - TEMA 5.3.1')],
 'icsa-12-039-01': [('Wonderware HMI Reports','3.42.835.0304 and prior')],
 'icsa-13-011-01': [('CODESYS Control Runtime embedded','Versions prior to 2.3.2.8'),('CODESYS Control Runtime full','Versions prior to 2.4.7.40'),('CODESYS Control RTE','Versions prior to 2.3.7.17'),('CoDeSys Runtime Toolkit','unknown')],
 'icsa-13-289-01': [('Firewall Services Module (FWSM)','unknown'),('Catalyst 6500 Series','unknown'),('7600 Series','unknown'),('Adaptive Security Appliance (ASA)','unknown')],
 'icsa-14-156-01': [('OpenSSL','unknown')],
 'icsa-14-086-01': [('TwidoSuite','2.31.04 and earlier'),('PowerSuite','2.6 and earlier'),('SoMove','1.7 and earlier'),('SoMachine','2.0, 3.0, 3.1, and 3.0 XS'),('Unity Pro','7.0 and earlier'),('UnityLoader','2.3 and earlier'),('Concept','2.6 SR7 and earlier'),('ModbusCommDTM sl','2.1.2 and earlier'),('PL7','4.5 SP5 and earlier'),('SFT2841','14, 13.1 and earlier'),('OPC Factory Server','3.50 and earlier'),('Modbus Serial Driver','V1.10 IE v37'),('Modbus Serial Driver','V2.2 IE12'),('Modbus Serial Driver','V3.2 IE12')],
 'icsa-15-225-01': [('PI Data Archive','prior to Version 3.4.395.64')],
 'icsa-15-335-01': [(name,'prior to 1.24.50') for name in ['PCD1.M0xx0/M2xx0','PCD2.M5xx0','PCD3.Mxxx0','PCD3.Mxx60','PCD7.D4xxxT5F','PCD7.D4xxV','PCD7.D4xxD','PCD7.D4xxWTPF']]+[(name,'prior to 1.24.41') for name in ['PCD3.T665','PCD3.T666']],
 'icsa-16-175-02': [('Visilogic','prior to Version 9.8.30')],
 'icsa-16-343-04': [('VDR G4e','5.220 and prior')],
 'icsa-17-192-05': [('PI ProcessBook','2015 R2 (3.6.0) and earlier'),('PI ActiveView','2015 R2 (3.6.0) and earlier')],
 'icsa-14-353-01b': [('NTP','prior to ntp-4.2.8p1')],
}

# Whole-corpus review: keep additional source-checked products and version expressions.
from tools.common.icsa_reviewed_product_overrides import PRODUCTS as REVIEWED_PRODUCTS
PRODUCTS.update(REVIEWED_PRODUCTS)
