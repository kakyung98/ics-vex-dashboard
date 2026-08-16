#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICS SBOM 예시 데이터셋 생성기 (CycloneDX 1.7)

KISA "SBOM 데이터필드 정의-CycloneDX.xlsx" 필드 정의와
"1_2_1_2_VxWorks_RTOS_SBOM 샘플.jsonc" 구조를 그대로 따르되,
대상을 산업제어시스템(ICS/OT) 자산으로 치환하여 1,000개의 SBOM을 생성한다.

생성물
  sbom/ICS_XXXX_<vendor>_<product>_SBOM.json   : SBOM 본문 1,000개
  sbom/index.csv                                : 자산 인덱스 (자산 메타 요약)
  sbom/ground_truth_vulnerable_components.csv   : VEX 판정 정답셋 (취약 버전 매핑)
  sbom/README.md                                : 데이터셋 설명

주의: 본 데이터셋은 합성(synthetic) 예시다. 벤더/제품 계열명과 OSS 버전은
실존 명칭을 참고했으나, 해시·시리얼·연락처·URL은 모두 가공된 placeholder이며
실제 제품의 실제 부품 구성을 나타내지 않는다. 각 문서의 dataset:synthetic
property 로 이를 명시한다.
"""

import csv
import hashlib
import json
import os
import random
import re
import sys
import uuid

# ---------------------------------------------------------------------------
# 기본 설정
# ---------------------------------------------------------------------------

TOTAL = 1000
SEED = 20260415
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT_DIR = os.path.abspath(os.path.join(BASE_DIR, "sbom"))

NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid5 네임스페이스 (결정적 생성)

CREATION_DATE = "2026-04-10"
TIMESTAMP = "2026-04-10T00:00:00Z"

TLP_CHOICES = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]
LIFECYCLE_CHOICES = ["design", "build", "post-build", "operations", "decommission"]

SECTORS = [
    "power-generation", "power-transmission", "power-distribution",
    "water-treatment", "wastewater", "oil-and-gas-upstream", "oil-and-gas-midstream",
    "chemical", "petrochemical", "manufacturing-discrete", "manufacturing-process",
    "transportation-rail", "transportation-metro", "building-automation",
    "semiconductor-fab", "pharmaceutical", "food-and-beverage", "steel-and-metals",
    "automotive", "pulp-and-paper", "district-heating", "port-and-logistics",
]

NETWORK_EXPOSURE = ["isolated-cell", "control-network", "dmz-routable", "remote-accessible"]
PATCH_CADENCE = ["vendor-scheduled-annual", "vendor-scheduled-semiannual",
                 "on-advisory-only", "maintenance-window-quarterly", "frozen-validated-state"]

# ---------------------------------------------------------------------------
# 벤더 카탈로그
#   key: (표기명, 국가, 도시, CPE vendor 토큰)
# ---------------------------------------------------------------------------

VENDORS = {
    "siemens":        ("Siemens AG", "DE", "Munich", "siemens"),
    "rockwell":       ("Rockwell Automation", "US", "Milwaukee", "rockwellautomation"),
    "schneider":      ("Schneider Electric", "FR", "Rueil-Malmaison", "schneider-electric"),
    "abb":            ("ABB Ltd", "CH", "Zurich", "abb"),
    "mitsubishi":     ("Mitsubishi Electric", "JP", "Tokyo", "mitsubishielectric"),
    "honeywell":      ("Honeywell International", "US", "Charlotte", "honeywell"),
    "yokogawa":       ("Yokogawa Electric", "JP", "Tokyo", "yokogawa"),
    "emerson":        ("Emerson Electric", "US", "Saint Louis", "emerson"),
    "ge":             ("GE Vernova", "US", "Cambridge", "ge"),
    "omron":          ("OMRON Corporation", "JP", "Kyoto", "omron"),
    "phoenix":        ("Phoenix Contact", "DE", "Blomberg", "phoenixcontact"),
    "wago":           ("WAGO GmbH", "DE", "Minden", "wago"),
    "beckhoff":       ("Beckhoff Automation", "DE", "Verl", "beckhoff"),
    "hitachi_energy": ("Hitachi Energy", "CH", "Zurich", "hitachienergy"),
    "sel":            ("Schweitzer Engineering Laboratories", "US", "Pullman", "selinc"),
    "moxa":           ("Moxa Inc.", "TW", "New Taipei", "moxa"),
    "advantech":      ("Advantech Co., Ltd.", "TW", "Taipei", "advantech"),
    "delta":          ("Delta Electronics", "TW", "Taipei", "deltaww"),
    "fuji":           ("Fuji Electric", "JP", "Tokyo", "fujielectric"),
    "bosch_rexroth":  ("Bosch Rexroth AG", "DE", "Lohr am Main", "boschrexroth"),
    "ls_electric":    ("LS ELECTRIC", "KR", "Anyang", "lselectric"),
    "keyence":        ("KEYENCE Corporation", "JP", "Osaka", "keyence"),
    "br":             ("B&R Industrial Automation", "AT", "Eggelsberg", "br-automation"),
    "pilz":           ("Pilz GmbH", "DE", "Ostfildern", "pilz"),
    "hima":           ("HIMA Paul Hildebrandt GmbH", "DE", "Bruehl", "hima"),
    "unitronics":     ("Unitronics", "IL", "Airport City", "unitronics"),
    "codesys":        ("CODESYS GmbH", "DE", "Kempten", "codesys"),
    "ptc":            ("PTC Inc.", "US", "Boston", "ptc"),
    "inductive":      ("Inductive Automation", "US", "Folsom", "inductiveautomation"),
    "aveva":          ("AVEVA Group plc", "GB", "Cambridge", "aveva"),
    "copadata":       ("COPA-DATA GmbH", "AT", "Salzburg", "copadata"),
    "belden":         ("Belden / Hirschmann", "DE", "Neckartenzlingen", "belden"),
    "westermo":       ("Westermo Network Technologies", "SE", "Vasteras", "westermo"),
    "red_lion":       ("Red Lion Controls", "US", "York", "redlion"),
    "danfoss":        ("Danfoss A/S", "DK", "Nordborg", "danfoss"),
    "idec":           ("IDEC Corporation", "JP", "Osaka", "idec"),
    "panasonic":      ("Panasonic Industry Co., Ltd.", "JP", "Osaka", "panasonic"),
    "hd_hyundai":     ("HD Hyundai Electric", "KR", "Seongnam", "hd-hyundai-electric"),
    "softing":        ("Softing Industrial Automation", "DE", "Haar", "softing"),
    "nari":           ("NARI Technology", "CN", "Nanjing", "naritech"),
}

# ---------------------------------------------------------------------------
# 제품 카탈로그
#   (vendor_key, family, device_class, cdx_type, os_key, purdue, protocols, models)
# ---------------------------------------------------------------------------

PRODUCTS = [
    # ---- PLC ----
    ("siemens", "SIMATIC S7-1500 CPU", "plc", "firmware", "proprietary-rtos", "1",
     ["profinet", "s7comm-plus", "opc-ua", "modbus-tcp"], ["1511-1 PN", "1513-1 PN", "1516-3 PN/DP", "1518-4 PN/DP"]),
    ("siemens", "SIMATIC S7-1200 CPU", "plc", "firmware", "proprietary-rtos", "1",
     ["profinet", "s7comm-plus", "modbus-tcp"], ["1212C", "1214C", "1215C", "1217C"]),
    ("siemens", "SIMATIC S7-400 CPU", "plc", "firmware", "proprietary-rtos", "1",
     ["profibus", "s7comm", "industrial-ethernet"], ["414-3", "416-3", "417-4H"]),
    ("rockwell", "ControlLogix Controller", "plc", "firmware", "vxworks", "1",
     ["ethernet-ip", "cip", "devicenet"], ["1756-L71", "1756-L73", "1756-L81E", "1756-L83E"]),
    ("rockwell", "CompactLogix Controller", "plc", "firmware", "vxworks", "1",
     ["ethernet-ip", "cip", "modbus-tcp"], ["5069-L306ER", "5069-L320ER", "5370-L33ER"]),
    ("rockwell", "MicroLogix Controller", "plc", "firmware", "proprietary-rtos", "1",
     ["ethernet-ip", "df1"], ["1400-B", "1100-C", "1200-E"]),
    ("schneider", "Modicon M340 Controller", "plc", "firmware", "vxworks", "1",
     ["modbus-tcp", "ethernet-ip", "canopen"], ["BMXP342020", "BMXP341000", "BMXP342030"]),
    ("schneider", "Modicon M580 ePAC", "plc", "firmware", "linux", "1",
     ["modbus-tcp", "ethernet-ip", "opc-ua", "dnp3"], ["BMEP582040", "BMEP584040", "BMEH586040"]),
    ("mitsubishi", "MELSEC iQ-R CPU", "plc", "firmware", "proprietary-rtos", "1",
     ["cc-link-ie", "melsoft", "modbus-tcp", "slmp"], ["R04CPU", "R08CPU", "R16CPU", "R32CPU"]),
    ("mitsubishi", "MELSEC-Q Series CPU", "plc", "firmware", "proprietary-rtos", "1",
     ["cc-link", "melsoft", "modbus-tcp"], ["Q03UDE", "Q06UDE", "Q13UDH"]),
    ("omron", "SYSMAC NJ Machine Controller", "plc", "firmware", "proprietary-rtos", "1",
     ["ethercat", "ethernet-ip", "opc-ua"], ["NJ101-1000", "NJ301-1200", "NJ501-1500"]),
    ("omron", "SYSMAC CJ2 PLC", "plc", "firmware", "proprietary-rtos", "1",
     ["fins", "ethernet-ip", "modbus-tcp"], ["CJ2M-CPU31", "CJ2H-CPU64", "CJ2H-CPU68"]),
    ("beckhoff", "TwinCAT Runtime Controller", "plc", "application", "windows", "1",
     ["ethercat", "opc-ua", "modbus-tcp", "profinet"], ["CX5140", "CX8190", "CX2043"]),
    ("wago", "PFC200 Controller", "plc", "firmware", "linux", "1",
     ["modbus-tcp", "profinet", "canopen", "mqtt", "opc-ua"], ["750-8202", "750-8206", "750-8212"]),
    ("phoenix", "AXC F 2152 Controller", "plc", "firmware", "linux", "1",
     ["profinet", "opc-ua", "modbus-tcp", "mqtt"], ["AXC-F-2152", "AXC-F-3152", "AXC-F-1152"]),
    ("br", "X20 Controller", "plc", "firmware", "proprietary-rtos", "1",
     ["powerlink", "opc-ua", "modbus-tcp"], ["X20CP1586", "X20CP3586", "X20CP0484"]),
    ("ls_electric", "XGT PLC CPU", "plc", "firmware", "proprietary-rtos", "1",
     ["modbus-tcp", "rapienet", "ethernet-ip"], ["XGK-CPUH", "XGI-CPUU", "XGR-CPUH"]),
    ("delta", "AS Series PLC", "plc", "firmware", "proprietary-rtos", "1",
     ["modbus-tcp", "ethernet-ip", "canopen"], ["AS228T-A", "AS332T-A", "AS324MT-A"]),
    ("unitronics", "UniStream PLC", "plc", "firmware", "linux", "1",
     ["modbus-tcp", "canopen", "mqtt"], ["USP-070-B10", "USP-104-B10", "USC-B10-T24"]),
    ("idec", "MicroSmart FC6A PLC", "plc", "firmware", "proprietary-rtos", "1",
     ["modbus-tcp", "bacnet-ip"], ["FC6A-C40R1AE", "FC6A-D32K3", "FC6A-C24R2C"]),
    ("panasonic", "FP7 Series PLC", "plc", "firmware", "proprietary-rtos", "1",
     ["modbus-tcp", "mewtocol"], ["AFP7CPS41", "AFP7CPS31", "AFP7CPS21"]),
    ("keyence", "KV-8000 PLC", "plc", "firmware", "proprietary-rtos", "1",
     ["ethernet-ip", "modbus-tcp", "kv-protocol"], ["KV-8000", "KV-7500", "KV-5500"]),
    ("fuji", "MICREX-SX PLC", "plc", "firmware", "proprietary-rtos", "1",
     ["modbus-tcp", "fl-net"], ["NP1PS-245R", "NP1PM-256E", "NP1PS-117R"]),
    ("codesys", "CODESYS Control Runtime", "plc-runtime", "application", "linux", "1",
     ["modbus-tcp", "opc-ua", "ethercat", "canopen", "profinet"],
     ["for Linux SL", "for PLCnext SL", "RTE V3", "for BeagleBone SL"]),

    # ---- RTU / Telecontrol ----
    ("abb", "RTU560 Telecontrol Unit", "rtu", "firmware", "linux", "1",
     ["iec-60870-5-104", "dnp3", "iec-61850-mms", "modbus-tcp"], ["560CMU05", "560CMR01", "560CIG10"]),
    ("schneider", "SCADAPack RTU", "rtu", "firmware", "vxworks", "1",
     ["dnp3", "modbus-tcp", "iec-60870-5-104"], ["474i", "535E", "570", "x70"]),
    ("ge", "D20 MX Substation Controller", "rtu", "firmware", "linux", "1",
     ["dnp3", "iec-61850-mms", "modbus-tcp"], ["D20MX", "D20EME", "D400"]),
    ("siemens", "SICAM A8000 RTU", "rtu", "firmware", "linux", "1",
     ["iec-60870-5-104", "iec-61850-mms", "dnp3", "modbus-tcp"], ["CP-8050", "CP-8031", "CP-8000"]),
    ("hitachi_energy", "RTU500 Series", "rtu", "firmware", "proprietary-rtos", "1",
     ["iec-60870-5-104", "iec-61850-mms", "dnp3"], ["560CMU80", "RTU520", "RTU540"]),
    ("moxa", "ioPAC Programmable Controller", "rtu", "firmware", "linux", "1",
     ["modbus-tcp", "dnp3", "mqtt"], ["8600-CPU30", "8500-C-T", "5542-C-T"]),
    ("red_lion", "Data Station Plus RTU", "rtu", "firmware", "linux", "1",
     ["modbus-tcp", "dnp3", "ethernet-ip", "mqtt"], ["DSPSX000", "DSPZR000", "DSPGT000"]),

    # ---- IED / Protection Relay ----
    ("sel", "SEL-451 Protection System", "ied", "firmware", "proprietary-rtos", "1",
     ["iec-61850-mms", "iec-61850-goose", "dnp3", "modbus-tcp"], ["451-5", "451-1", "487E", "421"]),
    ("sel", "SEL-3530 RTAC", "ied", "firmware", "linux", "1",
     ["dnp3", "iec-61850-mms", "modbus-tcp", "iec-60870-5-104"], ["3530", "3530-4", "3555"]),
    ("hitachi_energy", "REF615 Feeder Protection Relay", "ied", "firmware", "proprietary-rtos", "1",
     ["iec-61850-mms", "iec-61850-goose", "modbus-tcp", "dnp3"], ["REF615", "REF620", "RED615", "REU615"]),
    ("siemens", "SIPROTEC 5 Protection Relay", "ied", "firmware", "proprietary-rtos", "1",
     ["iec-61850-mms", "iec-61850-goose", "dnp3", "iec-60870-5-103"], ["7SJ85", "7SL86", "7UT85", "7SA86"]),
    ("ge", "Multilin UR Relay", "ied", "firmware", "proprietary-rtos", "1",
     ["iec-61850-mms", "iec-61850-goose", "dnp3", "modbus-tcp"], ["B30", "C60", "L90", "T35"]),
    ("schneider", "Easergy P3 Protection Relay", "ied", "firmware", "proprietary-rtos", "1",
     ["iec-61850-mms", "modbus-tcp", "dnp3"], ["P3U30", "P3L30", "P3F30"]),
    ("nari", "PCS-9611 Feeder Protection", "ied", "firmware", "proprietary-rtos", "1",
     ["iec-61850-mms", "iec-61850-goose", "modbus-tcp"], ["PCS-9611", "PCS-9705", "PCS-9671"]),
    ("hd_hyundai", "HiGEN Protection Relay", "ied", "firmware", "proprietary-rtos", "1",
     ["iec-61850-mms", "modbus-tcp", "dnp3"], ["HGR-100", "HGR-200", "HGR-300"]),

    # ---- HMI ----
    ("siemens", "SIMATIC HMI Comfort Panel", "hmi", "firmware", "windows", "2",
     ["profinet", "opc-ua", "s7comm-plus"], ["TP1200", "TP1500", "KP700", "TP2200"]),
    ("rockwell", "PanelView Plus Terminal", "hmi", "firmware", "windows", "2",
     ["ethernet-ip", "cip"], ["7 Standard 1000", "7 Performance 1500", "6 Compact 600"]),
    ("schneider", "Magelis GTU HMI", "hmi", "firmware", "linux", "2",
     ["modbus-tcp", "ethernet-ip", "opc-ua"], ["HMIGTU655", "HMIDT551", "HMIST6500"]),
    ("mitsubishi", "GOT2000 Graphic Terminal", "hmi", "firmware", "proprietary-rtos", "2",
     ["cc-link-ie", "melsoft", "modbus-tcp"], ["GT2712-STBA", "GT2510-VTBA", "GT2107-WTBD"]),
    ("advantech", "WebOP Operator Panel", "hmi", "firmware", "linux", "2",
     ["modbus-tcp", "ethernet-ip", "mqtt"], ["WOP-2100T", "WOP-3070T", "WOP-2070T"]),
    ("weintek_stub", "", "", "", "", "", [], []),  # placeholder removed below
    ("delta", "DOP-100 HMI", "hmi", "firmware", "proprietary-rtos", "2",
     ["modbus-tcp", "canopen"], ["DOP-107BV", "DOP-110CS", "DOP-103BQ"]),
    ("omron", "NA Series HMI", "hmi", "firmware", "windows", "2",
     ["ethernet-ip", "opc-ua", "modbus-tcp"], ["NA5-12W", "NA5-9W", "NA5-15W"]),
    ("pilz", "PMI Operator Terminal", "hmi", "firmware", "linux", "2",
     ["profinet", "modbus-tcp"], ["PMI 6 primo", "PMI v812", "PMI 5"]),

    # ---- SCADA / Supervisory software ----
    ("aveva", "AVEVA Plant SCADA", "scada-server", "application", "windows", "2",
     ["opc-ua", "opc-da", "modbus-tcp", "dnp3", "iec-60870-5-104"], ["2020 R2", "2023", "2023 R2"]),
    ("inductive", "Ignition SCADA Platform", "scada-server", "application", "java", "2",
     ["opc-ua", "modbus-tcp", "mqtt-sparkplug", "dnp3"], ["8.1", "8.1 Edge", "8.3"]),
    ("copadata", "zenon Supervisor", "scada-server", "application", "windows", "2",
     ["opc-ua", "iec-61850-mms", "iec-60870-5-104", "modbus-tcp"], ["10", "11", "12"]),
    ("siemens", "SIMATIC WinCC", "scada-server", "application", "windows", "2",
     ["opc-ua", "profinet", "s7comm-plus"], ["V7.5", "V8.0", "Unified V18"]),
    ("ge", "CIMPLICITY HMI/SCADA", "scada-server", "application", "windows", "2",
     ["opc-ua", "opc-da", "modbus-tcp"], ["11.1", "2022", "2023"]),
    ("schneider", "EcoStruxure Geo SCADA Expert", "scada-server", "application", "windows", "2",
     ["dnp3", "iec-60870-5-104", "modbus-tcp", "opc-ua"], ["2021", "2022", "2023"]),
    ("rockwell", "FactoryTalk View SE", "scada-server", "application", "windows", "2",
     ["ethernet-ip", "opc-ua", "cip"], ["12.00", "13.00", "14.00"]),

    # ---- Historian / MES / Level 3 ----
    ("aveva", "AVEVA Historian", "historian", "application", "windows", "3",
     ["opc-ua", "opc-hda", "sql"], ["2020 R2", "2023", "2023 R2"]),
    ("ge", "Proficy Historian", "historian", "application", "windows", "3",
     ["opc-ua", "opc-hda", "sql"], ["2022", "2023", "9.1"]),
    ("honeywell", "Uniformance PHD Historian", "historian", "application", "windows", "3",
     ["opc-ua", "opc-hda", "sql"], ["R500", "R400", "R321"]),
    ("emerson", "DeltaV Continuous Historian", "historian", "application", "windows", "3",
     ["opc-ua", "opc-hda"], ["14.3", "14.LTS", "15.LTS"]),
    ("yokogawa", "Exaquantum Plant Information System", "historian", "application", "windows", "3",
     ["opc-ua", "opc-hda", "sql"], ["R3.20", "R3.15", "R3.30"]),

    # ---- Engineering Workstation software ----
    ("siemens", "TIA Portal Engineering Suite", "engineering-workstation", "application", "windows", "3",
     ["profinet", "s7comm-plus", "opc-ua"], ["V17", "V18", "V19"]),
    ("rockwell", "Studio 5000 Logix Designer", "engineering-workstation", "application", "windows", "3",
     ["ethernet-ip", "cip"], ["32.00", "33.00", "34.00", "35.00"]),
    ("schneider", "EcoStruxure Control Expert", "engineering-workstation", "application", "windows", "3",
     ["modbus-tcp", "ethernet-ip", "opc-ua"], ["V15.1", "V16.0", "V16.1"]),
    ("mitsubishi", "GX Works3 Engineering Tool", "engineering-workstation", "application", "windows", "3",
     ["cc-link-ie", "melsoft"], ["1.080J", "1.090U", "1.100E"]),
    ("codesys", "CODESYS Development System", "engineering-workstation", "application", "windows", "3",
     ["modbus-tcp", "opc-ua", "ethercat"], ["V3.5 SP17", "V3.5 SP18", "V3.5 SP19"]),
    ("abb", "Automation Builder", "engineering-workstation", "application", "windows", "3",
     ["modbus-tcp", "profinet", "ethercat"], ["2.5", "2.6", "2.7"]),

    # ---- DCS ----
    ("emerson", "DeltaV MD Plus Controller", "dcs-controller", "firmware", "vxworks", "1",
     ["deltav-proprietary", "modbus-tcp", "opc-ua", "hart-ip"], ["MD Plus", "SX", "PK"]),
    ("honeywell", "Experion C300 Controller", "dcs-controller", "firmware", "vxworks", "1",
     ["fte", "modbus-tcp", "hart-ip", "opc-ua"], ["C300", "C200E", "UOC"]),
    ("yokogawa", "CENTUM VP Field Control Station", "dcs-controller", "firmware", "proprietary-rtos", "1",
     ["vnet-ip", "modbus-tcp", "hart-ip", "foundation-fieldbus"], ["AFV30D", "AFV10D", "AFV40S"]),
    ("abb", "AC 800M Controller", "dcs-controller", "firmware", "vxworks", "1",
     ["profibus", "modbus-tcp", "iec-61850-mms", "opc-ua"], ["PM866", "PM891", "PM864A"]),
    ("siemens", "SIMATIC PCS 7 AS Controller", "dcs-controller", "firmware", "proprietary-rtos", "1",
     ["profibus", "profinet", "opc-ua"], ["AS 410-5H", "AS 417-4", "AS 416-3"]),
    ("hitachi_energy", "Symphony Plus HPC800", "dcs-controller", "firmware", "vxworks", "1",
     ["modbus-tcp", "iec-61850-mms", "opc-ua"], ["HPC800", "BRC410", "SPC700"]),

    # ---- Safety Instrumented System ----
    ("schneider", "Triconex Tricon CX Controller", "sis-logic-solver", "firmware", "proprietary-rtos", "1",
     ["tristation", "modbus-tcp", "opc-ua"], ["Tricon CX", "Trident 3", "Tri-GP"]),
    ("hima", "HIMax Safety Controller", "sis-logic-solver", "firmware", "proprietary-rtos", "1",
     ["safeethernet", "modbus-tcp", "opc-ua"], ["X-CPU 31", "X-CPU 01", "HIMatrix F35"]),
    ("pilz", "PSS 4000 Safety Controller", "sis-logic-solver", "firmware", "proprietary-rtos", "1",
     ["safetynet-p", "profinet", "modbus-tcp"], ["PSSu H PLC1", "PSSu H FS", "PSS 4000-R"]),
    ("siemens", "SIMATIC S7-1500F Safety CPU", "sis-logic-solver", "firmware", "proprietary-rtos", "1",
     ["profisafe", "profinet", "opc-ua"], ["1511F-1 PN", "1516F-3 PN/DP", "1518F-4 PN/DP"]),
    ("rockwell", "GuardLogix Safety Controller", "sis-logic-solver", "firmware", "vxworks", "1",
     ["cip-safety", "ethernet-ip"], ["1756-L81ES", "1756-L83ES", "5069-L306ERS2"]),

    # ---- Protocol gateway / edge ----
    ("moxa", "MGate Protocol Gateway", "protocol-gateway", "firmware", "linux", "3.5",
     ["modbus-tcp", "ethernet-ip", "profinet", "dnp3", "iec-60870-5-104"],
     ["5105-MB-EIP", "5119", "5217A", "EIP3170I"]),
    ("softing", "edgeAggregator Gateway", "protocol-gateway", "application", "linux", "3.5",
     ["opc-ua", "mqtt", "modbus-tcp", "s7comm"], ["EA-500", "EA-300", "uaGate SI"]),
    ("hms_stub", "", "", "", "", "", [], []),  # placeholder removed below
    ("advantech", "ECU-1251 Edge Gateway", "protocol-gateway", "firmware", "linux", "3.5",
     ["modbus-tcp", "mqtt", "opc-ua", "dnp3"], ["ECU-1251", "ECU-1051", "ECU-4784"]),
    ("phoenix", "FL MGUARD Security Appliance", "industrial-firewall", "firmware", "linux", "3.5",
     ["ipsec", "modbus-tcp-dpi", "opc-ua"], ["RS4000", "RS2000", "CENTERPORT"]),
    ("belden", "EAGLE40 Industrial Firewall", "industrial-firewall", "firmware", "linux", "3.5",
     ["modbus-tcp-dpi", "iec-61850-dpi", "ipsec"], ["EAGLE40-4D", "EAGLE30", "EAGLE20"]),
    ("belden", "RSP Managed Switch", "industrial-switch", "firmware", "linux", "2",
     ["prp", "hsr", "iec-61850-mms", "snmp"], ["RSP35", "RSP20", "RSPE37"]),
    ("westermo", "Lynx DSS Managed Switch", "industrial-switch", "firmware", "linux", "2",
     ["snmp", "prp", "modbus-tcp"], ["Lynx-3510", "Lynx-5612", "RedFox-5528"]),
    ("moxa", "EDS Managed Ethernet Switch", "industrial-switch", "firmware", "linux", "2",
     ["snmp", "prp", "modbus-tcp"], ["EDS-4012", "EDS-508A", "EDS-G516E"]),
    ("siemens", "SCALANCE X Industrial Switch", "industrial-switch", "firmware", "linux", "2",
     ["profinet", "snmp", "prp"], ["XC216-4C", "X308-2", "XM416-4C"]),
    ("siemens", "RUGGEDCOM RX1500 Router", "industrial-router", "firmware", "linux", "3.5",
     ["snmp", "ipsec", "iec-61850-mms"], ["RX1500", "RX1400", "RX5000"]),

    # ---- Drives / Motion / Robotics ----
    ("abb", "ACS880 Industrial Drive", "vfd-drive", "firmware", "proprietary-rtos", "1",
     ["profinet", "ethernet-ip", "modbus-tcp", "ethercat"], ["ACS880-01", "ACS880-07", "ACS580-01"]),
    ("siemens", "SINAMICS S120 Drive", "vfd-drive", "firmware", "proprietary-rtos", "1",
     ["profinet", "profisafe", "ethernet-ip"], ["CU320-2 PN", "CU310-2 PN", "S210"]),
    ("danfoss", "VLT AutomationDrive", "vfd-drive", "firmware", "proprietary-rtos", "1",
     ["profinet", "modbus-tcp", "ethernet-ip"], ["FC-302", "FC-102", "FC-360"]),
    ("rockwell", "PowerFlex 755 Drive", "vfd-drive", "firmware", "proprietary-rtos", "1",
     ["ethernet-ip", "cip", "devicenet"], ["755", "755T", "527"]),
    ("bosch_rexroth", "IndraDrive Controller", "motion-controller", "firmware", "proprietary-rtos", "1",
     ["sercos-iii", "profinet", "ethercat", "ethernet-ip"], ["HCS01", "HCS02", "HMS01"]),
    ("bosch_rexroth", "IndraMotion MLC", "motion-controller", "firmware", "linux", "1",
     ["sercos-iii", "opc-ua", "profinet"], ["XM22", "XM42", "L75"]),
    ("fuji", "FRENIC-Ace Inverter", "vfd-drive", "firmware", "proprietary-rtos", "1",
     ["modbus-tcp", "profinet"], ["FRN0006E2S", "FRN0012E2S", "FRN0022E2S"]),
    ("mitsubishi", "MELFA Robot Controller", "robot-controller", "firmware", "proprietary-rtos", "1",
     ["cc-link-ie", "ethernet-ip", "melsoft"], ["CR800-D", "CR800-R", "CR750-Q"]),
    ("abb", "IRC5 Robot Controller", "robot-controller", "firmware", "vxworks", "1",
     ["profinet", "ethernet-ip", "devicenet"], ["IRC5 Compact", "IRC5 Single", "OmniCore C30"]),
    ("keyence", "CNC Motion Unit", "cnc-controller", "firmware", "proprietary-rtos", "1",
     ["ethernet-ip", "modbus-tcp"], ["MC-1", "MC-2", "MC-4"]),
    ("mitsubishi", "M800 CNC Controller", "cnc-controller", "firmware", "proprietary-rtos", "1",
     ["cc-link-ie", "melsoft", "ethernet-ip"], ["M830W", "M850W", "M80W"]),

    # ---- Instrumentation / Level 0-1 ----
    ("emerson", "Rosemount 3051S Transmitter", "field-transmitter", "firmware", "bare-metal", "0",
     ["hart", "hart-ip", "foundation-fieldbus"], ["3051S", "3051SMV", "3051CD"]),
    ("yokogawa", "EJA-E Series Transmitter", "field-transmitter", "firmware", "bare-metal", "0",
     ["hart", "foundation-fieldbus", "profibus-pa"], ["EJA110E", "EJA430E", "EJX910A"]),
    ("honeywell", "SmartLine ST800 Transmitter", "field-transmitter", "firmware", "bare-metal", "0",
     ["hart", "foundation-fieldbus"], ["ST800", "ST700", "STT850"]),
    ("abb", "Merging Unit SAM600", "merging-unit", "firmware", "proprietary-rtos", "0",
     ["iec-61850-sv", "iec-61850-goose", "ptp-1588"], ["SAM600-IO", "SAM600-CT", "SAM600-VT"]),
    ("schneider", "PowerLogic ION9000 Meter", "power-meter", "firmware", "linux", "1",
     ["modbus-tcp", "dnp3", "iec-61850-mms"], ["ION9000", "ION7650", "PM8000"]),
    ("ge", "EPM 9900 Power Meter", "power-meter", "firmware", "proprietary-rtos", "1",
     ["modbus-tcp", "dnp3", "iec-61850-mms"], ["EPM9900", "EPM7000", "EPM6100"]),

    # ---- OPC / connectivity servers ----
    ("ptc", "KEPServerEX Connectivity Platform", "opc-server", "application", "windows", "3",
     ["opc-ua", "opc-da", "modbus-tcp", "ethernet-ip", "s7comm"], ["6.11", "6.13", "6.15"]),
    ("softing", "dataFEED OPC Suite", "opc-server", "application", "windows", "3",
     ["opc-ua", "opc-da", "mqtt", "s7comm"], ["V5.20", "V5.22", "V5.30"]),
    ("aveva", "AVEVA OPC UA Server", "opc-server", "application", "windows", "3",
     ["opc-ua", "opc-da"], ["2020", "2023", "2023 R2"]),

    # ---- Building automation ----
    ("honeywell", "Excel Web II BACnet Controller", "bas-controller", "firmware", "linux", "1",
     ["bacnet-ip", "modbus-tcp", "lonworks"], ["XL1000C50", "XL1000C1000", "CIPer 50"]),
    ("siemens", "Desigo PXC Automation Station", "bas-controller", "firmware", "proprietary-rtos", "1",
     ["bacnet-ip", "modbus-tcp", "knx"], ["PXC100-E.D", "PXC200-E.D", "PXC7 Modular"]),
    ("schneider", "SmartX AS-P Controller", "bas-controller", "firmware", "linux", "1",
     ["bacnet-ip", "modbus-tcp", "lonworks"], ["AS-P", "AS-B", "RP-C"]),
    ("delta", "eZ Building Controller", "bas-controller", "firmware", "linux", "1",
     ["bacnet-ip", "modbus-tcp"], ["eZNS-1000", "eZNS-500", "DAC-633"]),

    # ---- Wireless / remote access ----
    ("phoenix", "Radioline Wireless Gateway", "wireless-gateway", "firmware", "freertos", "1",
     ["modbus-tcp", "trusted-wireless"], ["RAD-2400", "RAD-900", "RAD-868"]),
    ("moxa", "AWK Industrial Wireless AP", "wireless-gateway", "firmware", "linux", "2",
     ["snmp", "modbus-tcp", "wpa2"], ["AWK-3131A", "AWK-4131A", "AWK-1137C"]),
    ("emerson", "Wireless 1420 Gateway", "wireless-gateway", "firmware", "linux", "1",
     ["wirelesshart", "modbus-tcp", "opc-ua"], ["1420", "1410S", "1552WU"]),
]

# 잘못 들어간 placeholder 제거
PRODUCTS = [p for p in PRODUCTS if p[1]]

# ---------------------------------------------------------------------------
# 소프트웨어 부품 카탈로그
#   name, publisher, purl_type, purl_name, [ (version, [CVE...]) ], tags, role, license
#   버전 목록 중 일부는 실제 CVE 가 존재하는 취약 버전이다(정답셋으로 기록).
# ---------------------------------------------------------------------------

OSS = {
    "openssl": dict(
        name="OpenSSL", publisher="OpenSSL Project", purl="pkg:generic/openssl",
        cpe_vendor="openssl", cpe_product="openssl", license="Apache-2.0",
        role="cryptography", tags=["crypto", "tls", "oss"],
        desc="TLS/SSL 및 범용 암호 라이브러리. 장비의 보안 통신 채널과 인증서 처리를 담당한다.",
        versions=[
            ("1.0.2k", ["CVE-2017-3731", "CVE-2017-3732", "CVE-2016-7055"]),
            ("1.0.2u", ["CVE-2021-23840", "CVE-2021-3712"]),
            ("1.1.1g", ["CVE-2020-1971", "CVE-2021-3450", "CVE-2021-3711"]),
            ("1.1.1k", ["CVE-2021-3711", "CVE-2021-3712", "CVE-2022-0778"]),
            ("1.1.1n", ["CVE-2022-1292", "CVE-2022-2068", "CVE-2022-4304"]),
            ("3.0.7", ["CVE-2023-0286", "CVE-2023-0215", "CVE-2022-4304"]),
            ("3.0.13", []),
            ("3.1.4", []),
            ("3.2.1", []),
        ]),
    "busybox": dict(
        name="BusyBox", publisher="BusyBox Project", purl="pkg:generic/busybox",
        cpe_vendor="busybox", cpe_product="busybox", license="GPL-2.0-only",
        role="system-utilities", tags=["userland", "shell", "oss"],
        desc="임베디드 리눅스 기본 유틸리티 모음. 부팅 스크립트와 진단 셸 명령을 제공한다.",
        versions=[
            ("1.20.2", ["CVE-2017-16544", "CVE-2016-2147", "CVE-2018-1000500"]),
            ("1.30.1", ["CVE-2021-42374", "CVE-2021-42378", "CVE-2021-42386"]),
            ("1.31.1", ["CVE-2021-42375", "CVE-2021-42376", "CVE-2022-28391"]),
            ("1.33.1", ["CVE-2021-42379", "CVE-2021-42380", "CVE-2022-28391"]),
            ("1.35.0", ["CVE-2022-28391"]),
            ("1.36.1", []),
        ]),
    "zlib": dict(
        name="zlib", publisher="zlib Project", purl="pkg:generic/zlib",
        cpe_vendor="zlib", cpe_product="zlib", license="Zlib",
        role="compression", tags=["compression", "oss"],
        desc="펌웨어 이미지와 로그 압축/해제에 사용되는 무손실 압축 라이브러리.",
        versions=[
            ("1.2.8", ["CVE-2016-9840", "CVE-2016-9841", "CVE-2018-25032"]),
            ("1.2.11", ["CVE-2018-25032", "CVE-2022-37434"]),
            ("1.2.12", ["CVE-2022-37434"]),
            ("1.2.13", []),
            ("1.3.1", []),
        ]),
    "libcurl": dict(
        name="libcurl", publisher="curl Project", purl="pkg:generic/curl",
        cpe_vendor="haxx", cpe_product="libcurl", license="curl",
        role="http-client", tags=["http", "client", "oss"],
        desc="펌웨어 업데이트 다운로드 및 클라우드 원격 측정 업로드에 사용하는 HTTP/TLS 클라이언트.",
        versions=[
            ("7.29.0", ["CVE-2016-8615", "CVE-2018-1000120", "CVE-2019-5482"]),
            ("7.64.0", ["CVE-2019-5481", "CVE-2019-5482", "CVE-2020-8177"]),
            ("7.79.1", ["CVE-2022-22576", "CVE-2022-27774", "CVE-2022-32221"]),
            ("8.0.1", ["CVE-2023-27533", "CVE-2023-27536", "CVE-2023-38545"]),
            ("8.4.0", ["CVE-2023-46218", "CVE-2024-2379"]),
            ("8.7.1", []),
        ]),
    "lwip": dict(
        name="lwIP", publisher="lwIP Project", purl="pkg:generic/lwip",
        cpe_vendor="lwip_project", cpe_product="lwip", license="BSD-3-Clause",
        role="tcp-ip-stack", tags=["network", "tcpip", "oss"],
        desc="경량 TCP/IP 스택. 소형 제어기의 Modbus/TCP 및 진단 웹 통신 경로를 담당한다.",
        versions=[
            ("1.4.1", ["CVE-2014-1912", "CVE-2020-22283", "CVE-2020-22284"]),
            ("2.0.3", ["CVE-2020-22283", "CVE-2020-22284", "CVE-2020-22288"]),
            ("2.1.2", ["CVE-2020-22283", "CVE-2020-22285", "CVE-2020-22286"]),
            ("2.1.3", ["CVE-2023-5188"]),
            ("2.2.0", []),
        ]),
    "linux_kernel": dict(
        name="Linux Kernel", publisher="Linux Kernel Organization", purl="pkg:generic/linux",
        cpe_vendor="linux", cpe_product="linux_kernel", license="GPL-2.0-only",
        role="operating-system-kernel", tags=["kernel", "os", "oss"],
        desc="장비 운영체제 커널. 스케줄링, 메모리 관리, 디바이스 드라이버 계층을 제공한다.",
        versions=[
            ("3.10.108", ["CVE-2017-1000112", "CVE-2018-5333", "CVE-2019-11477"]),
            ("4.9.337", ["CVE-2019-11477", "CVE-2021-33909", "CVE-2022-0847"]),
            ("4.14.336", ["CVE-2021-33909", "CVE-2022-0847"]),
            ("4.19.325", ["CVE-2022-0847", "CVE-2023-32233"]),
            ("5.4.278", ["CVE-2023-32233", "CVE-2024-1086"]),
            ("5.10.220", ["CVE-2024-1086"]),
            ("5.15.160", []),
            ("6.1.90", []),
        ]),
    "dropbear": dict(
        name="Dropbear SSH", publisher="Matt Johnston", purl="pkg:generic/dropbear",
        cpe_vendor="dropbear_ssh_project", cpe_product="dropbear_ssh", license="MIT",
        role="remote-access", tags=["ssh", "remote", "oss"],
        desc="경량 SSH 서버. 현장 엔지니어의 원격 진단 셸 접속 경로를 제공한다.",
        versions=[
            ("2016.74", ["CVE-2016-7406", "CVE-2016-7407", "CVE-2016-7408"]),
            ("2019.78", ["CVE-2018-15599", "CVE-2020-36254"]),
            ("2020.81", ["CVE-2021-36369"]),
            ("2022.83", ["CVE-2023-48795"]),
            ("2024.85", []),
        ]),
    "openssh": dict(
        name="OpenSSH", publisher="OpenBSD Project", purl="pkg:generic/openssh",
        cpe_vendor="openbsd", cpe_product="openssh", license="BSD-2-Clause",
        role="remote-access", tags=["ssh", "remote", "oss"],
        desc="원격 관리 및 안전한 파일 전송에 사용되는 SSH 서버/클라이언트.",
        versions=[
            ("7.4p1", ["CVE-2018-15473", "CVE-2019-6111", "CVE-2016-10708"]),
            ("8.2p1", ["CVE-2020-15778", "CVE-2021-41617", "CVE-2023-48795"]),
            ("9.3p1", ["CVE-2023-38408", "CVE-2023-48795", "CVE-2024-6387"]),
            ("9.6p1", ["CVE-2024-6387"]),
            ("9.8p1", []),
        ]),
    "mbedtls": dict(
        name="Mbed TLS", publisher="Trusted Firmware", purl="pkg:generic/mbedtls",
        cpe_vendor="arm", cpe_product="mbed_tls", license="Apache-2.0",
        role="cryptography", tags=["crypto", "tls", "embedded", "oss"],
        desc="MCU 급 장비를 위한 경량 TLS 스택. 클라우드 및 게이트웨이 연결을 암호화한다.",
        versions=[
            ("2.16.3", ["CVE-2020-10932", "CVE-2020-16150", "CVE-2021-24119"]),
            ("2.28.0", ["CVE-2022-35409", "CVE-2023-43615"]),
            ("3.4.0", ["CVE-2023-43615"]),
            ("3.5.2", []),
        ]),
    "wolfssl": dict(
        name="wolfSSL", publisher="wolfSSL Inc.", purl="pkg:generic/wolfssl",
        cpe_vendor="wolfssl", cpe_product="wolfssl", license="GPL-2.0-or-later",
        role="cryptography", tags=["crypto", "tls", "embedded"],
        desc="실시간 제어기용 소형 TLS 라이브러리. 인증서 검증과 세션 암호화를 수행한다.",
        versions=[
            ("4.5.0", ["CVE-2021-3336", "CVE-2021-24116"]),
            ("5.5.0", ["CVE-2022-42905", "CVE-2023-3724"]),
            ("5.6.6", []),
        ]),
    "libxml2": dict(
        name="libxml2", publisher="GNOME Project", purl="pkg:generic/libxml2",
        cpe_vendor="xmlsoft", cpe_product="libxml2", license="MIT",
        role="xml-parser", tags=["xml", "parser", "oss"],
        desc="IEC 61850 SCL, PLCopen XML 등 설정 파일 파싱에 사용하는 XML 처리기.",
        versions=[
            ("2.9.4", ["CVE-2016-9318", "CVE-2017-5969", "CVE-2018-14567"]),
            ("2.9.10", ["CVE-2021-3517", "CVE-2021-3518", "CVE-2022-29824"]),
            ("2.9.14", ["CVE-2022-40303", "CVE-2022-40304", "CVE-2023-28484"]),
            ("2.10.4", ["CVE-2023-45322"]),
            ("2.12.5", []),
        ]),
    "expat": dict(
        name="Expat", publisher="libexpat Project", purl="pkg:generic/expat",
        cpe_vendor="libexpat_project", cpe_product="libexpat", license="MIT",
        role="xml-parser", tags=["xml", "parser", "oss"],
        desc="스트림 방식 XML 파서. 장치 기술 파일과 프로젝트 설정 처리에 사용된다.",
        versions=[
            ("2.2.0", ["CVE-2018-20843", "CVE-2019-15903"]),
            ("2.2.10", ["CVE-2022-22822", "CVE-2022-23852", "CVE-2022-25235"]),
            ("2.4.1", ["CVE-2022-25236", "CVE-2022-25315"]),
            ("2.5.0", ["CVE-2023-52425"]),
            ("2.6.2", []),
        ]),
    "sqlite": dict(
        name="SQLite", publisher="SQLite Consortium", purl="pkg:generic/sqlite",
        cpe_vendor="sqlite", cpe_product="sqlite", license="blessing",
        role="embedded-database", tags=["database", "storage", "oss"],
        desc="알람 이력, 트렌드 버퍼, 로컬 설정 저장을 위한 내장형 데이터베이스 엔진.",
        versions=[
            ("3.22.0", ["CVE-2018-8740", "CVE-2019-8457", "CVE-2020-11655"]),
            ("3.31.1", ["CVE-2020-13434", "CVE-2020-13630", "CVE-2021-20227"]),
            ("3.39.4", ["CVE-2022-46908", "CVE-2023-7104"]),
            ("3.41.2", ["CVE-2023-7104"]),
            ("3.45.1", []),
        ]),
    "net_snmp": dict(
        name="Net-SNMP", publisher="Net-SNMP Project", purl="pkg:generic/net-snmp",
        cpe_vendor="net-snmp", cpe_product="net-snmp", license="BSD-3-Clause",
        role="network-management", tags=["snmp", "management", "oss"],
        desc="네트워크 관리 시스템이 장비 상태를 폴링할 수 있게 하는 SNMP 에이전트.",
        versions=[
            ("5.7.3", ["CVE-2018-18065", "CVE-2019-20892", "CVE-2020-15862"]),
            ("5.8", ["CVE-2020-15861", "CVE-2020-15862", "CVE-2022-24805"]),
            ("5.9.1", ["CVE-2022-24805", "CVE-2022-24809"]),
            ("5.9.4", []),
        ]),
    "lighttpd": dict(
        name="lighttpd", publisher="lighttpd Project", purl="pkg:generic/lighttpd",
        cpe_vendor="lighttpd", cpe_product="lighttpd", license="BSD-3-Clause",
        role="web-server", tags=["web", "http", "oss"],
        desc="장비 내장 웹 설정 화면을 제공하는 경량 HTTP 서버.",
        versions=[
            ("1.4.45", ["CVE-2018-19052", "CVE-2019-11072"]),
            ("1.4.55", ["CVE-2022-22707", "CVE-2023-44487"]),
            ("1.4.64", ["CVE-2023-44487"]),
            ("1.4.76", []),
        ]),
    "goahead": dict(
        name="GoAhead Embedded Web Server", publisher="EmbedThis Software",
        purl="pkg:generic/goahead", cpe_vendor="embedthis", cpe_product="goahead",
        license="GPL-2.0-only", role="web-server", tags=["web", "http", "embedded"],
        desc="임베디드 장비의 설정 웹 UI 를 서비스하는 소형 웹 서버.",
        versions=[
            ("3.6.5", ["CVE-2017-17562", "CVE-2019-5096", "CVE-2019-5097"]),
            ("4.1.0", ["CVE-2021-42342"]),
            ("5.1.0", []),
            ("6.0.0", []),
        ]),
    "nginx": dict(
        name="nginx", publisher="F5 / nginx", purl="pkg:generic/nginx",
        cpe_vendor="f5", cpe_product="nginx", license="BSD-2-Clause",
        role="web-server", tags=["web", "reverse-proxy", "oss"],
        desc="감시 화면과 REST API 를 서비스하는 웹 서버 및 리버스 프록시.",
        versions=[
            ("1.14.2", ["CVE-2019-9511", "CVE-2019-9513", "CVE-2019-20372"]),
            ("1.18.0", ["CVE-2021-23017", "CVE-2022-41741", "CVE-2022-41742"]),
            ("1.20.1", ["CVE-2022-41741", "CVE-2022-41742"]),
            ("1.24.0", ["CVE-2023-44487"]),
            ("1.26.0", []),
        ]),
    "dnsmasq": dict(
        name="dnsmasq", publisher="Simon Kelley", purl="pkg:generic/dnsmasq",
        cpe_vendor="thekelleys", cpe_product="dnsmasq", license="GPL-2.0-only",
        role="network-services", tags=["dns", "dhcp", "oss"],
        desc="셀 네트워크 내부의 DNS 캐시 및 DHCP 주소 할당 서비스.",
        versions=[
            ("2.78", ["CVE-2017-14491", "CVE-2017-14492", "CVE-2020-25681"]),
            ("2.82", ["CVE-2020-25681", "CVE-2020-25684", "CVE-2021-3448"]),
            ("2.86", ["CVE-2022-0934", "CVE-2023-28450"]),
            ("2.90", []),
        ]),
    "wpa_supplicant": dict(
        name="wpa_supplicant", publisher="Jouni Malinen", purl="pkg:generic/wpa_supplicant",
        cpe_vendor="w1.fi", cpe_product="wpa_supplicant", license="BSD-3-Clause",
        role="wireless-security", tags=["wifi", "wpa", "oss"],
        desc="무선 백홀 링크의 WPA2/WPA3 인증 및 키 교환을 수행하는 서플리컨트.",
        versions=[
            ("2.6", ["CVE-2017-13077", "CVE-2017-13078", "CVE-2018-14526"]),
            ("2.9", ["CVE-2021-27803", "CVE-2021-30004", "CVE-2022-23303"]),
            ("2.10", ["CVE-2023-52160"]),
            ("2.11", []),
        ]),
    "u_boot": dict(
        name="Das U-Boot", publisher="DENX Software Engineering", purl="pkg:generic/u-boot",
        cpe_vendor="denx", cpe_product="u-boot", license="GPL-2.0-only",
        role="bootloader", tags=["bootloader", "boot", "oss"],
        desc="부트로더. 펌웨어 이미지 무결성 검증과 커널 로딩을 담당한다.",
        versions=[
            ("2018.03", ["CVE-2019-11059", "CVE-2019-13103", "CVE-2019-13106"]),
            ("2020.04", ["CVE-2020-10648", "CVE-2021-27097", "CVE-2022-30767"]),
            ("2021.10", ["CVE-2022-30767", "CVE-2022-33967"]),
            ("2023.10", []),
        ]),
    "glibc": dict(
        name="GNU C Library", publisher="GNU Project", purl="pkg:generic/glibc",
        cpe_vendor="gnu", cpe_product="glibc", license="LGPL-2.1-or-later",
        role="c-runtime", tags=["libc", "runtime", "oss"],
        desc="애플리케이션이 사용하는 표준 C 런타임 및 시스템 콜 래퍼.",
        versions=[
            ("2.17", ["CVE-2015-7547", "CVE-2018-11236", "CVE-2021-3999"]),
            ("2.28", ["CVE-2021-3999", "CVE-2021-33574", "CVE-2023-4911"]),
            ("2.31", ["CVE-2021-35942", "CVE-2023-4911"]),
            ("2.35", ["CVE-2023-4911", "CVE-2024-2961"]),
            ("2.38", []),
        ]),
    "musl": dict(
        name="musl libc", publisher="musl Project", purl="pkg:generic/musl",
        cpe_vendor="musl-libc", cpe_product="musl", license="MIT",
        role="c-runtime", tags=["libc", "runtime", "oss"],
        desc="용량이 제한된 임베디드 이미지를 위한 경량 표준 C 라이브러리.",
        versions=[
            ("1.1.24", ["CVE-2020-28928"]),
            ("1.2.2", ["CVE-2020-28928"]),
            ("1.2.4", []),
        ]),
    "mosquitto": dict(
        name="Eclipse Mosquitto", publisher="Eclipse Foundation", purl="pkg:generic/mosquitto",
        cpe_vendor="eclipse", cpe_product="mosquitto", license="EPL-2.0",
        role="messaging-broker", tags=["mqtt", "messaging", "oss"],
        desc="엣지 계층의 MQTT 브로커. 현장 데이터를 상위 시스템으로 발행한다.",
        versions=[
            ("1.5.8", ["CVE-2019-11779", "CVE-2021-28166"]),
            ("2.0.11", ["CVE-2021-34431", "CVE-2021-41039", "CVE-2023-0809"]),
            ("2.0.15", ["CVE-2023-0809", "CVE-2023-3592"]),
            ("2.0.18", []),
        ]),
    "open62541": dict(
        name="open62541 OPC UA Stack", publisher="open62541 Project", purl="pkg:generic/open62541",
        cpe_vendor="open62541", cpe_product="open62541", license="MPL-2.0",
        role="opc-ua-stack", tags=["opc-ua", "protocol", "oss"],
        desc="장비 내장 OPC UA 서버 구현. 태그 주소공간과 보안 채널을 제공한다.",
        versions=[
            ("1.2.2", ["CVE-2021-40206", "CVE-2022-25761"]),
            ("1.3.6", ["CVE-2023-31048"]),
            ("1.3.9", []),
        ]),
    "libmodbus": dict(
        name="libmodbus", publisher="libmodbus Project", purl="pkg:generic/libmodbus",
        cpe_vendor="libmodbus", cpe_product="libmodbus", license="LGPL-2.1-or-later",
        role="protocol-stack", tags=["modbus", "protocol", "oss"],
        desc="Modbus RTU/TCP 마스터·슬레이브 프레임 처리 라이브러리.",
        versions=[
            ("3.0.6", ["CVE-2019-14462", "CVE-2019-14463"]),
            ("3.1.4", ["CVE-2019-14462", "CVE-2019-14463"]),
            ("3.1.6", []),
            ("3.1.10", []),
        ]),
    "freertos": dict(
        name="FreeRTOS Kernel", publisher="Amazon Web Services", purl="pkg:generic/freertos-kernel",
        cpe_vendor="amazon", cpe_product="freertos", license="MIT",
        role="rtos-kernel", tags=["rtos", "kernel", "oss"],
        desc="실시간 태스크 스케줄링과 결정적 인터럽트 응답을 제공하는 RTOS 커널.",
        versions=[
            ("10.2.1", ["CVE-2021-31571", "CVE-2021-31572"]),
            ("10.4.3", ["CVE-2021-32020", "CVE-2021-43997"]),
            ("11.0.1", []),
        ]),
    "zephyr": dict(
        name="Zephyr RTOS", publisher="Zephyr Project", purl="pkg:generic/zephyr",
        cpe_vendor="zephyrproject", cpe_product="zephyr", license="Apache-2.0",
        role="rtos-kernel", tags=["rtos", "kernel", "oss"],
        desc="센서·게이트웨이 노드용 실시간 커널 및 디바이스 드라이버 프레임워크.",
        versions=[
            ("2.5.0", ["CVE-2021-3319", "CVE-2021-3323", "CVE-2021-3581"]),
            ("3.1.0", ["CVE-2023-3725", "CVE-2023-4257"]),
            ("3.6.0", []),
        ]),
    "log4j": dict(
        name="Apache Log4j", publisher="Apache Software Foundation", purl="pkg:maven/org.apache.logging.log4j/log4j-core",
        cpe_vendor="apache", cpe_product="log4j", license="Apache-2.0",
        role="logging", tags=["java", "logging", "oss"],
        desc="Java 기반 감시 서버의 이벤트/감사 로깅 프레임워크.",
        versions=[
            ("2.14.1", ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]),
            ("2.15.0", ["CVE-2021-45046", "CVE-2021-45105"]),
            ("2.17.0", ["CVE-2021-44832"]),
            ("2.20.0", []),
            ("2.23.1", []),
        ]),
    "tomcat": dict(
        name="Apache Tomcat", publisher="Apache Software Foundation", purl="pkg:maven/org.apache.tomcat/tomcat",
        cpe_vendor="apache", cpe_product="tomcat", license="Apache-2.0",
        role="application-server", tags=["java", "web", "oss"],
        desc="웹 기반 감시 클라이언트를 서비스하는 서블릿 컨테이너.",
        versions=[
            ("7.0.90", ["CVE-2019-0221", "CVE-2019-0232", "CVE-2020-1938"]),
            ("8.5.63", ["CVE-2021-25122", "CVE-2021-30640", "CVE-2021-41079"]),
            ("9.0.63", ["CVE-2022-42252", "CVE-2023-28708", "CVE-2023-44487"]),
            ("10.1.19", []),
        ]),
    "openjdk": dict(
        name="OpenJDK Runtime", publisher="Eclipse Adoptium", purl="pkg:generic/openjdk",
        cpe_vendor="oracle", cpe_product="jdk", license="GPL-2.0-with-classpath-exception",
        role="language-runtime", tags=["java", "runtime", "oss"],
        desc="감시/이력 서버 애플리케이션이 실행되는 Java 런타임.",
        versions=[
            ("8u202", ["CVE-2019-2602", "CVE-2019-2699", "CVE-2020-2803"]),
            ("11.0.14", ["CVE-2022-21426", "CVE-2022-21449", "CVE-2022-21496"]),
            ("17.0.6", ["CVE-2023-21930", "CVE-2023-21937"]),
            ("17.0.10", []),
        ]),
    "jackson": dict(
        name="Jackson Databind", publisher="FasterXML", purl="pkg:maven/com.fasterxml.jackson.core/jackson-databind",
        cpe_vendor="fasterxml", cpe_product="jackson-databind", license="Apache-2.0",
        role="serialization", tags=["java", "json", "oss"],
        desc="REST API 및 설정 파일의 JSON 직렬화/역직렬화 처리기.",
        versions=[
            ("2.9.10", ["CVE-2019-20330", "CVE-2020-8840", "CVE-2020-36518"]),
            ("2.12.3", ["CVE-2020-36518", "CVE-2022-42003", "CVE-2022-42004"]),
            ("2.13.4", ["CVE-2022-42003", "CVE-2022-42004"]),
            ("2.16.1", []),
        ]),
    "spring": dict(
        name="Spring Framework", publisher="VMware Tanzu", purl="pkg:maven/org.springframework/spring-core",
        cpe_vendor="vmware", cpe_product="spring_framework", license="Apache-2.0",
        role="application-framework", tags=["java", "framework", "oss"],
        desc="감시 서버 백엔드 서비스의 의존성 주입 및 웹 계층 프레임워크.",
        versions=[
            ("5.3.17", ["CVE-2022-22965", "CVE-2022-22968", "CVE-2022-22970"]),
            ("5.3.25", ["CVE-2023-20860", "CVE-2023-20861"]),
            ("6.0.9", ["CVE-2023-34035"]),
            ("6.1.4", []),
        ]),
    "dotnet": dict(
        origin="third-party-commercial",
        name="Microsoft .NET Framework", publisher="Microsoft Corporation", purl="pkg:generic/dotnet-framework",
        cpe_vendor="microsoft", cpe_product=".net_framework", license="NOASSERTION",
        role="language-runtime", tags=["windows", "runtime"],
        desc="Windows 기반 감시/엔지니어링 애플리케이션이 사용하는 관리형 런타임.",
        versions=[
            ("4.6.2", ["CVE-2018-8421", "CVE-2019-0545", "CVE-2020-1147"]),
            ("4.7.2", ["CVE-2020-1147", "CVE-2021-24112", "CVE-2021-26701"]),
            ("4.8", ["CVE-2021-26701", "CVE-2023-21808"]),
            ("4.8.1", []),
        ]),
    "vcredist": dict(
        origin="third-party-commercial",
        name="Microsoft Visual C++ Runtime", publisher="Microsoft Corporation", purl="pkg:generic/vcredist",
        cpe_vendor="microsoft", cpe_product="visual_c++_redistributable", license="NOASSERTION",
        role="c-runtime", tags=["windows", "runtime"],
        desc="네이티브 드라이버 및 통신 모듈이 링크하는 C/C++ 재배포 런타임.",
        versions=[("14.0.24215", []), ("14.16.27033", []), ("14.29.30139", []), ("14.38.33130", [])]),
    "sqlserver_express": dict(
        origin="third-party-commercial",
        name="Microsoft SQL Server Express", publisher="Microsoft Corporation", purl="pkg:generic/mssql-express",
        cpe_vendor="microsoft", cpe_product="sql_server", license="NOASSERTION",
        role="database", tags=["windows", "database"],
        desc="알람/이력 태그를 저장하는 관계형 데이터베이스 엔진.",
        versions=[
            ("2016 SP2", ["CVE-2019-1068", "CVE-2020-0618"]),
            ("2017 CU31", ["CVE-2022-29143", "CVE-2023-21528"]),
            ("2019 CU22", ["CVE-2023-21528"]),
            ("2022 CU11", []),
        ]),
    "treck_tcpip": dict(
        origin="third-party-commercial",
        name="Treck TCP/IP Stack", publisher="Treck Inc.", purl="pkg:generic/treck-tcpip",
        cpe_vendor="treck", cpe_product="tcp%2fip", license="NOASSERTION",
        role="tcp-ip-stack", tags=["network", "tcpip", "commercial"],
        desc="상용 임베디드 TCP/IP 스택. 계측 장비의 이더넷 통신 계층을 구성한다.",
        versions=[
            ("6.0.1.66", ["CVE-2020-11896", "CVE-2020-11897", "CVE-2020-11901"]),
            ("6.0.1.67", ["CVE-2020-11898", "CVE-2020-11900"]),
            ("6.0.1.68", []),
        ]),
    "ipnet": dict(
        origin="third-party-commercial",
        name="Interpeak IPnet TCP/IP Stack", publisher="Wind River Systems", purl="pkg:generic/ipnet",
        cpe_vendor="windriver", cpe_product="vxworks", license="NOASSERTION",
        role="tcp-ip-stack", tags=["network", "tcpip", "vxworks"],
        desc="VxWorks 계열 장비의 네트워크 스택. 소켓과 IP 계층 처리를 담당한다.",
        versions=[
            ("6.9", ["CVE-2019-12255", "CVE-2019-12256", "CVE-2019-12257", "CVE-2019-12260"]),
            ("7.0", ["CVE-2019-12258", "CVE-2019-12259", "CVE-2019-12262"]),
            ("7.2", []),
        ]),
    "codesys_rt": dict(
        origin="third-party-commercial",
        name="CODESYS Control Runtime System", publisher="CODESYS GmbH", purl="pkg:generic/codesys-control",
        cpe_vendor="codesys", cpe_product="control_runtime_system", license="NOASSERTION",
        role="plc-runtime", tags=["plc", "iec-61131", "runtime"],
        desc="IEC 61131-3 프로그램을 실행하는 제어 런타임. 온라인 변경과 통신 서버를 포함한다.",
        versions=[
            ("3.5.16.0", ["CVE-2021-30186", "CVE-2021-30188", "CVE-2021-30189"]),
            ("3.5.17.0", ["CVE-2022-22515", "CVE-2022-22517", "CVE-2022-31802"]),
            ("3.5.18.20", ["CVE-2023-37559", "CVE-2023-37560"]),
            ("3.5.19.20", ["CVE-2023-3663", "CVE-2023-3665"]),
            ("3.5.20.10", []),
        ]),
    "libpcap": dict(
        name="libpcap", publisher="The Tcpdump Group", purl="pkg:generic/libpcap",
        cpe_vendor="tcpdump", cpe_product="libpcap", license="BSD-3-Clause",
        role="packet-capture", tags=["network", "diagnostics", "oss"],
        desc="현장 진단용 패킷 캡처 라이브러리. 프로토콜 트러블슈팅에 사용된다.",
        versions=[
            ("1.8.1", ["CVE-2018-16301", "CVE-2019-15165"]),
            ("1.9.1", ["CVE-2019-15165", "CVE-2023-7256"]),
            ("1.10.4", []),
        ]),
    "ntp": dict(
        name="NTP Daemon", publisher="Network Time Foundation", purl="pkg:generic/ntp",
        cpe_vendor="ntp", cpe_product="ntp", license="NTP",
        role="time-sync", tags=["time", "ntp", "oss"],
        desc="이벤트 타임스탬프 정합성을 위한 시각 동기화 데몬.",
        versions=[
            ("4.2.8p10", ["CVE-2018-7182", "CVE-2018-7183", "CVE-2018-7184"]),
            ("4.2.8p13", ["CVE-2019-8936", "CVE-2020-11868"]),
            ("4.2.8p15", ["CVE-2023-26551"]),
            ("4.2.8p18", []),
        ]),
    "openvpn": dict(
        name="OpenVPN", publisher="OpenVPN Inc.", purl="pkg:generic/openvpn",
        cpe_vendor="openvpn", cpe_product="openvpn", license="GPL-2.0-only",
        role="vpn", tags=["vpn", "remote", "oss"],
        desc="원격 유지보수 접속을 위한 터널링 클라이언트/서버.",
        versions=[
            ("2.4.7", ["CVE-2020-11810", "CVE-2020-15078"]),
            ("2.5.5", ["CVE-2022-0547", "CVE-2023-46849", "CVE-2023-46850"]),
            ("2.6.9", []),
        ]),
    "libssh2": dict(
        name="libssh2", publisher="libssh2 Project", purl="pkg:generic/libssh2",
        cpe_vendor="libssh2", cpe_product="libssh2", license="BSD-3-Clause",
        role="remote-access", tags=["ssh", "library", "oss"],
        desc="설정 백업 전송에 사용하는 SSH/SFTP 클라이언트 라이브러리.",
        versions=[
            ("1.8.0", ["CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3858"]),
            ("1.9.0", ["CVE-2019-17498", "CVE-2020-22218"]),
            ("1.11.0", []),
        ]),
}

# 벤더 고유(비-OSS) 모듈 템플릿: (역할 키, 이름 접미, 설명)
VENDOR_MODULES = [
    ("control-engine", "Control Execution Engine",
     "제어 로직 스캔 사이클을 실행하고 I/O 이미지 테이블을 갱신하는 핵심 실행 엔진."),
    ("io-scanner", "I/O Scanner Module",
     "원격 I/O 및 필드 모듈과의 주기적 데이터 교환을 담당하는 스캐너 모듈."),
    ("config-store", "Configuration Store Service",
     "프로젝트 설정, 태그 정의, 사용자 계정 정보를 영구 저장하고 무결성을 검증하는 서비스."),
    ("diagnostics", "Diagnostics and Event Logger",
     "장비 상태 이벤트, 진단 코드, 감사 로그를 수집하고 보관하는 모듈."),
    ("web-ui", "Embedded Web Configuration UI",
     "브라우저 기반 설정 및 상태 조회 화면을 제공하는 내장 웹 애플리케이션."),
    ("fw-update", "Firmware Update Agent",
     "서명 검증을 포함한 펌웨어 이미지 수신, 검증, 활성화 절차를 수행하는 업데이트 에이전트."),
    ("secure-boot", "Secure Boot and Attestation Module",
     "부팅 체인 무결성 측정과 서명 검증을 수행하는 보안 부트 모듈."),
    ("user-auth", "Authentication and Access Control Service",
     "사용자 인증, 역할 기반 권한 부여, 세션 관리를 처리하는 접근 제어 서비스."),
    ("redundancy", "Redundancy Management Module",
     "이중화 쌍 간 상태 동기화와 무중단 절체를 관리하는 모듈."),
    ("time-sync", "Time Synchronization Service",
     "NTP/PTP 기반 시각 동기화와 이벤트 타임스탬프 정합성을 유지하는 서비스."),
    ("alarm-engine", "Alarm and Event Engine",
     "임계값 감시, 알람 우선순위 판정, 확인/해제 상태 관리를 수행하는 엔진."),
    ("historian-buffer", "Trend Buffer Service",
     "단기 트렌드 데이터를 순환 버퍼에 축적하고 상위 이력 서버로 전송하는 서비스."),
]

# 프로토콜 스택 모듈: 프로토콜 토큰 -> (표시명, 설명, 태그)
PROTOCOL_STACKS = {
    "modbus-tcp": ("Modbus/TCP Protocol Stack",
                   "Modbus TCP 서버/클라이언트 기능. 레지스터 및 코일 접근 요청을 처리한다.", ["modbus"]),
    "dnp3": ("DNP3 Outstation Stack",
             "DNP3 아웃스테이션 구현. 이벤트 클래스 폴링과 비요청 응답을 처리한다.", ["dnp3", "scada"]),
    "iec-61850-mms": ("IEC 61850 MMS Server Stack",
                      "IEC 61850 MMS 서버. 논리 노드 데이터 모델과 리포트 제어 블록을 제공한다.", ["iec61850"]),
    "iec-61850-goose": ("IEC 61850 GOOSE Publisher",
                        "보호 트립 신호를 밀리초 단위로 멀티캐스트하는 GOOSE 발행 스택.", ["iec61850", "goose"]),
    "iec-61850-sv": ("IEC 61850 Sampled Values Publisher",
                     "전류/전압 샘플 값을 주기적으로 발행하는 SV 스택.", ["iec61850", "sv"]),
    "iec-60870-5-104": ("IEC 60870-5-104 Telecontrol Stack",
                        "원방감시제어 통신 규약 스택. ASDU 송수신과 시간 동기를 처리한다.", ["iec60870"]),
    "ethernet-ip": ("EtherNet/IP CIP Stack",
                    "EtherNet/IP 및 CIP 오브젝트 모델을 구현한 산업용 이더넷 스택.", ["ethernet-ip", "cip"]),
    "profinet": ("PROFINET IO Device Stack",
                 "PROFINET IO 실시간 사이클릭 데이터 교환과 진단 알람 처리를 담당한다.", ["profinet"]),
    "profibus": ("PROFIBUS DP Master Stack", "PROFIBUS DP 마스터 통신 스택.", ["profibus"]),
    "ethercat": ("EtherCAT Master Stack",
                 "EtherCAT 분산 클록 동기화 및 프로세스 데이터 교환 마스터 스택.", ["ethercat"]),
    "opc-ua": ("OPC UA Server Stack",
               "OPC UA 주소공간, 구독, 보안 채널을 제공하는 서버 스택.", ["opc-ua"]),
    "opc-da": ("OPC DA Classic Interface",
               "DCOM 기반 OPC Data Access 클래식 인터페이스 어댑터.", ["opc-da", "dcom"]),
    "opc-hda": ("OPC HDA Interface", "이력 데이터 조회를 위한 OPC HDA 인터페이스.", ["opc-hda"]),
    "bacnet-ip": ("BACnet/IP Stack",
                  "건물 자동화 객체 모델과 COV 구독을 처리하는 BACnet/IP 스택.", ["bacnet"]),
    "mqtt": ("MQTT Client Stack", "엣지 데이터 발행을 위한 MQTT 클라이언트 스택.", ["mqtt"]),
    "mqtt-sparkplug": ("MQTT Sparkplug B Client",
                       "Sparkplug B 토픽 규약을 따르는 MQTT 발행/구독 클라이언트.", ["mqtt", "sparkplug"]),
    "hart-ip": ("HART-IP Gateway Stack", "HART 계측기 명령을 IP 로 중계하는 게이트웨이 스택.", ["hart"]),
    "cc-link-ie": ("CC-Link IE Field Stack", "CC-Link IE 필드 네트워크 통신 스택.", ["cc-link"]),
    "canopen": ("CANopen Stack", "CANopen 객체 사전 및 PDO/SDO 통신 스택.", ["canopen"]),
    "s7comm": ("S7 Communication Stack", "S7 통신 프로토콜 처리 스택.", ["s7comm"]),
    "s7comm-plus": ("S7CommPlus Communication Stack",
                    "암호화 세션을 포함한 S7CommPlus 통신 처리 스택.", ["s7comm"]),
    "snmp": ("SNMP Agent Module", "네트워크 관리용 SNMP v2c/v3 에이전트.", ["snmp"]),
    "prp": ("PRP/HSR Redundancy Stack", "무손실 이중화 네트워크(PRP/HSR) 프레임 처리 스택.", ["prp", "hsr"]),
    "fins": ("FINS Protocol Stack", "OMRON FINS 메시지 통신 스택.", ["fins"]),
    "melsoft": ("MELSOFT Connection Service", "엔지니어링 툴 접속을 처리하는 MELSOFT 통신 서비스.", ["melsoft"]),
    "slmp": ("SLMP Protocol Stack", "Seamless Message Protocol 통신 스택.", ["slmp"]),
    "sercos-iii": ("sercos III Stack", "sercos III 실시간 모션 통신 스택.", ["sercos"]),
    "powerlink": ("POWERLINK Stack", "Ethernet POWERLINK 실시간 통신 스택.", ["powerlink"]),
    "ipsec": ("IPsec VPN Module", "사이트 간 암호화 터널을 구성하는 IPsec 모듈.", ["ipsec", "vpn"]),
}

OS_BASE = {
    "vxworks": ("VxWorks RTOS Base Layer", "Wind River Systems", "windriver", "vxworks",
                "상용 실시간 운영체제 기반 계층. 결정적 태스크 스케줄링과 하드웨어 추상화를 제공한다.",
                ["6.9", "7 SR0620", "7 SR0650", "21.03", "21.11"]),
    "linux": ("Embedded Linux Base Platform", "Yocto Project", "yoctoproject", "poky",
              "임베디드 리눅스 배포 기반 계층. 커널, 부트로더, 루트 파일시스템을 포함한다.",
              ["3.1 dunfell", "4.0 kirkstone", "3.4 honister", "4.3 nanbield"]),
    "qnx": ("QNX Neutrino RTOS Base Layer", "BlackBerry QNX", "blackberry", "qnx_neutrino_rtos",
            "마이크로커널 구조의 상용 RTOS 기반 계층. 프로세스 격리와 실시간 응답을 제공한다.",
            ["6.6.0", "7.0", "7.1", "8.0"]),
    "windows": ("Windows IoT Enterprise Base Image", "Microsoft Corporation", "microsoft", "windows_10",
                "산업용 워크스테이션/패널 PC 의 Windows 기반 OS 이미지.",
                ["LTSC 2019", "LTSC 2021", "Server 2019", "Server 2022"]),
    "freertos": ("FreeRTOS Based Firmware Platform", "Amazon Web Services", "amazon", "freertos",
                 "FreeRTOS 커널 위에 구성된 소형 장치 펌웨어 플랫폼.",
                 ["10.2.1", "10.4.3", "10.5.1", "11.0.1"]),
    "zephyr": ("Zephyr RTOS Base Layer", "Zephyr Project", "zephyrproject", "zephyr",
               "Zephyr 커널 기반의 센서/게이트웨이 펌웨어 플랫폼.",
               ["2.5.0", "3.1.0", "3.4.0", "3.6.0"]),
    "java": ("Java Application Platform", "Eclipse Adoptium", "oracle", "jdk",
             "JVM 위에서 동작하는 감시 애플리케이션 실행 플랫폼.",
             ["11.0.14", "11.0.22", "17.0.6", "17.0.10"]),
    "proprietary-rtos": ("Vendor Proprietary RTOS Base Layer", None, None, None,
                         "벤더 자체 개발 실시간 운영체제 계층. 폐쇄형이며 공개 소스 구성요소를 최소화한다.",
                         ["2.4", "3.1", "4.0", "5.2", "6.1"]),
    "bare-metal": ("Bare-metal Firmware Runtime", None, None, None,
                   "운영체제 없이 동작하는 베어메탈 펌웨어 실행 계층. 인터럽트 기반 루프로 구성된다.",
                   ["1.2", "2.0", "2.6", "3.3"]),
}

# OS 별 기본 OSS 부품 풀
OSS_BY_OS = {
    "linux": ["linux_kernel", "busybox", "glibc", "musl", "openssl", "zlib", "libcurl",
              "dropbear", "openssh", "lighttpd", "nginx", "goahead", "u_boot", "sqlite",
              "libxml2", "expat", "net_snmp", "dnsmasq", "ntp", "libpcap", "openvpn",
              "libssh2", "mosquitto", "open62541", "libmodbus", "wpa_supplicant"],
    "vxworks": ["ipnet", "openssl", "zlib", "libxml2", "expat", "net_snmp", "ntp",
                "libcurl", "open62541", "libmodbus", "sqlite"],
    "qnx": ["openssl", "zlib", "libcurl", "libxml2", "sqlite", "net_snmp", "ntp", "open62541"],
    "windows": ["dotnet", "vcredist", "openssl", "zlib", "sqlite", "libxml2",
                "sqlserver_express", "libcurl", "expat"],
    "java": ["openjdk", "log4j", "tomcat", "jackson", "spring", "openssl", "zlib", "sqlite"],
    "freertos": ["freertos", "lwip", "mbedtls", "wolfssl", "expat", "libmodbus"],
    "zephyr": ["zephyr", "lwip", "mbedtls", "libmodbus"],
    "proprietary-rtos": ["openssl", "zlib", "lwip", "mbedtls", "wolfssl", "expat",
                         "libmodbus", "treck_tcpip", "ntp"],
    "bare-metal": ["lwip", "mbedtls", "treck_tcpip", "wolfssl"],
}

# CODESYS Control Runtime 을 OEM 으로 탑재하는 벤더/장비 유형.
# 하나의 상용 런타임이 다수 벤더 제품으로 파급되는 "공유 구현" 사례를 재현한다.
# (실제로 CODESYS 는 400여 장비 제조사에 OEM 공급되며, 2023년 V3 취약점
#  공개 시 전 산업이 동시에 영향받았다.)
CODESYS_OEM_VENDORS = {"codesys", "wago", "phoenix", "schneider", "abb",
                       "bosch_rexroth", "advantech", "moxa", "red_lion"}
CODESYS_OEM_CLASSES = {"plc", "plc-runtime", "rtu", "motion-controller",
                       "protocol-gateway", "engineering-workstation"}

DOC_ORG = {
    "name": "ICS-VEX Reference Dataset Author",
    "address": {"country": "KR", "region": "Seoul", "locality": "Gangnam-gu, Teheran-ro (reference placeholder)"},
    "contact": [{"name": "ICS SBOM Dataset Maintainer",
                 "email": "ics-sbom-dataset@example.invalid",
                 "phone": "NOASSERTION"}],
}


# ---------------------------------------------------------------------------
# 유틸
# ---------------------------------------------------------------------------

def slug(text):
    s = re.sub(r"[^0-9A-Za-z]+", "-", text).strip("-").lower()
    return re.sub(r"-{2,}", "-", s)


def det_uuid(key):
    return str(uuid.uuid5(NS, key))


def det_sha256(key):
    return hashlib.sha256(("ics-vex-synthetic::" + key).encode("utf-8")).hexdigest()


def org(name, country=None, region=None, contact_name="NOASSERTION"):
    """component 하위 manufacturer/supplier 조직 블록."""
    block = {"name": name}
    if country:
        block["address"] = {"country": country, "region": region,
                            "locality": "NOASSERTION"}
        block["contact"] = [{"name": contact_name,
                             "email": "noassertion@example.invalid",
                             "phone": "NOASSERTION"}]
    return block


def make_component(bom_ref, ctype, name, version, desc, publisher, purl,
                   tags, role, license_id="NOASSERTION", scope="required",
                   group=None, cpe=None, extra_props=None):
    comp = {
        "type": ctype,
        "bom-ref": bom_ref,
        "name": name,
        "version": version,
        "description": desc,
        "scope": scope,
        "publisher": publisher or "NOASSERTION",
        "manufacturer": {"name": publisher or "NOASSERTION"},
        "supplier": {"name": publisher or "NOASSERTION"},
    }
    props = [{"name": "module:role", "value": role}]
    if extra_props:
        props.extend(extra_props)
    comp["properties"] = props
    comp["tags"] = tags
    comp["licenses"] = [{"license": {"id": license_id}}]
    comp["copyright"] = "NOASSERTION"
    if group:
        comp["group"] = group
    comp["purl"] = "%s@%s" % (purl, version)
    if cpe:
        comp["cpe"] = cpe
    comp["hashes"] = [{"alg": "SHA-256", "content": det_sha256(bom_ref + version)}]
    return comp


# ---------------------------------------------------------------------------
# SBOM 1건 생성
# ---------------------------------------------------------------------------

def build_sbom(idx, rnd):
    prod = PRODUCTS[idx % len(PRODUCTS)]
    vkey, family, dev_class, cdx_type, os_key, purdue, protocols, models = prod
    vname, vcountry, vregion, cpe_vendor = VENDORS[vkey]

    model = models[(idx // len(PRODUCTS)) % len(models)]
    asset_id = "ICS-%04d" % (idx + 1)

    # ---- 제품 버전 -------------------------------------------------------
    maj = rnd.randint(1, 9)
    minr = rnd.randint(0, 24)
    pat = rnd.randint(0, 40)
    fw_version = "%d.%d.%d" % (maj, minr, pat)

    product_name = "%s %s" % (family, model)
    product_slug = slug(family + "-" + model)
    top_ref = "%s:%s:%s" % (dev_class, vkey, product_slug)

    serial = "urn:uuid:%s" % det_uuid("sbom::" + asset_id + "::" + product_slug)

    # ---- ICS 운영 컨텍스트 ----------------------------------------------
    sector = rnd.choice(SECTORS)
    exposure = rnd.choice(NETWORK_EXPOSURE)
    cadence = rnd.choice(PATCH_CADENCE)
    lifecycle = rnd.choice(LIFECYCLE_CHOICES)
    tlp = rnd.choice(TLP_CHOICES)
    safety_sil = None
    if dev_class in ("sis-logic-solver",):
        safety_sil = rnd.choice(["SIL2", "SIL3", "SIL3 (IEC 61508)"])
    elif dev_class in ("plc", "dcs-controller", "robot-controller"):
        safety_sil = rnd.choice([None, None, "SIL2", "PLd (ISO 13849)"])

    # ---- 부품 구성 -------------------------------------------------------
    components = []
    ground_truth = []

    # 1) OS/플랫폼 기반 계층
    os_name, os_pub, os_cpe_v, os_cpe_p, os_desc, os_versions = OS_BASE[os_key]
    os_ver = os_versions[rnd.randrange(len(os_versions))]
    os_ref = "platform:%s:%s" % (vkey, os_key)
    os_comp = make_component(
        os_ref, "operating-system" if os_key not in ("bare-metal",) else "platform",
        os_name, os_ver, os_desc,
        os_pub or vname,
        "pkg:generic/%s" % slug(os_name),
        ["platform", os_key], "base-platform",
        cpe=("cpe:2.3:o:%s:%s:%s:*:*:*:*:*:*:*" % (os_cpe_v, os_cpe_p, slug(os_ver))
             if os_cpe_v else None),
    )
    components.append(os_comp)

    # 2) OSS 부품 (OS 계열에 맞는 풀에서 선택)
    pool = list(OSS_BY_OS[os_key])
    rnd.shuffle(pool)
    lo = min(5, len(pool))
    n_oss = rnd.randint(lo, min(11, len(pool)))
    chosen_oss = pool[:n_oss]
    # 상용 제어 런타임을 OEM 으로 탑재하는 제품군에는 항상 포함시킨다.
    if (vkey in CODESYS_OEM_VENDORS and dev_class in CODESYS_OEM_CLASSES
            and "codesys_rt" not in chosen_oss):
        chosen_oss.append("codesys_rt")
    oss_refs = []
    for key in chosen_oss:
        spec = OSS[key]
        ver, cves = spec["versions"][rnd.randrange(len(spec["versions"]))]
        ref = "pkg:oss:%s" % key.replace("_", "-")
        cpe = "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*" % (spec["cpe_vendor"], spec["cpe_product"], ver)
        components.append(make_component(
            ref, "library", spec["name"], ver, spec["desc"], spec["publisher"],
            spec["purl"], spec["tags"], spec["role"],
            license_id=spec["license"], cpe=cpe,
            extra_props=[{"name": "component:origin",
                          "value": spec.get("origin", "third-party-open-source")}],
        ))
        oss_refs.append(ref)
        if cves:
            ground_truth.append((ref, spec["name"], ver, ";".join(cves)))

    # 3) 벤더 고유 모듈
    rnd.shuffle(VENDOR_MODULES)
    n_vendor = rnd.randint(3, 6)
    vendor_refs = []
    for role_key, suffix, desc in VENDOR_MODULES[:n_vendor]:
        ref = "mod:%s:%s" % (vkey, role_key)
        mod_ver = "%d.%d.%d" % (maj, rnd.randint(0, 12), rnd.randint(0, 30))
        components.append(make_component(
            ref, "application" if role_key in ("web-ui", "fw-update") else "library",
            "%s %s" % (family.split()[0], suffix), mod_ver, desc, vname,
            "pkg:generic/%s-%s" % (slug(vkey), role_key),
            [dev_class, role_key], role_key,
            group="com.%s" % slug(vkey),
            extra_props=[{"name": "component:origin", "value": "vendor-proprietary"}],
        ))
        vendor_refs.append(ref)

    # 4) 프로토콜 스택 모듈
    proto_refs = []
    for p in protocols:
        if p not in PROTOCOL_STACKS:
            continue
        pname, pdesc, ptags = PROTOCOL_STACKS[p]
        ref = "proto:%s:%s" % (vkey, p)
        pver = "%d.%d.%d" % (rnd.randint(1, 6), rnd.randint(0, 15), rnd.randint(0, 25))
        components.append(make_component(
            ref, "library", pname, pver, pdesc, vname,
            "pkg:generic/%s-stack" % slug(p), ptags + ["protocol"], "protocol-stack",
            group="com.%s" % slug(vkey),
            extra_props=[{"name": "protocol:identifier", "value": p},
                         {"name": "component:origin", "value": "vendor-proprietary"}],
        ))
        proto_refs.append(ref)

    # 5) 의존 관계
    dependencies = [{
        "ref": top_ref,
        "dependsOn": [os_ref] + vendor_refs + proto_refs,
    }, {
        "ref": os_ref,
        "dependsOn": oss_refs,
    }]
    for r in vendor_refs:
        picks = [x for x in oss_refs if rnd.random() < 0.35]
        dependencies.append({"ref": r, "dependsOn": picks or oss_refs[:1]})
    for r in proto_refs:
        picks = [x for x in oss_refs if rnd.random() < 0.25]
        dependencies.append({"ref": r, "dependsOn": picks or [os_ref]})
    for r in oss_refs:
        dependencies.append({"ref": r, "dependsOn": []})

    # ---- 상위 component 속성 --------------------------------------------
    top_props = [
        {"name": "ics:asset-id", "value": asset_id},
        {"name": "ics:device-class", "value": dev_class},
        {"name": "ics:purdue-level", "value": purdue},
        {"name": "ics:sector", "value": sector},
        {"name": "ics:protocols", "value": ",".join(protocols)},
        {"name": "ics:network-exposure", "value": exposure},
        {"name": "ics:patch-cadence", "value": cadence},
        {"name": "ics:base-platform", "value": os_key},
        {"name": "ics:vendor-model", "value": model},
        {"name": "dataset:synthetic", "value": "true"},
        {"name": "dataset:disclaimer",
         "value": "Synthetic reference SBOM for ICS-VEX research. Component composition, hashes, "
                  "contacts and URLs are fabricated and do not describe a real shipped product."},
    ]
    if safety_sil:
        top_props.append({"name": "ics:safety-integrity-level", "value": safety_sil})

    parent_hbom = "urn:cdx:%s/1#hw:%s:%s" % (
        det_uuid("hbom::" + product_slug), vkey, product_slug)

    top_component = {
        "type": cdx_type,
        "bom-ref": top_ref,
        "name": product_name,
        "version": fw_version,
        "description": "%s 계열 %s 자산의 소프트웨어 구성 명세. Purdue Level %s 에서 %s 환경에 운용된다." % (
            vname, dev_class.upper(), purdue, sector),
        "scope": "required",
        "publisher": vname,
        "purl": "pkg:generic/%s@%s" % (product_slug, fw_version),
        "copyright": "NOASSERTION",
        "cpe": "cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*" % (
            "o" if cdx_type in ("firmware", "operating-system") else "a",
            cpe_vendor, slug(family), fw_version),
        "manufacturer": org(vname, vcountry, vregion, "Product Security Incident Response Team"),
        "supplier": org(vname, vcountry, vregion, "NOASSERTION"),
        "properties": top_props,
        "tags": sorted(set([dev_class, os_key, vkey, sector] + protocols[:3])),
        "hashes": [{"alg": "SHA-256", "content": det_sha256(top_ref + fw_version)}],
        "licenses": [{"license": {"id": "NOASSERTION"}}],
        "pedigree": {
            "notes": "Synthetic pedigree placeholder. Populate origin, change history, procurement "
                     "path and integrity evidence from the vendor supply chain before production use."
        },
        "externalReferences": [
            {"type": "documentation",
             "url": ["https://example.invalid/ics/%s/%s" % (vkey, product_slug)],
             "comment": "Component datasheet or manual placeholder"},
            {"type": "release-notes",
             "url": ["https://example.invalid/ics/%s/%s/release-notes" % (vkey, product_slug)],
             "comment": "Firmware/software release-note placeholder"},
            {"type": "advisories",
             "url": ["https://example.invalid/ics/%s/psirt" % vkey],
             "comment": "Vendor PSIRT advisory feed placeholder used by the VEX pipeline"},
            {"type": "bom",
             "url": [parent_hbom],
             "comment": "Cross-file parent HBOM reference | component=%s hardware platform" % product_name},
        ],
    }

    # ---- 문서 조립 -------------------------------------------------------
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial,
        "version": 1,
        "properties": [
            {"name": "SBOM_CREATION_DATE", "value": CREATION_DATE},
            {"name": "SBOM_MODIFY_DATE", "value": CREATION_DATE},
        ],
        "metadata": {
            "timestamp": TIMESTAMP,
            "lifecycles": [{"phase": lifecycle}],
            "manufacturer": DOC_ORG,
            "tools": {
                "components": [{
                    "type": "application",
                    "bom-ref": "tool:ics-vex-sbom-generator",
                    "name": "ICS-VEX Reference SBOM Generator",
                    "version": "2026.04",
                    "publisher": "ICS-VEX Reference Dataset Author",
                    "description": "Deterministic generator that produces CycloneDX 1.7 reference "
                                   "SBOMs for industrial control system assets",
                    "externalReferences": [{
                        "type": "documentation",
                        "url": ["https://example.invalid/ics-vex/sbom-generator"],
                        "comment": "Placeholder documentation for the dataset generator",
                    }],
                }]
            },
            "distributionConstraints": {"tlp": tlp},
            "component": top_component,
        },
        "dependencies": dependencies,
        "components": components,
    }

    meta = {
        "asset_id": asset_id,
        "serial": serial,
        "vendor": vname,
        "product": product_name,
        "version": fw_version,
        "device_class": dev_class,
        "cdx_type": cdx_type,
        "purdue_level": purdue,
        "base_platform": os_key,
        "sector": sector,
        "network_exposure": exposure,
        "lifecycle": lifecycle,
        "tlp": tlp,
        "safety_sil": safety_sil or "",
        "protocols": ";".join(protocols),
        "component_count": len(components),
        "vulnerable_component_count": len(ground_truth),
    }
    filename = "%s_%s_%s_SBOM.json" % (asset_id, slug(vkey), product_slug)
    return filename, bom, meta, ground_truth


# ---------------------------------------------------------------------------
# 실행
# ---------------------------------------------------------------------------

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    rnd = random.Random(SEED)

    index_rows = []
    gt_rows = []

    for i in range(TOTAL):
        r = random.Random(SEED + i * 7919)
        filename, bom, meta, gt = build_sbom(i, r)
        path = os.path.join(OUT_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bom, f, ensure_ascii=False, indent=2)
            f.write("\n")
        meta["file"] = filename
        index_rows.append(meta)
        for ref, cname, cver, cves in gt:
            gt_rows.append({
                "file": filename,
                "asset_id": meta["asset_id"],
                "bom_ref": ref,
                "component": cname,
                "version": cver,
                "known_cves": cves,
            })

    idx_fields = ["file", "asset_id", "serial", "vendor", "product", "version",
                  "device_class", "cdx_type", "purdue_level", "base_platform",
                  "sector", "network_exposure", "lifecycle", "tlp", "safety_sil",
                  "protocols", "component_count", "vulnerable_component_count"]
    with open(os.path.join(OUT_DIR, "index.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=idx_fields)
        w.writeheader()
        for row in index_rows:
            w.writerow({k: row[k] for k in idx_fields})

    gt_fields = ["file", "asset_id", "bom_ref", "component", "version", "known_cves"]
    with open(os.path.join(OUT_DIR, "ground_truth_vulnerable_components.csv"),
              "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=gt_fields)
        w.writeheader()
        w.writerows(gt_rows)

    print("SBOM files      : %d" % len(index_rows))
    print("Ground-truth rows: %d" % len(gt_rows))
    print("Output dir      : %s" % OUT_DIR)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
