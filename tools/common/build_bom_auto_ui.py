from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
EN=Path('D:/ICS-VEX/local-service/sbom-vex/vex_operational_logic_20261117/english_ui')
text=(EN/'bom_workflow_ui.js').read_text(encoding='utf-8')
anchor='dirty=false;render();message(saved?'
start=text.index(anchor);end=text.index('\n}',start)
text=text[:start]+'''dirty=false;render();message(saved?'Saved operating scope loaded. The CVE-specific questions are displayed below.':'Enter the actual component scope and register evidence. Only questions required by this CVE are displayed below.');
 window.icsBomVexContext=context();
 if(selected.review_id){restoring=true;try{await window.icsOperationalVex.reopen(selected.review_id);}finally{restoring=false;}}
 else await window.icsOperationalVex.open(selected.cve);
'''+text[end:]
text=text.replace('Review the CVE conditions and product evidence below, then save the VEX assessment.','Answer the required operational questions below. The server calculates VEX; no verdict is selected.')
(ROOT/'src/item4/web/bom_vex_workflow_ui.js').write_text(text,encoding='utf-8')
print('BOM case selection now opens the automatic CVE questionnaire')
