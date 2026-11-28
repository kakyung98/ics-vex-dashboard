from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
path=ROOT/'tools/item4/serve_nist_operational_vex.py'
text=path.read_text(encoding='utf-8')
start=text.index('# Source-row observations');end=text.index('service.base.model = model',start)
text=text[:start]+'''# One decision path for direct reviews, BOM cases, saved reviews and exports.
# Operator-supplied verdicts and condition truth are never accepted.
V.VERSION=automatic.VERSION
V.plan=automatic.plan
V.evaluate=automatic.evaluate
V.export=automatic.export
'''+text[end:]
text=text.replace("(ROOT/'src/research/ui/operational_vex_choices.html')","(ROOT/'src/item4/web/evidence_based_vex_page.html')")
anchor="        html = html.replace((service.EN/'operating_profiles.html')"
text=text.replace(anchor,"        html=html.replace((service.EN/'operational_vex_ui.js').read_text(encoding='utf-8'),(ROOT/'src/item4/web/evidence_based_vex_ui.js').read_text(encoding='utf-8'),1)\n"+anchor,1)
start=text.index('    # The old compositor retains');end=text.index('    return str(soup)',start)
text=text[:start]+'''    for code in [profile_ui(),(ROOT/'src/item4/web/evidence_based_vex_ui.js').read_text(encoding='utf-8')]:
        script=soup.new_tag('script');script.string=code
        bom_script=next((s for s in soup.body.find_all('script') if 'let w=null,selected=null' in s.text),None)
        if bom_script:bom_script.insert_before(script)
        else:soup.body.append(script)
    for script in soup.find_all('script'):
        if 'let w=null,selected=null' in script.text:script.string=(ROOT/'src/item4/web/bom_vex_workflow_ui.js').read_text(encoding='utf-8')
    # The 167-item catalogue remains available for audit; input is CVE-specific.
    fields=soup.find(id='op-fields')
    if fields:
        details=soup.new_tag('details');summary=soup.new_tag('summary');summary.string='All 54 NIST source items / 167 collection details (optional catalogue)'
        fields.insert_before(details);details.append(summary);details.append(fields.extract())
'''+text[end:]
text=text.replace("app.add_api_route('/nist-three-axis-method.html'","app.add_api_route('/nist-auto-vex-method.html',lambda:FileResponse(ROOT/'site/nist-auto-vex-method.html',media_type='text/html'),methods=['GET'])\napp.add_api_route('/nist-auto-vex-rules.json',lambda:automatic.registry(),methods=['GET'])\napp.add_api_route('/nist-three-axis-method.html'",1)
path.write_text(text,encoding='utf-8')
print('Installed automatic-only plan, assessment and export')
