"""Explain recorded identification evidence without changing any verdict."""


def explain_identification(result, sbom):
    raw=(sbom or {}).get('metadata',{}).get('component',{}) or {}
    result['analysis_scope']={
        'asset_name':raw.get('name') or 'Not supplied',
        'asset_cpe':raw.get('cpe'),
        'asset_identity_analyzed':bool(result.get('asset_analysis')),
        'analyzed_components':len(result.get('components',[])),
        'explanation':'Component entries and the representative asset are analyzed separately. Asset findings are shown below and included in VEX review; its CPE is never inherited by dependencies.' if result.get('asset_analysis') else result.get('asset_analysis_note') or 'Only entries in components were identified in this run. The representative asset CPE was not independently analyzed. Start a new run to apply the current asset analysis.'}
    for row in list(result.get('components',[]))+([result['asset_analysis']] if result.get('asset_analysis') else []):
        comp=row.get('component',{});validation=row.get('validation',{})
        candidates=row.get('l2',{}).get('candidates') or row.get('l4',{}).get('candidates') or []
        cpes=comp.get('cpes') or []
        if isinstance(cpes,str):cpes=[cpes]
        verified=any(c.get('features',{}).get('dictionary_verified_input_cpe') for c in candidates)
        valid=validation.get('status')=='validated'
        stages=[]
        for key,title in [('l2','L2 · Product retrieval'),('l3','L3 · Installed version'),('l4','L4 · Product identity')]:
            stage=row.get(key) or {};agent=stage.get('agent') or {}
            if key=='l2':
                observed=stage.get('normalized') or 'No product-name proposal'
                meaning='A model name proposal expands the search. It is not a verified product identity.' if agent else 'Dictionary retrieval uses this item’s own identifiers and name. A ranked candidate alone is not an accepted identity.'
                if stage.get('structured_input'):
                    meaning='Rules preserve the original model identifier and rank dictionary candidates. No model inference or replacement product-name generation occurs.'
                action='Compare the original manufacturer, product name and identifiers with the dictionary candidates.'
            elif key=='l3':
                observed=stage.get('normalized') or 'Installed version unconfirmed'
                meaning='A missing version, advisory range or synthetic release label cannot establish the installed version.' if not stage.get('normalized') else 'Version evidence is recorded separately from product identity and CVE applicability.'
                action='Supply the actual installed version/build and its inventory or update record.'
            else:
                observed='Identity accepted' if valid else 'Identity deferred'
                meaning='The selected dictionary identity passed the recorded evidence checks.' if valid else 'The recorded evidence did not establish one acceptable dictionary identity. This does not mean the product is absent from NVD.'
                action='Resolve the recorded name, manufacturer, identifier or component-type conflicts; retain competing products until supported.'
            stages.append({'stage':key,'title':title,'observed':observed,'meaning':meaning,'next_step':action,
                           'model_status':agent.get('status','not_recorded'),'executed':row.get('execution',{}).get(key,{}).get('executed')})
        comparisons=[]
        parts={'a':'application','o':'operating system','h':'hardware'}
        allowed={'device':{'h'},'library':{'a'},'application':{'a'},'operating-system':{'o'},'firmware':{'a','o'}}.get(comp.get('component_type'))
        for c in candidates[:3]:
            conflicts=list(c.get('conflicts') or [])
            if allowed and c.get('part') not in allowed:conflicts.append('component_type_differs_from_dictionary_part')
            comparisons.append({'vendor':c.get('vendor'),'product':c.get('product'),'part':parts.get(c.get('part'),c.get('part')),
                'cpe':c.get('cpe'),'conflicts':conflicts,'accepted':c.get('candidate_id')==validation.get('selected_candidate_id') and valid})
        row['diagnostics']={'input_cpes':cpes,'input_type':comp.get('component_type'),
            'model_observations':row.get('l2',{}).get('structured_input',{}).get('model_observations',[]),
            'l2_contract':row.get('l2',{}).get('agent',{}).get('contract') if isinstance(row.get('l2',{}).get('agent'),dict) else None,
            'cpe_checks':row.get('l2',{}).get('retrieval',{}).get('input_cpe_checks',[]),
            'input_manufacturer':comp.get('manufacturer') or comp.get('supplier'),
            'input_purl':comp.get('purl'),
            'cpe_check':'supplied CPE found in the recorded dictionary evidence' if verified else 'supplied CPE not confirmed by the recorded dictionary evidence' if cpes else 'no component CPE supplied',
            'stages':stages,'candidate_comparisons':comparisons,'reason_codes':validation.get('reasons',[]),
            'candidate_scope':'CISA links are product/advisory candidates, separate from NVD identity acceptance. They do not establish that the installed release is affected or fixed.',
            'conclusion':'No retrieved candidates is not evidence of no vulnerabilities.' if not row.get('cves') else 'Retrieved CVEs require product/version applicability and exploitability review.'}
    return result
