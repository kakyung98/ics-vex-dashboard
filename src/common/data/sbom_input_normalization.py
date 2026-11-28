"""Normalize the project's literal workbook layout at the analysis boundary."""
from copy import deepcopy


def to_analysis_input(sbom):
    if not isinstance(sbom, dict):
        raise ValueError('SBOM must be a JSON object')
    result = deepcopy(sbom)
    def properties(obj):
        value = obj.get('properties')
        if isinstance(value, dict):
            obj['properties'] = [{'name': k, 'value': str(v)} for k, v in value.items()]
    properties(result)
    metadata = result.get('metadata') or {}
    properties(metadata)
    properties(metadata.get('component') or {})
    if 'lifecycles_phase' in metadata and 'lifecycles' not in metadata:
        metadata['lifecycles'] = [{'phase': metadata['lifecycles_phase']}]
    for component in result.get('components', []):
        properties(component)
        # The workbook permits CPE only on the representative asset. An explicit
        # shared reference identifies the same component; never infer this link
        # merely from similar names, positions or manufacturer strings.
        asset=metadata.get('component') or {}
        if (asset.get('bom-ref') and asset.get('bom-ref')==component.get('bom-ref')
            and asset.get('cpe') and not component.get('cpe')):
            component['cpe']=asset['cpe']
    return result
