"""Canonical product copy for asset operational information, never source evidence."""
import re

_KO = (
    ('운영 환경 정보', '자산 운영 정보'), ('운영자 입력 정보', '자산 운영 정보'),
    ('운영자 제공 정보', '자산 운영 정보'), ('운영 컨텍스트', '자산 운영 정보'),
    ('운영 맥락', '자산 운영 정보'), ('운영맥락', '자산 운영 정보'),
    ('운영정보', '자산 운영 정보'), ('운영 정보', '자산 운영 정보'),
    ('운영 데이터', '자산 운영 정보'), ('운영 사실', '자산 운영 정보'),
    ('운영 값', '자산 운영 정보 값'), ('운영값', '자산 운영 정보 값'),
    ('자산 값', '자산 운영 정보 값'), ('운영 속성', '자산 운영 정보 항목'),
    ('운영자 입력', '자산 운영 정보 입력'), ('운영 질문', '자산 운영 정보 질문'),
    ('운영 프로필', '자산 운영 정보'), ('현장 정보', '자산 운영 정보'),
)
_EN = re.compile(r'(?<!asset )(?<!Asset )\b(?:operating|operational) '
                 r'(?:information|context|facts|data|profiles?|inputs?|values?)\b', re.I)


def canonical_asset_information_text(text):
    """Normalize UI/document copy; callers must not pass quotes or asset values."""
    for old in ('자산 운영정보', '자산운영정보', '자산 운영맥락'):
        text = text.replace(old, '자산 운영 정보')
    for old, new in _KO:
        text = re.sub(r'(?<!자산 )' + re.escape(old), new, text)
    text = _EN.sub(lambda m: 'Asset operational information' if m[0][0].isupper()
                   else 'asset operational information', text)
    text = (text.replace('자산의 자산 운영 정보', '자산 운영 정보')
            .replace("asset's asset operational information", 'asset operational information')
            .replace('asset asset operational information', 'asset operational information')
            .replace('Asset operating profile', 'Asset operational information')
            .replace('asset operating profile', 'asset operational information')
            .replace('자산 운영 정보으로', '자산 운영 정보로')
            .replace('자산 운영 정보을', '자산 운영 정보를')
            .replace('자산 운영 정보은', '자산 운영 정보는')
            .replace('자산 운영 정보과', '자산 운영 정보와'))
    return re.sub(r'자산 운영 정보이(?=\s|[.,·:;!?]|$)', '자산 운영 정보가', text)
