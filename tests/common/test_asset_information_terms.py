from src.common.web.asset_information_terms import canonical_asset_information_text as canonical
from src.item4.web.saved_review_translations import english_message


def test_old_and_current_product_copy_share_one_term():
    for old in ('운영 맥락', '운영정보', '자산 운영정보', '운영 사실', '현장 정보'):
        assert canonical(old) == '자산 운영 정보'
    for old in ('Operating context', 'Operating profile', 'Operational information'):
        assert canonical(old) == 'Asset operational information'
    assert canonical('자산 운영 정보로 판단') == '자산 운영 정보로 판단'
    assert canonical('운영 맥락으로 판단') == '자산 운영 정보로 판단'


def test_product_copy_normalization_is_idempotent_and_preserves_identifiers():
    text='자산 운영 정보 / Asset operational information / operating_context / CVE-2020-1234'
    assert canonical(text) == text
    assert canonical(canonical('운영자 입력 정보')) == '자산 운영 정보'


def test_saved_project_diagnostics_accept_previous_terminology():
    assert english_message('운영 질문 생성') == english_message('자산 운영 정보 질문 생성')
    assert 'This older diagnostic' not in english_message('운영 질문 생성')


def test_html_presentation_preserves_embedded_source_and_input_text():
    from src.common.web.english_ui_translations import english_ui
    source='<div id="source-data" hidden>{"quote":"운영 맥락","product":"C1"}</div>'
    user_input='<textarea>운영 맥락</textarea>'
    rendered=english_ui('<h2>운영 맥락</h2>'+source+user_input)
    assert '<h2>자산 운영 정보</h2>' in rendered
    assert source in rendered and user_input in rendered
