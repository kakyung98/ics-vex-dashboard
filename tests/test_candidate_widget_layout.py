from src.candidate_widget import scope_css,widget_parts


def test_embedded_workflow_does_not_import_standalone_sidebar_geometry():
    css=scope_css('aside{position:fixed;left:0;height:100vh}aside nav a,.notice{color:red}@media(max-width:760px){aside{width:220px}.notice{padding:12px}}')
    assert 'position:fixed' not in css and '#candidate-workspace aside' not in css
    assert '#candidate-workspace .notice{color:red}' in css
    assert '#candidate-workspace .notice{padding:12px}' in css


def test_experimental_notice_is_a_normal_content_block_not_a_sidebar():
    html,_=widget_parts()
    assert '<div class="notice" role="note">' in html
    assert '<aside class="notice">' not in html
    assert '#candidate-workspace aside' not in html
    assert 'position:fixed' not in html.split('</style>',1)[0]
