from src.source_function_retrieval import rank


def test_source_search_expands_retrieval_without_creating_function_facts():
    functions=[{'id':'F1','name':'adler32','file':'adler32.c','line':1,'code_excerpt':'checksum calculation'},
               {'id':'F2','name':'inflate','file':'inflate.c','line':4,'code_excerpt':'decode compressed stream code length table'},
               {'id':'F3','name':'helper','file':'other.c','line':9,'code_excerpt':'unrelated helper'}]
    selected=rank(functions,'decode compressed stream code length',limit=1)
    assert selected[0]['id']=='F2' and selected[0]['score_is_not_confidence']
    assert rank(functions,'unseen invented_function',known_names=['adler32'],limit=1)[0]['id']=='F1'
    assert {f['id'] for f in rank(functions,'invented_function')}=={'F1','F2','F3'}
