"""Prepare an HTML import for Hancom, without automating the desktop app."""
from pathlib import Path
import markdown

ROOT=Path(__file__).resolve().parents[2]
source=ROOT/'docs/ITEM4_RULE_EVALUATION_DESIGN.md'
text=source.read_text(encoding='utf-8')
text=text.replace('이번 문서 개정은 설계서 PDF 부록으로 추가한다. 원본 85페이지는 보존하고, 앞선 본문과 평가 정책이 충돌하는 경우 이 개정 범위에서는 본 부록을 따른다. HWP 원본의 편집 가능 버전 갱신 여부는 문서 생성 기록에 별도 표시한다.',
    '이번 문서 개정은 원본 설계서 뒤에 부록으로 추가한다. 앞선 본문과 평가 정책이 충돌하는 경우 이 개정 범위에서는 본 부록을 따른다. HWP 편집 가능 원본과 PDF의 갱신 상태는 문서 생성 기록에 별도로 남긴다.')
source.write_text(text,encoding='utf-8')
html=markdown.markdown(text,extensions=['tables'])
html=html.replace('<table>','<table border="1" cellspacing="0" cellpadding="5" width="100%">')
css='body{font-family:맑은 고딕;font-size:10pt;line-height:160%;} h1{font-size:18pt;} h2{font-size:14pt;page-break-before:always;} h3{font-size:12pt;} td,th{border:1px solid #999;font-size:9pt;} th{background:#e6edf5;}'
target=ROOT/'artifacts/item4_rule_evaluation_v1/Item4_Native_Appendix.html'
target.write_text('<!DOCTYPE html><html><head><meta charset="UTF-8"><style>'+css+'</style></head><body>'+html+'</body></html>',encoding='utf-8')
print(target)
