"""Build the Pages artifact without exposing methodology navigation or pages.

The source and local development UI are retained. This is a public UI filter,
not access control for files or source history in the GitHub repository.
"""
from pathlib import Path
from urllib.parse import urlsplit
import argparse,json,re,shutil

HIDDEN_PAGES={'sbom-to-cve.html'}
ANCHOR=re.compile(r'<a\b[^>]*>.*?</a>',re.I|re.S)
HREF=re.compile(r'\bhref\s*=\s*([\"\'])(.*?)\1',re.I|re.S)

def public_html(html):
    def link(match):
        href=HREF.search(match[0])
        if href and Path(urlsplit(href[2]).path).name in HIDDEN_PAGES:return ''
        return match[0]
    html=ANCHOR.sub(link,html)
    # Retire a Method group only when removing the link leaves it empty.
    return re.sub(r'<div\b[^>]*class=[\"\'][^\"\']*\bnavlabel\b[^\"\']*[\"\'][^>]*>\s*Method(?: Overview)?\s*</div>\s*(?=<div\b[^>]*class=[\"\'][^\"\']*\bnavlabel\b|</nav>)','',html,flags=re.I|re.S)

def prepare(source,output):
    source=source.resolve();output=output.resolve()
    if output==source or source.is_relative_to(output):raise ValueError('Output must not contain the source directory')
    if output.exists():raise FileExistsError('Use a new output directory; no existing data is removed')
    shutil.copytree(source,output,ignore=lambda folder,names:[n for n in names if n in HIDDEN_PAGES])
    count=0
    for path in output.rglob('*.html'):
        original=path.read_text(encoding='utf-8');updated=public_html(original)
        if original!=updated:path.write_text(updated,encoding='utf-8');count+=1
        assert not any(Path(urlsplit(m[2]).path).name in HIDDEN_PAGES for m in HREF.finditer(updated))
    assert not any(output.rglob('sbom-to-cve.html'))
    print(json.dumps({'methodology_hidden':True,'HTML_files_updated':count,'output':str(output),'local_source_unchanged':True}))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path('site'));p.add_argument('--output',type=Path,default=Path('_public_site'))
    a=p.parse_args();prepare(a.source,a.output)
