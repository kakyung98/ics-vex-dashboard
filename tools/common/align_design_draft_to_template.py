"""Align the design draft's formatting with the delivered NVAS manual template.

The template (양식.hwp) and the draft are both HWP 5.1 compound files. Hancom
automation is unavailable on this machine (the HwpObject type library is not
registered, and registering it is an administrator change), so the formatting
is applied by rewriting HWP records directly.

Shape records are fixed length, so retuning DocInfo CHAR_SHAPE/PARA_SHAPE and
the section PAGE_DEF moves nothing else in the stream. The only structural
edits are the two cover memo paragraphs that are removed and the three shape
records appended for the cover and figure captions.

Layout caches (PARA_LINE_SEG) are left in place; Hancom recomputes pagination
when the document is opened, which is also when the table of contents page
numbers must be refreshed.
"""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct
import zlib

import olefile
import pythoncom
from win32com.storagecon import (
    STGM_READWRITE, STGM_SHARE_EXCLUSIVE, STGM_TRANSACTED)

ROOT = Path(__file__).resolve().parents[2]
DRAFT = ROOT / '생성형 AI 모델 기반 VEX 자동 생성 시스템 설계서 초안.hwp'
TEMPLATE = Path.home() / 'Desktop' / '양식.hwp'
ARCHIVE = ROOT / 'docs/archive/format_align_20261120'
REPORT = ROOT / 'results/format_align_20261120'

MM = 7200 / 25.4                      # HWPUNIT per millimetre
TAG_ID_MAPPINGS, TAG_FACE_NAME = 17, 19
TAG_CHAR_SHAPE, TAG_PARA_SHAPE, TAG_STYLE = 21, 25, 26
TAG_PARA_HEADER, TAG_PARA_TEXT, TAG_PARA_CHAR_SHAPE = 66, 67, 68
TAG_PAGE_DEF = 73
MAP_CHAR_SHAPE, MAP_PARA_SHAPE = 9, 13  # ID_MAPPINGS slot order
ALIGN_BOTH, ALIGN_CENTER = 0, 3

# Template shapes, resolved in the analysis step: 장 17pt centred, 절 15pt,
# 내용 ○ and 내용 - body levels, 캡션, and the cover's 20pt centred lines.
TPL_CHAPTER, TPL_SECTION = 48, 56
TPL_LEAD, TPL_BODY, TPL_CAPTION = 11, 1, 12


# ---------------------------------------------------------------- record layer

def iter_records(buf):
    """Yield (tag, level, payload) for each HWP record in a decompressed stream."""
    pos = 0
    while pos + 4 <= len(buf):
        head = struct.unpack_from('<I', buf, pos)[0]
        pos += 4
        tag, level, size = head & 0x3FF, (head >> 10) & 0x3FF, head >> 20
        if size == 0xFFF:
            size = struct.unpack_from('<I', buf, pos)[0]
            pos += 4
        yield tag, level, buf[pos:pos + size]
        pos += size


def pack_records(records):
    out = bytearray()
    for tag, level, payload in records:
        size = len(payload)
        if size < 0xFFF:
            out += struct.pack('<I', tag | (level << 10) | (size << 20))
        else:
            out += struct.pack('<II', tag | (level << 10) | (0xFFF << 20), size)
        out += payload
    return bytes(out)


def read_stream(path, name):
    with olefile.OleFileIO(str(path)) as ole:
        compressed = struct.unpack_from(
            '<I', ole.openstream('FileHeader').read(), 36)[0] & 1
        data = ole.openstream(name).read()
    return zlib.decompress(data, -15) if compressed else data


def write_streams(path, streams, compressed=True):
    """Replace whole streams inside an existing compound file.

    HWP deflates DocInfo and BodyText but stores PrvText verbatim, so the
    caller states which of the two it is writing.
    """
    stg = pythoncom.StgOpenStorage(
        str(path), None,
        STGM_READWRITE | STGM_SHARE_EXCLUSIVE | STGM_TRANSACTED)
    for name, raw in streams.items():
        if compressed:
            comp = zlib.compressobj(9, zlib.DEFLATED, -15)
            body = comp.compress(raw) + comp.flush()
        else:
            body = raw
        node = stg
        parts = name.split('/')
        for part in parts[:-1]:
            node = node.OpenStorage(
                part, None, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, None)
        stream = node.OpenStream(
            parts[-1], None, STGM_READWRITE | STGM_SHARE_EXCLUSIVE)
        stream.SetSize(len(body))
        stream.Seek(0, 0)
        stream.Write(body)
        stream.Commit(0)
        del stream
        if node is not stg:
            node.Commit(0)
            del node
    stg.Commit(0)
    del stg


# ----------------------------------------------------------------- shape edits

def para_get(payload):
    prop1 = struct.unpack_from('<I', payload, 0)[0]
    left, right, indent, up, down, line_old = struct.unpack_from('<6i', payload, 4)
    return dict(align=(prop1 >> 2) & 7, left=left, right=right, indent=indent,
                up=up, down=down, line=line_old,
                line_new=struct.unpack_from('<I', payload, 50)[0])


def para_set(payload, **kw):
    out = bytearray(payload)
    if 'align' in kw:
        prop1 = struct.unpack_from('<I', out, 0)[0]
        prop1 = (prop1 & ~(7 << 2)) | ((kw['align'] & 7) << 2)
        struct.pack_into('<I', out, 0, prop1)
    for name, offset in (('left', 4), ('right', 8), ('indent', 12),
                         ('up', 16), ('down', 20)):
        if name in kw:
            struct.pack_into('<i', out, offset, int(round(kw[name])))
    if 'line' in kw:                       # both the legacy and 5.0.2.5 fields
        struct.pack_into('<i', out, 24, int(kw['line']))
        struct.pack_into('<I', out, 50, int(kw['line']))
    return bytes(out)


def char_set(payload, size=None, bold=None):
    out = bytearray(payload)
    if size is not None:
        struct.pack_into('<i', out, 42, int(round(size * 100)))
    if bold is not None:
        attr = struct.unpack_from('<I', out, 46)[0]
        attr = (attr | 0x2) if bold else (attr & ~0x2)
        struct.pack_into('<I', out, 46, attr)
    return bytes(out)


def char_fonts(payload, source):
    """Copy the seven per-language face ids from another CHAR_SHAPE."""
    out = bytearray(payload)
    out[0:14] = source[0:14]
    return bytes(out)


# --------------------------------------------------------------------- reading

def template_metrics():
    doc = read_stream(TEMPLATE, 'DocInfo')
    paras = [p for t, _, p in iter_records(doc) if t == TAG_PARA_SHAPE]
    body = read_stream(TEMPLATE, 'BodyText/Section0')
    page = next(p for t, _, p in iter_records(body) if t == TAG_PAGE_DEF)
    return {
        'chapter': para_get(paras[TPL_CHAPTER]),
        'section': para_get(paras[TPL_SECTION]),
        'lead': para_get(paras[TPL_LEAD]),
        'body': para_get(paras[TPL_BODY]),
        'caption': para_get(paras[TPL_CAPTION]),
        'page': struct.unpack_from('<9i', page, 0),
    }


def para_text(payload):
    text = payload.decode('utf-16le', 'replace')
    out, i = [], 0
    while i < len(text):
        code = ord(text[i])
        if code in (1, 2, 3, 4, 11, 12, 14, 15, 16, 17, 18, 21, 22, 23):
            i += 8
            continue
        out.append(text[i] if code > 31 else ' ')
        i += 1
    return ''.join(out).strip()


# -------------------------------------------------------------------- doc edit

def rebuild_docinfo(raw, template):
    records = list(iter_records(raw))
    char_idx = [i for i, r in enumerate(records) if r[0] == TAG_CHAR_SHAPE]
    para_idx = [i for i, r in enumerate(records) if r[0] == TAG_PARA_SHAPE]
    n_char, n_para = len(char_idx), len(para_idx)
    notes = []

    def edit_para(shape, **kw):
        i = para_idx[shape]
        tag, level, payload = records[i]
        records[i] = (tag, level, para_set(payload, **kw))
        notes.append(f'ps{shape}: ' + ', '.join(f'{k}={v}' for k, v in kw.items()))

    # 1. Every 135% body/heading shape goes to the template's 180%.
    #    Table cells (112%) and the drawing anchors stay as they are.
    for shape in (21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 34, 36):
        edit_para(shape, line=180)

    # 2. Cover and 목차 titles: centred like the template's cover.
    edit_para(21, align=ALIGN_CENTER)

    # 3. 장 / 절 headings.
    chapter = template['chapter']
    edit_para(26, align=chapter['align'], up=chapter['up'], down=chapter['down'])
    edit_para(27, align=template['section']['align'])

    # 4. Body hierarchy: □ lead paragraph and the - sentences beneath it.
    lead, body = template['lead'], template['body']
    edit_para(28, align=lead['align'], left=lead['left'],
              up=lead['up'], down=lead['down'])
    # The draft spells the dash out, so the template's left margin is applied to
    # the dash itself and the hanging indent is kept for the wrapped lines,
    # which keeps the bullet column of the template with real wrapped text.
    edit_para(29, align=body['align'],
              left=body['left'] + records_indent(records, para_idx, 29),
              up=body['up'], down=body['down'])

    # 5. Figure captions: centred, template spacing above.
    edit_para(30, align=template['caption']['align'])

    # 6. Appended shapes: cover 20pt, 목차 20pt, caption 11pt, centred paragraph.
    body_char = records[char_idx[7]][2]          # 휴먼명조 12pt body run
    toc_char = records[char_idx[8]][2]           # HY헤드라인M cover/목차 run
    gothic_char = records[char_idx[6]][2]        # 함초롬돋움 11pt
    new_chars = [
        char_set(char_fonts(body_char, body_char), size=20),   # cover lines
        char_set(char_fonts(toc_char, toc_char), size=20),     # 목차 title
        char_set(char_fonts(gothic_char, gothic_char), size=11),  # caption
    ]
    new_para = para_set(records[para_idx[23]][2], align=ALIGN_CENTER, line=180,
                        left=0, right=0, indent=0, up=0, down=0)

    insert_at = char_idx[-1] + 1
    records[insert_at:insert_at] = [(TAG_CHAR_SHAPE, 0, c) for c in new_chars]
    para_insert = para_idx[-1] + 1 + len(new_chars)
    records.insert(para_insert, (TAG_PARA_SHAPE, 0, new_para))

    ids = dict(cover_char=n_char, toc_char=n_char + 1, caption_char=n_char + 2,
               cover_para=n_para)

    # 7. ID_MAPPINGS counts must match the records that follow it.
    for i, (tag, level, payload) in enumerate(records):
        if tag == TAG_ID_MAPPINGS:
            counts = list(struct.unpack('<18i', payload))
            counts[MAP_CHAR_SHAPE] += len(new_chars)
            counts[MAP_PARA_SHAPE] += 1
            records[i] = (tag, level, struct.pack('<18i', *counts))
            notes.append(f'ID_MAPPINGS charShape={counts[MAP_CHAR_SHAPE]} '
                         f'paraShape={counts[MAP_PARA_SHAPE]}')
            break

    return pack_records(records), ids, notes


def records_indent(records, para_idx, shape):
    """Hanging indent of a paragraph shape, as a positive number."""
    return -min(0, para_get(records[para_idx[shape]][2])['indent'])


# ------------------------------------------------------------------ body edits

COVER_SUBTITLE = '설계서 초안'
COVER_DATE = '2026. 11. 20.'
DROP_PREFIXES = ('현재 시스템의 제품 식별', '개정 기준')


def rebuild_section(raw, ids, template):
    records = list(iter_records(raw))
    groups, current = [], None
    for item in records:
        tag, level, payload = item
        if tag == TAG_PARA_HEADER:
            current = {'level': level, 'items': [item], 'text': '', 'shape': None}
            current['shape'] = struct.unpack_from('<H', payload, 8)[0]
            groups.append(current)
        elif current is not None and level > current['level']:
            current['items'].append(item)
            if tag == TAG_PARA_TEXT:
                current['text'] += para_text(payload)
        else:
            groups.append({'level': level, 'items': [item], 'text': '',
                           'shape': None})
            current = None

    actions, kept = [], []
    cover_done = {'subtitle': False, 'date': False, 'toc': False}
    for group in groups:
        text, shape = group['text'], group['shape']
        if shape is not None and text.startswith(DROP_PREFIXES):
            actions.append(f'표지 문단 삭제: {text[:28]}…')
            continue
        if shape == 22 and text == COVER_SUBTITLE and not cover_done['subtitle']:
            retag(group, para=ids['cover_para'], char=ids['cover_char'])
            cover_done['subtitle'] = True
            actions.append('표지 부제 중앙 20pt')
        elif shape == 23 and text.startswith(COVER_DATE) and not cover_done['date']:
            retag(group, para=ids['cover_para'], char=ids['cover_char'])
            cover_done['date'] = True
            actions.append('표지 날짜·기관 중앙 20pt')
        elif shape == 21 and text == '목차' and not cover_done['toc']:
            retag(group, char=ids['toc_char'])
            cover_done['toc'] = True
            actions.append('목차 제목 20pt')
        elif shape == 30 and text.startswith('그림 '):
            retag(group, char=ids['caption_char'])
            actions.append(f'캡션 11pt: {text[:24]}')
        kept.extend(group['items'])

    out = bytearray(pack_records(kept))
    # Page margins: copy the template's definition.
    pos = 0
    for tag, _, payload in iter_records(bytes(out)):
        head_len = 4 if len(payload) < 0xFFF else 8
        if tag == TAG_PAGE_DEF:
            page = list(struct.unpack_from('<9i', payload, 0))
            tpl = template['page']
            before = [round(v / MM, 1) for v in page[4:8]]
            page[4:8] = list(tpl[4:8])      # top, bottom, header, footer
            struct.pack_into('<9i', out, pos + head_len, *page)
            actions.append('여백 상/하/머리말/꼬리말 '
                           f'{before} → {[round(v / MM, 1) for v in tpl[4:8]]} mm')
        pos += head_len + len(payload)
    return bytes(out), actions, cover_done


def retag(group, para=None, char=None):
    items = group['items']
    tag, level, payload = items[0]
    payload = bytearray(payload)
    if para is not None:
        struct.pack_into('<H', payload, 8, para)
    items[0] = (tag, level, bytes(payload))
    if char is None:
        return
    for i, (t, lv, pl) in enumerate(items):
        if t == TAG_PARA_CHAR_SHAPE:
            runs = bytearray(pl)
            for r in range(len(runs) // 8):
                struct.pack_into('<I', runs, r * 8 + 4, char)
            items[i] = (t, lv, bytes(runs))


# ----------------------------------------------------------------------- entry

def refresh_preview():
    """Drop the removed cover memos from the stored text preview.

    The preview is what Explorer and Hancom's open dialog show; Hancom itself
    only regenerates it on save.
    """
    with olefile.OleFileIO(str(DRAFT)) as ole:
        text = ole.openstream('PrvText').read().decode('utf-16le', 'replace')
    lines = [l for l in text.split('\r\n')
             if not l.startswith(DROP_PREFIXES)]
    new = '\r\n'.join(lines)
    if new == text:
        return None
    write_streams(DRAFT, {'PrvText': new.encode('utf-16le')}, compressed=False)
    return len(text) - len(new)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true',
                    help='write the restyled document in place')
    ap.add_argument('--preview-only', action='store_true',
                    help='only refresh the stored text preview')
    args = ap.parse_args()

    if args.preview_only:
        print('preview trimmed chars:', refresh_preview())
        return

    template = template_metrics()
    doc_raw = read_stream(DRAFT, 'DocInfo')
    sec_raw = read_stream(DRAFT, 'BodyText/Section0')

    new_doc, ids, doc_notes = rebuild_docinfo(doc_raw, template)
    new_sec, body_notes, cover_done = rebuild_section(sec_raw, ids, template)
    assert all(cover_done.values()), f'cover paragraphs not matched: {cover_done}'

    summary = {
        'template': str(TEMPLATE),
        'draft': str(DRAFT),
        'shape_changes': doc_notes,
        'content_changes': body_notes,
        'docinfo_bytes': [len(doc_raw), len(new_doc)],
        'section_bytes': [len(sec_raw), len(new_sec)],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    if not args.apply:
        print('\ndry run: nothing written (pass --apply)')
        return

    ARCHIVE.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    backup = ARCHIVE / DRAFT.name
    if not backup.exists():
        shutil.copy2(DRAFT, backup)
    write_streams(DRAFT, {'DocInfo': new_doc, 'BodyText/Section0': new_sec})
    summary['preview_trimmed_chars'] = refresh_preview()

    summary['backup'] = str(backup.relative_to(ROOT))
    summary['sha256'] = hashlib.sha256(DRAFT.read_bytes()).hexdigest()
    summary['bytes'] = DRAFT.stat().st_size
    (REPORT / 'format_align.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('\napplied; backup at', backup)


if __name__ == '__main__':
    main()
