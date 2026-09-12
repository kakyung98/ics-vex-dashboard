#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identify the vulnerable function for each CVE, for callgraph Q2 targeting.

The problem callgraph_reach.py hit: it needs the name of the vulnerable function,
but data/code_evidence.json stores only a hunk excerpt (no signature). Here we
locate that excerpt inside the collected snapshot file and read off the *enclosing*
function with tree-sitter — robust, offline, no diff parsing.

For each CVE that has both a code_evidence entry (repo/file/vuln_code) and a
source snapshot:
  1. find the file (by basename) in data/source_snapshots/<CVE>/
  2. take distinctive lines from vuln_code, locate them in that file
  3. tree-sitter the file, find the function_definition spanning those lines
  4. record the enclosing function name(s)

Output: data/vuln_funcs.json = {CVE: [funcnames]} — consumed by callgraph_reach.py.
"""
import json
import os
import re
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP = os.path.join(BASE, "data", "source_snapshots")
# Only the files a fix touches, at the fix's parent commit - for a component with
# no whole-source snapshot (the Linux kernel). Enough to attribute hunks to
# functions; never read by Q2-Q4, which need the whole program.
PARTIAL = os.path.join(BASE, "data", "partial_snapshots")


def _snap_root(cve):
    full = os.path.join(SNAP, cve)
    return full if os.path.isdir(full) else os.path.join(PARTIAL, cve)
CE = os.path.join(BASE, "data", "code_evidence.json")
OUT = os.path.join(BASE, "data", "vuln_funcs.json")

import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser

C_LANG = Language(tree_sitter_c.language())
CPP_LANG = Language(tree_sitter_cpp.language())
EXT_CPP = {".cc", ".cpp", ".cxx", ".hpp", ".hh"}


def _parser(path):
    return Parser(CPP_LANG if os.path.splitext(path)[1].lower() in EXT_CPP else C_LANG)


def _funcname(node, src):
    """Name of a function_definition node (mirrors callgraph_reach.py)."""
    decl = node.child_by_field_name("declarator")
    seen = 0
    while decl is not None and decl.type != "function_declarator" and seen < 6:
        d = decl.child_by_field_name("declarator")
        if d is None:
            for c in decl.children:
                if c.type in ("function_declarator", "identifier", "pointer_declarator",
                              "parenthesized_declarator"):
                    d = c
                    break
        decl = d
        seen += 1
    if decl is None:
        return None
    idn = decl.child_by_field_name("declarator") if decl.type == "function_declarator" else decl
    q = [idn] if idn else []
    while q:
        n = q.pop()
        if n is None:
            continue
        if n.type in ("identifier", "field_identifier"):
            return src[n.start_byte:n.end_byte].decode("utf-8", "ignore")
        q.extend(n.children)
    return None


try:
    import tree_sitter_java
    JAVA_LANG = Language(tree_sitter_java.language())
except Exception:                                   # optional grammar
    JAVA_LANG = None
# The K&R scanner is shared with callgraph_reach.py, so a definition the Q2 graph
# can see is also one a target can be attributed to.
from callgraph_reach import _KR_DEF, _KW, _match_brace
_PERL_SUB = re.compile(rb"^sub[ \t]+([A-Za-z_]\w*)[^\n{]*\{", re.M)


def _match_brace_perl(src, i):
    """_match_brace for Perl: `#` comments and backslash escapes only. C's
    quote rule misreads Perl - `don't` in a comment or `s/'//` opened a "char
    literal" that ran on and dropped link_hash_cert from c_rehash."""
    depth, n = 0, len(src)
    while i < n:
        c = src[i:i + 1]
        if c == b"\\":
            i += 2
            continue
        if c == b"#" and (i == 0 or src[i - 1:i] in b" \t\n") and src[i - 1:i] != b"$":
            j = src.find(b"\n", i)
            i = n if j < 0 else j
        elif c == b"{":
            depth += 1
        elif c == b"}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _brace_spans(src, pattern, skip=(), match=_match_brace):
    """(start_line, end_line, name) for regex-found definitions with a {} body."""
    out = []
    for m in pattern.finditer(src):
        nm = m.group(1).decode("utf-8", "ignore")
        if nm in skip:
            continue
        brace = src.find(b"{", m.end() - 1)
        end = match(src, brace) if brace >= 0 else None
        if end is not None:
            out.append((src.count(b"\n", 0, m.start()), src.count(b"\n", 0, end), nm))
    return out


def _funcs_by_line(path):
    """(start_line, end_line, name) for every function in one file, 0-based.

    C/C++ by tree-sitter plus the K&R regex scan (zlib 1.2.12's inflate.c is K&R
    and the parse lost `inflate` itself, so CVE-2022-37434's fix had nowhere to
    land); Java methods by tree-sitter-java; Perl `sub`s for OpenSSL's c_rehash,
    the script both CVE-2022-1292 and CVE-2022-2068 are in."""
    src = open(path, "rb").read()
    ext = os.path.splitext(path)[1].lower()
    if ext == ".java":
        if JAVA_LANG is None:
            return []
        tree = Parser(JAVA_LANG).parse(src)
        spans, stack = [], [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type in ("method_declaration", "constructor_declaration"):
                nm = n.child_by_field_name("name")
                if nm is not None:
                    spans.append((n.start_point[0], n.end_point[0],
                                  src[nm.start_byte:nm.end_byte].decode("utf-8", "ignore")))
            stack.extend(n.children)
        return spans
    if src[:2] == b"#!" and b"perl" in src[:200].lower():
        return _brace_spans(src, _PERL_SUB, match=_match_brace_perl)
    tree = _parser(path).parse(src)
    spans = []  # (start_line, end_line, name)
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "function_definition":
            nm = _funcname(n, src)
            if nm:
                spans.append((n.start_point[0], n.end_point[0], nm, n.has_error))
        stack.extend(n.children)
    # Supplement: definitions the parse lost, and - for a definition whose node
    # contains a parse ERROR - a longer regex span. tree-sitter's error recovery
    # closed busybox ash's readtoken1 at line 12502 of 12820, and the parsesub
    # code CVE-2021-42375's fix edits fell outside every function.
    kr_all = _brace_spans(src, _KR_DEF, _KW)
    kr = {}
    for sp in kr_all:                     # longest span per name, for the lookup
        if sp[2] not in kr or sp[1] - sp[0] > kr[sp[2]][1] - kr[sp[2]][0]:
            kr[sp[2]] = sp
    out, have = [], set()
    for s, e, nm, err in spans:
        have.add(nm)
        k = kr.get(nm)
        if err and k and k[1] > e and abs(k[0] - s) <= 3:
            s, e = k[0], k[1]
        out.append((s, e, nm))
    # every lost definition, #if/#else alternates included
    out += [sp for sp in kr_all if sp[2] not in have]
    return out


def _find_file(root, basename):
    for dp, _dn, fns in os.walk(root):
        if basename in fns:
            return os.path.join(dp, basename)
    # try suffix match (code_evidence 'file' can be a path)
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if fn == basename:
                return os.path.join(dp, fn)
    return None


def _distinctive_lines(blob):
    """Lines worth anchoring on: non-trivial, likely unique."""
    out = []
    for ln in (blob or "").splitlines():
        s = ln.strip()
        if len(s) < 12:
            continue
        if s in ("{", "}", "*/", "/*") or s.startswith(("//", "* ", "*")):
            continue
        if re.fullmatch(r"[}\);,]+", s):
            continue
        out.append(s)
    return out


def enclosing_funcs(cve, ev):
    root = os.path.join(SNAP, cve)
    if not os.path.isdir(root):
        return None, "no-snapshot"
    fpath = _find_file(root, os.path.basename(ev.get("file", "")))
    if not fpath:
        return None, "file-not-in-snapshot"
    try:
        spans = _funcs_by_line(fpath)
    except Exception as e:
        return None, "parse-error:%s" % str(e)[:40]
    if not spans:
        return None, "no-functions"
    text = open(fpath, encoding="utf-8", errors="ignore").read().splitlines()
    anchors = _distinctive_lines(ev.get("vuln_code")) + _distinctive_lines(ev.get("patched_code"))
    hit = Counter()
    for a in anchors:
        for i, line in enumerate(text):
            if a in line:
                for s, e, nm in spans:
                    if s <= i <= e:
                        hit[nm] += 1
                break  # first occurrence is enough per anchor
    if not hit:
        return None, "anchors-unmatched"
    # keep the strongly-supported functions
    top = hit.most_common()
    best = [nm for nm, c in top if c >= max(2, top[0][1] // 2)]
    return (best or [top[0][0]]), "ok"


# --------------------------------------------------------------- patch-driven
# The code_evidence path above is capped at the 34 CVEs that carry a stored
# vuln/patched pair. The fix commits themselves cover far more of the snapshot
# corpus, so drive extraction from the patch diffs and keep code_evidence as a
# fallback.
TIERA = os.environ.get("TIERA_JSON",
                       r"C:\Users\user\Desktop\cve-genie\webapp\data\icsvex_tierA.json")
EXT_SRC = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java"}
# files a context vote may come from (implementation, not header)
EXT_IMPL = (".c", ".cc", ".cpp", ".cxx", ".java", ".in")
SKIP_SEG = {"test", "tests", "example", "examples", "fuzz", "fuzzing", "doc",
            "docs", "benchmark", "benchmarks", ".github", "contrib"}
_FILE_RE = re.compile(r"^Filename: (.+?):$", re.M)
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", re.M)


def _lead(block):
    """Unchanged lines before a hunk's first +/- line."""
    n = 0
    for l in block.splitlines():
        if l[:1] in ("+", "-"):
            return n
        n += 1
    return n


# A function header at column 0 inside a hunk's leading context: git names the
# function *above* the hunk start, which is stale when the changed function's own
# header is among the 3 context lines (CVE-2021-33909: git said seq_set_overflow,
# the fix is in seq_buf_alloc two lines further down).
_HEADER = re.compile(r"^[A-Za-z_][^;]*\b([A-Za-z_]\w*)\s*\([^;]*$|^([A-Za-z_]\w*)\s*\([^;]*$")


def _lead_header(block):
    name = None
    for l in block.splitlines():
        if l[:1] in ("+", "-"):
            break
        t = l[1:]
        if t[:1].isalpha() or t[:1] == "_":
            m = _HEADER.match(t)
            if m:
                n = _ctx_name(t)
                if n:
                    name = n
    return name


def _iter_hunks(content):
    """Yield (path, old_start_line, [removed lines]) for each hunk of a patch blob."""
    parts = _FILE_RE.split(content or "")
    for i in range(1, len(parts) - 1, 2):
        path, body = parts[i], parts[i + 1]
        marks = list(_HUNK_RE.finditer(body))
        for j, m in enumerate(marks):
            end = marks[j + 1].start() if j + 1 < len(marks) else len(body)
            block = body[m.end():end]
            removed = [l[1:] for l in block.splitlines() if l.startswith("-")]
            # position of the first changed line, not of the leading context
            yield path, int(m.group(1)) + _lead(block.split("\n", 1)[-1]), removed


PATCHD = os.path.join(BASE, "data", "patches")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.M)


def _iter_hunks_diff(text):
    """Same, for a real unified diff (tools/fetch_patches.py cache)."""
    marks = list(_DIFF_FILE_RE.finditer(text or ""))
    for i, fm in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        body = text[fm.end():end]
        path = fm.group(1).strip()
        hs = list(_HUNK_RE.finditer(body))
        for j, m in enumerate(hs):
            hend = hs[j + 1].start() if j + 1 < len(hs) else len(body)
            block = body[m.end():hend]
            removed = [l[1:] for l in block.splitlines() if l.startswith("-")]
            # position of the first changed line, not of the leading context
            yield path, int(m.group(1)) + _lead(block.split("\n", 1)[-1]), removed


_SUBJECT = re.compile(r"^Subject: (.*)$", re.M)
_RELEASE = re.compile(
    # "2021-05-04, Version 16.1.0 (Current)" is Node's release subject; it and
    # "[maven-release-plugin] prepare release" were cached under zlib and log4j
    r"^(\[PATCH[^\]]*\]\s*)?(\d{4}-\d{2}-\d{2},\s*Version\b|\[maven-release-plugin\]"
    r"|release\b|releasing\b|bump\b|prepare for\b|version\b|RELEASE:"
    r"|[A-Za-z][\w.+-]*\s+v?\d+(\.\d+){1,3}\s*$|v?\d+(\.\d+){1,3}\s*$)", re.I)


def _is_release(diff_text):
    """Is this cached diff a release/version-bump commit rather than a fix?"""
    m = _SUBJECT.search(diff_text or "")
    return bool(m and _RELEASE.search(m.group(1).strip()))


def load_patch_hunks(cve, tier_blobs):
    """Hunk iterators for a CVE: the full cached diffs when present, else the
    tier-A blobs (truncated at 6000 chars, so source hunks are often missing)."""
    d = os.path.join(PATCHD, cve)
    if os.path.isdir(d):
        diffs = [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".diff")]
        if diffs:
            loaded = [open(p, encoding="utf-8", errors="ignore").read() for p in diffs]
            # 24% of cached diffs are release commits ("zlib 1.2.12", "Bump
            # version", "Prepare for release"). A release touches everything that
            # changed since the last one, so its votes only dilute the fix's.
            # Keep them only when nothing else exists for this CVE.
            fixes = [t for t in loaded if not _is_release(t)]
            return [("diff", t) for t in (fixes or loaded)]
    return [("blob", b) for b in (tier_blobs or [])]


_TEST_FILE = re.compile(r"(runtests|test[^/]*|[^/]*_tests?)\.(c|cc|cpp|cxx|h)$")


def _is_src(path):
    low = path.replace("\\", "/").lower()
    ext = os.path.splitext(low)[1]
    # Build-time templates are source too: sqlite's shell is src/shell.c.in
    # (CVE-2022-46908) and OpenSSL's c_rehash is the Perl tools/c_rehash.in.
    # Their language is decided from content in _funcs_by_line.
    if ext == ".in":
        inner = os.path.splitext(low[:-3])[1]
        if inner and inner not in EXT_SRC:
            return False                  # Makefile.am.in, foo.xml.in ...
    elif ext not in EXT_SRC:
        return False
    # test harnesses at the repo root (libxml2's testapi.c, expat's runtests.c)
    # escaped the directory rule and turned CVE-2021-3517/3518 into
    # test_xmlPopInputCallbacks and friends
    if _TEST_FILE.search(low.split("/")[-1]):
        return False
    return not (SKIP_SEG & set(low.split("/")[:-1]))


def _find_by_suffix(root, relpath):
    """Locate a patch path in the snapshot by the longest matching path suffix."""
    want = [p for p in relpath.replace("\\", "/").split("/") if p]
    best, best_n = None, 0
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if fn != want[-1]:
                continue
            have = os.path.join(dp, fn).replace("\\", "/").split("/")
            n = 0
            while n < len(want) and n < len(have) and want[-1 - n] == have[-1 - n]:
                n += 1
            if n > best_n:
                best, best_n = os.path.join(dp, fn), n
    return best


_HUNK_CTX = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@ ?(.*)$", re.M)
# a macro wrapping the real name: `PREFIX(prologTok)(const ENCODING *enc ...`
_WRAPPED = re.compile(r"\b[A-Z][A-Z0-9_]*\(\s*([A-Za-z_]\w*)\s*\)\s*\(")
_CALLED = re.compile(r"([A-Za-z_]\w*)\s*\(")
# statement keywords git may show as a hunk's context (C, plus Perl and Java,
# whose `foreach $f (...)` became a "function" of CVE-2022-2068)
_CTX_KW = {"if", "for", "while", "switch", "return", "sizeof", "defined", "foreach",
           "elsif", "unless", "until", "my", "catch", "synchronized", "new"}


def _macro_like(name):
    """ALL_CAPS tokens are export/attribute/generator macros, never the target."""
    return name.isupper() or (name.replace("_", "").isupper() and len(name) > 3)


def _ctx_name(ctx):
    """The function a git hunk-header context line names, or None."""
    m = _WRAPPED.search(ctx)
    if m:
        return m.group(1)
    for m in _CALLED.finditer(ctx):
        n = m.group(1)
        if n not in _CTX_KW and not _macro_like(n):
            return n
    return None                       # `typedef struct ...`, `extern "C" {`


def _hunk_contexts(text):
    """[(path, function name)] from git's per-hunk function context, corrected
    by a function header in the hunk's own leading context."""
    out, path = [], None
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("+++ b/"):
            path = line[6:].strip()
            continue
        m = _HUNK_CTX.match(line)
        if m and path:
            lead = []
            for l in lines[i + 1:]:
                if l.startswith(("@@", "diff --git", "--- ", "+++ ")):
                    break
                lead.append(l)
            n = _lead_header("\n".join(lead)) or _ctx_name(m.group(1))
            if n:
                out.append((path, n))
    return out



_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
# a single Capitalised word is a person's name or English prose, not an identifier
_PROSE = re.compile(r"^[A-Z][a-z]+$")
# names every C file shares - they cannot tell one project from another
_COMMON_IDS = {"return", "NULL", "const", "char", "size_t", "static", "void",
               "unsigned", "sizeof", "struct", "else", "break", "goto", "error",
               "free", "memcpy", "memset", "strlen", "while", "uint32_t", "uint8_t",
               "int32_t", "long", "case", "default", "TRUE", "FALSE", "true", "false"}

def _path_lines(sources):
    """{diff path: distinctive unchanged or removed lines} across the diffs -
    the lines that must already exist in the snapshot file if it is the same
    file the fix was written against."""
    out = {}
    for kind, content in sources:
        if kind != "diff":
            continue
        path = None
        for line in (content or "").splitlines():
            if line.startswith("+++ b/"):
                path = line[6:].strip()
                continue
            if line.startswith(("--- ", "diff --git", "@@", "index ")):
                continue
            if path and line[:1] in (" ", "-"):
                t = line[1:].strip()
                if len(t) < 12 or t.startswith(("//", "/*", "*", "#include")):
                    continue
                # License headers are prose, not code: a fix that refreshes the
                # contributor list made expat's older xmltok.c look like a
                # foreign file (its "missing" names were Cuoq, Greg, Pipping...)
                if any(k in t for k in ("Copyright", "(c)", "@", "http", "License", "licen")):
                    continue
                out.setdefault(path, []).append(t)
    return out

_DEF_CACHE = {}


def _defined_in_one_file(root, name, path):
    """Is `name` defined (not just declared or called) in exactly one snapshot
    file of the same language as `path`?"""
    ext = os.path.splitext(path)[1].lower()
    exts = (".java",) if ext == ".java" else (".c", ".cc", ".cpp", ".cxx")
    key = (root, name, exts)
    if key not in _DEF_CACHE:
        pat = re.compile(r"^(?:[A-Za-z_][\w \t\*]*?[ \t\*])?%s[ \t]*\([^;]*$"
                         % re.escape(name), re.M)
        files = set()
        for dp, _dn, fns in os.walk(root):
            for fn in fns:
                if fn.lower().endswith(exts):
                    fp = os.path.join(dp, fn)
                    try:
                        if pat.search(open(fp, encoding="utf-8", errors="ignore").read()):
                            files.add(fp)
                    except OSError:
                        pass
        _DEF_CACHE[key] = len(files) == 1
    return _DEF_CACHE[key]


def enclosing_funcs_from_patch(cve, sources):
    """Enclosing function names for every source hunk of a CVE's fix commit(s).

    `sources` is [(kind, text)] from load_patch_hunks: "diff" = a real unified
    diff, "blob" = the truncated tier-A rendering."""
    root = _snap_root(cve)
    if not os.path.isdir(root):
        return None, "no-snapshot"
    hit = Counter()
    cache = {}
    path_lines = _path_lines(sources)
    seen_src = missing_file = False
    for kind, content in sources:
        it = _iter_hunks_diff(content) if kind == "diff" else _iter_hunks(content)
        for path, old_start, removed in it:
            if not _is_src(path):
                continue
            seen_src = True
            if path not in cache:
                fpath = _find_by_suffix(root, path)
                ent = False
                if not fpath:
                    missing_file = True
                if fpath:
                    try:
                        ent = (_funcs_by_line(fpath),
                               open(fpath, encoding="utf-8",
                                    errors="ignore").read().splitlines())
                    except Exception:
                        ent = False
                    # Same file, or merely the same file NAME? Decide by content:
                    # the diff's own unchanged/removed lines must be in it. A path
                    # rule got this wrong both ways - libssh2's src/packet.c
                    # matched dropbear's packet.c (Terrapin), while OpenBSD's
                    # usr.bin/ssh/ssh-agent.c is legitimately portable's root
                    # ssh-agent.c.
                    if ent:
                        # Measured on identifiers, not whole lines: a fix written
                        # against a newer API rewrites the lines but keeps the
                        # names. On the four decisive cases the overlap was
                        # 0.8 / 1.0 (same project, older version), 1.0 (OpenBSD
                        # vs portable layout) and 0.13 / 0.10 (libssh2 onto
                        # dropbear); whole-line agreement rejected the two older-
                        # version cases along with the foreign one.
                        ids = {t for l in path_lines.get(path, ())
                               for t in _IDENT.findall(l)
                               if not _PROSE.match(t)} - _COMMON_IDS
                        if ids:
                            body = chr(10).join(ent[1])
                            have = sum(1 for t in ids
                                       if re.search(r"\b%s\b" % re.escape(t), body))
                            if have / len(ids) < 0.5:
                                ent = False
                                missing_file = True
                cache[path] = ent
            if not cache[path]:
                continue
            spans, text = cache[path]
            matched = False
            for a in _distinctive_lines("\n".join(removed)):
                occ = [k for k, line in enumerate(text) if a in line]
                if not occ:
                    continue
                # Nearest to the hunk's own position, not first in the file:
                # macro-heavy code repeats lines across functions, and the first
                # occurrence credited them to whichever function came earliest.
                i = min(occ, key=lambda k: abs(k - (old_start - 1)))
                for s, e, nm in spans:
                    if s <= i <= e:
                        hit[nm] += 1
                        matched = True
            if not matched:
                # no anchor matched (snapshot != patch parent): fall back to the
                # hunk's old-side start line
                i = old_start - 1
                for s, e, nm in spans:
                    if s <= i <= e:
                        hit[nm] += 1
    # Second vote: git's hunk-header context. Counted only for files that
    # resolve inside this snapshot, and only for names that file really uses -
    # a diff for another project cited under this CVE must not vote.
    for kind, content in sources:
        if kind != "diff":
            continue
        for path, name in _hunk_contexts(content):
            # Implementation files only. In a header git's context is merely the
            # nearest prototype above the change: expat.h turned a doc/version
            # edit into XML_SetBillionLaughsAttackProtectionActivationThreshold
            # and displaced the correct storeRawNames for CVE-2022-25315.
            if os.path.splitext(path)[1].lower() not in EXT_IMPL:
                continue
            ent = cache.get(path)
            if not ent:
                continue
            _spans, text = ent
            pat = re.compile(r"\b%s\s*\)?\s*\(" % re.escape(name))
            if any(pat.search(ln) for ln in text):
                hit[name] += 1
            elif _defined_in_one_file(root, name, path):
                # Moved, not absent: OpenSSH 8.5 moved subprocess() from auth.c
                # to misc.c, so CVE-2021-41617's fix (all added lines, hunk
                # context `subprocess`) named a function that the 8.2p1 misc.c
                # lacks. The file itself agreed on content, so this is the same
                # project; the name must be defined in exactly one other file.
                hit[name] += 1
    # a macro is never the vulnerable function
    for n in [n for n in hit if _macro_like(n)]:
        del hit[n]
    if not hit:
        if not seen_src:
            return None, "no-source-hunk"
        return None, ("file-not-in-snapshot" if missing_file else "anchors-unmatched")
    top = hit.most_common()
    # Relative threshold only. The old absolute floor of 2 votes let one stray
    # anchor vote decide: in expat CVE-2022-25235 the fix edits macros expanded
    # into six functions, each named once by git's hunk context, and `nameLength`
    # won alone on a single extra vote. A bigger target set is the safe error -
    # Q2/Q3 need every target unreachable before they may clear - while a wrong
    # single target is the unsafe one. top//2 is never above the old rule's floor
    # (max(2, top//2)), so no target set can shrink relative to it; (top+1)//2
    # was tried first and did shrink four CVEs whenever the top count was odd.
    # Union, not a vote threshold. With release commits already excluded, every
    # function a fix commit's hunk lands in is part of the fix. Thresholding the
    # counts made membership depend on how many copies of a diff happened to be
    # cached: CVE-2022-29824's fix touches xmlBufferAdd, which was kept or dropped
    # between two runs over the same commit. A larger set is also the safe error
    # (Q2/Q3 may only clear when every target is unreachable).
    # No cap. A 16-entry cap cut libssh2's CVE-2019-3855 fix - 25 functions -
    # down to 16 and dropped real ones (coverage 0.60 against git's own hunk
    # context), which is the arbitrary membership this union exists to remove.
    best = [nm for nm, _c in top]
    return best, "ok"


def main():
    ce = json.load(open(CE, encoding="utf-8")) if os.path.exists(CE) else {}
    tier = json.load(open(TIERA, encoding="utf-8")) if os.path.isfile(TIERA) else {}
    patches = {}
    for cve, v in tier.items():
        blobs = [pc.get("content") or "" for pc in (v.get("patch_commits") or [])]
        if any(blobs):
            patches[cve] = blobs

    snaps = set()
    for base in (SNAP, PARTIAL):
        if os.path.isdir(base):
            snaps |= {d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))}
    # only a CVE with a source snapshot can be resolved at all
    out, stats = {}, Counter()
    for cve in sorted(snaps):
        funcs, why, via = None, "no-input", "-"
        sources = load_patch_hunks(cve, patches.get(cve))
        if sources:
            funcs, why = enclosing_funcs_from_patch(cve, sources)
            via = sources[0][0]
        if not funcs and isinstance(ce.get(cve), dict) and ce[cve].get("file"):
            f2, w2 = enclosing_funcs(cve, ce[cve])
            if f2:
                funcs, why, via = f2, w2, "code_ev"
            elif via == "-":
                why, via = w2, "code_ev"
        stats["%s/%s" % (via, why)] += 1
        if funcs:
            out[cve] = funcs
            print("%-18s %-8s -> %s" % (cve, via, funcs[:6]))
        else:
            print("%-18s %-8s -- %s" % (cve, via, why))
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("\n== %d / %d CVEs resolved to a vulnerable function ==" % (len(out), sum(stats.values())))
    for k, v in sorted(stats.items(), key=lambda x: -x[1]):
        print("   %-28s %d" % (k, v))
    print("->", OUT)


if __name__ == "__main__":
    main()
