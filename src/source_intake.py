#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""업로드된 소스 ZIP을 받아 함수·호출그래프·CFG 색인을 만든다.

업로드 파일은 신뢰할 수 없는 입력이다
-------------------------------------
사용자가 올린 ZIP은 데이터이지 코드가 아니다. 이 모듈은 **읽기만** 한다 —
압축을 풀고 텍스트로 파싱할 뿐, 아무것도 실행하지 않고 빌드하지 않는다.
막는 것들:

  * **Zip slip** — 아카이브 안의 `../../etc/passwd` 같은 경로. 모든 경로를
    목적지 아래로 정규화해 확인하고, 벗어나면 그 항목을 버린다.
  * **심볼릭 링크** — ZIP은 링크를 담을 수 있고, 링크를 따라가면 추출 디렉터리
    밖을 쓰게 된다. 링크 항목은 건너뛴다.
  * **Zip bomb** — 압축 해제 총량과 항목 수에 상한을 둔다. 상한에 닿으면 그
    지점에서 멈추고 잘렸다고 보고한다 (조용히 성공한 척하지 않는다).
  * **절대 경로 / 드라이브 문자** — 전부 떼어내고 상대 경로로만 쓴다.

CFG를 정규 파서 없이 만드는 이유와 그 한계
------------------------------------------
ICS 펌웨어 소스는 대부분 C/C++ 이고, 임의 프로젝트를 빌드 없이 정확히 파싱하려면
전처리기 상태(매크로, `#ifdef` 조합, include 경로)를 알아야 한다. 업로드 한
덩어리에는 그 정보가 없다. 그래서 여기서 만드는 CFG는 **구문 수준 근사**다:

  * 분기/반복/점프 키워드에서 블록을 끊고 블록 간 엣지를 잇는다.
  * 호출 그래프는 "알려진 함수 이름 + `(`" 로 잇는다. 함수 포인터와 가상
    디스패치는 보이지 않는다.
  * `#if 0` 과 명백한 상수 거짓 분기는 죽은 코드로 표시한다.

이 근사가 틀리는 방향이 중요하다. 못 본 호출(함수 포인터)은 **도달 가능을
놓치는** 쪽이므로, 도달 불가 판정은 과신이 된다. 그래서 src/cfg_vex.py 는
"도달 불가"를 단독으로 `not_affected` 근거로 쓰지 않고 간접 호출이 존재하면
판정을 유보한다 — 근사의 한계를 판정 규칙이 흡수한다.
"""
import io
import os
import re
import shutil
import zipfile

# 상한. 넉넉하되 무한하지 않게.
MAX_FILES = 20000
MAX_TOTAL_BYTES = 600 * 1024 * 1024      # 압축 해제 총량 600MB
MAX_FILE_BYTES = 12 * 1024 * 1024        # 개별 파일 12MB (소스 파일은 이보다 훨씬 작다)

LANG_EXT = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".py": "python", ".java": "java",
    ".cs": "csharp", ".js": "javascript", ".ts": "typescript", ".go": "go",
    ".rs": "rust",
}
# 벤더 디렉터리는 색인하되 엔트리포인트 후보에서는 빼고 싶을 때가 있어 표시만 해 둔다.
_VENDOR_HINT = re.compile(
    r"(^|/)(third[_-]?party|vendor|external|deps?|node_modules|test|tests)(/|$)", re.I)


def extract_zip(zip_path, dest_dir):
    """ZIP을 dest_dir 아래로 안전하게 푼다. 무엇을 버렸는지 함께 보고한다."""
    os.makedirs(dest_dir, exist_ok=True)
    dest_real = os.path.realpath(dest_dir)
    written = total = 0
    skipped = {"outside": 0, "symlink": 0, "too_big": 0, "dir": 0}
    truncated = None

    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if written >= MAX_FILES:
                truncated = "file count limit (%d)" % MAX_FILES
                break
            if total >= MAX_TOTAL_BYTES:
                truncated = "uncompressed size limit (%d MB)" % (MAX_TOTAL_BYTES >> 20)
                break
            if info.is_dir():
                skipped["dir"] += 1
                continue
            # ZIP의 유닉스 모드 상위 4비트가 0xA 면 심볼릭 링크다.
            if (info.external_attr >> 16) & 0xF000 == 0xA000:
                skipped["symlink"] += 1
                continue
            if info.file_size > MAX_FILE_BYTES:
                skipped["too_big"] += 1
                continue

            rel = _safe_relpath(info.filename)
            if rel is None:
                skipped["outside"] += 1
                continue
            out = os.path.join(dest_real, rel)
            # 정규화한 뒤에도 목적지 안에 있는지 다시 확인한다 (심볼릭 링크가
            # 이미 만들어져 있는 경우를 포함해).
            if not os.path.realpath(os.path.dirname(out) or dest_real).startswith(dest_real):
                skipped["outside"] += 1
                continue
            os.makedirs(os.path.dirname(out), exist_ok=True)
            try:
                with zf.open(info) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
            except Exception:
                continue
            written += 1
            total += info.file_size

    return {"root": dest_real, "files": written, "bytes": total,
            "skipped": skipped, "truncated": truncated}


def _safe_relpath(name):
    """아카이브 경로를 목적지 안쪽 상대경로로. 벗어나면 None."""
    n = name.replace("\\", "/")
    n = re.sub(r"^[A-Za-z]:", "", n)            # 드라이브 문자 제거
    parts = []
    for p in n.split("/"):
        if p in ("", ".", ".."):                # 상위 이동은 통째로 거부
            if p == "..":
                return None
            continue
        parts.append(p)
    return os.path.join(*parts) if parts else None


# ---- 함수 / 호출 / CFG 색인 -------------------------------------------------

# C/C++ 함수 정의: 반환형 ... 이름( ... ) { .
#
# 세 가지를 모두 받아야 실제 코드에서 쓸모가 있다. zlib 하나만 넣어 봐도 셋이
# 다 나온다:
#   1) 여는 중괄호가 다음 줄에 있는 경우        -> `)` 와 `{` 사이에 \s (개행 포함)
#   2) K&R 구식 정의                            -> `)` 와 `{` 사이에 파라미터 선언들
#        int ZEXPORT deflateInit_(strm, level)
#            z_streamp strm;
#            int level;
#        {
#   3) 파라미터에 함수 포인터가 들어간 경우      -> 괄호 한 겹 중첩 허용
#
# 그리고 선언(프로토타입)은 반드시 빼야 한다. `)` 뒤에 `;` 가 오면 중괄호를 만나지
# 못하므로 자연히 걸러진다 - zlib 의 `OF((...))` 매크로 프로토타입이 이 경로로
# 탈락한다.
_C_FUNC = re.compile(
    r"(?m)^[ \t]*(?:[A-Za-z_][\w \t\*&:<>,\[\]]*?[ \t\*&])??"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*"
    r"\((?:[^;{()]|\([^()]*\))*\)"          # 파라미터 (함수 포인터 1겹 허용)
    r"[ \t]*(?:const[ \t]*)?"
    r"(?:\s*[A-Za-z_][\w \t\*&\[\],]*;)*"   # K&R 파라미터 선언들 (없어도 됨)
    r"\s*\{")
_PY_FUNC = re.compile(r"(?m)^[ \t]*def[ \t]+(?P<name>\w+)[ \t]*\(")
_JAVAISH_FUNC = re.compile(
    r"(?m)^[ \t]*(?:public|private|protected|static|final|synchronized|[ \t])+"
    r"[\w<>\[\]\.]+[ \t]+(?P<name>\w+)[ \t]*\([^;{)]*\)[ \t]*\{")

_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch",
             "do", "else", "case", "default", "new", "delete", "throw"}

_CALL = re.compile(r"\b([A-Za-z_]\w*)[ \t]*\(")
# 블록을 끊는 지점. CFG의 분기 구조는 이 키워드들에서 나온다.
_BRANCH = re.compile(r"\b(if|else|for|while|switch|case|default|goto|return|"
                     r"break|continue|try|catch)\b")
_DEAD = re.compile(r"#if\s+0\b|\bif\s*\(\s*0\s*\)|\bif\s*\(\s*false\s*\)")


def _strip_comments(text, lang):
    """주석과 문자열 리터럴을 공백으로 — 그 안의 식별자가 호출로 잡히지 않게."""
    if lang == "python":
        text = re.sub(r"#[^\n]*", "", text)
        text = re.sub(r"('''|\"\"\")(?:.|\n)*?\1", '""', text)
    else:
        text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
        text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    text = re.sub(r"'(?:\\.|[^'\\\n])*'", "''", text)
    return text


def _body(text, open_brace):
    """여는 중괄호부터 짝이 맞는 닫는 중괄호까지. 못 찾으면 파일 끝까지."""
    depth = 0
    for i in range(open_brace, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:i + 1]
    return text[open_brace:]


def _py_body(text, start):
    """파이썬: def 줄의 들여쓰기보다 깊은 동안이 본문."""
    lines = text[start:].splitlines(True)
    if not lines:
        return ""
    base = len(lines[0]) - len(lines[0].lstrip())
    out = [lines[0]]
    for ln in lines[1:]:
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= base:
            break
        out.append(ln)
    return "".join(out)


def _cfg_of(body):
    """본문 하나의 제어흐름 근사: 블록 수, 분기 수, 죽은 코드 여부.

    완전한 블록 그래프를 세우는 대신 판정에 실제로 쓰이는 것만 센다 — 호출이
    분기 안에 있는지(조건부 호출), 죽은 코드 안에 있는지. 쓰지 않을 그래프를
    세우는 것은 정확해 보이기만 하고 검증은 안 되는 코드가 된다.
    """
    branches = len(_BRANCH.findall(body))
    return {"blocks": branches + 1, "branches": branches,
            "has_dead_code": bool(_DEAD.search(body))}


def index_tree(root):
    """소스 트리 전체의 함수 색인 + 호출 그래프.

    돌려주는 것:
      functions : {name: [{file, line, lang, calls, cfg, in_dead_code}]}
      callers   : {callee: {caller, ...}}
      files     : 색인한 파일 수
    """
    functions, callers = {}, {}
    files = langs = 0
    indirect_calls = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        for fn in filenames:
            lang = LANG_EXT.get(os.path.splitext(fn)[1].lower())
            if not lang:
                continue
            path = os.path.join(dirpath, fn)
            try:
                raw = io.open(path, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            files += 1
            rel = os.path.relpath(path, root).replace("\\", "/")
            text = _strip_comments(raw, lang)
            # 함수 포인터 호출의 흔적. 보이지 않는 엣지가 있다는 신호로만 쓴다.
            indirect_calls += len(re.findall(r"\(\s*\*\s*\w+\s*\)\s*\(", text))
            indirect_calls += len(re.findall(r"->\s*\w+\s*\(", text))

            rx = (_PY_FUNC if lang == "python"
                  else _JAVAISH_FUNC if lang in ("java", "csharp")
                  else _C_FUNC)
            for m in rx.finditer(text):
                name = m.group("name")
                if name in _KEYWORDS:
                    continue
                if lang == "python":
                    body = _py_body(text, m.start())
                else:
                    brace = text.find("{", m.end() - 1)
                    body = _body(text, brace) if brace >= 0 else ""
                calls = {c for c in _CALL.findall(body)
                         if c not in _KEYWORDS and c != name}
                rec = {"file": rel, "line": text[:m.start()].count("\n") + 1,
                       "lang": lang, "calls": sorted(calls),
                       "cfg": _cfg_of(body),
                       "vendor_path": bool(_VENDOR_HINT.search(rel))}
                functions.setdefault(name, []).append(rec)
                for c in calls:
                    callers.setdefault(c, set()).add(name)

    return {"functions": functions,
            "callers": {k: sorted(v) for k, v in callers.items()},
            "files": files, "indirect_call_sites": indirect_calls}


def entry_points(index):
    """외부에서 들어올 수 있는 지점의 근사.

    `main` 이 있으면 그것, 없으면 **아무도 부르지 않는 함수들**(루트). 라이브러리
    스냅샷에는 main 이 없고 공개 API가 곧 진입점이므로 루트 집합이 그 역할을 한다.
    정확하지 않다는 것을 이름으로 드러내려고 `approximate` 를 함께 돌려준다.
    """
    funcs, callers = index["functions"], index["callers"]
    mains = [n for n in funcs if n in ("main", "wmain", "WinMain", "app_main")]
    if mains:
        return {"entries": sorted(mains), "kind": "main", "approximate": False}
    roots = sorted(n for n in funcs if not callers.get(n))
    return {"entries": roots, "kind": "unreferenced-roots", "approximate": True}


def reaches(index, target, entries, max_depth=40):
    """진입점들에서 target 까지 호출 경로가 있는가. 경로 하나를 함께 돌려준다."""
    funcs = index["functions"]
    if target not in funcs:
        return {"reachable": False, "reason": "target not defined in this tree",
                "path": None}
    seen, queue = set(entries), [(e, [e]) for e in entries]
    while queue:
        node, path = queue.pop(0)
        if node == target:
            return {"reachable": True, "path": path, "depth": len(path) - 1}
        if len(path) > max_depth:
            continue
        for rec in funcs.get(node, []):
            for c in rec["calls"]:
                if c not in seen and c in funcs:
                    seen.add(c)
                    queue.append((c, path + [c]))
    return {"reachable": False, "reason": "no call path from the entry set",
            "path": None, "visited": len(seen)}


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("usage: source_intake.py <source-dir>")
        raise SystemExit(2)
    idx = index_tree(sys.argv[1])
    ep = entry_points(idx)
    print("files=%d functions=%d indirect_call_sites=%d"
          % (idx["files"], len(idx["functions"]), idx["indirect_call_sites"]))
    print("entries: %s (%s, approximate=%s)"
          % (len(ep["entries"]), ep["kind"], ep["approximate"]))
    if len(sys.argv) > 2:
        print(json.dumps(reaches(idx, sys.argv[2], ep["entries"]), indent=2))
