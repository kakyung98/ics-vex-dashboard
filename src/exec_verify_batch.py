#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
실행 검증 배치 러너 (WSL + AddressSanitizer).

data/verify_specs.json 의 스펙을 순회하며, 각 CVE 마다
  1) 취약 ref / 패치 ref 로 각각 클론 후 ASan 빌드
  2) tools/triggers/<CVE>.c 를 양쪽 라이브러리에 링크해 실행
  3) 취약본에서만 sanitizer 신호가 나오면 EXPLOITABLE 로 확정
을 수행한다. CVE-GENIE/FORGE 의 방어적 재현 절차와 동일하다.

기존 tools/exec_verify_c.sh(단일 CVE 하드코딩)를 대체하는 스케일 버전이다.
스펙과 트리거만 추가하면 코드 수정 없이 커버리지가 늘어난다.

안전 설계:
  - 자체 완결형 라이브러리만. 외부 타깃·네트워크 공격 없음
  - 격리 작업 디렉터리, 빌드/실행 각각 타임아웃
  - 취약 vs 패치 대조로 트리거의 판별력을 함께 검증(음성 대조군)

출력: results/exec_verification_batch.json
사용: python src/exec_verify_batch.py [--only CVE-1,CVE-2] [--limit N] [--jobs N]
"""
import argparse
import json
import os
import subprocess
import sys

BASE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SPECS = os.path.join(BASE, "data", "verify_specs.json")
OUT = os.path.join(BASE, "results", "exec_verification_batch.json")
WORK = "/tmp/ics_vex_verify"

CLONE_TIMEOUT = 300
BUILD_TIMEOUT = 1800
RUN_TIMEOUT = 120

# 빌드 레시피: ASan 플래그를 넣고 정적 라이브러리/실행파일을 만든다.
ASAN = "-fsanitize=address -g -O1 -fno-omit-frame-pointer"
BUILD_CMDS = {
    "configure_static": 'CFLAGS="%s" ./configure --static >/dev/null 2>&1 && make -s -j"$(nproc)" >/dev/null 2>&1' % ASAN,
    "autogen":          './autogen.sh >/dev/null 2>&1 || ./buildconf >/dev/null 2>&1; '
                        'CFLAGS="%s" ./configure --disable-shared --enable-static >/dev/null 2>&1 '
                        '&& make -s -j"$(nproc)" >/dev/null 2>&1' % ASAN,
    "autoreconf":       'autoreconf -fi >/dev/null 2>&1; '
                        'CFLAGS="%s" ./configure --disable-shared --enable-static >/dev/null 2>&1 '
                        '&& make -s -j"$(nproc)" >/dev/null 2>&1' % ASAN,
    "cmake":            'cmake -S . -B build -DCMAKE_C_FLAGS="%s" -DBUILD_SHARED_LIBS=OFF '
                        '>/dev/null 2>&1 && cmake --build build -j "$(nproc)" >/dev/null 2>&1' % ASAN,
    "make_plain":       'make -s -j"$(nproc)" CFLAGS="%s" >/dev/null 2>&1' % ASAN,
    "make_defconfig":   'make -s defconfig >/dev/null 2>&1 && '
                        'make -s -j"$(nproc)" CFLAGS="%s" >/dev/null 2>&1' % ASAN,
    "openssl":          './config no-shared no-asm -d %s >/dev/null 2>&1 '
                        '&& make -s -j"$(nproc)" build_libs >/dev/null 2>&1' % ASAN,
    "nginx":            './auto/configure --with-cc-opt="%s" --with-ld-opt="-fsanitize=address" '
                        '>/dev/null 2>&1 && make -s -j"$(nproc)" >/dev/null 2>&1' % ASAN,
}


def wsl(cmd, timeout, cwd=None):
    """WSL 안에서 bash 명령 실행. (rc, stdout+stderr) 반환."""
    full = ("cd %s && " % cwd if cwd else "") + cmd
    try:
        p = subprocess.run(["wsl", "-e", "bash", "-lc", full],
                           capture_output=True, timeout=timeout)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
        return p.returncode, out
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT after %ds" % timeout
    except FileNotFoundError:
        return 127, "WSL not available"


def clone(repo, ref, dest):
    """ref 로 클론. 태그/브랜치면 얕은 클론, 커밋 해시(또는 <commit>^)면 전체 후 checkout."""
    rc, _ = wsl("test -d %s/.git" % dest, 30)
    if rc == 0:
        return True, "cached"
    bare = ref.rstrip("^")
    is_sha = len(bare) >= 7 and all(c in "0123456789abcdef" for c in bare.lower())
    if ref.endswith("^") or is_sha:
        # 커밋 해시(및 부모)는 얕은 클론으로 못 잡는다 -> 전체 클론 후 checkout
        rc, out = wsl("rm -rf %s && git clone -q %s %s && cd %s && "
                      "git -c advice.detachedHead=false checkout -q %s"
                      % (dest, repo, dest, dest, ref), CLONE_TIMEOUT)
    else:
        rc, out = wsl("rm -rf %s && git -c advice.detachedHead=false clone -q --depth 1 "
                      "--branch %s %s %s" % (dest, ref, repo, dest), CLONE_TIMEOUT)
    return rc == 0, out[-400:]


def build(spec, srcdir):
    cmd = BUILD_CMDS.get(spec["build"])
    if not cmd:
        return False, "build recipe '%s' not implemented" % spec["build"]
    rc, out = wsl(cmd, BUILD_TIMEOUT, cwd=srcdir)
    ok, _ = wsl("test -e %s/%s" % (srcdir, spec["lib"]), 30)
    if ok != 0:
        return False, "artifact %s missing after build" % spec["lib"]
    return True, out[-400:]


def run_trigger(trigger_wsl, srcdir, lib, tag):
    """트리거를 해당 빌드에 링크해 실행. (crashed, signal, tail) 반환.
    crashed 가 None 이면 컴파일 실패."""
    exe = "%s/t_%s" % (WORK, tag)
    rc, out = wsl("gcc -fsanitize=address -g %s -I%s -I%s/include -I%s/lib %s/%s "
                  "-o %s -lpthread -lm 2>&1"
                  % (trigger_wsl, srcdir, srcdir, srcdir, srcdir, lib, exe), 300)
    if rc != 0:
        return None, None, "compile failed: " + out[-300:]
    rc, out = wsl("ASAN_OPTIONS=detect_leaks=0 %s 2>&1" % exe, RUN_TIMEOUT)
    sig = None
    for line in out.splitlines():
        if "AddressSanitizer:" in line:
            sig = line.split("AddressSanitizer:")[1].strip().split()[0]
            break
    return ("AddressSanitizer" in out), sig, out[-300:]


def verify(spec):
    cve = spec["cve"]
    res = {"cve": cve, "cwe": spec.get("cwe"), "component": spec["component"],
           "vuln_version": spec["vuln_ref"], "patched_version": spec["patched_ref"],
           "ref_basis": spec.get("ref_basis"),
           "vuln_crash": False, "patched_crash": False, "signal": "",
           "verdict": "INCONCLUSIVE", "stage": None, "detail": None,
           "method": "WSL + AddressSanitizer, build vuln vs patched, execute trigger"}

    if spec["status"] != "verifiable-c":
        res["verdict"] = "NOT_VERIFIABLE"
        res["stage"] = "classification"
        res["detail"] = spec.get("reason")
        return res
    if spec["needs_trigger"] or not spec.get("trigger"):
        res["verdict"] = "NEEDS_TRIGGER"
        res["stage"] = "trigger"
        res["detail"] = "no trigger at tools/triggers/%s.c" % cve
        return res
    if not spec["vuln_ref"] or not spec["patched_ref"]:
        res["verdict"] = "NEEDS_REFS"
        res["stage"] = "refs"
        res["detail"] = "vuln/patched ref pair incomplete (basis=%s)" % spec.get("ref_basis")
        return res

    slug = cve.replace("-", "_").lower()
    dirs = {}
    for tag, ref in (("vuln", spec["vuln_ref"]), ("patch", spec["patched_ref"])):
        d = "%s/%s_%s" % (WORK, slug, tag)
        ok, detail = clone(spec["repo"], ref, d)
        if not ok:
            res["verdict"] = "CLONE_FAILED"; res["stage"] = "clone:" + tag; res["detail"] = detail
            return res
        ok, detail = build(spec, d)
        if not ok:
            res["verdict"] = "BUILD_FAILED"; res["stage"] = "build:" + tag; res["detail"] = detail
            return res
        dirs[tag] = d

    trigger_wsl = "%s/%s" % (_wsl_base(), spec["trigger"])
    lib = spec["lib"]
    crashed_v, sig_v, tail_v = run_trigger(trigger_wsl, dirs["vuln"], lib, slug + "_vuln")
    if crashed_v is None:
        res["verdict"] = "TRIGGER_COMPILE_FAILED"; res["stage"] = "trigger:vuln"; res["detail"] = tail_v
        return res
    crashed_p, sig_p, tail_p = run_trigger(trigger_wsl, dirs["patch"], lib, slug + "_patch")
    if crashed_p is None:
        res["verdict"] = "TRIGGER_COMPILE_FAILED"; res["stage"] = "trigger:patch"; res["detail"] = tail_p
        return res

    res["vuln_crash"] = bool(crashed_v)
    res["patched_crash"] = bool(crashed_p)
    res["signal"] = "AddressSanitizer: %s" % sig_v if sig_v else ""
    res["stage"] = "complete"
    if crashed_v and not crashed_p:
        res["verdict"] = "EXPLOITABLE"
    elif not crashed_v:
        res["verdict"] = "NOT_TRIGGERED"
        res["detail"] = "trigger did not reproduce on the vulnerable build"
    else:
        res["verdict"] = "NOT_DISCRIMINATING"
        res["detail"] = "both builds crashed; trigger cannot separate vuln from patched"
    return res


_WSL_BASE = None


def _wsl_base():
    global _WSL_BASE
    if _WSL_BASE is None:
        rc, out = wsl("wslpath -a '%s'" % BASE.replace("\\", "\\\\"), 30)
        _WSL_BASE = out.strip() if rc == 0 and out.strip() else "/mnt/c"
    return _WSL_BASE


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="쉼표로 구분한 CVE 목록만 실행")
    ap.add_argument("--limit", type=int, help="findings 많은 순으로 N개만")
    ap.add_argument("--skip-blocked", action="store_true",
                    help="검증 불가/트리거 미확보 건을 결과에서 제외")
    args = ap.parse_args()

    specs = json.load(open(SPECS, encoding="utf-8"))
    if args.only:
        want = {c.strip() for c in args.only.split(",")}
        specs = [s for s in specs if s["cve"] in want]
    runnable = [s for s in specs if s["status"] == "verifiable-c" and not s["needs_trigger"]]
    runnable.sort(key=lambda s: -s["findings"])
    if args.limit:
        runnable = runnable[:args.limit]

    rc, _ = wsl("true", 30)
    if rc == 127:
        print("WSL 을 사용할 수 없습니다. 이 하네스는 WSL + gcc + ASan 이 필요합니다.")
        return 1
    wsl("mkdir -p %s" % WORK, 60)

    print("실행 대상: %d CVE (트리거 확보분)" % len(runnable))
    results = []
    for i, s in enumerate(runnable, 1):
        print("[%d/%d] %s (%s, findings=%d) ..." % (i, len(runnable), s["cve"],
                                                    s["component"], s["findings"]), flush=True)
        r = verify(s)
        results.append(r)
        print("        -> %s  vuln_crash=%s patched_crash=%s %s"
              % (r["verdict"], r["vuln_crash"], r["patched_crash"], r["signal"]), flush=True)

    if not args.skip_blocked:
        done = {r["cve"] for r in results}
        for s in specs:
            if s["cve"] not in done:
                results.append(verify(s))   # 분류/트리거 단계에서 즉시 반환

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(results, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    import collections
    c = collections.Counter(r["verdict"] for r in results)
    print("\n[검증 결과]")
    for k, v in c.most_common():
        print("  %-24s %4d" % (k, v))
    print("\noutput: %s" % os.path.relpath(OUT, BASE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
