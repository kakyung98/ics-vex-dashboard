"""Build and smoke-test the generated suite with installed MSVC/CMake/Ninja."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import argparse

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "evaluation/virtual_sw_100"


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--suite',default='evaluation/virtual_sw_100')
    parser.add_argument('--expected',type=int,default=100)
    parser.add_argument('--log-name',default='virtual_sw_100')
    parser.add_argument('--verify-only',action='store_true',help='Validate an already successful recorded build/test run without rebuilding')
    args=parser.parse_args()
    suite=(ROOT/args.suite).resolve()
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    vs = Path(subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-property", "installationPath"], text=True).strip())
    vcvars = vs / "Common7/Tools/VsDevCmd.bat"
    base = vs / "Common7/IDE/CommonExtensions/Microsoft/CMake"
    cmake = base / "CMake/bin/cmake.exe"
    ninja = base / "Ninja/ninja.exe"
    ctest = cmake.parent / "ctest.exe"
    env_script = ROOT / 'results' / (args.log_name+'_env.cmd')
    env_script.write_text(f'@echo off\ncall "{vcvars}" -arch=x64 -host_arch=x64 >nul\nif errorlevel 1 exit /b %errorlevel%\nset\n', encoding="utf-8")
    output = subprocess.check_output(["cmd.exe", "/d", "/c", str(env_script)], text=True, errors="replace")
    env = {k.upper():v for k,v in os.environ.items()}
    for line in output.splitlines():
        if "=" in line and not line.startswith("="):
            key, value = line.split("=", 1); env[key.upper()] = value
    build = suite / "build"
    logs = ROOT / 'results' / args.log_name
    logs.mkdir(parents=True, exist_ok=True)
    commands = [
        ("configure", [str(cmake), "-S", str(suite), "-B", str(build), "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={ninja.as_posix()}", "-DCMAKE_BUILD_TYPE=Debug"]),
        ("build", [str(cmake), "--build", str(build), "--parallel", "8"]),
        ("ctest", [str(ctest), "--test-dir", str(build), "--output-on-failure", "-j", "8"]),
    ]
    results = {"profile": "windows-msvc-x64-static-debug", "stages": []}
    if args.verify_only:
        results=json.loads((logs/'build_summary.json').read_text())
        assert {s['stage'] for s in results['stages']}=={'configure','build','ctest'}
        assert all(s['returncode']==0 for s in results['stages'])
    for stage, command in ([] if args.verify_only else commands):
        start = time.monotonic()
        print(f"{stage}: running", flush=True)
        with (logs / f"{stage}.log").open("w", encoding="utf-8") as f:
            p = subprocess.run(command, cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT, timeout=600)
        results["stages"].append({"stage":stage, "returncode":p.returncode, "seconds":round(time.monotonic()-start,3), "log":str((logs/f"{stage}.log").relative_to(ROOT))})
        (logs / "build_summary.json").write_text(json.dumps(results,indent=2),encoding="utf-8")
        print(f"{stage}: exit {p.returncode}",flush=True)
        if p.returncode: raise SystemExit(p.returncode)
    rows = json.loads((suite / "oracle/cases.json").read_text(encoding="utf-8"))
    binaries = []
    for row in rows:
        executable = build / "bin" / (row["id"]+".exe")
        record = {"id":row["id"],"sha256":hashlib.sha256(executable.read_bytes()).hexdigest(),"link_map":(build/"maps"/(row["id"]+".map")).exists()}
        if row["scenario"] == "guarded":
            run = subprocess.run([str(executable), "x"*220], capture_output=True, text=True, timeout=10)
            assert run.returncode == 4 and "rejected" in run.stdout and "library=" not in run.stdout
            record["oversize_guard_test"] = "pass"
        binaries.append(record)
    assert len(binaries)==args.expected and all(r["link_map"] for r in binaries)
    guard_count=sum(r['scenario']=='guarded' for r in rows)
    results.update({"binary_count":len(binaries),"binaries":binaries,"guard_tests":guard_count,"compile_commands":str((build/'compile_commands.json').relative_to(ROOT)),"smoke_tests":len(rows)})
    (logs / "build_summary.json").write_text(json.dumps(results,indent=2),encoding="utf-8")
    manifest=json.loads((suite/"manifest.json").read_text(encoding="utf-8"));manifest["build_verified"]=True;manifest["build_verification_scope"]=f"MSVC build, {len(rows)} benign smoke tests, {guard_count} guard checks; not CVE exploitability verification"
    (suite/"manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    print(f"{len(rows)} binaries, {len(rows)} smoke tests, {guard_count} guard checks: PASS",flush=True)


if __name__ == "__main__": main()
